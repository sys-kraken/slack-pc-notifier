"""
Slack -> PC Notifier: Render relay
-----------------------------------
Receives Slack Events API callbacks (message events for every conversation
you're a member of), verifies the request came from Slack, filters out noise
(your own messages, edits/deletes, bot chatter), resolves friendly
channel/user names, and forwards a small JSON payload to a listener running
on your PC (reached through your Cloudflare Tunnel).

Env vars required (set these in the Render dashboard, never commit them):
  SLACK_SIGNING_SECRET   - from Slack app's Basic Information page
  SLACK_USER_TOKEN       - xoxp-... user OAuth token (see SETUP.md)
  SLACK_SELF_USER_ID      - your Slack user ID (e.g. U0123ABC456), used to
                             skip notifying you about your own messages
  PC_NOTIFY_URL           - public URL of your PC listener, e.g.
                             https://notify.yourdomain.com/notify
  RELAY_SHARED_SECRET     - random string shared with the PC listener so it
                             only accepts requests that came from this relay
"""

import hashlib
import hmac
import os
import re
import time
import logging

import requests
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("slack-relay")

app = Flask(__name__)

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_USER_TOKEN = os.environ["SLACK_USER_TOKEN"]
SLACK_SELF_USER_ID = os.environ.get("SLACK_SELF_USER_ID", "")
PC_NOTIFY_URL = os.environ["PC_NOTIFY_URL"]
RELAY_SHARED_SECRET = os.environ["RELAY_SHARED_SECRET"]

SLACK_API = "https://slack.com/api"

# Simple in-memory caches (fine for a single personal-use dyno)
_channel_name_cache = {}
_user_name_cache = {}
_seen_event_ids = set()  # de-dupe Slack's at-least-once retries

SUBTYPES_TO_IGNORE = {
    "message_changed",
    "message_deleted",
    "message_replied",
    "channel_join",
    "channel_leave",
    "bot_message",
}


def verify_slack_signature(req) -> bool:
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    if not timestamp:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False  # protect against replay attacks
    except ValueError:
        return False

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    computed = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()
    slack_sig = req.headers.get("X-Slack-Signature", "")
    return hmac.compare_digest(computed, slack_sig)


def slack_api_get(method, params):
    try:
        resp = requests.get(
            f"{SLACK_API}/{method}",
            headers={"Authorization": f"Bearer {SLACK_USER_TOKEN}"},
            params=params,
            timeout=5,
        )
        data = resp.json()
        if not data.get("ok"):
            log.warning("Slack API %s failed: %s", method, data.get("error"))
            return None
        return data
    except requests.RequestException as e:
        log.warning("Slack API %s error: %s", method, e)
        return None


def resolve_channel_name(channel_id, channel_type):
    if channel_id in _channel_name_cache:
        return _channel_name_cache[channel_id]

    name = channel_id
    if channel_type == "im":
        name = "Direct Message"
    else:
        data = slack_api_get("conversations.info", {"channel": channel_id})
        if data:
            ch = data.get("channel", {})
            name = "#" + ch.get("name", channel_id) if ch.get("name") else channel_id

    _channel_name_cache[channel_id] = name
    return name


def resolve_user_name(user_id):
    if not user_id:
        return "Someone"
    if user_id in _user_name_cache:
        return _user_name_cache[user_id]

    name = user_id
    data = slack_api_get("users.info", {"user": user_id})
    if data:
        user = data.get("user", {})
        profile = user.get("profile", {})
        name = profile.get("display_name") or profile.get("real_name") or user.get("name") or user_id

    _user_name_cache[user_id] = name
    return name


def forward_to_pc(title, message):
    try:
        resp = requests.post(
            PC_NOTIFY_URL,
            json={"title": title, "message": message},
            headers={"X-Relay-Secret": RELAY_SHARED_SECRET},
            timeout=6,
        )
        if resp.status_code >= 300:
            log.warning("PC listener returned %s: %s", resp.status_code, resp.text[:200])
    except requests.RequestException as e:
        # Your PC might be offline / tunnel down - don't crash the relay, just log it.
        log.warning("Could not reach PC listener: %s", e)


# HEAD is what uptime monitors (UptimeRobot etc.) send by default. Flask
# derives it from GET automatically, but it's listed explicitly so a keep-warm
# pinger can't be broken by an innocent-looking edit to this route.
# Slack sends its own markup rather than display text: user mentions arrive as
# <@U123>, channels as <#C123|name>, links as <url|label>, and &<> are HTML
# escaped. Left alone, a toast reads "<@U06F8T2AVK8> sent you a ticket".
_REF_RE = re.compile(r"<([@#!])([^>|]+)(?:\|([^>]*))?>")
_LINK_RE = re.compile(r"<((?:https?|mailto|tel):[^>|]+)(?:\|([^>]*))?>")


def humanize_slack_text(text: str) -> str:
    """Turn Slack's mrkdwn into something readable in a Windows toast."""
    if not text:
        return text

    # Links first, so their URLs can't be mistaken for a <...> reference.
    text = _LINK_RE.sub(lambda m: m.group(2) or m.group(1), text)

    def _ref(m):
        kind, body, label = m.group(1), m.group(2), m.group(3)
        if kind == "@":
            # Slack usually omits the label, so resolve the id via the API.
            return "@" + (label or resolve_user_name(body))
        if kind == "#":
            if label:
                return "#" + label
            name = resolve_channel_name(body, "channel")
            return name if name.startswith("#") else "#" + name
        if kind == "!":
            if body in ("here", "channel", "everyone"):
                return "@" + body
            if body.startswith("subteam^"):
                return label or "@team"
            return label or ("@" + body)
        return m.group(0)

    text = _REF_RE.sub(_ref, text)

    # Unescape last: doing it earlier could manufacture a bogus <...> ref.
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")



@app.route("/health", methods=["GET", "HEAD"])
def health():
    return jsonify(status="ok")


@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_signature(request):
        return "invalid signature", 401

    body = request.get_json(silent=True) or {}

    # Slack's one-time URL verification handshake when you first set the
    # Events API request URL in the Slack app config.
    if body.get("type") == "url_verification":
        return jsonify(challenge=body.get("challenge"))

    if body.get("type") != "event_callback":
        return "", 200

    event_id = body.get("event_id")
    if event_id:
        if event_id in _seen_event_ids:
            return "", 200  # already processed this one (Slack retry)
        _seen_event_ids.add(event_id)
        if len(_seen_event_ids) > 2000:
            _seen_event_ids.clear()

    event = body.get("event", {})

    if event.get("type") == "message" and event.get("subtype") not in SUBTYPES_TO_IGNORE:
        user_id = event.get("user")

        # Don't notify me about my own messages.
        if user_id and user_id == SLACK_SELF_USER_ID:
            return "", 200

        text = event.get("text", "").strip()
        if not text:
            return "", 200  # e.g. a file share with no text - skip for now

        channel_id = event.get("channel", "")
        channel_type = event.get("channel_type", "")

        sender = resolve_user_name(user_id)
        channel_label = resolve_channel_name(channel_id, channel_type)

        if channel_type == "im":
            title = f"Slack DM from {sender}"
        else:
            title = f"{sender} in {channel_label}"

        forward_to_pc(title, humanize_slack_text(text)[:300])

    return "", 200


if __name__ == "__main__":
    # Local dev only; Render runs this via gunicorn (see render.yaml).
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
