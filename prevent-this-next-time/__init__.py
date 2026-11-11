"""Hermes plugin for connector writes governed by a chat-managed rulebook."""
from __future__ import annotations

import asyncio
import os
import re
import sqlite3

from .adapters import Rejected, encode, send
from .rulebook import Rulebook, read_config

TOOLSET = "rulebook"
TOOLS = frozenset({"rulebook_capabilities", "rulebook_write"})
SAFE_TOOLS = TOOLS | {"clarify"}
CONTROL = re.compile(r"^(review|approve|deny) ([a-f0-9]{16})[.!]?$", re.I)
RULE = re.compile(r"^(?:from now on,\s*)?(ask me before|never) (?:running )?([\w.-]+) (?:in|to|on|for) ([#@\w.-]+?)[.!]?$", re.I)
SLACK = re.compile(r"^(?:from now on,\s*)?(ask me before|never) posting in (#[\w.-]+?)[.!]?$", re.I)
MANAGE = re.compile(r"^(undo|check) rule ([\w.-]+) (?:in|to|on|for) ([#@\w.-]+?)[.!]?$", re.I)
PREFIX = re.compile(r"^(?:from now on\b|ask me before\b|never\b|(?:undo|check) rule\b|(?:review|approve|deny) [a-f0-9]{8,}\b)", re.I)
SUGGESTION = ("Try: From now on, ask me before running slack.post in #customer-updates. "
              "Or: Never run slack.post in #customer-updates. Send Rulebook for supported actions.")
BLOCK_RUN = re.compile(r"^never run ([\w.-]+) (?:in|to|on|for) ([#@\w.-]+?)[.!]?$", re.I)
SLACK_BLOCK = re.compile(r"^(?:from now on,\s*)?never post in (#[\w.-]+?)[.!]?$", re.I)


def parse(text):
    if text.lower().rstrip(".!") == "rulebook":
        return ("list",)
    if match := CONTROL.fullmatch(text):
        return (match[1].lower(), match[2].lower())
    if match := MANAGE.fullmatch(text):
        return (match[1].lower(), match[2].lower(), match[3].lower())
    if match := SLACK_BLOCK.fullmatch(text):
        return ("block", "slack.post", match[1].lower())
    if match := SLACK.fullmatch(text):
        return ("ask" if match[1].lower().startswith("ask") else "block", "slack.post", match[2].lower())
    if match := BLOCK_RUN.fullmatch(text):
        return ("block", match[1].lower(), match[2].lower())
    if match := RULE.fullmatch(text):
        return ("ask" if match[1].lower().startswith("ask") else "block", match[2].lower(), match[3].lower())
    if PREFIX.match(text):
        return ("help",)
    return None


def authorized(config, platform, source):
    owner = config["owner"].get("telegram_user_id")
    return (platform == source.get("platform") == "telegram" and source.get("chat_type") == "dm"
            and source.get("chat_id") == source.get("user_id") == owner and not source.get("thread_id")
            and not source.get("is_bot") and not source.get("shared_session"))


def capabilities(book):
    return {name: {"fields": list(action.fields), "targets": sorted(action.targets)}
            for name, action in book.actions.items()}


def inbound(home, deliver, text, platform, source, *, owner_authenticated=False):
    command = parse(text.strip()) if isinstance(text, str) and len(text) <= 512 else None
    if command is None:
        return None
    try:
        book = Rulebook(home, deliver)
        if not owner_authenticated and not authorized(book.config, platform, source):
            return {"action": "handled", "reply": "Only the authenticated owner can manage rules."}
        if command[0] == "help":
            reply = SUGGESTION
        elif command[0] == "list":
            lines = [f"{name}: {', '.join(action['targets'])}" for name, action in capabilities(book).items()]
            reply = "Enforceable actions:\n" + "\n".join(lines)[:2900]
        elif len(command) == 2:
            reply = book.approval(command[1], command[0])
        else:
            rule = book.change(command[1], command[2], command[0])
            reply = f"{rule['mode'].upper()}: {rule['action']} → {rule['destination']}"
            if rule["revision"]:
                reply += f" · {rule['revision']}"
    except Rejected as exc:
        reply = str(exc)
    except (OSError, ValueError, sqlite3.Error):
        reply = "Rulebook state is unavailable. No approval can be retried without checking the provider."
    return {"action": "handled", "reply": reply}


def gate(home, name):
    try:
        config, _ = read_config(home)
    except (Rejected, OSError, ValueError):
        # The installed plugin defaults closed on unreadable state.
        return {"action": "block", "message": "Rulebook configuration is unavailable."}
    if (config["protected"] or os.environ.get("RULEBOOK_PROTECTED") == "1") and name not in SAFE_TOOLS:
        return {"action": "block", "message": "Tool is outside the protected profile's allowlist."}
    return None



def native_owner_context(get_env):
    """Require the gateway's current authenticated OS owner, never the model's arguments."""
    if not hasattr(os, "getuid"):
        return None
    owner = f"uid:{os.getuid()}"
    source = {key: get_env(f"HERMES_SESSION_{name}", "") for key, name in (
        ("platform", "PLATFORM"), ("user_id", "USER_ID"), ("actor_id", "ACTOR_ID"),
        ("chat_id", "CHAT_ID"), ("chat_type", "CHAT_TYPE"),
    )}
    if (source["platform"] != "local" or source["user_id"] != owner or source["actor_id"] != owner
            or source["chat_type"] != "dm" or not source["chat_id"]
            or get_env("HERMES_CRON_SESSION", "") == "1"):
        return None
    return source


def register(ctx):
    from agent.secret_scope import get_secret
    from hermes_constants import get_hermes_home
    from gateway.session_context import get_session_env

    # Hermes installs user plugins per profile. Use the active routed home for every invocation.
    def deliver(action, payload):
        return send(action, payload, get_secret)

    def opened():
        home = get_hermes_home()
        book = Rulebook(home, deliver)
        if book.config["protected"] and os.environ.get("RULEBOOK_PROTECTED") != "1":
            raise Rejected("Start this profile with the protected launcher.")
        return book

    def safe(handler):
        def invoke(args, **_):
            try:
                return encode(handler(opened(), args))
            except Rejected as exc:
                return encode({"status": "refused", "message": str(exc)})
            except (OSError, ValueError, sqlite3.Error):
                return encode({"status": "unavailable", "message": "Rulebook state unavailable. Check the provider before retrying."})
        return invoke

    def list_tools(book, _):
        return capabilities(book)

    def write(book, args):
        if not isinstance(args, dict) or set(args) != {"action", "target", "fields"}:
            raise Rejected("Provide exactly action, target, and fields.")
        return book.write(args["action"], args["target"], args["fields"])

    for name, handler, description, properties in (
        ("rulebook_capabilities", list_tools, "List connector actions the rulebook can enforce and their operator-configured target aliases.", {}),
        ("rulebook_write", write, "Run an enforceable connector write. A rule can block it or stage it for owner approval; never claim it was sent without a receipt.",
         {"action": {"type": "string"}, "target": {"type": "string"},
          "fields": {"type": "object", "additionalProperties": {"type": "string"}}}),
    ):
        ctx.register_tool(name=name, toolset=TOOLSET, handler=safe(handler), schema={
            "name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False},
        })

    def handle_inbound(text, platform, source):
        home = get_hermes_home()
        protected = os.environ.get("RULEBOOK_PROTECTED") == "1"
        command = parse(text.strip()) if isinstance(text, str) and len(text) <= 512 else None
        if not protected and command is None:
            return None
        try:
            book = opened()
            if protected and not authorized(book.config, platform, source):
                return {"action": "handled", "reply": "This profile is available only in the owner's Telegram DM."}
        except (Rejected, OSError, ValueError, sqlite3.Error):
            return {"action": "handled", "reply": "Rulebook is unavailable. Start the configured profile with its launcher."}
        return inbound(home, deliver, text, platform, source)

    async def handle(text, platform, source, **_):
        return await asyncio.to_thread(handle_inbound, text, platform, source)

    def handle_native(user_message, parent_session_id="", **_):
        if get_session_env("HERMES_SESSION_PLATFORM", "") != "local":
            return None
        command = parse(user_message.strip()) if isinstance(user_message, str) and len(user_message) <= 512 else None
        try:
            book = opened()
            source = native_owner_context(get_session_env)
            if parent_session_id or source is None or not book.config["owner"].get("local", True):
                if command or book.config["protected"]:
                    return {"action": "block", "message": "Only the authenticated local owner can use this profile."}
                return None
            if command is None:
                return None
            result = inbound(get_hermes_home(), deliver, user_message, "local", source,
                             owner_authenticated=True)
            return {"action": "block", "message": result["reply"]}
        except (Rejected, OSError, ValueError, sqlite3.Error):
            if command or os.environ.get("RULEBOOK_PROTECTED") == "1":
                return {"action": "block", "message": "Rulebook is unavailable. Check this profile's setup."}
            return None

    ctx.register_hook("pre_llm_call", handle_native)
    ctx.register_hook("post_gateway_admission", handle)
    ctx.register_hook("pre_tool_call", lambda tool_name, **_: gate(get_hermes_home(), tool_name))
