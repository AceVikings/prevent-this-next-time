"""Hermes v0.23.1 startup guard for a dedicated Telegram profile.

Run using the Python interpreter from the Hermes installation. This is an
operator command, never an agent tool.
"""
from __future__ import annotations

import argparse
import importlib
import os
import sqlite3
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

plugin = importlib.import_module("prevent-this-next-time")
core = importlib.import_module("prevent-this-next-time.rulebook")
from_module = importlib.import_module("prevent-this-next-time.adapters")
Rejected, require = from_module.Rejected, from_module.require

NAME = "prevent-this-next-time"
ALLOWED_TOOLSETS = {"rulebook", "clarify", "no_mcp"}
TOP_LEVEL = {"_config_version", "model", "agent", "gateway", "platforms", "platform_toolsets",
             "mcp_servers", "plugins", "skills", "known_plugin_toolsets"}


def validate_raw(raw):
    require(isinstance(raw, dict) and raw.keys() <= TOP_LEVEL, "Unexpected Hermes configuration in protected profile.")
    require(raw.get("mcp_servers", {}) == {}, "Protected startup refused: MCP servers are configured.")
    require(raw.get("gateway") == {"standalone": True}, "Set gateway.standalone: true and no other gateway options.")
    require(raw.get("plugins") == {"enabled": [NAME]}, "Enable only Prevent This Next Time.")
    require(raw.get("skills") == {"inline_shell": False}, "Disable inline skill shell.")
    require(not raw.get("agent", {}).keys() - {"disabled_toolsets"}, "Unexpected protected agent options.")
    model = raw.get("model", {})
    require(isinstance(model, (str, dict)) and (isinstance(model, str) or model.keys() <= {
        "default", "provider", "base_url", "context_length"}), "Unexpected model settings.")
    platforms = raw.get("platforms", {})
    require(set(platforms) == {"telegram"} and platforms["telegram"].get("enabled") is True
            and platforms["telegram"].keys() <= {"enabled", "extra"}
            and platforms["telegram"].get("extra", {}).keys() <= {"fallback_ips"},
            "Telegram must be the only configured gateway adapter.")
    sets = raw.get("platform_toolsets", {})
    require(set(sets) == {"telegram", "cli"}, "Pin both Telegram and CLI toolsets.")
    for values in sets.values():
        require(isinstance(values, list) and all(isinstance(x, str) for x in values)
                and {"rulebook", "no_mcp"} <= set(values) <= ALLOWED_TOOLSETS,
                "Only rulebook, no_mcp, and optional clarify toolsets are allowed.")


def preflight(home, init=False):
    from ruamel.yaml import YAML

    raw = YAML(typ="safe").load((home / "config.yaml").read_text())
    validate_raw(raw)
    config, _ = core.read_config(home)
    require(config["protected"], "Set protected: true in the rulebook configuration.")
    require(not any((home / folder / "telegram-approved.json").exists()
                    for folder in ("pairing", "platforms/pairing")), "Remove Telegram pairing grants from this dedicated profile.")
    require(not (home / "gateway.json").exists(), "Remove legacy gateway.json.")
    require(not (home / "cron" / "jobs.json").exists(), "Use a fresh profile with no cron jobs file.")
    if init:
        core.initialize(home)
        return []

    with core.Rulebook(home, None).transaction():
        pass

    from agent.secret_scope import get_secret
    from gateway.run import load_gateway_config_for_runner
    from hermes_cli import plugins
    from hermes_cli.config import load_config_readonly
    from hermes_cli.tools_config import _get_platform_tools
    from hermes_constants import get_hermes_home
    from model_tools import get_tool_definitions

    require(get_hermes_home().resolve() == home, "Hermes resolved a different profile.")
    plugins.discover_plugins()
    effective = load_config_readonly()
    require(not effective.get("mcp_servers"), "Protected startup refused: effective MCP servers are configured.")
    gateway = load_gateway_config_for_runner()
    require(not gateway.multiplex_profiles and not gateway.profile_routes, "Gateway must be standalone.")
    require({p.value for p, c in gateway.platforms.items() if c.enabled} == {"telegram"} and
            {p.value for p in gateway.get_connected_platforms()} == {"telegram"},
            "Only Telegram may be enabled and connected in the protected gateway.")
    owner = config["owner"]["telegram_user_id"]
    grants = ("TELEGRAM_ALLOW_ALL_USERS", "TELEGRAM_GROUP_ALLOWED_USERS", "TELEGRAM_GROUP_ALLOWED_CHATS",
              "TELEGRAM_ALLOWED_CHATS", "TELEGRAM_ALLOW_BOTS", "GATEWAY_ALLOWED_USERS", "GATEWAY_ALLOW_ALL_USERS")
    require(get_secret("TELEGRAM_ALLOWED_USERS", "") == owner and not any(get_secret(key) for key in grants),
            "Set Telegram's allowlist to exactly the owner and remove supplemental Telegram or gateway grants.")
    require(os.environ.get("RULEBOOK_PROTECTED") == "1", "Protected launcher marker was overridden.")

    inventories = set()
    for platform in ("telegram", "cli"):
        enabled = _get_platform_tools(effective, platform, include_default_mcp_servers=False)
        require(set(enabled) <= ALLOWED_TOOLSETS, "Effective profile toolsets include an alternate path.")
        tools = {t["function"]["name"] for t in get_tool_definitions(
            enabled_toolsets=sorted(enabled), quiet_mode=True, skip_tool_search_assembly=True)}
        require(plugin.TOOLS <= tools <= plugin.SAFE_TOOLS, "Effective profile tools are missing or unsafe.")
        inventories |= tools
    require(plugins.get_pre_tool_call_block_message("rulebook_unapproved_probe", {}) and
            plugins.has_hook("post_gateway_admission"), "Policy hooks did not load.")
    return sorted(inventories)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    home = args.home.expanduser().resolve(strict=True)
    os.environ["HERMES_HOME"] = str(home)
    os.environ["RULEBOOK_PROTECTED"] = "1"
    sys.argv[:] = ["hermes", "gateway", "run"]
    try:
        # Load profile env in the same process used to validate and launch Hermes.
        from hermes_cli import main as hermes
        tools = preflight(home, init=args.init)
        if args.init:
            print("Initialized rulebook state.")
        else:
            print("Protected profile verified. Tools: " + ", ".join(tools), flush=True)
            if not args.check:
                hermes.main()
    except (Rejected, OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, sqlite3.Error) as exc:
        print(f"Protected startup refused ({type(exc).__name__}): " +
              (str(exc) if isinstance(exc, Rejected) else "profile or runtime state is invalid."), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
