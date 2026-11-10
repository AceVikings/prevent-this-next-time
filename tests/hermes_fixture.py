"""Child process for the pinned Hermes integration suite."""
import asyncio
import importlib
import io
import json
import os
import sys
import urllib.request
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

mode, root, log = sys.argv[1:]
sys.argv[:] = ["hermes", "gateway", "run"]
os.environ["HERMES_HOME"] = root
os.environ["TELEGRAM_BOT_TOKEN"] = "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
os.environ["TELEGRAM_ALLOWED_USERS"] = "12345678"
os.environ["RULEBOOK_SLACK_TOKEN"] = "fixture-token"
if mode == "healthy":
    os.environ["RULEBOOK_PROTECTED"] = "1"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hermes_cli import main, plugins
from gateway.run_inbound_consumer import run_post_admission_hook
from gateway.session import SessionSource
from gateway.platforms.base import BasePlatformAdapter
from gateway.config import Platform
from model_tools import handle_function_call
from tools.mcp_tool_discovery import discover_mcp_tools

plugins.discover_plugins()
assert plugins.has_hook("post_gateway_admission")
source = SessionSource(platform=Platform.TELEGRAM, chat_id="12345678", user_id="12345678")


def chat(text):
    return asyncio.run(run_post_admission_hook(
        SimpleNamespace(config=None), SimpleNamespace(message_id="1", text=text), source, "test"
    ))


def guarded(text):
    return json.loads(handle_function_call("rulebook_write", {
        "action": "slack.post", "target": "#customer-updates", "fields": {"text": text},
    }, enabled_toolsets=["rulebook"]))


assert chat("From now on, never post in #customer-updates.")[1].startswith("BLOCK:")
assert guarded("guarded-block")["status"] == "blocked"
assert not Path(log).exists()
if mode == "ordinary":
    names = discover_mcp_tools()
    assert names, "MCP alternate server did not register. Install Hermes with the mcp extra."
    name = "mcp__alternate__post"
    assert name in names, names
    result = handle_function_call(name, {"text": "ordinary-bypass"}, enabled_toolsets=["alternate"])
    assert "fixture-1" in result, result
    assert json.loads(Path(log).read_text()) == {"channel": "C0123456789", "text": "ordinary-bypass"}
    print("Ordinary control: guarded write blocked; actual alternate MCP tool wrote to the fixture.")
else:
    launcher = importlib.import_module("scripts.protected_gateway")
    assert set(launcher.preflight(Path(root).resolve())) == {"clarify", "rulebook_capabilities", "rulebook_write"}
    alternate = handle_function_call("mcp__alternate__post", {"text": "protected-bypass"})
    assert "allowlist" in alternate, alternate
    assert chat("From now on, ask me before posting in #customer-updates.")[1].startswith("ASK:")
    content = "approved exact body ![img](https://example.invalid/p.png) MEDIA:/private/test.pdf"
    staged = guarded(content)
    assert staged["status"] == "staged", staged
    ident = staged["id"]
    preview = chat(f"Review {ident}")[1]
    assert "approved exact body" in preview
    assert not BasePlatformAdapter.extract_images(preview)[0]
    assert not BasePlatformAdapter.extract_media(preview)[0]
    assert not Path(log).exists()
    with patch.object(urllib.request, "build_opener") as opener:
        response = opener.return_value.open
        response.return_value = io.BytesIO(b'{"ok":true,"ts":"123.45"}')
        assert "Receipt: 123.45" in chat(f"Approve {ident}")[1]
        assert "unavailable" in chat(f"Approve {ident}")[1]
        response.assert_called_once()
        request = response.call_args.args[0]
        assert request.full_url == "https://slack.com/api/chat.postMessage"
        assert request.headers["Authorization"] == "Bearer fixture-token"
        body = json.loads(request.data)
        assert body["channel"] == "C0123456789" and body["text"] == content
    print("Protected fixture: alternate dispatch denied; owner review shows the exact staged write.")
