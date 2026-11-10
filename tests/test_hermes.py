import importlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERMES_PYTHON = os.getenv("HERMES_TEST_PYTHON")
core = importlib.import_module("prevent-this-next-time.rulebook")


@unittest.skipUnless(HERMES_PYTHON, "set HERMES_TEST_PYTHON to the pinned Hermes interpreter")
class HermesIntegration(unittest.TestCase):
    def fixture(self, parent, name, protected, alternate):
        home = parent / name
        (home / "rulebook").mkdir(parents=True)
        (home / "plugins").mkdir()
        (home / "plugins" / "prevent-this-next-time").symlink_to(ROOT / "prevent-this-next-time")
        config = json.loads((ROOT / "examples/rulebook.json").read_text())
        config["protected"] = protected
        (home / "rulebook" / "config.json").write_text(json.dumps(config))
        raw = (ROOT / "examples/protected-config.yaml").read_text()
        log = parent / f"{name}.jsonl"
        if alternate:
            raw = raw.replace("mcp_servers: {}", "mcp_servers:\n  alternate:\n    command: "
                              + json.dumps(HERMES_PYTHON) + "\n    args: " + json.dumps([
                                  str(ROOT / "tests/alternate_writer.py"), str(log)]) + "\n    lazy: false\n    env: " + json.dumps({
                                      "PYTHONPATH": os.getenv("PYTHONPATH", "")}))
        (home / "config.yaml").write_text(raw)
        core.initialize(home)
        return home, log

    def run_child(self, *args, expected=0, extra_env=None):
        env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "PYTHONPATH") if key in os.environ}
        env.update(extra_env or {})
        result = subprocess.run([HERMES_PYTHON, *map(str, args)], cwd=ROOT, env=env,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_actual_alternate_mcp_route_and_protected_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            ordinary, ordinary_log = self.fixture(parent, "ordinary", False, True)
            self.assertIn("actual alternate MCP tool wrote",
                          self.run_child(ROOT / "tests/hermes_fixture.py", "ordinary", ordinary, ordinary_log))
            protected, protected_log = self.fixture(parent, "protected", True, True)
            self.assertIn("MCP servers are configured", self.run_child(
                ROOT / "scripts/protected_gateway.py", "--home", protected, "--check", expected=1))
            self.assertFalse(protected_log.exists())
            healthy, healthy_log = self.fixture(parent, "healthy", True, False)
            self.assertIn("alternate dispatch denied",
                          self.run_child(ROOT / "tests/hermes_fixture.py", "healthy", healthy, healthy_log))


    def test_protected_refuses_supplemental_gateway_principals(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, _ = self.fixture(Path(tmp), "protected", True, False)
            env = {"TELEGRAM_BOT_TOKEN": "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                   "TELEGRAM_ALLOWED_USERS": "12345678", "GATEWAY_ALLOWED_USERS": "*"}
            self.assertIn("remove supplemental", self.run_child(
                ROOT / "scripts/protected_gateway.py", "--home", home, "--check", expected=1, extra_env=env))
            (home / "pairing").mkdir(exist_ok=True)
            (home / "pairing" / "telegram-approved.json").write_text('{"9876": {}}')
            self.assertIn("Remove Telegram pairing grants", self.run_child(
                ROOT / "scripts/protected_gateway.py", "--home", home, "--check", expected=1))


if __name__ == "__main__":
    unittest.main()
