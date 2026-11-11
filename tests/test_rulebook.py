import concurrent.futures
import importlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

plugin = importlib.import_module("prevent-this-next-time")
core = importlib.import_module("prevent-this-next-time.rulebook")
adapters = importlib.import_module("prevent-this-next-time.adapters")
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "rulebook.json"
OWNER = {"platform": "telegram", "chat_type": "dm", "chat_id": "12345678", "user_id": "12345678"}


class RulebookTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.file = self.home / "rulebook" / "config.json"
        self.file.parent.mkdir()
        self.file.write_text(EXAMPLE.read_text())
        core.initialize(self.home)
        self.writes = []
        self.now = 1000
        self.book = core.Rulebook(self.home, self.deliver, lambda: self.now)

    def deliver(self, action, request):
        self.writes.append((action.name, request))
        return "test-receipt"

    def command(self, text, **source):
        return plugin.inbound(self.home, self.deliver, text, "telegram", OWNER | source)["reply"]

    def stage(self, text="exact draft"):
        self.book.change("slack.post", "#customer-updates", "ask")
        return self.book.write("slack.post", "#customer-updates", {"text": text})["id"]

    def test_one_message_block_and_undo(self):
        self.assertIn("BLOCK: slack.post", self.command("From now on, never post in #customer-updates."))
        self.assertIn("BLOCK:", self.command("Check rule slack.post in #customer-updates"))
        fresh = core.Rulebook(self.home, self.deliver)
        self.assertEqual(fresh.write("slack.post", "#customer-updates", {"text": "blocked"})["status"], "blocked")
        self.assertEqual(self.writes, [])
        self.assertEqual(fresh.write("slack.post", "#sandbox", {"text": "allowed"})["status"], "sent")
        self.assertIn("ALLOW:", self.command("Undo rule slack.post in #customer-updates"))
        self.assertEqual(fresh.write("slack.post", "#customer-updates", {"text": "allowed"})["status"], "sent")

    def test_all_example_connectors_use_same_policy(self):
        for name, action in self.book.actions.items():
            target = next(iter(action.targets))
            self.assertIn("ASK:", self.command(f"From now on, ask me before running {name} in {target}."))
            fields = dict.fromkeys(action.fields, "example")
            book = core.Rulebook(self.home, self.deliver)
            ident = book.write(name, target, fields)["id"]
            self.assertIn(name, self.command(f"Review {ident}"))
            self.assertIn("Sent", self.command(f"Approve {ident}"))
        self.assertEqual([name for name, _ in self.writes], list(self.book.actions))

    def test_no_approval_from_other_user_group_or_platform(self):
        self.book = core.Rulebook(self.home, self.deliver)
        ident = self.stage("approved content only")
        for source in ({"user_id": "987654"}, {"chat_type": "group"}, {"chat_id": "987654"},
                       {"platform": "slack"}, {"shared_session": True}, {"is_bot": True}):
            self.assertIn("Only the authenticated owner", self.command(f"Approve {ident}", **source))
        self.assertIn("Review the exact", self.command(f"Approve {ident}"))
        self.assertIn("approved content only", self.command(f"Review {ident}"))
        self.assertEqual(self.writes, [])
        self.assertIn("Sent", self.command(f"Approve {ident}"))
        self.assertIn("unavailable", self.command(f"Approve {ident}"))
        self.assertEqual([request["body"]["text"] for _, request in self.writes], ["approved content only"])

    def test_deny_expire_and_invalidate(self):
        ident = self.stage()
        self.assertIn("Nothing sent", self.book.approval(ident, "deny"))
        with self.assertRaises(adapters.Rejected):
            self.book.approval(ident, "approve")
        ident = self.stage()
        self.now += core.TTL
        with self.assertRaises(adapters.Rejected):
            self.book.approval(ident, "approve")
        ident = self.stage()
        self.book.change("slack.post", "#customer-updates", "block")
        with self.assertRaises(adapters.Rejected):
            self.book.approval(ident, "approve")
        self.assertEqual(self.writes, [])

    def test_adapter_or_owner_change_invalidates_staged_payload(self):
        ident = self.stage()
        self.book.approval(ident, "review")
        config = json.loads(self.file.read_text())
        config["owner"]["telegram_user_id"] = "4321"
        self.file.write_text(json.dumps(config))
        with self.assertRaisesRegex(adapters.Rejected, "stale"):
            self.book.approval(ident, "approve")
        self.assertEqual(self.writes, [])

    def test_concurrent_approve_is_one_shot(self):
        ident = self.stage()
        self.book.approval(ident, "review")
        barrier = threading.Barrier(2)

        def approve():
            barrier.wait()
            try:
                return self.book.approval(ident, "approve")
            except adapters.Rejected:
                return "rejected"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: approve(), range(2)))
        self.assertEqual(results.count("rejected"), 1)
        self.assertEqual(len(self.writes), 1)

    def test_ambiguous_delivery_cannot_be_replayed(self):
        ident = self.stage()

        def unknown(action, request):
            self.deliver(action, request)
            raise adapters.DeliveryUnknown("unknown")

        self.book.approval(ident, "review")
        self.book.deliver = unknown
        with self.assertRaises(adapters.DeliveryUnknown):
            self.book.approval(ident, "approve")
        with self.assertRaises(adapters.Rejected):
            self.book.approval(ident, "approve")
        self.assertEqual(len(self.writes), 1)

    def test_fail_closed_on_missing_database_or_unknown_target(self):
        with self.assertRaises(adapters.Rejected):
            self.book.write("slack.post", "C0123456790", {"text": "raw id"})
        with self.assertRaises(adapters.Rejected):
            self.book.write("slack.post", "#sandbox", {"text": "injection", "channel": "elsewhere"})
        self.book.db.unlink()
        with self.assertRaises(core.sqlite3.Error):
            self.book.write("slack.post", "#sandbox", {"text": "missing state"})
        self.assertFalse(self.book.db.exists())
        self.assertEqual(self.writes, [])

    def test_aliases_share_rule_for_same_canonical_destination(self):
        config = json.loads(self.file.read_text())
        config["actions"]["slack.post"]["targets"]["#alias"] = "C0123456789"
        self.file.write_text(json.dumps(config))
        fresh = core.Rulebook(self.home, self.deliver)
        fresh.change("slack.post", "#customer-updates", "block")
        self.assertEqual(fresh.write("slack.post", "#alias", {"text": "blocked"})["status"], "blocked")

    def test_github_case_alias_cannot_bypass_rule(self):
        config = json.loads(self.file.read_text())
        config["actions"]["github.create_issue"]["targets"]["case-variant"] = "EXAMPLE/Example"
        self.file.write_text(json.dumps(config))
        book = core.Rulebook(self.home, self.deliver)
        book.change("github.create_issue", "example-repo", "block")
        self.assertEqual(book.write("github.create_issue", "case-variant",
                                    {"title": "test", "text": "test"})["status"], "blocked")
        self.assertEqual(self.writes, [])

    def test_action_alias_cannot_reach_same_provider_route(self):
        actions = json.loads(EXAMPLE.read_text())["actions"]
        alternate = json.loads(json.dumps(actions["github.create_issue"]))
        alternate["targets"] = {"alternate": "example"}
        alternate["https"]["url"] = "https://api.github.com/repos/example/{destination}/issues"
        actions["github.alternate"] = alternate
        with self.assertRaisesRegex(adapters.Rejected, "same HTTPS write endpoint"):
            adapters.parse_actions(actions)

    def test_preview_keeps_exact_content_without_active_chat_syntax(self):
        text = "![img](https://example.invalid/p.png) MEDIA:/private/a.pdf ``` <b>literal</b>"
        self.book = core.Rulebook(self.home, self.deliver)
        ident = self.stage(text)
        preview = self.command(f"Review {ident}").split("```")[1].removeprefix("json\n")
        self.assertEqual(json.loads(preview)["body"]["text"], text)
        for active in ("![", "https://", "MEDIA:", "/private/", "<b>", "```"):
            self.assertNotIn(active, preview)

    def test_dispatch_does_not_follow_redirects_and_ignores_provider_text(self):
        import io
        import urllib.error
        action = self.book.actions["slack.post"]
        _, request = action.prepare("#sandbox", {"text": "hello"})

        class Opener:
            def __init__(self, data):
                self.data = data

            def open(self, req, timeout):
                self.req = req
                if isinstance(self.data, Exception):
                    raise self.data
                return io.BytesIO(self.data)

        opener = Opener(b'{"ok":true,"ts":"123.45","text":"untrusted instruction"}')
        self.assertEqual(adapters.send(action, request, lambda _: "test-secret", opener), "123.45")
        self.assertEqual(json.loads(opener.req.data)["channel"], "C0123456790")
        self.assertEqual(opener.req.headers["Authorization"], "Bearer test-secret")
        with self.assertRaises(adapters.DeliveryUnknown):
            adapters.send(action, request, lambda _: "test-secret", Opener(b'{"ok":false,"ts":"123.45"}'))
        self.assertIsNone(adapters.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid"))

    @unittest.skipUnless(hasattr(core.os, "getuid"), "native Unix owner identity")
    def test_native_owner_context_requires_actor_route_and_private_session(self):
        owner = f"uid:{core.os.getuid()}"
        base = {"HERMES_SESSION_PLATFORM": "local", "HERMES_SESSION_USER_ID": owner,
                "HERMES_SESSION_ACTOR_ID": owner, "HERMES_SESSION_CHAT_TYPE": "dm",
                "HERMES_SESSION_CHAT_ID": "native-chat"}
        self.assertIsNotNone(plugin.native_owner_context(base.get))
        for key, value in (("HERMES_SESSION_ACTOR_ID", "other-user"), ("HERMES_SESSION_USER_ID", "other-user"),
                           ("HERMES_SESSION_PLATFORM", "telegram"), ("HERMES_SESSION_CHAT_TYPE", "group"),
                           ("HERMES_SESSION_CHAT_ID", ""), ("HERMES_CRON_SESSION", "1")):
            changed = dict(base)
            changed[key] = value
            self.assertIsNone(plugin.native_owner_context(changed.get))

    def test_new_connectors_send_documented_requests_and_parse_receipts(self):
        import io
        from unittest.mock import Mock

        fields = {"title": "test title", "text": "test body"}
        cases = [
            ("linear.create_issue", "engineering", "https://api.linear.app/graphql", "token",
             {"data": {"issueCreate": {"success": True, "issue": {"id": "issue-1"}}}}, "issue-1"),
            ("asana.create_task", "team-project", "https://app.asana.com/api/1.0/tasks", "Bearer token",
             {"data": {"gid": "10001"}}, "10001"),
            ("clickup.create_task", "team-list", "https://api.clickup.com/api/v2/list/123456789/task", "token",
             {"id": "task-1"}, "task-1"),
            ("todoist.create_task", "personal", "https://api.todoist.com/api/v1/tasks", "Bearer token",
             {"id": "task-2"}, "task-2"),
        ]
        for name, alias, url, auth, response, receipt in cases:
            with self.subTest(name=name):
                action = self.book.actions[name]
                target, request = action.prepare(alias, fields)
                opener = Mock()
                opener.open.return_value = io.BytesIO(json.dumps(response).encode())
                self.assertEqual(adapters.send(action, request, lambda _: "token", opener), receipt)
                sent = opener.open.call_args.args[0]
                self.assertEqual(sent.full_url, url)
                self.assertEqual(sent.headers["Authorization"], auth)
                body = json.loads(sent.data)
                if name.startswith("linear."):
                    self.assertIn("issueCreate(input: $input)", body["query"])
                    self.assertEqual(body["variables"]["input"],
                                     {"teamId": target, "title": fields["title"], "description": fields["text"]})
                elif name.startswith("asana."):
                    self.assertEqual(body["data"], {"projects": [target], "name": fields["title"], "notes": fields["text"]})
                elif name.startswith("clickup."):
                    self.assertEqual(body, {"name": fields["title"], "description": fields["text"]})
                else:
                    self.assertEqual(body, {"project_id": target, "content": fields["title"], "description": fields["text"]})

    def test_linear_receipt_requires_nested_success_without_graphql_errors(self):
        import io
        from unittest.mock import Mock

        action = self.book.actions["linear.create_issue"]
        _, request = action.prepare("engineering", {"title": "test", "text": "test"})
        for success, errors in ((False, []), (True, [{"message": "partial failure"}])):
            reply = {"data": {"issueCreate": {"success": success, "issue": {"id": "issue-1"}}}, "errors": errors}
            opener = Mock()
            opener.open.return_value = io.BytesIO(json.dumps(reply).encode())
            with self.assertRaises(adapters.DeliveryUnknown):
                adapters.send(action, request, lambda _: "token", opener)

    def test_untrusted_http_destinations_and_templates_are_rejected(self):
        for field, value in (("url", "https://{destination}.example.com"), ("url", "http://example.com"), ("url", "https://wrong.example/post"),
                             ("url", "https://example.com/?x={destination}"), ("secret", "OPENAI_API_KEY"), ("secret", "RULEBOOK_UNDECLARED_TOKEN"),
                             ("headers", {"Authorization": "leak"}),
                             ("body", {"channel": "$destination", "text": "$unknown"})):
            with self.subTest(field=field, value=value):
                spec = json.loads(EXAMPLE.read_text())["actions"]
                spec["slack.post"]["https"][field] = value
                with self.assertRaises(adapters.Rejected):
                    adapters.parse_actions(spec)


if __name__ == "__main__":
    unittest.main()
