"""Profile-local policy and durable, one-shot approval queue."""
from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from .adapters import DeliveryUnknown, Rejected, encode, exact_keys, fingerprint, parse_actions, preview, require

SCHEMA = """
CREATE TABLE meta (version INTEGER NOT NULL);
INSERT INTO meta VALUES (1);
CREATE TABLE rules (
 action TEXT NOT NULL, destination TEXT NOT NULL, mode TEXT NOT NULL,
 revision TEXT NOT NULL, PRIMARY KEY(action, destination)
);
CREATE TABLE pending (
 id TEXT PRIMARY KEY, action TEXT NOT NULL, destination TEXT NOT NULL,
 revision TEXT NOT NULL, adapter TEXT NOT NULL, payload TEXT NOT NULL,
 expires INTEGER NOT NULL, state TEXT NOT NULL
);
"""
TTL = 15 * 60


def read_config(home):
    path = Path(home) / "rulebook" / "config.json"
    if path.stat().st_size > 512 * 1024:
        raise Rejected("Rulebook configuration is too large.")

    def no_duplicates(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "Duplicate configuration key.")
        return result

    config = json.loads(path.read_text(), object_pairs_hook=no_duplicates)
    exact_keys(config, {"owner", "actions", "protected"})
    require(type(config["protected"]) is bool, "Set protected to true or false.")
    owner = config["owner"]
    exact_keys(owner, set(), {"telegram_user_id", "local"})
    require(type(owner.get("local", True)) is bool, "Local owner access must be true or false.")
    if "telegram_user_id" in owner:
        require(isinstance(owner["telegram_user_id"], str) and re.fullmatch(r"[1-9][0-9]{0,19}",
                owner["telegram_user_id"]), "Configure a numeric Telegram owner ID.")
    require(owner.get("telegram_user_id") or owner.get("local", True), "Enable at least one owner interface.")
    return config, parse_actions(config["actions"])


def initialize(home):
    folder = Path(home) / "rulebook"
    read_config(home)
    db = folder / "policy.sqlite3"
    # Atomic exclusive creation: an existing database is never overwritten.
    fd = os.open(db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.executescript(SCHEMA)


class Rulebook:
    def __init__(self, home, deliver, clock=time.time):
        self.home = Path(home)
        self.config, self.actions = read_config(home)
        self.db = self.home / "rulebook" / "policy.sqlite3"
        self.deliver = deliver
        self.clock = clock

    @contextlib.contextmanager
    def transaction(self):
        with contextlib.closing(sqlite3.connect(self.db.absolute().as_uri() + "?mode=rw", uri=True,
                                               timeout=5, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                require(conn.execute("SELECT version FROM meta").fetchall() == [(1,)], "Unsupported policy database.")
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def binding(self, action):
        return fingerprint([action.revision, self.config['owner']])

    def action(self, name):
        require(isinstance(name, str) and name in self.actions, "Action is not enforceable. Use rulebook_capabilities.")
        return self.actions[name]

    def target(self, action, alias):
        require(isinstance(alias, str) and alias in action.targets, "Unknown destination. Use rulebook_capabilities.")
        return action.targets[alias]

    @staticmethod
    def policy(conn, name, dest):
        row = conn.execute("SELECT mode, revision FROM rules WHERE action=? AND destination=?", (name, dest)).fetchone()
        require(row is None or row[0] in ("block", "ask"), "Invalid rule state.")
        return row or ("allow", "")

    def change(self, name, alias, mode):
        require(mode in ("ask", "block", "undo", "check"), "Invalid rule operation.")
        action = self.action(name)
        dest = self.target(action, alias)
        with self.transaction() as conn:
            if mode == "check":
                mode, revision = self.policy(conn, name, dest)
                return {"mode": mode, "action": name, "destination": dest, "revision": revision}
            revision = secrets.token_hex(8)
            if mode == "undo":
                conn.execute("DELETE FROM rules WHERE action=? AND destination=?", (name, dest))
                mode = "allow"
            else:
                conn.execute("INSERT OR REPLACE INTO rules VALUES (?, ?, ?, ?)", (name, dest, mode, revision))
            conn.execute("UPDATE pending SET state='stale', payload='' WHERE action=? AND destination=? AND state IN ('pending','reviewed','claimed')",
                         (name, dest))
            return {"mode": mode, "action": name, "destination": dest, "revision": revision}

    def write(self, name, alias, fields):
        action = self.action(name)
        dest, payload = action.prepare(alias, fields)
        with self.transaction() as conn:
            mode, revision = self.policy(conn, name, dest)
            if mode == "block":
                return {"status": "blocked", "action": name, "destination": dest}
            if mode == "ask":
                now = int(self.clock())
                conn.execute("UPDATE pending SET state='expired', payload='' WHERE state IN ('pending','reviewed') AND expires<=?", (now,))
                existing = conn.execute(
                    "SELECT id FROM pending WHERE action=? AND destination=? AND revision=? AND adapter=? AND payload=? AND state IN ('pending','reviewed')",
                    (name, dest, revision, self.binding(action), encode(payload)),
                ).fetchone()
                ident = existing[0] if existing else secrets.token_hex(8)
                if not existing:
                    require(conn.execute("SELECT COUNT(*) FROM pending WHERE state IN ('pending','reviewed')").fetchone()[0] < 100,
                            "Approval queue is full.")
                    conn.execute("INSERT INTO pending VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                                 (ident, name, dest, revision, self.binding(action), encode(payload), now + TTL))
                return {"status": "staged", "id": ident, "action": name, "destination": dest,
                        "owner_instructions": f"In your authenticated owner chat, send Review {ident}, then Approve {ident} or Deny {ident}."}
            receipt = self.deliver(action, payload)
        return {"status": "sent", "receipt": receipt}

    def approval(self, ident, operation):
        require(operation in ("review", "approve", "deny"), "Invalid approval operation.")
        with self.transaction() as conn:
            row = conn.execute("SELECT action, destination, revision, adapter, payload, expires, state FROM pending WHERE id=?",
                               (ident,)).fetchone()
            require(row and row[-1] in ("pending", "reviewed") and row[-2] > self.clock(), "Approval is unavailable or expired.")
            name, dest, revision, adapter, body, _, _ = row
            action = self.action(name)
            require(self.binding(action) == adapter and self.policy(conn, name, dest) == ("ask", revision), "Approval is stale.")
            if operation == "review":
                conn.execute("UPDATE pending SET state='reviewed' WHERE id=?", (ident,))
                return f"{name} → {dest}\n```json\n{preview(json.loads(body))}\n```\nApprove {ident} or Deny {ident}"
            if operation == "deny":
                conn.execute("UPDATE pending SET state='denied', payload='' WHERE id=?", (ident,))
                return f"Denied {ident}. Nothing sent."
            require(row[-1] == "reviewed", "Review the exact staged write before approving.")
            # Commit the claim before touching the provider. A crash cannot replay it.
            conn.execute("UPDATE pending SET state='claimed', payload='' WHERE id=?", (ident,))
        failure = None
        with self.transaction() as conn:
            state, = conn.execute("SELECT state FROM pending WHERE id=?", (ident,)).fetchone()
            require(state == "claimed" and self.policy(conn, name, dest) == ("ask", revision), "Approval is stale.")
            # Re-read the adapter on release; configuration drift invalidates outstanding consent.
            current, latest = read_config(self.home)
            require(latest.get(name) and fingerprint([latest[name].revision, current['owner']]) == adapter, "Approval is stale.")
            try:
                receipt = self.deliver(action, json.loads(body))
            except Rejected as exc:
                failure = exc
                conn.execute("UPDATE pending SET state=? WHERE id=?",
                             ("unknown" if isinstance(exc, DeliveryUnknown) else "failed", ident))
            else:
                conn.execute("UPDATE pending SET state='sent' WHERE id=?", (ident,))
        if failure:
            raise failure
        return f"Sent {name} to {dest}. Receipt: {receipt}"
