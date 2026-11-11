"""Trusted operator declarations; agent calls cannot select endpoints, headers, or credentials."""
from __future__ import annotations

import hashlib
import http.client
import uuid
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

KEY = re.compile(r"[a-z][a-z0-9_-]{0,47}")
ALIAS = re.compile(r"[#@]?[a-z][a-z0-9_.-]{0,63}")
FIELD = re.compile(r"[a-z][a-z0-9_]{0,31}")
RESPONSE_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
PROVIDER_HOSTS = {
    "RULEBOOK_SLACK_TOKEN": "slack.com",
    "RULEBOOK_DISCORD_TOKEN": "discord.com",
    "RULEBOOK_GITHUB_TOKEN": "api.github.com",
    "RULEBOOK_NOTION_TOKEN": "api.notion.com",
    "RULEBOOK_LINEAR_TOKEN": "api.linear.app",
    "RULEBOOK_ASANA_TOKEN": "app.asana.com",
    "RULEBOOK_CLICKUP_TOKEN": "api.clickup.com",
    "RULEBOOK_TODOIST_TOKEN": "api.todoist.com",
}
CUSTOM_SECRET = "RULEBOOK_BRIDGE_TOKEN"
CREDENTIAL_HEADER = re.compile(r"(?:api-key|x-[a-z0-9-]*api-key|private-token)", re.I)
DEST = re.compile(r"[A-Za-z0-9_.:@+!/-]{1,160}")
MAX_PREVIEW = 2800
_JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_INERT = str.maketrans({c: f"\\u{ord(c):04x}" for c in "![]<>`/@"})


class Rejected(ValueError):
    """Safe to report in chat."""


class DeliveryUnknown(Rejected):
    """A provider receipt could not be confirmed."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def preview(value):
    # Hermes scans even fenced replies for media. Keep active syntax out of the
    # JSON strings before presenting them as literal text in the owner DM.
    return _JSON_STRING.sub(lambda match: match[0].translate(_INERT).replace("MEDIA:", r"MEDIA\u003a"),
                            encode(value))


def fingerprint(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def require(ok, message):
    if not ok:
        raise Rejected(message)


def exact_keys(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= value.keys()
            and value.keys() <= set(required) | set(optional), "Invalid configuration fields.")


@dataclass(frozen=True)
class Action:
    name: str
    fields: tuple[str, ...]
    targets: dict
    dispatch: dict
    revision: str

    def prepare(self, alias, fields):
        require(isinstance(alias, str) and alias in self.targets, "Unknown destination. Use rulebook_capabilities.")
        require(isinstance(fields, dict) and set(fields) == set(self.fields), "Fields must match the action declaration.")
        require(all(isinstance(v, str) and v.strip() for v in fields.values()), "Fields must be nonempty text.")
        require(sum(map(len, fields.values())) <= MAX_PREVIEW, "Write exceeds the approval preview limit.")
        destination = self.targets[alias]
        values = {"destination": destination, **fields}
        rendered = _render(self.dispatch["body"], values)
        url = self.dispatch["url"].replace("{destination}", destination)
        payload = {"url": url, "body": rendered}
        require(len(preview(payload)) <= MAX_PREVIEW, "Write exceeds the approval preview limit.")
        return destination, payload


def _render(value, fields):
    if isinstance(value, dict):
        return {k: _render(v, fields) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, fields) for v in value]
    if isinstance(value, str) and value.startswith("$"):
        return fields[value[1:]]
    return value


def _body_tokens(value, depth=0):
    require(depth <= 12, "Adapter body is too deeply nested.")
    if isinstance(value, dict):
        return set().union(*(_body_tokens(v, depth + 1) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_body_tokens(v, depth + 1) for v in value))
    if isinstance(value, str) and value.startswith("$"):
        return {value[1:]}
    return set()


def parse_actions(values):
    require(isinstance(values, dict) and 1 <= len(values) <= 64, "Declare between 1 and 64 actions.")
    actions = {}
    routes = set()
    resolved_routes = set()
    for name, raw in values.items():
        require(isinstance(name, str) and len(name.split(".")) == 2 and all(
            KEY.fullmatch(k) for k in name.split(".")), "Action must be connector.action.")
        exact_keys(raw, {"fields", "targets", "https"})
        fields, targets, spec = raw["fields"], raw["targets"], raw["https"]
        require(isinstance(fields, list) and 1 <= len(fields) <= 8 and
                all(isinstance(f, str) and FIELD.fullmatch(f) and f != "destination" for f in fields)
                and len(set(fields)) == len(fields), "Invalid action fields.")
        require(isinstance(targets, dict) and 1 <= len(targets) <= 100, "Invalid destinations.")
        targets = dict(targets)
        for alias, target in targets.items():
            require(isinstance(alias, str) and ALIAS.fullmatch(alias) and isinstance(target, str)
                    and DEST.fullmatch(target) and not any(part in ("", ".", "..") for part in target.split("/")),
                    "Invalid destination alias or canonical ID.")
            if name == "github.create_issue":
                require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", target), "Use a GitHub owner/repository ID.")
                targets[alias] = target.lower()
            elif name == "slack.post":
                require(re.fullmatch(r"[CGD][A-Z0-9]{2,39}", target), "Use an uppercase Slack conversation ID.")
            elif name == "discord.post":
                require(re.fullmatch(r"[1-9][0-9]{14,21}", target), "Use a Discord channel snowflake.")
            elif name in ("asana.create_task", "clickup.create_task"):
                require(re.fullmatch(r"[1-9][0-9]{0,39}", target), "Use the numeric project or list ID.")
            elif name == "todoist.create_task":
                require(re.fullmatch(r"[A-Za-z0-9]{1,64}", target), "Use the Todoist API v1 project ID.")
            elif name in ("notion.comment", "linear.create_issue"):
                try:
                    targets[alias] = str(uuid.UUID(target))
                except ValueError:
                    raise Rejected("Use a Notion page or Linear team UUID.") from None
        exact_keys(spec, {"url", "method", "secret", "auth", "body", "receipt"}, {"require", "headers"})
        require(isinstance(spec["url"], str) and len(spec["url"]) < 400, "Invalid adapter URL.")
        url = spec["url"]
        parts = urlsplit(url.replace("{destination}", "DESTINATION"))
        require(parts.scheme == "https" and parts.hostname and parts.netloc == parts.hostname and
                not parts.query and not parts.fragment and "{" not in url.replace("{destination}", "")
                and "}" not in url.replace("{destination}", "") and "DESTINATION" not in parts.netloc
                and (url.count("{destination}") == 0 or "{destination}" in urlsplit(url).path),
                "Use a fixed HTTPS host and optional destination in the URL path.")
        auth = spec["auth"]
        header_auth = isinstance(auth, dict) and auth.keys() == {"header"} and isinstance(auth["header"], str) and CREDENTIAL_HEADER.fullmatch(auth["header"])
        secret = spec["secret"]
        require(isinstance(secret, str) and (secret in PROVIDER_HOSTS or secret == CUSTOM_SECRET),
                "Use a credential declared in the plugin manifest.")
        require(PROVIDER_HOSTS.get(secret, parts.hostname) == parts.hostname,
                "The credential can only be used with its provider host.")
        require(spec["method"] in ("POST", "PUT", "PATCH", "DELETE") and
                (auth in ("Bearer", "Bot", "Raw") or header_auth), "Invalid method or credential declaration.")
        headers = spec.get("headers", {})
        require(isinstance(headers, dict) and len(headers) <= 8 and all(
            isinstance(k, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,40}", k)
            and k.lower() in {"notion-version", "accept", "x-github-api-version"}
            and isinstance(v, str) and re.fullmatch(r"[ -~]{1,160}", v)
            for k, v in headers.items()), "Invalid or unsupported static header.")
        require(isinstance(spec["body"], dict), "Adapter body must be a JSON object.")
        tokens = _body_tokens(spec["body"])
        require(set(fields) <= tokens <= set(fields) | {"destination"} and
                ("destination" in tokens or "{destination}" in url), "Map every field and the destination.")
        require(isinstance(spec["receipt"], str) and RESPONSE_PATH.fullmatch(spec["receipt"]), "Invalid receipt key.")
        require("require" not in spec or isinstance(spec["require"], str) and RESPONSE_PATH.fullmatch(spec["require"]),
                "Invalid success key.")
        route = (spec["method"], parts.netloc, parts.path.rstrip("/"))
        require(route not in routes, "Declare each write endpoint once so a second action cannot bypass its rules.")
        expanded = {(spec["method"], parts.netloc, urlsplit(url.replace("{destination}", target)).path.rstrip("/").lower())
                    for target in targets.values()}
        require(not (expanded & resolved_routes), "Two actions resolve to the same HTTPS write endpoint.")
        routes.add(route)
        resolved_routes |= expanded
        actions[name] = Action(name, tuple(fields), targets, spec, fingerprint(raw))
    return actions


def response_value(result, path):
    for key in path.split("."):
        result = result.get(key) if isinstance(result, dict) else None
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(action, payload, get_secret, opener=None):
    spec = action.dispatch
    token = get_secret(spec["secret"])
    if not isinstance(token, str) or not token.strip() or any(c in token for c in "\r\n"):
        raise Rejected("Connector credential is unavailable.")
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    auth = spec["auth"]
    if isinstance(auth, dict):
        credential = {auth["header"]: token}
    else:
        credential = {"Authorization": token if auth == "Raw" else f"{auth} {token}"}
    try:
        request = urllib.request.Request(payload["url"], data=encode(payload["body"]).encode(),
                                        method=spec["method"], headers={
                                            **spec.get("headers", {}),
                                            "Content-Type": "application/json",
                                            **credential,
                                            "User-Agent": "Hermes-Rulebook/0.1",
                                        })
        with opener.open(request, timeout=4) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("oversize receipt")
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("errors"):
            raise ValueError("provider returned errors")
        if "require" in spec and response_value(result, spec["require"]) is not True:
            raise ValueError("missing success marker")
        receipt = response_value(result, spec["receipt"])
        if type(receipt) not in (str, int) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", str(receipt)):
            raise ValueError("missing receipt")
        return str(receipt)
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        raise DeliveryUnknown("Delivery could not be confirmed. Check the provider before retrying.") from None
