# Prevent This Next Time

A Hermes Agent plugin for rules that run before a connector write. Tell your Hermes bot, “From now on, ask me before posting in #customer-updates.” The next matching write stops at an approval request. “Never post in #customer-updates” blocks it outright.

Rules apply to configured actions and canonical destinations. Slack is one example. The same rule engine handles Discord messages, GitHub and Linear issues, Notion comments, tasks in Asana, ClickUp and Todoist, and other connectors that expose a supported write API. [Hermes plugin documentation](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins)

| Example declaration | Write | Destination |
| --- | --- | --- |
| Slack | Post a plain-text message | Channel ID |
| Discord | Post a message without mentions | Channel ID |
| GitHub | Create an issue | Repository owner/name |
| Notion | Comment on a page | Page ID |
| [Linear](https://linear.app/developers/graphql) | Create an issue | Team UUID |
| [Asana](https://developers.asana.com/reference/createtask) | Create a task | Project GID |
| [ClickUp](https://developer.clickup.com/reference/createtask) | Create a task | List ID |
| [Todoist](https://developer.todoist.com/api/v1/) | Create a task | API v1 project ID |

## Setup on Hermes v0.23.1

Use a new Hermes profile dedicated to the rulebook. Do not replace the config for your everyday profile. Set the Telegram token and owner ID through the profile's normal Hermes secret setup, and configure an inference model there if you want Hermes to act on ordinary chat messages.

1. Copy or symlink this repo's `prevent-this-next-time/` into `<profile-home>/plugins/prevent-this-next-time/`. Use the settings from [protected-config.yaml](examples/protected-config.yaml) as the profile's `config.yaml`. Add a `model` section for your chosen provider if needed.
2. Set `TELEGRAM_ALLOWED_USERS` to your one numeric user ID. Unset `TELEGRAM_ALLOW_ALL_USERS`. The plugin also independently checks the admitted Telegram DM's user and chat IDs against that owner.
3. Create `<profile-home>/rulebook/config.json` from [rulebook.json](examples/rulebook.json). Set your owner ID. Keep the actions you will use, and verify each target ID in its provider before assigning an alias. Set the relevant `RULEBOOK_…` credentials in the profile secret store. Give the credential only the permissions it needs (Slack: `chat:write`, with bot membership in the intended channels).
4. Use the Hermes installation's Python interpreter to initialize state once and launch the gateway:

   ```sh
   "$HERMES_PYTHON" scripts/protected_gateway.py --home "$PROFILE_HOME" --init
   "$HERMES_PYTHON" scripts/protected_gateway.py --home "$PROFILE_HOME" --check
   "$HERMES_PYTHON" scripts/protected_gateway.py --home "$PROFILE_HOME"
   ```

Stop any other gateway serving this profile or token before starting the protected launcher. The launcher is tied to Hermes v0.23.1 because effective tool inventory and gateway configuration are internal Hermes APIs. The plugin directory itself uses the plugin registration API. Rerun the integration suite before changing the Hermes version.

For the four task and issue providers added in 0.2.0, configure the corresponding personal API credential using the manifest's `RULEBOOK_LINEAR_TOKEN`, `RULEBOOK_ASANA_TOKEN`, `RULEBOOK_CLICKUP_TOKEN`, or `RULEBOOK_TODOIST_TOKEN` slot. Use a sandbox destination for the first write. For Todoist, use the project ID returned by API v1 so aliases for the same project use the same identifier.

## In chat

| Message to the owner Telegram bot | Effect |
| --- | --- |
| `Rulebook` | List configured actions and aliases. |
| `From now on, ask me before posting in #customer-updates` | Set a Slack Ask rule in one message. |
| `Never run github.create_issue in example-repo` | Block a configured GitHub write. |
| `Check rule github.create_issue in example-repo` | Show the policy without writing to the provider. |
| `Undo rule github.create_issue in example-repo` | Remove the rule and invalidate its pending writes. |
| `Review <id>`, then `Approve <id>` or `Deny <id>` | Show and then release or discard the exact queued request. |

Ask requests expire after 15 minutes. Approval claims are committed before sending, so the same ID cannot be replayed after a crash, timeout, or retry. If a provider response cannot be confirmed, check the provider before staging a new request. Requests up to the preview limit are shown in full. The local SQLite database contains staged write content; keep the profile directory private.

## Add a connector

A declaration defines one enforceable operation. It specifies agent-fillable text fields, aliases mapped to provider IDs, a fixed HTTPS endpoint and method, a profile secret, a JSON body template, and a provider receipt field. A JSON value of `$field` or `$destination` substitutes the complete value. A URL may include `{destination}` in its path. Connector authentication can use a Bearer token, a bot token, a raw Authorization value, or a supported API-key header. No agent argument can change the host, headers, credential, or canonical destination.

Use the provider-specific secret for the bundled declarations. Use the optional `RULEBOOK_BRIDGE_TOKEN` for an operator-configured HTTPS connector or bridge. Use a bridge-issued credential dedicated to that host.

For APIs that need OAuth refresh, file uploads, signed requests, or a non-HTTP transport, put that logic in a trusted HTTPS adapter exposing one narrow operation per route. It must enforce its own resource and credential boundaries and return a verifiable JSON receipt. Adapters and their destination mappings are trusted operator configuration; the plugin does not discover identities from provider display names. Define each semantic write once to avoid an equivalent action bypassing its rule.

The protected profile keeps generic MCP, shell, browser, code execution, delegation, and native connector tools out of the agent's inventory. An unsupported operation cannot be called from this profile through the rulebook. The Telegram conversation itself remains available for replies. Rules do not constrain other Hermes profiles, separate applications using the same account, or a local operator with access to change trusted configuration. Rotate credentials with the gateway stopped and discard pending approvals when changing the provider account.

## Data and permissions

The plugin reads its configuration and SQLite database under the active Hermes profile. Staged request data stays in that database until release, denial, expiration cleanup, or a rule change. The plugin obtains declared connector credentials through Hermes's profile secret API and sends a credential and write payload to the configured HTTPS endpoint when the rule allows dispatch. The plugin does not store credentials or collect telemetry.

The optional operator launcher reads gateway configuration and checks the installed tool inventory, pairing grants, and cron state before running the standard Hermes gateway. It uses Hermes v0.23.1 internals for those checks. The installed plugin uses Hermes registration hooks and does not invoke the launcher, shell commands, or background services.

## Verify

```sh
python3 -m unittest discover -s tests -v
HERMES_TEST_PYTHON="$HERMES_PYTHON" python3 -m unittest discover -s tests -v
"$HERMES_PYTHON" -m hermes_cli.main plugins validate ./prevent-this-next-time --install-deps
```

Use Hermes with the `mcp` extra for the second command. The integration suite loads the actual Hermes plugin, invokes its gateway admission hook and tool dispatch, and uses a real stdio MCP server with a local write ledger. It proves the alternate tool can write in the ordinary profile and that the protected launcher rejects the same MCP configuration. The fixture never posts to an external provider.
