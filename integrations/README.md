# Integrations

Each client runs the same local MCP server, `outpost mcp`, over standard input and output. It
is installed from the `outpost-oob` package and needs [uv](https://docs.astral.sh/uv/) for
`uvx`. Three variables configure it:

| Variable | Meaning |
|---|---|
| `OUTPOST_API_URL` | base address of the instance's API, e.g. `http://127.0.0.1:9080` |
| `OUTPOST_API_KEY` | the instance's API key, used to create channels |
| `OUTPOST_HOME` | where key files live, default `~/.config/outpost` (`channels/<label>.json`) |

Records are opened by this local server; the instance holds nothing readable. The skill in
`skills/outpost/SKILL.md` says when and how an agent uses the tools.

## Claude Code

Server only, for every project (`--scope user`):

```bash
claude mcp add outpost --scope user \
  -e OUTPOST_API_URL=http://127.0.0.1:9080 -e OUTPOST_API_KEY="$KEY" \
  -- uvx --from outpost-oob outpost mcp
```

Copy the skill to `~/.claude/skills/outpost/SKILL.md` to go with it.

Server and skill as a plugin: `claude-code/` is a marketplace holding the plugin
`claude-code/outpost/` (`.claude-plugin/plugin.json`, `.mcp.json`, `skills/outpost/SKILL.md`).
The plugin asks for the API address and key when it is enabled; the key is kept in secure
storage.

```bash
claude plugin marketplace add ./integrations/claude-code
claude plugin install outpost@outpost
```

`claude plugin validate integrations/claude-code/outpost` and
`claude plugin validate integrations/claude-code` pass (the first warns that the plugin has no
listing icon).

## Claude Desktop

`claude-desktop/manifest.json` is an MCP Bundle manifest (`manifest_version` 0.3). The bundle
holds only the manifest; the server runs as `uvx --from outpost-oob outpost mcp`, and the API
address and key are asked for at install. Pack it with:

```bash
npx @anthropic-ai/mcpb pack integrations/claude-desktop outpost.mcpb
```

`mcpb validate` accepts the manifest and `mcpb pack` builds it. The specification describes
`binary` servers as executables inside the bundle and gives no example of a server started
from a command on `PATH`; `entry_point` is set to `uvx` only to satisfy that shape. `uvx` must
be on the `PATH` Claude Desktop starts servers with; if it is not, give its absolute path as
`command`.

Without a bundle, add an entry to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "outpost": {
      "command": "uvx",
      "args": ["--from", "outpost-oob", "outpost", "mcp"],
      "env": { "OUTPOST_API_URL": "http://127.0.0.1:9080", "OUTPOST_API_KEY": "<key>" }
    }
  }
}
```

## Codex CLI

Add `codex/config.toml` to `~/.codex/config.toml`. It forwards the three variables from the
environment Codex starts in (`env_vars`), raises `tool_timeout_sec` to 60 seconds, since
`outpost_list` may wait up to 30, and approves the tools in advance
(`default_tools_approval_mode = "approve"`), without which `codex exec` refuses every call. The same server can be added with:

```bash
codex mcp add outpost --env OUTPOST_API_URL=http://127.0.0.1:9080 --env OUTPOST_API_KEY="$KEY" \
  -- uvx --from outpost-oob outpost mcp
```

Codex reads skills from `~/.agents/skills` (user) and `.agents/skills` (repository). Install
the skill with:

```bash
mkdir -p ~/.agents/skills/outpost && cp skills/outpost/SKILL.md ~/.agents/skills/outpost/
```

## Versions

The plugin and bundle versions follow the package version in `pyproject.toml`.
`tests/test_integrations.py` checks that, and that the plugin's copy of the skill matches
`skills/outpost/SKILL.md`.
