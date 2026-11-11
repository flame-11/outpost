"""The integration files run `uvx --from outpost-oob outpost mcp`, carry the package version and the same skill."""

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTEGRATIONS = ROOT / "integrations"
COMMAND = ["uvx", "--from", "outpost-oob", "outpost", "mcp"]


def package() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def test_the_distribution_is_outpost_oob_with_the_outpost_command() -> None:
    project = package()
    assert project["name"] == "outpost-oob"
    assert project["scripts"] == {"outpost": "outpost.cli:main", "outpost-admin": "outpost.admin:main"}


def test_the_skill_has_name_and_description_front_matter() -> None:
    text = (ROOT / "skills" / "outpost" / "SKILL.md").read_text()
    front = text.split("---")[1]
    fields = dict(line.split(": ", 1) for line in front.strip().splitlines())
    assert fields["name"] == "outpost"
    assert fields["description"]


def test_the_claude_code_plugin_carries_the_server_and_the_same_skill() -> None:
    plugin = INTEGRATIONS / "claude-code" / "outpost"
    manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["version"] == package()["version"]
    server = json.loads((plugin / ".mcp.json").read_text())["mcpServers"]["outpost"]
    assert [server["command"], *server["args"]] == COMMAND
    for reference in server["env"].values():
        assert reference.removeprefix("${user_config.").removesuffix("}") in manifest["userConfig"]
    assert (plugin / "skills" / "outpost" / "SKILL.md").read_text() == (ROOT / "skills/outpost/SKILL.md").read_text()
    marketplace = json.loads((INTEGRATIONS / "claude-code" / ".claude-plugin" / "marketplace.json").read_text())
    assert marketplace["plugins"][0]["source"] == "./outpost"


def test_the_desktop_extension_runs_the_server_with_user_config() -> None:
    manifest = json.loads((INTEGRATIONS / "claude-desktop" / "manifest.json").read_text())
    assert manifest["version"] == package()["version"]
    config = manifest["server"]["mcp_config"]
    assert [config["command"], *config["args"]] == COMMAND
    assert config["env"] == {
        "OUTPOST_API_URL": "${user_config.api_url}",
        "OUTPOST_API_KEY": "${user_config.api_key}",
    }
    assert manifest["user_config"]["api_key"]["sensitive"] is True
    assert {tool["name"] for tool in manifest["tools"]} == {
        "outpost_addresses",
        "outpost_list",
        "outpost_read",
        "outpost_assemble",
    }


def test_the_codex_snippet_runs_the_server() -> None:
    server = tomllib.loads((INTEGRATIONS / "codex" / "config.toml").read_text())["mcp_servers"]["outpost"]
    assert [server["command"], *server["args"]] == COMMAND
    assert {"OUTPOST_API_URL", "OUTPOST_API_KEY"} <= set(server["env_vars"])
