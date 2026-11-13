"""Rule tests: one rule, one honest example of what it catches."""

from mcpseal.config import ServerSpec
from mcpseal.rules import evaluate


def spec(**kwargs):
    base = {"name": "srv", "source": "/tmp/mcp.json", "client": "generic"}
    base.update(kwargs)
    return ServerSpec(**base)


def rule_ids(servers, root=None):
    return {finding.rule_id for finding in evaluate(servers, root=root)}


def test_clean_server_has_no_findings():
    server = spec(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem@2025.8.15", "./src"],
        env={"LOG_LEVEL": "info"},
    )
    assert evaluate([server]) == []


def test_mcp001_literal_secret_in_env():
    server = spec(command="node", env={"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123"})
    assert "MCP001" in rule_ids([server])


def test_mcp001_env_reference_is_fine():
    server = spec(command="node", env={"GITHUB_TOKEN": "${GITHUB_TOKEN}", "API_KEY": "$API_KEY"})
    assert "MCP001" not in rule_ids([server])


def test_mcp002_unpinned_npx():
    server = spec(command="npx", args=["-y", "@modelcontextprotocol/server-github"])
    assert "MCP002" in rule_ids([server])


def test_mcp002_pinned_runners_pass():
    npx = spec(command="npx", args=["-y", "@modelcontextprotocol/server-github@1.2.3"])
    uvx = spec(name="git", command="uvx", args=["mcp-server-git==0.6.2"])
    assert "MCP002" not in rule_ids([npx, uvx])


def test_mcp003_shell_wrapper():
    server = spec(command="/bin/bash", args=["-c", "npx -y @evil/tools"])
    assert "MCP003" in rule_ids([server])


def test_mcp003_bare_bash_without_c_is_allowed():
    server = spec(command="bash", args=["-l"])
    assert "MCP003" not in rule_ids([server])


def test_mcp004_broad_filesystem_roots():
    for root in ("/", "~", "/home/harry", "/Users/harry"):
        server = spec(
            command="npx",
            args=["@modelcontextprotocol/server-filesystem@1.0.0", root],
        )
        assert "MCP004" in rule_ids([server]), root


def test_mcp004_narrow_root_passes():
    server = spec(
        command="npx",
        args=["@modelcontextprotocol/server-filesystem@1.0.0", "/home/harry/work/app"],
    )
    assert "MCP004" not in rule_ids([server])


def test_mcp005_write_access():
    server = spec(
        command="npx",
        args=["@modelcontextprotocol/server-filesystem@1.0.0", "./data", "--allow-write"],
    )
    assert "MCP005" in rule_ids([server])


def test_mcp006_privileged_container_with_socket():
    server = spec(
        command="docker",
        args=["run", "-i", "--rm", "--privileged", "-v",
              "/var/run/docker.sock:/var/run/docker.sock", "img:1.2.3"],
    )
    ids = rule_ids([server])
    assert "MCP006" in ids
    assert "MCP011" not in ids


def test_mcp007_plaintext_remote():
    assert "MCP007" in rule_ids([spec(url="http://tools.example.com/mcp")])
    assert "MCP007" not in rule_ids([spec(url="http://localhost:3000/mcp")])


def test_mcp008_unauthenticated_remote():
    assert "MCP008" in rule_ids([spec(url="https://api.example.com/mcp")])
    assert "MCP008" not in rule_ids(
        [spec(url="https://api.example.com/mcp", headers={"Authorization": "Bearer ${TOKEN}"})]
    )


def test_mcp009_tls_verification_disabled():
    env_off = spec(command="node", env={"NODE_TLS_REJECT_UNAUTHORIZED": "0"})
    flag_off = spec(name="curl", command="mcp-remote", args=["--insecure", "https://x.example.com"])
    assert "MCP009" in rule_ids([env_off])
    assert "MCP009" in rule_ids([flag_off])


def test_mcp010_state_changing_tools_auto_approved():
    risky = spec(command="node", auto_approve=["write_file", "delete_file"])
    blanket = spec(name="all", command="node", auto_approve=True)
    assert "MCP010" in rule_ids([risky])
    assert "MCP010" in rule_ids([blanket])


def test_mcp010_read_only_auto_approve_is_fine():
    server = spec(command="node", auto_approve=["read_file", "list_directory"])
    assert "MCP010" not in rule_ids([server])


def test_mcp011_unpinned_container_image():
    server = spec(command="docker", args=["run", "-p", "8080:80", "nginx"])
    assert "MCP011" in rule_ids([server])


def test_mcp012_shell_metacharacters():
    server = spec(command="uvx", args=["tool==1.0.0", "--target", "a; rm -rf /"])
    assert "MCP012" in rule_ids([server])


def test_mcp013_inline_code():
    server = spec(command="python3", args=["-c", "print('hello')"])
    assert "MCP013" in rule_ids([server])


def test_mcp014_duplicate_registration():
    first = spec(name="files-a", command="npx", args=["pkg@1.0.0", "./src"])
    second = spec(name="files-b", command="npx", args=["pkg@1.0.0", "./src"])
    ids = rule_ids([first, second])
    assert "MCP014" in ids


def test_mcp015_cwd_outside_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    server = spec(command="node", cwd="/etc")
    assert "MCP015" in rule_ids([server], root=str(root))


def test_mcp016_credentials_in_url():
    userinfo = spec(url="https://user:pass@api.example.com/mcp",
                    headers={"Authorization": "Bearer ${TOKEN}"})
    query = spec(url="https://api.example.com/mcp?api_key=abcd1234",
                 headers={"Authorization": "Bearer ${TOKEN}"})
    assert "MCP016" in rule_ids([userinfo])
    assert "MCP016" in rule_ids([query])


def test_disabled_servers_are_skipped():
    server = spec(command="docker", args=["run", "--privileged", "img"], disabled=True)
    assert evaluate([server]) == []


def test_findings_are_sorted_by_severity():
    servers = [
        spec(name="a", command="node"),
        spec(name="b", command="docker", args=["run", "--privileged", "img"]),
    ]
    severities = [finding.severity for finding in evaluate(servers)]
    assert severities[0] == "critical"
