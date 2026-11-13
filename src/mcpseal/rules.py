"""The rule set.

Each rule is a small, explainable check over one normalised server spec. A rule
returns a list of evidence strings: empty means the server passed, and every
evidence line becomes one finding. Nothing here talks to the network, launches a
server, or resolves DNS - this is a pure static review of the configuration.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .config import ENV_REF_RE, ServerSpec

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SECRET_NAME_RE = re.compile(
    r"(API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)",
    re.IGNORECASE,
)
SECRET_VALUE_PREFIXES = (
    "sk-", "sk_live_", "sk_test_", "rk_live_",
    "ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
    "xoxb-", "xoxp-", "xapp-", "AKIA", "ASIA", "AIza",
    "glpat-", "nvapi-", "hf_", "shpat_", "dop_v1_", "SG.",
)

PACKAGE_RUNNERS = {"npx", "pnpx", "bunx", "dlx", "uvx", "pipx"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe",
          "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
INTERPRETERS = {"python", "python3", "python3.11", "python3.12", "node", "deno",
                "bun", "ruby", "perl", "php"}
INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
CONTAINER_CLIS = {"docker", "podman", "nerdctl"}
BROAD_ROOTS = {
    "/", "//", "~", "$home", "${home}", "%userprofile%", "/home", "/users",
    "/root", "c:/", "c:\\", "c:", "d:/", "d:\\", "/volumes", "/mnt", "/data",
}
AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "apikey",
                     "x-auth-token", "x-token", "bearer"}
DOCKER_VALUE_FLAGS = {
    "--name", "-p", "--publish", "-v", "--volume", "-e", "--env", "--env-file",
    "--network", "--net", "--pid", "--user", "-u", "--entrypoint", "--mount",
    "--cap-add", "--cap-drop", "-w", "--workdir", "--label", "--platform",
    "--restart", "--memory", "-m", "--hostname", "-h", "--add-host",
}
SHELL_METACHARS = (";", "&&", "||", "`", "$(")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal"}


@dataclass
class Finding:
    """One rule violation, with everything a human needs to act on it."""

    rule_id: str
    severity: str
    title: str
    server: str
    source: str
    evidence: List[str]
    why: str
    fix: str
    ref: str = ""

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), self.server, self.rule_id)


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    why: str
    fix: str
    check: Callable[[ServerSpec, Dict[str, Any]], List[str]]
    ref: str = ""


def _basename(command: Optional[str]) -> str:
    if not command:
        return ""
    return os.path.basename(str(command).replace("\\", "/")).lower()


def _has_version(spec: str) -> bool:
    """True when a package spec is pinned (``pkg@1.2.3``, ``pkg==1.2.3``, digest)."""
    if not spec:
        return False
    if "==" in spec or "@sha256:" in spec:
        return True
    if spec.startswith("@"):
        idx = spec.find("@", 1)
        return idx > 0 and bool(spec[idx + 1:])
    idx = spec.find("@")
    return idx > 0 and bool(spec[idx + 1:])


def _first_package(args: List[str]) -> Optional[str]:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _is_broad_root(path: str) -> bool:
    if not path:
        return False
    raw = path.strip()
    if raw in ("/", "//", "\\", "\\\\"):
        return True
    normal = raw.replace("\\", "/").rstrip("/")
    if not normal:
        return False
    if normal.lower() in {p.rstrip("/") for p in BROAD_ROOTS}:
        return True
    # a single user's whole home directory, the usual over-broad default
    if re.match(r"^/(home|Users|root)/[^/]+$", normal):
        return True
    if re.match(r"^[A-Za-z]:/(Users|Documents and Settings)/[^/]+$", normal):
        return True
    return False


def _docker_image(args: List[str]) -> Optional[str]:
    """Best-effort image extraction from ``docker run`` style arguments."""
    tokens = list(args)
    lowered = [t.lower() for t in tokens]
    start = 0
    if "run" in lowered:
        start = lowered.index("run") + 1
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-"):
            if "=" not in token and token.lower() in DOCKER_VALUE_FLAGS:
                index += 2
                continue
            index += 1
            continue
        return token
    return None


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    tag = last.rsplit(":", 1)[1]
    return bool(tag) and tag.lower() != "latest"


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #

def check_secret_in_env(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    evidence = []
    for key in sorted(server.env):
        value = server.env[key]
        if not value or ENV_REF_RE.match(value.strip()):
            continue
        name_hit = bool(SECRET_NAME_RE.search(key))
        prefix_hit = value.startswith(SECRET_VALUE_PREFIXES)
        if prefix_hit or (name_hit and len(value) >= 8):
            reason = "matches a known credential prefix" if prefix_hit else "name looks like a credential"
            evidence.append(
                "env %s holds a literal value (%d chars, %s)" % (key, len(value), reason)
            )
    return evidence


def check_unpinned_package(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    runner = _basename(server.command)
    if runner not in PACKAGE_RUNNERS:
        return []
    package = _first_package(server.args)
    if not package:
        return []
    if _has_version(package):
        return []
    return ["%s resolves %s at install time - no version or digest is pinned" % (runner, package)]


def check_shell_wrapper(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    shell = _basename(server.command)
    if shell not in SHELLS:
        return []
    inline = [a for a in server.args if a.lower() in ("-c", "/c", "-command", "--command", "-encodedcommand")]
    if not inline:
        return []
    script = " ".join(server.args)
    snippet = script if len(script) <= 90 else script[:87] + "..."
    return ["%s %s runs an opaque command string: %s" % (shell, inline[0], snippet)]


def check_broad_filesystem_root(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    evidence = []
    for arg in server.args:
        if _is_broad_root(arg):
            evidence.append("argument %r exposes an entire filesystem tree" % arg)
    return evidence


def check_write_access(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    write_flags = []
    for arg in server.args:
        low = arg.lower()
        if low in ("--allow-write", "--write", "--read-write", "--allow-delete", "--allow-move", "--allow-git"):
            write_flags.append(arg)
    if not write_flags:
        return []
    roots = [a for a in server.args if _is_broad_root(a)]
    scope = ("over root %r" % roots[0]) if roots else "over its configured root"
    return ["write/delete is enabled (%s) %s" % (", ".join(sorted(set(write_flags))), scope)]


def check_container_escape(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if _basename(server.command) not in CONTAINER_CLIS:
        return []
    evidence = []
    joined = " ".join(server.args)
    if "--privileged" in server.args:
        evidence.append("--privileged gives the container full host capability")
    if re.search(r"--(network|net)[= ]host", joined):
        evidence.append("--network host puts the server on the host network stack")
    if re.search(r"--pid[= ]host", joined):
        evidence.append("--pid host shares the host process namespace")
    if "/var/run/docker.sock" in joined:
        evidence.append("the docker socket is mounted - the server can control the host daemon")
    for index, arg in enumerate(server.args):
        if arg in ("-v", "--volume", "--mount") and index + 1 < len(server.args):
            mount = server.args[index + 1]
            source = mount.split(":")[0]
            if source in ("/", "//") or _is_broad_root(source):
                evidence.append("host root %r is mounted into the container" % mount)
    if re.search(r"--cap-add[= ](ALL|SYS_ADMIN)", joined, re.IGNORECASE):
        evidence.append("--cap-add ALL/SYS_ADMIN restores near-root capabilities")
    return evidence


def check_plaintext_transport(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if not server.url or not server.url.lower().startswith("http://"):
        return []
    host = server.url.split("://", 1)[1].split("/", 1)[0].split(":")[0].lower()
    if host in LOCAL_HOSTS:
        return []
    return ["remote endpoint %s uses plaintext HTTP; tool arguments and results travel in the clear" % server.url]


def check_unauthenticated_remote(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if not server.url or not server.url.lower().startswith("https://"):
        return []
    names = {key.lower() for key in server.headers}
    if names & AUTH_HEADER_NAMES:
        return []
    return ["remote endpoint %s is configured with no authentication header" % server.url]


def check_tls_verification_disabled(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    evidence = []
    for key, value in sorted(server.env.items()):
        if key.upper() == "NODE_TLS_REJECT_UNAUTHORIZED" and value.strip() == "0":
            evidence.append("env NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS checks process-wide")
        if key.upper() in ("PYTHONHTTPSVERIFY", "CURL_CA_BUNDLE_CHECK") and value.strip() == "0":
            evidence.append("env %s=0 disables certificate validation" % key)
    for arg in server.args:
        if arg.lower() in ("--insecure", "-k", "--no-verify", "--skip-tls-verify",
                           "--disable-ssl-verification", "--tls-skip-verify"):
            evidence.append("flag %s skips certificate verification" % arg)
    return evidence


READ_ONLY_PREFIXES = (
    "read", "list", "get", "search", "find", "show", "view", "fetch",
    "query", "describe", "inspect", "stat", "head", "count", "export",
)


def _is_read_only_tool(name: str) -> bool:
    """Heuristic: does this tool name look incapable of changing state?"""
    token = str(name).strip().lower().replace("-", "_")
    if token in ("*", "all", "any"):
        return False
    if any(word in token for word in ("write", "delete", "remove", "exec", "run",
                                      "create", "update", "put", "post", "patch",
                                      "drop", "kill", "install", "deploy", "send",
                                      "commit", "push", "upload", "move", "rename",
                                      "set", "edit", "apply", "approve", "pay")):
        return False
    return token.startswith(READ_ONLY_PREFIXES)


def check_auto_approve(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    auto = server.auto_approve
    if auto is None or auto is False:
        return []
    if auto is True:
        return ["auto-approve is enabled for every tool on this server"]
    if isinstance(auto, str) and auto.strip().lower() in ("true", "yes", "always", "*"):
        return ["auto-approve is set to %r" % auto]
    if isinstance(auto, dict):
        names = [key for key in auto if not _is_read_only_tool(key)]
        if names:
            return ["auto-approve rules cover state-changing tool(s): %s" % ", ".join(sorted(names))]
        return []
    if isinstance(auto, (list, tuple)):
        risky = [str(item) for item in auto if not _is_read_only_tool(item)]
        if not risky:
            return []
        return [
            "auto-approve covers %d tool(s) that can change state: %s"
            % (len(risky), ", ".join(sorted(risky)))
        ]
    return []


def check_unpinned_image(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if _basename(server.command) not in CONTAINER_CLIS:
        return []
    image = _docker_image(server.args)
    if not image:
        return []
    if _image_pinned(image):
        return []
    return ["image %s is not pinned to a tag or digest, so every restart can pull new code" % image]


def check_shell_metachars(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    evidence = []
    for arg in server.args:
        for token in SHELL_METACHARS:
            if token in arg:
                evidence.append("argument %r contains shell metacharacters %r" % (arg, token))
                break
    return evidence


def check_inline_code(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if _basename(server.command) not in INTERPRETERS:
        return []
    for index, arg in enumerate(server.args):
        if arg.lower() in INLINE_CODE_FLAGS and index + 1 < len(server.args):
            code = server.args[index + 1]
            snippet = code if len(code) <= 80 else code[:77] + "..."
            return ["inline code passed via %s is never reviewed or updated: %s" % (arg, snippet)]
    return []


def check_duplicate_server(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    duplicates = ctx.get("duplicates") or {}
    key = (server.source, _basename(server.command), tuple(server.args), server.url)
    names = [n for n in duplicates.get(key, []) if n != server.name]
    if not names:
        return []
    return ["registered twice with an identical launch under %s" % ", ".join(sorted(names))]


def check_cwd_outside_project(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    root = ctx.get("root")
    if not root or not server.cwd:
        return []
    try:
        base = os.path.abspath(root)
        target = os.path.abspath(os.path.join(base, server.cwd))
        inside = os.path.commonpath([base, target]) == base
    except (ValueError, OSError):
        return []
    if inside:
        return []
    return ["cwd %r resolves outside the audited project (%s)" % (server.cwd, target)]


def check_credentials_in_url(server: ServerSpec, ctx: Dict[str, Any]) -> List[str]:
    if not server.url:
        return []
    evidence = []
    rest = server.url.split("://", 1)[1] if "://" in server.url else server.url
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        evidence.append("URL embeds credentials in userinfo (user:password@host)")
    query = server.url.split("?", 1)[1] if "?" in server.url else ""
    if query and re.search(
        r"(token|key|secret|password|api[_-]?key|sig)=", query, re.IGNORECASE
    ):
        evidence.append("credential-looking parameter in the URL query string")
    return evidence


RULES: List[Rule] = [
    Rule(
        id="MCP001",
        severity="critical",
        title="Credential hardcoded in server environment",
        why=(
            "The key sits in plaintext in a file that gets committed, synced and shared. "
            "Anyone who reads the config - or any tool the agent runs - has the credential, "
            "and rotating it means editing every copy."
        ),
        fix=(
            "Replace the literal with an environment reference such as ${GITHUB_TOKEN} and "
            "keep the real value in your shell profile or a secret manager. Rotate anything "
            "already committed."
        ),
        ref="MCP security best practices: no secrets in client config",
        check=check_secret_in_env,
    ),
    Rule(
        id="MCP002",
        severity="high",
        title="Unpinned package executed at launch",
        why=(
            "An unpinned npx/uvx spec installs whatever the registry serves that day. "
            "One compromised release and the agent launches attacker code with your filesystem "
            "and network access, with no change on your side."
        ),
        fix="Pin an exact version (pkg@1.2.3 or pkg==1.2.3) and bump it deliberately.",
        ref="Supply chain: dependency confusion and malicious release takeovers",
        check=check_unpinned_package,
    ),
    Rule(
        id="MCP003",
        severity="high",
        title="Server launched through a shell wrapper",
        why=(
            "A shell string hides the real command from every reviewer and from the client's own "
            "argument handling. Whatever is interpolated into it runs as you, and the server you "
            "think you installed is not necessarily the one that starts."
        ),
        fix="Call the binary directly and pass argv entries instead of a shell -c string.",
        ref="CWE-78: OS command injection",
        check=check_shell_wrapper,
    ),
    Rule(
        id="MCP004",
        severity="high",
        title="Filesystem server rooted at a whole tree",
        why=(
            "Rooting a filesystem server at /, your home directory or a whole user profile hands "
            "the model read access to SSH keys, cloud credentials, browser profiles and every "
            "other project on the machine."
        ),
        fix="Point the server at the single project directory it needs (e.g. ./src or ~/work/app).",
        ref="Principle of least privilege",
        check=check_broad_filesystem_root,
    ),
    Rule(
        id="MCP005",
        severity="high",
        title="Write and delete access enabled",
        why=(
            "Read-only mistakes are recoverable. With write access an injected instruction or one "
            "hallucinated call can delete source files, rewrite config, or corrupt the directory "
            "the server was pointed at."
        ),
        fix="Run read-only unless the workflow genuinely writes, and keep the writable root narrow.",
        ref="Prompt injection impact: destructive tool calls",
        check=check_write_access,
    ),
    Rule(
        id="MCP006",
        severity="critical",
        title="Container escape surface exposed",
        why=(
            "A container with --privileged, a mounted docker socket, host networking or host PID "
            "shares the host's power. The container boundary stops being a boundary, so a "
            "compromised server owns the machine."
        ),
        fix="Drop the privileged flags, never mount the docker socket, and use a user namespace.",
        ref="Container security: privileged mode is host root",
        check=check_container_escape,
    ),
    Rule(
        id="MCP007",
        severity="high",
        title="Remote MCP endpoint over plaintext HTTP",
        why=(
            "Every tool call and result crosses the network in the clear, including the file "
            "content you ask about and the credentials in headers. Anyone on the path can read "
            "and rewrite the conversation."
        ),
        fix="Use https:// for any non-local endpoint, or tunnel it over SSH.",
        ref="CWE-319: Cleartext transmission of sensitive information",
        check=check_plaintext_transport,
    ),
    Rule(
        id="MCP008",
        severity="medium",
        title="Remote endpoint configured without authentication",
        why=(
            "An unauthenticated endpoint accepts tool calls from anyone who can reach it, and "
            "there is nothing tying a response to your session. That is request forgery waiting "
            "to happen."
        ),
        fix="Add an Authorization (or X-API-Key) header sourced from an environment reference.",
        ref="OWASP API Security: broken authentication",
        check=check_unauthenticated_remote,
    ),
    Rule(
        id="MCP009",
        severity="critical",
        title="TLS verification disabled",
        why=(
            "With certificate checks off, any man in the middle can impersonate the server, read "
            "every tool result, and return forged data the model will trust as fact."
        ),
        fix="Remove the flag or the NODE_TLS_REJECT_UNAUTHORIZED=0 env entry and install the CA instead.",
        ref="CWE-295: Improper certificate validation",
        check=check_tls_verification_disabled,
    ),
    Rule(
        id="MCP010",
        severity="high",
        title="State-changing tools auto-approved without review",
        why=(
            "Auto-approve removes the only human checkpoint between a model decision and a side "
            "effect. A prompt injection in a file, an issue or a web page then writes, deletes or "
            "executes silently, and nothing in the UI shows it happened."
        ),
        fix=(
            "Auto-approve read-only tools only (read_*, list_*, get_*), and keep anything that "
            "writes, deletes, executes or pays behind a prompt."
        ),
        ref="Human in the loop for destructive actions",
        check=check_auto_approve,
    ),
    Rule(
        id="MCP011",
        severity="medium",
        title="Container image not pinned",
        why=(
            "An image without a tag or digest is whatever :latest means today. Upstream can "
            "change it without warning, so your audited configuration stops describing what runs."
        ),
        fix="Pin a version tag or, better, a sha256 digest.",
        ref="Reproducible, auditable deployments",
        check=check_unpinned_image,
    ),
    Rule(
        id="MCP012",
        severity="medium",
        title="Shell metacharacters inside an argument",
        why=(
            "If any part of this argument is built from a variable, the metacharacters turn it "
            "into command chaining. Even hardcoded, it signals the command is doing shell work "
            "that should have been argv."
        ),
        fix="Split the command into separate argv entries and pass values as plain arguments.",
        ref="CWE-78: OS command injection",
        check=check_shell_metachars,
    ),
    Rule(
        id="MCP013",
        severity="medium",
        title="Inline code shipped as a launch argument",
        why=(
            "Code embedded in the config is invisible to your dependency scanner, unpinned, "
            "unversioned and unreviewed, and it changes whenever someone edits the config."
        ),
        fix="Move the script into a pinned package or a reviewed file in the repository.",
        ref="Reviewability of executed code",
        check=check_inline_code,
    ),
    Rule(
        id="MCP014",
        severity="low",
        title="Server registered twice with the same launch",
        why=(
            "Duplicate registrations produce duplicate tool names, so the model may call the "
            "wrong copy and you cannot tell which one ran. It also doubles the context cost."
        ),
        fix="Delete the duplicate entry and keep one canonical registration.",
        ref="Tool selection ambiguity",
        check=check_duplicate_server,
    ),
    Rule(
        id="MCP015",
        severity="low",
        title="Working directory outside the audited project",
        why=(
            "A cwd outside the repository means relative paths resolve somewhere unexpected, and "
            "the server can reach files the project was never meant to expose."
        ),
        fix="Set cwd to the project root, or a subdirectory of it.",
        ref="Least privilege for working directories",
        check=check_cwd_outside_project,
    ),
    Rule(
        id="MCP016",
        severity="high",
        title="Credential embedded in the endpoint URL",
        why=(
            "URLs end up in logs, error messages and crash reports. A token in the URL is leaked "
            "every time the connection is logged, and query-string secrets are the first thing a "
            "proxy records."
        ),
        fix="Move the credential into an Authorization header sourced from an environment reference.",
        ref="CWE-598: Sensitive information in query strings",
        check=check_credentials_in_url,
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}


def _duplicate_map(servers: List[ServerSpec]) -> Dict[tuple, List[str]]:
    groups: Dict[tuple, List[str]] = {}
    for server in servers:
        key = (server.source, _basename(server.command), tuple(server.args), server.url)
        groups.setdefault(key, []).append(server.name)
    return {key: names for key, names in groups.items() if len(names) > 1}


def evaluate(servers: List[ServerSpec], root: Optional[str] = None) -> List[Finding]:
    """Run every rule over every enabled server and return sorted findings."""
    context: Dict[str, Any] = {
        "root": root,
        "duplicates": _duplicate_map(servers),
    }
    findings: List[Finding] = []
    for server in servers:
        if server.disabled:
            continue
        for rule in RULES:
            evidence = rule.check(server, context) or []
            if not evidence:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    server=server.name,
                    source=server.source,
                    evidence=list(evidence),
                    why=rule.why,
                    fix=rule.fix,
                    ref=rule.ref,
                )
            )
    findings.sort(key=lambda finding: finding.sort_key())
    return findings


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
