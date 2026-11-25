#!/usr/bin/env python3
"""Read-only Linux GitHub access evidence. No malware or persistence scanning."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import dataclass
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

FILE_LIMIT = 2 * 1024 * 1024
OUTPUT_LIMIT = 8 * 1024 * 1024
ITEM_LIMIT = 2000
EDITOR_DB_LIMIT = 1000
TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,100}\Z")
EXTENSION = r"[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+"
ACCOUNT_KEY = re.compile(r"(github(?:-enterprise)?)-([A-Za-z0-9][A-Za-z0-9_.@ -]{0,120}?)(-usages)?\Z")
PREFERENCE_KEY = re.compile(r"(" + EXTENSION + r")-(github(?:-enterprise)?)\Z")
SYNC_KEYS = ("sync.currentAuthenticationProvider", "sync.currentSessionId", "sync.enable",
             "userDataSync.account", "userDataSyncAccount", "userDataSyncAccountPreference",
             "userDataSyncAccount.authenticationProvider")


def safe_url(value: str) -> str:
    """Discard URL userinfo, query/fragment and executable remote-helper forms."""
    try:
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https", "ssh", "git"} or not parsed.hostname:
                raise ValueError()
            host = parsed.hostname
            if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
                raise ValueError()
            if ":" in host:
                host = "[" + host + "]"
            port = ":" + str(parsed.port) if parsed.port else ""
            return urlunsplit((parsed.scheme, host + port, parsed.path, "", ""))
        scp = re.fullmatch(r"(?:[^@\s/:]+@)?([A-Za-z0-9.-]+):([^\s]+)", value)
        if scp and not scp[2].startswith(":"):
            return scp[1] + ":" + scp[2].split("?", 1)[0].split("#", 1)[0]
    except (ValueError, TypeError):
        pass
    return "<local or nonstandard destination; value withheld>"


def safe_text(value: object, secrets=()) -> str:
    text = str(value)
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
                  "[PRIVATE KEY WITHHELD]", text, flags=re.S)
    text = re.sub(r"(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)", "[REDACTED]", text)
    text = re.sub(r"(?i)(?:authorization|password|access_token|oauth_token)\s*[:=]\s*[^\r\n]+",
                  "[CREDENTIAL FIELD WITHHELD]", text)
    text = re.sub(r"(?:https?|ssh|git)://[^\s<>\"']+", lambda m: safe_url(m[0]), text)
    result = "".join(("\\n" if c == "\n" else "\\r" if c == "\r" else "\\t" if c == "\t"
                      else f"\\x{ord(c):02x}") if unicodedata.category(c).startswith("C") else c for c in text)
    return result if len(result) <= 4000 else result[:4000] + " [truncated]"


def read_bounded(path: Path, limit=FILE_LIMIT) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError("not a regular file")
        data = file.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file size limit exceeded")
        return data


@dataclass
class Result:
    code: int = -1
    out: bytes = b""
    err: bytes = b""
    problem: str = ""


def run(argv, *, env=None, cwd=None, timeout=10, limit=OUTPUT_LIMIT) -> Result:
    """Bound time/output and kill the complete subprocess group on interruption."""
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    except (FileNotFoundError, PermissionError, OSError):
        return Result(problem="tool unavailable")
    output = [bytearray(), bytearray()]
    problem = ""
    started = time.monotonic()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 0)
            selector.register(child.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    problem = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        if sum(map(len, output)) > limit:
                            problem = "output limit exceeded"
                            break
                if problem:
                    break
            if not problem:
                try:
                    child.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    problem = "timeout"
    finally:
        # Also kill descendants retaining pipes after their parent exits.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()
        child.stderr.close()
    return Result(child.returncode, bytes(output[0][:limit]), bytes(output[1][:limit]), problem)


class Reporter:
    def __init__(self, stream=sys.stdout, report=None, secrets=()):
        self.stream = stream
        self.secrets = list(secrets)
        self.entries = []
        self.number = 0
        self.report = None
        if report is not None:
            fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.report = os.fdopen(fd, "w", encoding="utf-8")

    def write(self, text):
        for stream in (self.stream, self.report):
            if stream is not None:
                stream.write(text + "\n")
                stream.flush()

    def section(self, number, title):
        self.number = number
        self.write(f"\n── {number}. {safe_text(title, self.secrets)} " + "─" * 12)

    def emit(self, status, text):
        message = safe_text(text, self.secrets)
        self.entries.append((self.number, status, message))
        self.write(f"[{status:<8}] {message}")

    def counts(self):
        return Counter(status for _, status, _ in self.entries)

    def close(self):
        if self.report:
            self.report.close()


def key_metadata(data: bytes) -> dict:
    """Read OpenSSH encryption metadata, without decrypting or exposing key data."""
    result = {"kind": "unknown", "fingerprint": "", "hardware": False}
    if data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        try:
            encoded = b"".join(data.splitlines()[1:-1])
            raw = base64.b64decode(encoded, validate=True)
            if not raw.startswith(b"openssh-key-v1\0"):
                return result
            cursor = len(b"openssh-key-v1\0")
            fields = []
            for _ in range(3):
                length = struct.unpack_from(">I", raw, cursor)[0]
                cursor += 4
                if length > len(raw) - cursor:
                    return result
                fields.append(raw[cursor:cursor + length])
                cursor += length
            count = struct.unpack_from(">I", raw, cursor)[0]
            cursor += 4
            if count != 1:
                return result
            size = struct.unpack_from(">I", raw, cursor)[0]
            cursor += 4
            public = raw[cursor:cursor + size]
            cursor += size
            private_size = struct.unpack_from(">I", raw, cursor)[0]
            cursor += 4
            if len(public) != size or private_size == 0 or cursor + private_size != len(raw):
                return result
            public_type_size = struct.unpack_from(">I", public)[0]
            public_type = public[4:4 + public_type_size]
            if not public_type.startswith((b"ssh-", b"ecdsa-", b"sk-")):
                return result
            cipher, kdf, _ = fields
            if cipher == b"none" and kdf != b"none":
                return result
            result.update(kind="plain" if cipher == b"none" else "encrypted",
                          fingerprint="SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("="),
                          hardware=public_type.startswith(b"sk-"))
        except (ValueError, struct.error):
            pass
    elif b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in data or b"Proc-Type: 4,ENCRYPTED" in data:
        result["kind"] = "encrypted-pem"
    elif re.match(br"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", data):
        result["kind"] = "pem"
    return result


def parse_gh_hosts(text: str) -> list[dict]:
    """Recognize gh's simple generated YAML layout, never extract token values.

    This is deliberately not a general YAML parser. Complex YAML is UNKNOWN.
    """
    if text.strip() in ("", "{}"):
        return []
    hosts = {}
    host = None
    users_indent = None
    child_indent = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line or ":" not in line:
            raise ValueError("unsupported gh configuration layout")
        indent = len(line) - len(line.lstrip())
        key, value = line.strip().split(":", 1)
        key, value = key.strip("\"'"), value.strip()
        if indent == 0:
            if value not in ("", "{}") or not re.fullmatch(r"[A-Za-z0-9.-]+", key):
                raise ValueError("unsupported gh configuration layout")
            host, users_indent, child_indent = key, None, None
            hosts.setdefault(host, {"active": None, "users": set()})
        elif host:
            if child_indent is None:
                child_indent = indent
            if indent == child_indent:
                users_indent = indent if key == "users" else None
                if key == "user":
                    login = value.strip("\"'")
                    if not LOGIN.fullmatch(login):
                        raise ValueError("unsupported gh account value")
                    hosts[host]["active"] = login
                    hosts[host]["users"].add(login)
            elif users_indent is not None and indent > users_indent and value in ("", "{}"):
                # Credential property names are excluded even when empty.
                if key not in {"oauth_token", "git_protocol", "user", "refresh_token"}:
                    if not LOGIN.fullmatch(key):
                        raise ValueError("unsupported gh account value")
                    hosts[host]["users"].add(key)
        else:
            raise ValueError("unsupported gh configuration layout")
    return [{"host": host, "login": login, "active": login == info["active"]}
            for host, info in hosts.items() for login in sorted(info["users"])]


def gh_results(payload) -> list[tuple[str, str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("hosts"), dict):
        raise ValueError("unsupported gh JSON")
    rows = payload["hosts"].get("github.com", [])
    if not isinstance(rows, list):
        raise ValueError("unsupported gh account list")
    results = []
    for row in rows[:ITEM_LIMIT]:
        if not isinstance(row, dict):
            raise ValueError("unsupported gh account record")
        login = row.get("login", "")
        login = login if isinstance(login, str) and LOGIN.fullmatch(login) else "unresolved identity"
        source = row.get("tokenSource", "")
        source = source if source in (*TOKEN_VARS, "keyring") else "saved credential"
        detail = f"github.com account: {login}; active: {row.get('active') is True}; source: {source}"
        state = row.get("state")
        if state == "success" and login != "unresolved identity":
            results.append(("VERIFIED", detail + "; credential accepted; reported identity mapping requires independent confirmation"))
        elif state == "error":
            results.append(("REVIEW", detail + "; authentication check failed (not proof of revocation)"))
        else:
            results.append(("UNKNOWN", detail + "; authentication not established"))
    return results


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect refused", headers, fp)


def github_identity(token: str, timeout: float) -> tuple[str | None, str]:
    """Resolve a credential against a fixed TLS endpoint, without proxy/redirects."""
    if not token or len(token) > 8192 or not re.fullmatch(r"[!-~]+", token):
        return None, "credential format unsupported"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request("https://api.github.com/user", headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "User-Agent": "local-github-access-audit", "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                return None, "identity endpoint returned a non-success status"
            data = response.read(FILE_LIMIT + 1)
            if len(data) > FILE_LIMIT:
                return None, "identity response exceeded limit"
            body = json.loads(data)
            login = body.get("login") if isinstance(body, dict) else None
            if isinstance(login, str) and LOGIN.fullmatch(login):
                return login, ""
            return None, "identity response schema unsupported"
    except urllib.error.HTTPError as error:
        return None, "credential rejected" if error.code == 401 else "identity endpoint unavailable or redirect refused"
    except (OSError, ValueError, urllib.error.URLError):
        return None, "identity network check failed; raw errors withheld"


def vscode_results(rows) -> list[tuple[str, str]]:
    result = []
    for key, raw in rows:
        preference = PREFERENCE_KEY.fullmatch(key)
        account = ACCOUNT_KEY.fullmatch(key)
        if preference:
            label = raw.decode("utf-8") if isinstance(raw, bytes) else raw
            try:
                decoded = json.loads(label)
                label = decoded if isinstance(decoded, str) else label
            except (ValueError, TypeError):
                pass
            if isinstance(label, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@ -]{0,120}", label):
                result.append(("EVIDENCE", f"Cached account preference: {preference[1]} -> {preference[2]} account {label}"))
        elif account:
            try:
                entries = json.loads(raw)
                if not isinstance(entries, list):
                    continue
                for entry in entries[:ITEM_LIMIT]:
                    if not isinstance(entry, dict):
                        continue
                    extension = entry.get("extensionId" if account[3] else "id", "")
                    if not isinstance(extension, str) or not re.fullmatch(EXTENSION, extension):
                        continue
                    association = "historical usage" if account[3] else "saved access " + ("denied" if entry.get("allowed") is False else "allowed")
                    result.append(("EVIDENCE", f"{account[1]} account {account[2]} -> {extension}; {association}"))
            except (ValueError, TypeError, UnicodeError):
                continue
        elif key in SYNC_KEYS:
            # Session IDs and arbitrary JSON are not identities and are withheld.
            result.append(("EVIDENCE", f"Settings Sync metadata present: {key}; identity requires Accounts confirmation"))
    return result


class Audit:
    def __init__(self, options, reporter, env=None):
        self.options, self.report = options, reporter
        self.env = dict(os.environ if env is None else env)
        self.home = Path(options.home).absolute()
        self.isolated = self.home.resolve() != Path.home().resolve()
        self.config_home = Path(self.env.get("XDG_CONFIG_HOME", str(self.home / ".config"))) if not self.isolated else self.home / ".config"
        self.tools = {tool: shutil.which(tool, path=self.env.get("PATH")) for tool in ("git", "ssh-keygen", "ssh-add", "gh", "code")}
        self.repos = []
        self.configs = []
        self.tool_versions = {}
        self.child_env = dict(self.env)
        for key in list(self.child_env):
            if key.startswith("GIT_") or key in {"SSH_ASKPASS", "GIT_ASKPASS"}:
                self.child_env.pop(key, None)
        self.child_env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.config_home),
                              GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat",
                              GH_PAGER="cat", GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
                              GH_NO_EXTENSION_UPDATE_NOTIFIER="1", SSH_ASKPASS_REQUIRE="never", LC_ALL="C")
        if self.isolated:
            for key in (*TOKEN_VARS, "SSH_AUTH_SOCK", "GH_CONFIG_DIR", "GH_HOST"):
                self.child_env.pop(key, None)

    def execute(self, tool, args, **kwargs):
        if not self.tools.get(tool):
            return Result(problem="tool unavailable")
        return run([self.tools[tool], *args], env=self.child_env, timeout=self.options.timeout, **kwargs)

    def git(self, path, *args):
        return self.execute("git", ["--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false",
                                   "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
                                   "-c", "log.showSignature=false", "-C", str(path), *args])

    def problem(self, result, description):
        if result.problem or result.code != 0:
            self.report.emit("UNKNOWN", description + ": " + (result.problem or "command failed; raw output withheld"))
            return True
        return False

    def permissions(self, path, *, private=False):
        try:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                self.report.emit("SKIPPED", f"{path}: symlink; target not followed")
                return False
            bits = stat.S_IMODE(mode)
            unsafe = bool(bits & (0o077 if private else 0o022))
            self.report.emit("REVIEW" if unsafe else "INFO", f"{path}: permissions {bits:04o}" + ("; broader access than expected" if unsafe else ""))
            if path.stat().st_uid != os.getuid():
                self.report.emit("REVIEW", f"{path}: owned by a different user")
            return True
        except OSError:
            self.report.emit("UNKNOWN", f"{path}: permissions unavailable")
            return False

    def tools_section(self):
        self.report.section(1, "Tools and coverage")
        self.report.emit("INFO", "Mode: " + ("local + online gh identity verification" if self.options.online else "local only; credentials not validated online"))
        self.report.emit("INFO", f"Target home: {self.home}; GitHub.com personal accounts; malware checks deferred")
        for tool, path in self.tools.items():
            self.report.emit("INFO" if path else "SKIPPED", f"{tool}: {path or 'not available'}")
            if path and tool in {"git", "gh"}:
                self.report.emit("CHECK", f"Reading {tool} version")
                result = self.execute(tool, ["--version"])
                if not self.problem(result, f"{tool} version"):
                    match = re.search(rb"(?:git|gh) version (\d+\.\d+\.\d+)", result.out)
                    if match:
                        self.tool_versions[tool] = match[1].decode()
                        self.report.emit("INFO", f"{tool} version {self.tool_versions[tool]}")
        self.report.emit("INFO", f"Runtime: Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}; subprocess timeout {self.options.timeout:g}s")
        if self.isolated:
            self.report.emit("INFO", "Alternate home: caller's agent, XDG/gh overrides and environment credentials excluded")
        if not self.isolated:
            for key in sorted(self.env):
                if key.startswith("GIT_"):
                    self.report.emit("MANUAL", f"Environment override {key} is set; repository inspection excludes process-level Git overrides")

    def ssh_section(self):
        self.report.section(2, "SSH keys and agent")
        roots = list(dict.fromkeys([self.home / ".ssh", *map(Path, self.options.key_dir)]))
        candidates = []
        for root in roots:
            self.report.emit("CHECK", f"Inspecting SSH directory {root}")
            if not root.exists():
                self.report.emit("SKIPPED", f"{root}: directory absent")
                continue
            if not self.permissions(root, private=True):
                continue
            try:
                for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda error: self.report.emit("UNKNOWN", "SSH directory could not be enumerated; coverage incomplete")):
                    if len(Path(directory).relative_to(root).parts) >= 3:
                        if dirs:
                            self.report.emit("SKIPPED", f"{directory}: deeper key directories outside scan depth")
                        dirs[:] = []
                    dirs[:] = [d for d in dirs if not Path(directory, d).is_symlink()]
                    for name in files:
                        candidates.append(Path(directory, name))
                        if len(candidates) >= ITEM_LIMIT:
                            break
                    if len(candidates) >= ITEM_LIMIT:
                        self.report.emit("UNKNOWN", "SSH file count limit reached; coverage incomplete")
                        break
            except OSError:
                self.report.emit("UNKNOWN", f"{root}: directory unreadable")
        found = 0
        for path in candidates:
            if path.is_symlink():
                self.report.emit("SKIPPED", f"{path}: symlink; target not followed")
                continue
            if path.suffix == ".pub" or path.name in {"known_hosts", "known_hosts.old", "authorized_keys", "config"}:
                continue
            try:
                data = read_bounded(path)
            except (OSError, ValueError):
                self.report.emit("UNKNOWN", f"{path}: unreadable or exceeds file limit")
                continue
            if b"PRIVATE KEY-----" not in data[:100]:
                continue
            found += 1
            self.report.emit("CHECK", f"Checking private key {path}")
            self.permissions(path, private=True)
            metadata = key_metadata(data)
            if metadata["fingerprint"]:
                self.report.emit("EVIDENCE", f"{path}: {metadata['fingerprint']} (embedded public-key fingerprint)")
            if metadata["hardware"]:
                self.report.emit("MANUAL", f"{path}: hardware-backed key; device presence/PIN policy unverified")
            elif metadata["kind"] in {"encrypted", "encrypted-pem"}:
                self.report.emit("EVIDENCE", f"{path}: encrypted private-key container; passphrase strength and full key validity untested")
            elif metadata["kind"] in {"plain", "pem"}:
                check = self.execute("ssh-keygen", ["-y", "-P", "", "-f", str(path)])
                if check.code == 0 and not check.problem:
                    self.report.emit("REVIEW", f"{path}: no passphrase; key can be loaded with an empty passphrase")
                elif metadata["kind"] == "plain" and path.stat().st_mode & 0o077:
                    self.report.emit("REVIEW", f"{path}: OpenSSH container has no passphrase encryption; full key validation blocked or failed (check permissions)")
                else:
                    self.report.emit("UNKNOWN", f"{path}: empty-passphrase check failed ({check.problem or 'unsupported, encrypted, invalid or unsafe permissions'})")
            else:
                self.report.emit("UNKNOWN", f"{path}: malformed or unsupported private-key format")
        self.report.emit("INFO", f"Private-key candidates inspected: {found}; keys elsewhere are outside coverage")
        self.ssh_config(self.home / ".ssh/config", set())
        if not self.isolated:
            self.ssh_config(Path("/etc/ssh/ssh_config"), set())
        if not self.isolated and self.env.get("SSH_AUTH_SOCK"):
            self.report.emit("CHECK", "Listing agent identity fingerprints (no authentication attempted)")
            result = self.execute("ssh-add", ["-l"])
            if result.code == 1 and not result.problem:
                self.report.emit("INFO", "SSH agent has no loaded identities")
            elif not self.problem(result, "SSH agent identity list"):
                fingerprints = re.findall(rb"SHA256:[A-Za-z0-9+/]+", result.out)
                for fingerprint in fingerprints[:ITEM_LIMIT]:
                    self.report.emit("EVIDENCE", "Agent identity available: " + fingerprint.decode() + "; account and lifetime unknown")
                if not fingerprints and result.out.strip():
                    self.report.emit("UNKNOWN", "SSH agent fingerprint format unsupported")
        else:
            self.report.emit("SKIPPED", "Caller SSH agent not selected or SSH_AUTH_SOCK absent")
        self.report.emit("MANUAL", "SSH aliases and User git do not identify a GitHub account; no SSH connection attempted")

    def ssh_config(self, path, seen, depth=0, base=None):
        if base is None:
            base = Path("/etc/ssh") if path.is_relative_to("/etc/ssh") else self.home / ".ssh"
        if path in seen:
            return
        seen.add(path)
        if depth > 8 or len(seen) > 100:
            self.report.emit("UNKNOWN", "SSH include limit reached")
            return
        if not path.exists() and not path.is_symlink():
            return
        try:
            text = read_bounded(path).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            self.report.emit("UNKNOWN", f"SSH configuration {path}: unreadable, oversized, or symlink")
            return
        self.report.emit("EVIDENCE", f"SSH configuration source: {path}; static inspection, conditions not evaluated")
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.match(r"\s*([A-Za-z]+)(?:\s+|=)(.*)", line)
            if not match:
                continue
            key, value = match[1].lower(), match[2].strip()
            where = f"{path}:{line_number}"
            if key in {"proxycommand", "localcommand", "remotecommand", "knownhostscommand"} or (key == "match" and re.search(r"\bexec\b", value)):
                self.report.emit("REVIEW", f"{where}: SSH {match[1]} command configured; content withheld, never executed")
            elif key in {"host", "hostname", "user", "identityfile", "identityagent", "identitiesonly", "forwardagent", "addkeystoagent"}:
                if not re.fullmatch(r"[A-Za-z0-9_./~:@*?%! +\[\]-]{1,300}", value):
                    value = "<nonstandard value withheld>"
                self.report.emit("REVIEW" if key == "forwardagent" and value.lower() != "no" else "EVIDENCE",
                                 f"{where}: {match[1]} {value}; configured, not evaluated")
            elif key == "include":
                self.report.emit("EVIDENCE", f"{where}: SSH Include directive present")
                for pattern in value.split():
                    if not re.fullmatch(r"[A-Za-z0-9_./~*?\[\]-]+", pattern):
                        self.report.emit("MANUAL", f"{where}: quoted or nonstandard include requires manual review")
                        continue
                    expanded = self.expand(pattern, base)
                    matches = glob.glob(str(expanded))[:100]
                    if not matches:
                        self.report.emit("INFO", f"{where}: include matched no files; empty include globs are allowed")
                    for included in matches:
                        self.ssh_config(Path(included), seen, depth + 1, base)

    def gh_section(self):
        self.report.section(3, "GitHub CLI accounts")
        config = Path(self.env.get("GH_CONFIG_DIR", str(self.config_home / "gh"))) if not self.isolated else self.config_home / "gh"
        path = config / "hosts.yml"
        self.report.emit("CHECK", f"Inspecting saved GitHub CLI account metadata: {path}")
        if path.exists() or path.is_symlink():
            try:
                for row in parse_gh_hosts(read_bounded(path).decode("utf-8")):
                    self.report.emit("EVIDENCE", f"Saved gh account: {row['host']} / {row['login']}; configured active: {row['active']}; credential validity untested")
                    if row["host"] != "github.com":
                        self.report.emit("MANUAL", f"{row['host']}: online verification excluded; only github.com is supported")
            except (OSError, ValueError, UnicodeError):
                self.report.emit("UNKNOWN", "Saved gh metadata unreadable or unsupported YAML; credential values withheld")
        else:
            self.report.emit("INFO", "No saved gh hosts file at the selected location; this does not rule out environment/keyring access")
        if not self.isolated:
            for variable in TOKEN_VARS:
                if self.env.get(variable):
                    self.report.emit("REVIEW", f"{variable} is set; can override saved credentials for applicable hosts; value withheld")
        if not self.options.online:
            self.report.emit("SKIPPED", "Live gh account verification disabled; use --online to check current authentication")
            return
        if not self.tools["gh"]:
            self.report.emit("SKIPPED", "gh unavailable; cannot verify accounts")
            return
        self.report.emit("CHECK", "Checking gh account-verification capabilities")
        help_result = self.execute("gh", ["auth", "status", "--help"])
        if self.problem(help_result, "gh auth status capabilities"):
            return
        args = ["auth", "status", "--hostname", "github.com", "--json", "hosts"]
        if b"--no-refresh" in help_result.out:
            args.append("--no-refresh")
        elif self.tool_versions.get("gh") == "2.93.0":
            self.report.emit("INFO", "gh 2.93.0: using version-reviewed status implementation without automatic refresh")
        else:
            self.report.emit("SKIPPED", "gh lacks --no-refresh and this version's refresh behavior is unverified; no live request made")
            return
        # A configured HTTP Unix socket or proxy changes where credentials travel.
        if any(self.env.get(k) for k in ("GH_DEBUG", "GH_HTTP_UNIX_SOCKET", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")):
            self.report.emit("SKIPPED", "Online verification requires reviewing configured debug/proxy/socket overrides first")
            return
        for config_file in (config / "config.yml", path):
            if config_file.exists() or config_file.is_symlink():
                try:
                    if b"http_unix_socket" in read_bounded(config_file).lower():
                        self.report.emit("SKIPPED", "gh HTTP Unix socket configuration present; online verification requires manual review")
                        return
                except (OSError, ValueError):
                    self.report.emit("UNKNOWN", "gh configuration unreadable; live verification skipped")
                    return
        self.report.emit("CHECK", "Verifying GitHub.com account identities (no repository write test)")
        result = self.execute("gh", args)
        if self.problem(result, "gh identity verification"):
            return
        try:
            payload = json.loads(result.out)
            rows = gh_results(payload)
            for entry, (status, message) in zip(payload["hosts"].get("github.com", []), rows):
                if status == "VERIFIED":
                    self.report.emit("EVIDENCE", message)
                    self.verify_gh_identity(entry)
                else:
                    self.report.emit(status, message)
            if not rows:
                self.report.emit("UNKNOWN", "gh returned no GitHub.com account verification records")
        except (ValueError, TypeError, UnicodeError):
            self.report.emit("UNKNOWN", "gh returned malformed/unsupported account JSON; raw output withheld")

    def verify_gh_identity(self, entry):
        label = entry.get("login", "")
        if not isinstance(label, str) or not LOGIN.fullmatch(label):
            self.report.emit("UNKNOWN", "Reported gh identity cannot be safely selected")
            return
        token = None
        if entry.get("active") is True:
            token = self.env.get("GH_TOKEN") or self.env.get("GITHUB_TOKEN")
        if token is None:
            args = ["auth", "token", "--hostname", "github.com", "--user", label]
            if self.tool_versions.get("gh") != "2.93.0":
                capabilities = self.execute("gh", ["auth", "token", "--help"])
                if capabilities.problem or capabilities.code or b"--no-refresh" not in capabilities.out:
                    self.report.emit("UNKNOWN", f"{label}: token read cannot be guaranteed non-refreshing; identity unresolved")
                    return
                args.append("--no-refresh")
            token_env = {key: value for key, value in self.child_env.items() if key not in TOKEN_VARS}
            self.report.emit("CHECK", f"Resolving actual identity for gh account label {label}; token stays in memory")
            credential = run([self.tools["gh"], *args], env=token_env, timeout=self.options.timeout, limit=8192)
            if credential.problem or credential.code:
                self.report.emit("UNKNOWN", f"{label}: saved credential could not be read; values/errors withheld")
                return
            try:
                token = credential.out.decode("ascii").strip()
            except UnicodeError:
                self.report.emit("UNKNOWN", f"{label}: unsupported credential encoding")
                return
        self.report.secrets.append(token)
        self.report.emit("CHECK", f"Confirming identity via GitHub /user for reported account {label}")
        actual, problem = github_identity(token, self.options.timeout)
        if actual:
            self.report.emit("VERIFIED", f"GitHub.com authenticated identity: {actual}; gh active: {entry.get('active') is True}; repository write access untested")
            if actual != label:
                self.report.emit("REVIEW", f"Actual identity {actual} differs from reported/saved account label {label}")
        else:
            self.report.emit("UNKNOWN", f"{label}: actual identity unresolved: {problem}")

    def vscode_section(self):
        self.report.section(4, "VS Code accounts and extensions")
        roots = [self.config_home / "Code", self.config_home / "Code - Insiders",
                 self.home / ".vscode-server/data", self.home / ".vscode-server-insiders/data",
                 self.home / "snap/code/current/.config/Code", *map(Path, self.options.code_dir)]
        databases = set()
        for root in dict.fromkeys(roots):
            if not root.exists():
                continue
            self.report.emit("CHECK", f"Inspecting VS Code data: {root}")
            if root.is_symlink():
                self.report.emit("SKIPPED", f"{root}: symlink; supply the explicit real location with --code-dir")
                continue
            for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda error: self.report.emit("UNKNOWN", "VS Code directory could not be enumerated; coverage incomplete")):
                relative = Path(directory).relative_to(root)
                dirs[:] = [d for d in dirs if d in {"User", "globalStorage", "workspaceStorage", "profiles"} or
                           relative.name in {"profiles", "workspaceStorage"}]
                dirs.sort(key=lambda name: ({"User": 0, "globalStorage": 1, "profiles": 2, "workspaceStorage": 4}.get(name, 3), name))
                if len(relative.parts) >= 5:
                    dirs[:] = []
                if "state.vscdb" in files:
                    databases.add(Path(directory, "state.vscdb"))
                if len(databases) >= EDITOR_DB_LIMIT:
                    self.report.emit("UNKNOWN", "VS Code database count limit reached; coverage incomplete")
                    break
        total = 0
        no_data_count = 0
        for path in sorted(databases):
            self.report.emit("CHECK", f"Reading account metadata: {path}")
            try:
                if path.is_symlink() or path.stat().st_size > 128 * 1024 * 1024:
                    raise ValueError()
                wal = Path(str(path) + "-wal")
                if wal.exists() and wal.stat().st_size:
                    self.report.emit("UNKNOWN", f"{path}: active WAL data; close VS Code and rerun for a consistent read-only view")
                    continue
                with sqlite3.connect(path.absolute().as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0.2) as db:
                    deadline = time.monotonic() + self.options.timeout
                    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                    db.execute("PRAGMA trusted_schema=OFF")
                    keys = db.execute("SELECT key FROM ItemTable WHERE key LIKE 'github-%' OR key LIKE '%-github' OR key LIKE '%-github-enterprise' OR key LIKE 'sync.%' OR key LIKE 'userDataSyncAccount%' OR key = 'userDataSync.account' LIMIT ?", (ITEM_LIMIT + 1,)).fetchall()
                    if len(keys) > ITEM_LIMIT:
                        self.report.emit("UNKNOWN", f"{path}: metadata row limit reached")
                    rows = []
                    for (key,) in keys[:ITEM_LIMIT]:
                        if isinstance(key, str) and (ACCOUNT_KEY.fullmatch(key) or PREFERENCE_KEY.fullmatch(key) or key in SYNC_KEYS):
                            row = db.execute("SELECT value FROM ItemTable WHERE key=? AND length(value)<=?", (key, FILE_LIMIT)).fetchone()
                            if row:
                                rows.append((key, row[0]))
                    results = vscode_results(rows)
                    total += len(results)
                    for status, message in results:
                        self.report.emit(status, f"{path}: {message}")
                    if not results and rows:
                        self.report.emit("UNKNOWN", f"{path}: account metadata schema unsupported; confirm in Accounts")
                    elif not results:
                        no_data_count += 1
            except (OSError, ValueError, sqlite3.Error, UnicodeError):
                self.report.emit("UNKNOWN", f"{path}: database unreadable, unsupported, oversized, or inconsistent; raw data withheld")
        extension_roots = [self.home / (name + "/extensions") for name in
                           (".vscode", ".vscode-insiders", ".vscode-server", ".vscode-server-insiders")]
        for root in extension_roots:
            if root.exists() and not root.is_symlink():
                self.report.emit("CHECK", f"Reading extension manifests: {root}")
                for manifest in sorted(root.glob("*/package.json"))[:ITEM_LIMIT]:
                    try:
                        data = json.loads(read_bounded(manifest))
                        identity = str(data.get("publisher", "")) + "." + str(data.get("name", ""))
                        version = data.get("version", "")
                        if re.fullmatch(EXTENSION, identity) and re.fullmatch(r"[A-Za-z0-9.+_-]{1,60}", str(version)):
                            self.report.emit("INFO", f"Extension installed: {identity}@{version}; activation/account not inferred")
                    except (OSError, ValueError, AttributeError):
                        self.report.emit("UNKNOWN", f"{manifest}: manifest unreadable or unsupported")
        self.report.emit("INFO", f"Account association records: {total}; databases inspected: {len(databases)}")
        self.report.emit("INFO", f"Editor databases without account metadata: {no_data_count}; absence does not prove signed out")
        self.report.emit("MANUAL", "VS Code Accounts -> Manage Extension Account Preferences: confirm current account for each extension and profile")
        self.report.emit("MANUAL", "VS Code Settings Sync: confirm account in Accounts; cached session IDs do not identify a usable session")
        self.report.emit("MANUAL", "Remote SSH/containers/WSL/portable or custom data directories outside these locations require a separate run or --code-dir; extensions with private sign-in storage need their own account UI")
        self.report.emit("INFO", "VS Code secret storage was not decrypted; the editor and extensions were not launched")

    def expand(self, value, base):
        if value.startswith("~/"):
            return self.home / value[2:]
        path = Path(value)
        return path if path.is_absolute() else base / path

    def config_records(self, result):
        if self.problem(result, "Git configuration inspection"):
            return []
        parts = result.out.split(b"\0")
        records = []
        for i in range(0, len(parts) - 1, 2):
            origin = parts[i].decode("utf-8", errors="replace")
            entry = parts[i + 1].decode("utf-8", errors="replace")
            key, _, value = entry.partition("\n")
            if origin != "command line:":
                records.append((origin, key, value))
        if len(records) > ITEM_LIMIT:
            self.report.emit("UNKNOWN", "Git configuration record limit reached; coverage incomplete")
        return records[:ITEM_LIMIT]

    def git_section(self):
        self.report.section(5, "Git access and configuration")
        if not self.tools["git"]:
            self.report.emit("SKIPPED", "git unavailable; repository checks cannot run")
            return
        requested = list(dict.fromkeys(map(Path, self.options.repo))) if self.options.repo else [Path.cwd()]
        for candidate in requested:
            self.report.emit("CHECK", f"Inspecting repository location: {candidate}")
            root = self.git(candidate, "rev-parse", "--show-toplevel")
            if root.problem or root.code:
                if self.options.repo:
                    raise ValueError("explicit repository cannot be inspected: " + str(candidate))
                self.report.emit("UNKNOWN" if root.problem else "SKIPPED", "Current directory repository unavailable: " + (root.problem or "outside a working repository"))
                continue
            path = Path(os.fsdecode(root.out.removesuffix(b"\n")))
            if path not in self.repos:
                self.repos.append(path)
        contexts = self.repos or [self.home]
        for path in contexts:
            self.report.emit("CHECK", f"Reading Git configuration: {path}")
            records = self.config_records(self.git(path, "config", "--null", "--list", "--show-origin", "--includes"))
            self.configs.append((path, records))
            for origin in dict.fromkeys(origin for origin, _, _ in records):
                self.report.emit("EVIDENCE", f"Git configuration source: {origin}")
            for origin, key, value in records:
                lowered = key.lower()
                if lowered.startswith("remote.") and lowered.endswith((".url", ".pushurl")):
                    self.report.emit("EVIDENCE", f"{origin}: {key}: {safe_url(value)}; configured destination, identity unverified")
                elif lowered.endswith(".helper") and lowered.startswith("credential"):
                    known = value.split(" ", 1)[0] if value else "reset"
                    kind = known if known in {"store", "cache", "manager", "manager-core", "libsecret", "osxkeychain", "wincred", "reset"} else "custom command (withheld)"
                    self.report.emit("REVIEW" if kind in {"store", "custom command (withheld)"} else "EVIDENCE", f"{origin}: credential helper: {kind}; not executed")
                elif lowered.startswith("url.") and lowered.endswith((".insteadof", ".pushinsteadof")):
                    base = key[4:key.rfind(".")]
                    self.report.emit("REVIEW", f"{origin}: URL rewrite -> {safe_url(base)}; configured source {safe_url(value)}")
                elif lowered in {"core.sshcommand", "core.fsmonitor", "core.gitproxy"} or lowered.startswith("alias."):
                    self.report.emit("REVIEW", f"{origin}: executable Git setting {key}; command withheld, never executed")
                elif lowered in {"core.hookspath", "core.excludesfile", "include.path"} or lowered.startswith("includeif."):
                    label = "conditional include" if lowered.startswith("includeif.") else key
                    self.report.emit("EVIDENCE", f"{origin}: {label}: {value}")
                elif lowered in {"user.name", "user.email"}:
                    self.report.emit("INFO", f"{origin}: Git {key} configured; author metadata, not authentication")
                elif lowered.endswith(".extraheader") or lowered in {"http.extraheader", "http.proxy"}:
                    self.report.emit("REVIEW", f"{origin}: HTTP authentication/proxy setting present; value withheld")
            if path in self.repos:
                location = self.git(path, "rev-parse", "--path-format=absolute", "--git-common-dir")
                hooks = Path(os.fsdecode(location.out.removesuffix(b"\n"))) / "hooks" if location.code == 0 and not location.problem else None
                configured = [value for _, key, value in records if key.lower() == "core.hookspath"]
                if configured:
                    hooks = self.expand(configured[-1], path)
                if hooks:
                    self.report.emit("CHECK", f"Inspecting hooks directory: {hooks}")
                    if hooks.is_dir() and not hooks.is_symlink():
                        for hook in sorted(hooks.iterdir())[:ITEM_LIMIT]:
                            if hook.name.endswith(".sample"):
                                continue
                            self.report.emit("REVIEW", f"Git hooks entry: {hook}; not executed")
                    elif hooks.is_symlink():
                        self.report.emit("MANUAL", f"Git hooks directory {hooks}: symlink, not followed")
        self.report.emit("INFO", "No helpers, hooks, aliases, external diffs, SSH commands or workspace tasks were executed")

    def hidden_section(self):
        self.report.section(6, "Hidden changes and credential storage")
        for path, records in self.configs:
            ignores = [self.config_home / "git/ignore"]
            ignores += [self.expand(value, path) for _, key, value in records if key.lower() == "core.excludesfile"]
            tracked = []
            if path in self.repos:
                self.report.emit("CHECK", f"Inspecting tracked paths and hidden-change flags: {path}")
                listing = self.git(path, "ls-files", "-v", "-z")
                if not self.problem(listing, "Git index flag inspection"):
                    entries = listing.out.split(b"\0")
                    if len(entries) > ITEM_LIMIT:
                        self.report.emit("UNKNOWN", f"{path}: tracked path display limit reached; first {ITEM_LIMIT} entries inspected")
                    for entry in entries[:ITEM_LIMIT]:
                        if len(entry) < 3:
                            continue
                        flag, name = chr(entry[0]), os.fsdecode(entry[2:])
                        candidate = path / name
                        if flag.islower():
                            self.report.emit("REVIEW", f"{candidate}: assume-unchanged flag")
                        if flag.upper() == "S":
                            self.report.emit("EVIDENCE", f"{candidate}: skip-worktree flag; may be legitimate sparse checkout")
                        if Path(name).name == ".gitignore":
                            ignores.append(candidate)
                            tracked.append(name)
                        if flag.upper() != "S" and not candidate.exists() and not candidate.is_symlink():
                            self.report.emit("REVIEW", f"{candidate}: tracked path missing from working tree")
                ignores.append(path / ".gitignore")
                exclude = self.git(path, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
                if not self.problem(exclude, "Git exclude location"):
                    ignores.append(Path(os.fsdecode(exclude.out.removesuffix(b"\n"))))
                if tracked:
                    history = self.git(path, "log", "-5", "--no-show-signature", "--no-decorate", "--format=%h %ct", "--", *tracked)
                    if not self.problem(history, "Ignore-file history"):
                        for line in history.out.splitlines():
                            if re.fullmatch(rb"[0-9a-f]{4,64} [0-9]+", line):
                                self.report.emit("EVIDENCE", "Ignore-file commit hash/time: " + line.decode())
            for ignore in dict.fromkeys(ignores):
                if ignore.exists() or ignore.is_symlink():
                    try:
                        contents = read_bounded(ignore)
                        self.report.emit("EVIDENCE", f"Ignore source {ignore}: SHA256 {hashlib.sha256(contents).hexdigest()}; contents withheld")
                    except (OSError, ValueError):
                        self.report.emit("UNKNOWN", f"Ignore source {ignore}: unreadable, oversized, or symlink")
        gh_dir = Path(self.env.get("GH_CONFIG_DIR", str(self.config_home / "gh"))) if not self.isolated else self.config_home / "gh"
        stores = [self.home / ".git-credentials", self.config_home / "git/credentials", gh_dir / "hosts.yml", self.home / ".netrc"]
        for path in stores:
            if path.exists() or path.is_symlink():
                self.report.emit("CHECK", f"Inspecting credential storage permissions: {path}")
                self.permissions(path, private=True)
                self.report.emit("EVIDENCE", f"Credential-capable storage exists: {path}; values not displayed or validated")
        if not self.repos:
            self.report.emit("SKIPPED", "No working repository selected; index and repository-ignore checks unavailable")
        self.report.emit("INFO", "Credential storage checks cover selected standard files only; keyrings, custom helper stores and other files require separate review")

    def summary(self):
        self.report.section(7, "Summary and manual GitHub checks")
        for message in (
            "Personal GitHub Settings -> Sessions: review browser/mobile sessions",
            "Personal GitHub Settings -> Applications -> Installed GitHub Apps: review installation permissions and repositories",
            "Repository Settings: review deploy keys, collaborators, webhooks, Actions workflows/secrets and runners",
            "Repository Activity: record authenticated push actor, timestamp and suspicious commit SHA; author names alone do not establish the pusher",
        ):
            self.report.emit("MANUAL", message)
        counts = self.report.counts()
        for label in ("REVIEW", "VERIFIED", "EVIDENCE", "MANUAL", "UNKNOWN", "SKIPPED"):
            self.report.emit("INFO", f"{label}: {counts[label]}")
        sections = {}
        for number, status, _ in self.report.entries:
            if status in {"REVIEW", "MANUAL", "UNKNOWN", "SKIPPED"}:
                sections.setdefault(number, Counter())[status] += 1
        for number, count in sorted(sections.items()):
            self.report.emit("INFO", f"Section {number}: " + ", ".join(f"{status}={count[status]}" for status in sorted(count)))
        self.report.emit("DONE", "Audit complete within stated coverage; no access revoked or repository contents changed")

    def perform(self):
        self.report.write("GitHub Access Audit")
        for section in (self.tools_section, self.ssh_section, self.gh_section, self.vscode_section,
                        self.git_section, self.hidden_section, self.summary):
            section()


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        secrets = [value for key, value in os.environ.items() if re.search(r"TOKEN|SECRET|PASSWORD|API_KEY", key, re.I) and len(value) >= 4]
        if message.startswith("unrecognized arguments:"):
            message = "unrecognized arguments (values withheld); see --help"
        message = re.sub(r"(invalid .*? value: ).*", r"\1<value withheld>", message)
        self.print_usage(sys.stderr)
        self.exit(2, "ERROR: " + safe_text(message, secrets) + "\n")


def arguments(argv=None):
    parser = SafeParser(description="Read-only Linux GitHub access audit with grouped live output. No malware scanning.")
    parser.add_argument("--repo", action="append", default=[], metavar="PATH", help="working repository; repeatable (default: current repository)")
    parser.add_argument("--home", default=str(Path.home()), metavar="PATH", help="target home; an alternate home disables caller credentials and online checks")
    parser.add_argument("--key-dir", action="append", default=[], metavar="PATH", help="additional directory of SSH key candidates")
    parser.add_argument("--code-dir", action="append", default=[], metavar="PATH", help="additional VS Code user-data root")
    parser.add_argument("--online", action="store_true", help="verify gh identities on github.com; no write test or SSH connection")
    parser.add_argument("--report", type=Path, metavar="PATH", help="also write a new private report (refuses existing paths)")
    parser.add_argument("--timeout", type=float, default=10, metavar="SECONDS", help="per-command timeout, 0 < seconds <= 60 (default: 10)")
    options = parser.parse_args(argv)
    if not 0 < options.timeout <= 60:
        parser.error("timeout must be greater than 0 and at most 60 seconds")
    if not Path(options.home).is_dir():
        parser.error("home must be an existing directory")
    if options.online and Path(options.home).resolve() != Path.home().resolve():
        parser.error("--online cannot be used with an alternate --home")
    for path in [*options.repo, *options.key_dir, *options.code_dir]:
        if not Path(path).is_dir():
            parser.error("repository/key/editor path must be an existing directory: " + safe_text(path))
    return options


def main(argv=None):
    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10+ is required", file=sys.stderr)
        return 2
    reporter = None
    secrets = [value for key, value in os.environ.items() if re.search(r"TOKEN|SECRET|PASSWORD|API_KEY", key, re.I) and len(value) >= 4]
    try:
        options = arguments(argv)
        reporter = Reporter(report=options.report, secrets=secrets)
        Audit(options, reporter).perform()
        return 0
    except KeyboardInterrupt:
        if reporter:
            reporter.emit("UNKNOWN", "Audit interrupted; results and coverage are incomplete")
        return 130
    except BrokenPipeError:
        return 1
    except (OSError, ValueError, sqlite3.Error) as error:
        message = str(error) if isinstance(error, ValueError) else type(error).__name__ + "; operation unavailable (raw error withheld)"
        print("ERROR: " + safe_text(message, secrets), file=sys.stderr)
        if reporter:
            reporter.emit("UNKNOWN", "Audit incomplete: " + message)
        return 2
    finally:
        if reporter:
            reporter.close()


if __name__ == "__main__":
    raise SystemExit(main())
