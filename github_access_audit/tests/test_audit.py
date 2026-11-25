"""Credential-boundary and real-tool tests; all account fixtures are synthetic."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("access_audit", ROOT / "audit.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)
SENTINEL = "ghp_" + "s" * 36


def command(*args, cwd=None):
    env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0", "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, check=True)


def database(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB)")
        db.executemany("INSERT INTO ItemTable VALUES (?, ?)", rows)


class UnitTests(unittest.TestCase):
    def test_sanitization(self):
        for text in [SENTINEL, "https://user:password@github.com/a/b?token=" + SENTINEL,
                     "Authorization: Bearer " + SENTINEL]:
            with self.subTest(text=text[:12]):
                output = audit.safe_text(text)
                self.assertNotIn(SENTINEL, output)
                self.assertNotIn("password", output)
        self.assertEqual(audit.safe_text("a\nb\x1b[31m"), "a\\nb\\x1b[31m")
        self.assertEqual(audit.safe_text("秘密"), "秘密")
        self.assertNotIn("opaque-credential", audit.safe_text("opaque-credential", ["opaque-credential"]))

    def test_safe_destinations(self):
        cases = {
            "https://user:password@github.com/o/r?secret=hidden#fragment": "https://github.com/o/r",
            "git@github-work:o/r.git": "github-work:o/r.git",
            "ssh://git@github.com:443/o/r": "ssh://github.com:443/o/r",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(audit.safe_url(source), expected)
        for value in ["ext::sh -c bad", "https://[invalid", "", "relative/private"]:
            with self.subTest(value=value):
                self.assertIn("withheld", audit.safe_url(value))

    def test_gh_saved_accounts(self):
        text = "github.com:\n    user: alice\n    oauth_token: " + SENTINEL + "\n    users:\n        alice:\n        bob:\n            oauth_token: " + SENTINEL + "\n"
        rows = audit.parse_gh_hosts(text)
        self.assertEqual({r["login"] for r in rows}, {"alice", "bob"})
        self.assertTrue(next(r for r in rows if r["login"] == "alice")["active"])
        self.assertNotIn(SENTINEL, repr(rows))
        self.assertEqual(audit.parse_gh_hosts("{}\n"), [])
        self.assertEqual(audit.parse_gh_hosts(""), [])
        for bad in ["not yaml", "github.com: [bad]", "github.com:\n  user: &alias value"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit.parse_gh_hosts(bad)

    def test_online_json_checks_each_state(self):
        payload = {"hosts": {"github.com": [
            {"state": "success", "login": "alice", "active": True, "tokenSource": "keyring", "token": SENTINEL},
            {"state": "error", "login": "bob", "error": SENTINEL},
            {"state": "timeout", "login": "carol"},
        ]}}
        rows = audit.gh_results(payload)
        self.assertEqual([r[0] for r in rows], ["VERIFIED", "REVIEW", "UNKNOWN"])
        self.assertNotIn(SENTINEL, repr(rows))
        for bad in [{}, {"hosts": []}, {"hosts": {"github.com": "bad"}}]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit.gh_results(bad)

    def test_vscode_metadata_is_evidence_only(self):
        rows = [
            ("github-alice-usages", json.dumps([{"extensionId": "github.copilot", "lastUsed": 1}])),
            ("github-alice", json.dumps([{"id": "github.vscode-pull-request-github", "allowed": False}])),
            ("github.copilot-github", "bob"),
            ("secret://github", SENTINEL),
            ("github-authentication", json.dumps({"accessToken": SENTINEL})),
        ]
        result = audit.vscode_results(rows)
        text = repr(result)
        self.assertIn("alice", text)
        self.assertIn("bob", text)
        self.assertIn("github.copilot", text)
        self.assertIn("denied", text)
        self.assertNotIn(SENTINEL, text)
        self.assertTrue(all(status == "EVIDENCE" for status, _ in result))

    def test_key_metadata_malformed_and_encrypted(self):
        self.assertEqual(audit.key_metadata(b"not a key")["kind"], "unknown")
        self.assertEqual(audit.key_metadata(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")["kind"], "encrypted-pem")
        self.assertEqual(audit.key_metadata(b"-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n-----END OPENSSH PRIVATE KEY-----")["kind"], "unknown")

    def test_reporter_counts_and_private_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.txt"
            stream = io.StringIO()
            reporter = audit.Reporter(stream, path, [SENTINEL])
            reporter.section(2, "Keys")
            reporter.emit("REVIEW", SENTINEL)
            reporter.emit("UNKNOWN", "Unreadable")
            self.assertEqual(reporter.counts()["REVIEW"], 1)
            reporter.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), stream.getvalue())
            self.assertNotIn(SENTINEL, path.read_text())
            with self.assertRaises(FileExistsError):
                audit.Reporter(io.StringIO(), path)

    def test_command_bounds_and_no_raw_errors(self):
        result = audit.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
        self.assertEqual(result.problem, "timeout")
        result = audit.run([sys.executable, "-c", "print('x'*10000)"], limit=100)
        self.assertEqual(result.problem, "output limit exceeded")
        self.assertEqual(audit.run(["/nonexistent/audit-tool"]).problem, "tool unavailable")

    def test_bounded_file_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "data"
            p.write_bytes(b"abc")
            self.assertEqual(audit.read_bounded(p, 3), b"abc")
            with self.assertRaises(ValueError):
                audit.read_bounded(p, 2)
            p.unlink()
            p.symlink_to("missing")
            with self.assertRaises(OSError):
                audit.read_bounded(p)

    def test_actual_identity_api_is_bounded_and_never_redirects(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return b'{"login":"actual-user"}'
        with patch("urllib.request.OpenerDirector.open", return_value=Response()) as request:
            login, problem = audit.github_identity("opaque-fixture-token", 1)
            self.assertEqual((login, problem), ("actual-user", ""))
            sent = request.call_args.args[0]
            self.assertEqual(sent.full_url, "https://api.github.com/user")
            self.assertIn("opaque-fixture-token", sent.get_header("Authorization"))
        with self.assertRaises(audit.urllib.error.HTTPError):
            audit.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://untrusted.invalid")

    def test_identity_api_negative_and_input_variation(self):
        for token in ["", "with newline\n", "x" * 8193, "秘密"]:
            with self.subTest(token=token[:10]):
                self.assertIsNone(audit.github_identity(token, 1)[0])
        for code in [401, 403, 302]:
            with self.subTest(code=code):
                error = audit.urllib.error.HTTPError("https://api.github.com/user", code, SENTINEL, {}, None)
                with patch("urllib.request.OpenerDirector.open", side_effect=error):
                    login, problem = audit.github_identity("fixture-token", 1)
                self.assertIsNone(login)
                self.assertNotIn(SENTINEL, problem)
                self.assertIn("rejected" if code == 401 else "unavailable", problem)
        with patch("urllib.request.OpenerDirector.open", side_effect=OSError(SENTINEL)):
            self.assertIn("network", audit.github_identity("fixture-token", 1)[1])

    def test_special_file_read_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fifo"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                audit.read_bounded(path)

    def test_cli_errors_do_not_echo_credential_values(self):
        result = subprocess.run(["bash", str(ROOT / "audit.sh"), "--unrecognized=" + SENTINEL], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(SENTINEL, result.stderr)


class OnlineBoundaryTests(unittest.TestCase):
    def setUp(self):
        blocker = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Unexpected network: supply a fake response"))
        blocker.start()
        self.addCleanup(blocker.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        tool = self.base / "gh"
        self.calls = self.base / "calls.jsonl"
        tool.write_text("#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\n"
                        "args=sys.argv[1:]\n"
                        "with Path(" + repr(str(self.calls)) + ").open('a') as f: f.write(json.dumps(args)+'\\n')\n"
                        "if '--help' in args: print('gh authentication help')\n"
                        "elif 'status' in args: print(json.dumps({'hosts':{'github.com':[{'state':'success','login':'saved-user','active':True,'tokenSource':'keyring'}]}}))\n"
                        "elif 'token' in args: print('opaque-fixture-token')\n")
        tool.chmod(0o700)
        self.options = SimpleNamespace(home=str(Path.home()), repo=[], key_dir=[], code_dir=[], timeout=1, online=True)
        self.output = io.StringIO()
        self.worker = audit.Audit(self.options, audit.Reporter(self.output),
                                  env={"PATH": str(self.base), "GH_CONFIG_DIR": str(self.base / "config")})
        self.worker.tool_versions["gh"] = "2.93.0"

    def test_online_verifies_actual_identity_and_detects_stale_account_label(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return b'{"login":"actual-user"}'
        with patch("urllib.request.OpenerDirector.open", return_value=Response()):
            self.worker.gh_section()
        output = self.output.getvalue()
        self.assertIn("actual-user", output)
        self.assertIn("differs", output)
        self.assertIn("VERIFIED", output)
        self.assertNotIn("opaque-fixture-token", output)
        calls = self.calls.read_text()
        self.assertIn('"token"', calls)
        self.assertNotIn("--show-token", calls)

    def test_unknown_refresh_capability_skips_online_calls(self):
        self.worker.tool_versions["gh"] = "2.92.0"
        self.worker.gh_section()
        self.assertIn("refresh", self.output.getvalue())
        self.assertNotIn('"token"', self.calls.read_text())
        self.assertNotIn('"--json"', self.calls.read_text())

    def test_environment_override_is_verified_without_reading_saved_token(self):
        self.worker.env["GH_TOKEN"] = "opaque-fixture-token"
        self.worker.child_env["GH_TOKEN"] = "opaque-fixture-token"
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return b'{"login":"env-user"}'
        with patch("urllib.request.OpenerDirector.open", return_value=Response()):
            self.worker.gh_section()
        self.assertIn("env-user", self.output.getvalue())
        self.assertNotIn('"token"', self.calls.read_text())

    def test_proxy_configuration_skips_network(self):
        self.worker.env["HTTPS_PROXY"] = "http://proxy.invalid"
        self.worker.gh_section()
        self.assertIn("proxy", self.output.getvalue())
        self.assertNotIn('"--json"', self.calls.read_text())

    def test_modern_cli_suppresses_refresh_for_status_and_token(self):
        tool = self.base / "gh"
        tool.write_text(tool.read_text().replace("gh authentication help", "--no-refresh"))
        self.worker.tool_versions["gh"] = "2.100.0"
        with patch("urllib.request.OpenerDirector.open", side_effect=OSError("fixture offline")):
            self.worker.gh_section()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        status = next(call for call in calls if "status" in call and "--json" in call)
        token = next(call for call in calls if "token" in call and "--help" not in call)
        self.assertIn("--no-refresh", status)
        self.assertIn("--no-refresh", token)
        self.assertIn("identity unresolved", self.output.getvalue())

    def test_host_socket_override_skips_network(self):
        config = self.base / "config"
        config.mkdir()
        (config / "hosts.yml").write_text('github.com:\n    user: saved-user\n    "http_unix_socket": /tmp/example.sock\n')
        self.worker.gh_section()
        self.assertIn("socket", self.output.getvalue())
        self.assertNotIn('"--json"', self.calls.read_text())


class RealToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.repo = Path(self.tmp.name) / "repo space 秘密"
        self.repo.mkdir()
        self.marker = Path(self.tmp.name) / "EXECUTED"
        command("git", "init", "-q", str(self.repo))
        command("git", "-C", str(self.repo), "config", "user.name", "Fixture")
        command("git", "-C", str(self.repo), "config", "user.email", "fixture@example.invalid")
        for name in ("hidden.txt", "sparse.txt", ".gitignore"):
            (self.repo / name).write_text("fixture\n")
        command("git", "-C", str(self.repo), "add", ".")
        command("git", "-C", str(self.repo), "commit", "-qm", "fixture")
        command("git", "-C", str(self.repo), "update-index", "--assume-unchanged", "hidden.txt")
        command("git", "-C", str(self.repo), "update-index", "--skip-worktree", "sparse.txt")

    def invoke(self, *args, env=None):
        return subprocess.run(["bash", str(ROOT / "audit.sh"), "--home", str(self.home), "--repo", str(self.repo), *args],
                              capture_output=True, text=True, env=env, timeout=30)

    def test_real_shell_flow_is_readonly_and_redacted(self):
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700)
        for name, password in [("plain", ""), ("locked", "fixture-passphrase")]:
            command("ssh-keygen", "-q", "-t", "ed25519", "-a", "1", "-N", password, "-f", str(ssh / name))
        (ssh / "plain").chmod(0o644)
        (ssh / "broken").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n")
        (ssh / "config").write_text("Host github-fixture\n HostName github.com\n IdentityFile ~/.ssh/plain\n ForwardAgent yes\n Match exec \"touch " + str(self.marker) + "\"\n ProxyCommand touch " + str(self.marker) + "\n")
        (self.home / ".bashrc").write_text("touch " + str(self.marker))
        command("git", "-C", str(self.repo), "config", "credential.helper", "!touch " + str(self.marker))
        command("git", "-C", str(self.repo), "config", "core.fsmonitor", "touch " + str(self.marker))
        command("git", "-C", str(self.repo), "remote", "add", "origin", "https://user:" + SENTINEL + "@github.com/o/r?token=" + SENTINEL)
        hook = self.repo / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\ntouch " + str(self.marker))
        hook.chmod(0o700)
        state = self.home / ".config/Code/User/globalStorage/state.vscdb"
        database(state, [("github-alice-usages", '[{"extensionId":"github.copilot"}]'),
                         ("github.copilot-github", "alice"), ("secret://test", SENTINEL)])
        before = hashlib.sha256(state.read_bytes()).digest()
        report = Path(self.tmp.name) / "audit.txt"
        result = self.invoke("--report", str(report))
        self.assertEqual(result.returncode, 0, result.stderr)
        for section in range(1, 8):
            self.assertIn(f"── {section}.", result.stdout)
        for expected in ["no passphrase", "encrypted", "hidden.txt", "skip-worktree", "alice", "github.copilot", "UNKNOWN", "credential helper", "ForwardAgent"]:
            self.assertIn(expected, result.stdout)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr + report.read_text())
        self.assertFalse(self.marker.exists())
        self.assertEqual(hashlib.sha256(state.read_bytes()).digest(), before)
        self.assertFalse(Path(str(state) + "-wal").exists())
        self.assertTrue((ssh / "plain").exists())
        self.assertIn("hooks", result.stdout)

    def test_invalid_arguments_and_isolation(self):
        for args, expected in [(["--repo", "/not/a/repo"], "repository"),
                               (["--timeout", "0"], "timeout"),
                               (["--online"], "home"),
                               (["--home", "/not/a/home"], "home")]:
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr.lower())

    def test_corrupt_database_symlinks_and_oversized(self):
        state = self.home / ".config/Code/User/globalStorage/state.vscdb"
        state.parent.mkdir(parents=True)
        state.write_bytes(b"broken sqlite")
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh/link").symlink_to(state)
        large = self.home / ".git-credentials"
        large.write_bytes(b"x" * (audit.FILE_LIMIT + 1))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("UNKNOWN", result.stdout)
        self.assertIn("symlink", result.stdout)

    def test_nested_includes_global_ignores_and_duplicate_repos(self):
        (self.home / ".gitconfig").write_text('[include]\n path = extra.config\n[core]\n excludesFile = ~/.global-ignore\n')
        (self.home / "extra.config").write_text('[url "ssh://git@github.com/"]\n insteadOf = https://github.com/\n')
        (self.home / ".global-ignore").write_text("*.private\n")
        result = self.invoke("--repo", str(self.repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("extra.config", result.stdout)
        self.assertIn(".global-ignore", result.stdout)
        self.assertIn("URL rewrite", result.stdout)

    def test_real_key_metadata_agent_and_escaped_filenames(self):
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700)
        key = ssh / "key\n秘密"
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        metadata = audit.key_metadata(key.read_bytes())
        self.assertEqual(metadata["kind"], "plain")
        public = key.with_name(key.name + ".pub").read_bytes().split()[1]
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public)).digest()).decode().rstrip("=")
        self.assertEqual(metadata["fingerprint"], expected)
        socket = self.home / "agent.sock"
        agent = command("ssh-agent", "-a", str(socket), "-s").stdout
        pid = int(re.search(rb"SSH_AGENT_PID=(\d+)", agent)[1])
        self.addCleanup(lambda: os.kill(pid, signal.SIGTERM))
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "SSH_AUTH_SOCK": str(socket)}
        subprocess.run(["ssh-add", str(key)], env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True)
        result = self.invoke(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Agent identity available: " + expected, result.stdout)
        self.assertIn("no passphrase; key can be loaded", result.stdout)
        self.assertIn("key\\n秘密", result.stdout)

    def test_profile_workspace_and_extension_account_evidence(self):
        root = self.home / ".config/Code/User"
        for path, label in [(root / "profiles/work/globalStorage/state.vscdb", "work-user"),
                            (root / "workspaceStorage/workspace/state.vscdb", "workspace-user")]:
            database(path, [("github.copilot-github", label), ("userDataSyncAccountPreference", "session-id-not-an-account")])
        manifest = self.home / ".vscode/extensions/github.copilot-1.0/package.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"publisher": "github", "name": "copilot", "version": "1.0", "main": str(self.marker)}))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("work-user", result.stdout)
        self.assertIn("workspace-user", result.stdout)
        self.assertIn("github.copilot@1.0", result.stdout)
        self.assertIn("Settings Sync metadata", result.stdout)
        self.assertNotIn("session-id-not-an-account", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_editor_database_without_account_records_is_coverage_information(self):
        path = self.home / ".config/Code/User/globalStorage/state.vscdb"
        database(path, [("editor.unrelatedSetting", "value")])
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("databases without account metadata: 1", result.stdout)
        self.assertNotIn("no recognized account associations", result.stdout)
        self.assertIn("absence does not prove signed out", result.stdout)

    def test_ssh_includes_are_static_and_empty_globs_are_information(self):
        ssh = self.home / ".ssh"
        ssh.mkdir()
        (ssh / "conf.d").mkdir()
        (ssh / "config").write_text("Include conf.d/*.conf\nInclude absent/*.conf\n")
        (ssh / "conf.d/one.conf").write_text("ProxyCommand touch " + str(self.marker) + "\nInclude config\n")
        output = io.StringIO()
        options = SimpleNamespace(home=str(self.home), repo=[], key_dir=[], code_dir=[], timeout=1, online=False)
        worker = audit.Audit(options, audit.Reporter(output))
        worker.ssh_config(ssh / "config", set())
        self.assertIn("SSH ProxyCommand command configured", output.getvalue())
        self.assertIn("include matched no files", output.getvalue())
        self.assertNotIn("[UNKNOWN", output.getvalue())
        self.assertFalse(self.marker.exists())

    def test_wal_database_is_explicitly_unavailable(self):
        path = self.home / ".config/Code/User/globalStorage/state.vscdb"
        database(path, [("github.copilot-github", "alice")])
        with sqlite3.connect(path) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO ItemTable VALUES ('github.b-github','bob')")
            writer.commit()
            result = self.invoke()
            self.assertIn("active WAL", result.stdout)
            self.assertNotIn("Cached account preference", result.stdout)

    def test_report_conflict_and_missing_runtime(self):
        report = Path(self.tmp.name) / "existing.txt"
        report.write_text("preserve this")
        result = self.invoke("--report", str(report))
        self.assertEqual(result.returncode, 2)
        self.assertIn("FileExistsError", result.stderr)
        self.assertEqual(report.read_text(), "preserve this")
        bindir = Path(self.tmp.name) / "bash-only"
        bindir.mkdir()
        (bindir / "bash").symlink_to(shutil.which("bash"))
        result = self.invoke(env={"PATH": str(bindir)})
        self.assertEqual(result.returncode, 2)
        self.assertIn("Python 3.10+", result.stderr)

    def test_interruption_keeps_partial_report(self):
        bindir = Path(self.tmp.name) / "slow-bin"
        bindir.mkdir()
        tool = bindir / "git"
        tool.write_text("#!/bin/sh\nsleep 10\n")
        tool.chmod(0o700)
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
        report = Path(self.tmp.name) / "interrupted.txt"
        process = subprocess.Popen(["bash", str(ROOT / "audit.sh"), "--home", str(self.home), "--report", str(report)],
                                   cwd=self.home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if report.exists() and "Reading git version" in report.read_text():
                break
            time.sleep(0.02)
        process.send_signal(signal.SIGINT)
        out, err = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, err)
        self.assertIn(b"interrupted", out)
        self.assertIn("incomplete", report.read_text())

    def test_no_repository_and_missing_optional_tools(self):
        bindir = Path(self.tmp.name) / "bin"
        bindir.mkdir()
        for tool in ("bash", "python3", "dirname"):
            (bindir / tool).symlink_to(shutil.which(tool))
        env = dict(os.environ, PATH=str(bindir))
        result = subprocess.run(["bash", str(ROOT / "audit.sh"), "--home", str(self.home)], cwd=self.home,
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SKIPPED", result.stdout)
        self.assertIn("git", result.stdout)

    def test_live_output_precedes_slow_check(self):
        bindir = Path(self.tmp.name) / "bin"
        bindir.mkdir()
        tool = bindir / "git"
        tool.write_text("#!/bin/sh\nsleep 3\nexit 1\n")
        tool.chmod(0o700)
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
        process = subprocess.Popen(["bash", str(ROOT / "audit.sh"), "--home", str(self.home), "--timeout", "0.2"],
                                   cwd=self.home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        started = time.monotonic()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(1.5), "No live output before slow external command")
            first = os.read(process.stdout.fileno(), 4096)
        self.assertIn(b"GitHub Access Audit", first)
        self.assertLess(time.monotonic() - started, 2)
        out, err = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, err)
        self.assertIn(b"timeout", first + out)


if __name__ == "__main__":
    unittest.main()
