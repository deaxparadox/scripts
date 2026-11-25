# GitHub access audit

## Purpose and agreed scope

Create a script that helps a developer investigate unwanted commits, deleted code,
and unexpected ignore-file changes. Identify local authentication paths and
configuration evidence without claiming that a saved account is usable or that
an unfamiliar setting proves an attack.

The user approved seven grouped sections with live output. Malware scanning,
system persistence, processes, and network surveillance are deferred.

Working branch: existing `main`. Base branch: `main`. No branch creation,
switching, merge, or push is included.

## Verified starting point

- This repository contains standalone scripts and configuration examples, with
  no existing audit script, dependency manifest, or test suite.
- Available locally: Bash 5.2.21, Python 3.13.11, Git 2.43.0, OpenSSH 9.6p1,
  GitHub CLI 2.93.0, and a VS Code launcher. ShellCheck is unavailable.
- The installed `gh auth status --help` supports JSON but does not support
  `--no-refresh`. Current online documentation includes that newer flag.
  Compatibility must be checked rather than assuming the latest CLI interface.
- GitHub CLI JSON reports account state separately from process exit status;
  a zero JSON-mode exit status does not establish successful authentication.
- VS Code stores authentication usage and preferences separately from extension
  installation. Its account metadata can be historical and cannot prove current
  credential validity. Different profiles and remote installations need explicit
  coverage reporting.
- The user's existing, untracked `AGENTS.MD` must remain untouched unless they
  approve recording the proposed stack/test commands in its Environment section.

## Proposed implementation

Add `github_access_audit/audit.sh`, a shell launcher for
`github_access_audit/audit.py`, plus a README and tests in that directory.
Use Python's standard library for argument parsing, bounded subprocesses,
structured output parsing, and read-only SQLite access. Do not install packages.

The Python helper avoids brittle shell parsing of JSON, SQLite, filenames,
and subprocess failures. The user-facing entry point remains a `.sh` script.
Use standard Python 3.10+ features and Bash; verify on the installed versions.

Proposed command interface:

```sh
bash github_access_audit/audit.sh
bash github_access_audit/audit.sh --repo /path/to/repository
bash github_access_audit/audit.sh --repo /path/to/one --repo /path/to/two --online
bash github_access_audit/audit.sh --report /private/path/access-audit.txt
```

- Local-only by default. Online identity verification requires `--online`.
- Audit the current repository when no `--repo` is given; if the current directory
  is outside a repository, explicitly skip repository checks.
- Inspect the current user's standard SSH, Git, GitHub CLI, and VS Code locations.
  Allow explicit additional key/editor locations; report uncovered locations.
  Do not recursively scan the entire filesystem or every repository by default.
- Provide an explicit target-home option for offline fixture tests and inspection
  of another directory. Disable use of the caller's agent, environment credentials,
  and live account verification when inspecting another home.
- Optional report creation uses restrictive permissions and refuses to overwrite
  an existing path. The report contains the same sanitized results as the terminal.
- Missing optional tools produce visible `SKIPPED` results. Invalid arguments,
  missing required Python runtime, or an unusable report destination fail clearly.
- Bound subprocess duration and file reads. Escape terminal control characters
  from filenames and metadata. Show timeouts, malformed records, and interrupted
  runs explicitly; do not turn them into successful checks.

## Output and acceptance criteria

Print each section once, flush a `CHECK` message before work starts, and flush
each result as it becomes available. Output also streams when piped. Avoid
fabricated progress percentages or an end-only wall of output.

Statuses: `INFO`, `CHECK`, `DONE`, `VERIFIED`, `EVIDENCE`, `REVIEW`, `MANUAL`,
`UNKNOWN`, and `SKIPPED`. `DONE` means a check finished, not that access is secure.
`VERIFIED` names exactly what a live check established; successful identity
authentication does not establish permission to push to every repository.

1. **Tools and coverage:** tools, versions where safely available, selected mode,
   selected repositories, locations inspected, and unavailable capabilities.
2. **SSH keys and agent:** discover private-key candidates in standard and
   explicitly supplied locations; check permissions, fingerprints, and whether
   an empty passphrase can load them. Report encrypted, empty-passphrase, and
   unsupported/unreadable results distinctly. Recognize hardware-backed key
   limitations. List agent fingerprints without key comments or key material.
   Inspect identity selection, forwarding, includes, and command-bearing SSH
   configuration without executing it. A host alias or `User git` is not a
   verified GitHub account identity. Do not initiate SSH connections.
3. **GitHub CLI accounts:** report saved hosts/accounts and configured active
   selection as evidence; detect credential environment-variable names without
   values. With `--online`, use supported JSON account verification without
   printing tokens. Suppress automatic refresh on versions that support it;
   older versions require a verified non-refreshing path, otherwise visibly
   skip that capability. Inspect each JSON account's state, not just exit code.
   Restrict live checks to GitHub.com for this personal-account use case; flag
   other configured hosts for manual review instead of sending credentials to
   arbitrary configured endpoints.
4. **VS Code accounts and extensions:** inspect standard local/Insiders and
   available remote-server/profile locations, extension manifests, and allowlisted
   account/extension preference and usage metadata in read-only storage. Show
   account labels with extension associations where the schema supports it.
   Never decrypt or enumerate secret-storage values. Treat cached information
   as evidence; provide the Accounts / Manage Extension Account Preferences
   manual confirmation when current selection is not established. Inventory
   alone is not an account check. Unsupported schemas remain visible.
5. **Git access and configuration:** inspect remotes, push URLs, credential-helper
   configuration, URL rewrites, SSH commands, aliases, include sources, and hooks.
   Separate Git author settings from authenticated identities. Show sanitized
   destinations and command presence/location; never execute helpers, hooks,
   aliases, `Match exec`, `ProxyCommand`, or workspace tasks. Use inspection-only
   Git commands with optional writes, pagers, fsmonitor, external diffs, and
   text conversion disabled as relevant. No fetch, pull, push, checkout, or reset.
6. **Hidden changes and credential storage:** inspect repository/global ignore
   sources, nested tracked ignore files, `.git/info/exclude`, and index flags
   (`assume-unchanged` / `skip-worktree`). Identify credential-file presence and
   unsafe permissions in selected standard locations. Report ignore history
   metadata and changed paths without printing potentially sensitive file contents.
   No general filesystem-wide secret scan.
7. **Summary and manual GitHub checks:** counts plus section references for review
   findings, verified identities, manual work, and unknown/skipped checks. Include
   personal-account sessions/installed apps and repository deploy keys,
   collaborators, Actions, webhooks, and suspicious push actors as manual checks.
   Do not use organization-only features or claim the audit revokes any access.

## Credential and execution boundaries

Never print private/public key bodies, credential values, authorization headers,
token-bearing URLs, raw credential-helper commands, raw account storage, or
unfiltered subprocess errors. Allowlist output fields and sanitize every output
path, including errors and report output. Do not use `--show-token`.

Never source startup files, evaluate discovered commands, launch VS Code or its
extensions, install anything, change passphrases, edit configurations, or log out
accounts. SQLite is opened read-only. Selected tools are still part of the local
trust boundary; the script is not a forensic guarantee on a compromised OS.

## Discovery checks

- Lateral spread: reviewed the repository's standalone Python utility and SSH
  examples. No existing audit or test framework needs extending. Credential
  paths exist independently in SSH, Git, `gh`, and VS Code, so each needs its
  own section and uncertainty labels.
- Causal depth: unwanted commits could come from several authentication paths
  or local tools. The script gathers evidence across those paths; this discovery
  pass has not inspected the user's accounts or established the incident's cause.

## Test plan and proposed tooling

There is no established test tooling. Recommend Python's built-in `unittest`
instead of adding pytest: no installation is needed, and it supports fixtures,
subprocess integration tests, and parameterized cases through `subTest`.
An alternative is pytest, which requires approval of a new local dependency.
Spec confirmation should also confirm the recommended standard-library choice.

Proposed commands (record in Environment only after user confirmation):

```sh
python3 -m unittest discover -s github_access_audit/tests -v
bash -n github_access_audit/audit.sh
bash github_access_audit/audit.sh --help
bash github_access_audit/audit.sh --repo .
```

Write failing tests first, then implement and refactor with tests passing.

- **Unit:** key-format classification, redaction, URL sanitization, configuration
  parsers, CLI JSON state handling, VS Code allowlisted metadata parsing, report
  statuses, and summary counts. Test new/changed functions in isolation.
- **Integration:** real temporary Git repositories and generated encrypted/plain
  OpenSSH keys; real temporary SQLite editor databases; file permissions and
  report creation. External online services are faked. Prove hooks, credential
  helpers, SSH configuration commands, and startup files are never executed.
- **Flow:** run the sections together over fixture homes containing multiple
  accounts, profiles, repos, environment overrides, index flags, and unsafe storage.
- **End-to-end:** invoke the real `.sh` entry point against fixtures without
  internal mocks. Confirm ordered sections, live output before a deliberately
  slow external check completes, correctly grouped findings, and private reports.
- **Negative:** missing tools, invalid paths/options, malformed/encrypted keys,
  inaccessible/corrupt/locked databases, invalid authentication, timeouts, output
  destination conflicts, interruption, and an unsupported CLI refresh capability.
  Assert the actual diagnostic and preserve the relevant uncertainty state.
- **Input variation:** empty, duplicate, Unicode, whitespace/newline/control
  characters, symlinks, unusual remote URLs, nested includes, oversized data,
  and sparse-checkout/index flags. Use `subTest` for parameterized input cases.
- **System:** skipped — no system service, deployment, malware, or performance
  workload is being implemented. Runtime bounds are covered by negative tests.
- **Real-world verification:** run the real terminal entry point locally in
  offline mode and inspect its streamed output. This script is called directly
  by a shell user; no frontend/backend UI calls it. Online tests use fixtures;
  the user's real online verification remains opt-in. State clearly that live
  GitHub account validation was not exercised if no real online run is requested.

After tests pass, document results in this spec, update the tracked item only
when the applicable verification is complete, and commit the coherent feature
on the already checked-out branch without including the user's `AGENTS.MD` or
any generated private report. Never push.

## Implementation and verification evidence

Implemented the shell launcher, standard-library Python audit, README, root
README entry, and 32 tests. The Environment section in the user's local
`AGENTS.MD` records the confirmed runtime and commands; that existing untracked
file is not included in the feature commit.

Online mode additionally resolves accepted credentials through the fixed
GitHub.com `/user` endpoint. A credential read from `gh auth token` is held only
in memory, with `--no-refresh` on supporting versions; 2.93.0 uses its reviewed
non-refreshing implementation. The identity request refuses redirects and
does not use environment proxies. Saved CLI labels remain evidence until that
identity check succeeds. Tokens are never passed as command-line arguments or
written to the report.

Editor databases without any account records are grouped as coverage information;
unsupported existing account schemas remain unknown. Application/profile data
is inspected before workspace data, with a 1,000-database bound. User and system
SSH configurations are inspected statically; unmatched include globs are normal
information, and command-bearing directives are not evaluated.

Executed on the local Linux system, 2026-11-25:

- **Unit, integration, flow, end-to-end, negative, input variation:**
  `python3 -m unittest discover -s github_access_audit/tests -v` passed all
  32 tests. The suite covers actual Git repositories, plain/encrypted SSH keys,
  a real temporary agent with a loaded key, SQLite account storage including
  profile/workspace/WAL cases, non-execution of discovered commands, private
  report creation, secret-free errors, interruption, bounded commands, missing
  dependencies, alternate-home isolation, environment overrides, non-refreshing
  CLI variants, and identity-label mismatch handling. External identity responses
  are faked and unexpected network access is blocked in the online-boundary tests.
- **Shell syntax:** `bash -n github_access_audit/audit.sh` passed.
- **CLI entry point:** `bash github_access_audit/audit.sh --help` passed.
- **Real-world terminal verification:** `bash github_access_audit/audit.sh --repo .`
  completed with all seven sections streaming to a private local report. Final
  run exited 0 in approximately 0.37 seconds, with no stderr. It inspected 206
  editor databases and reported seven saved account associations. It found three
  SSH keys loadable with an empty passphrase and two custom credential helpers.
  No local key names or account identities are copied into this repository.
  Summary: five review findings, zero verified accounts, 128 evidence records,
  ten manual checks, zero unknown checks, and one skipped online check. The
  report has mode 0600 inside a temporary directory with mode 0700.
- **Compatibility:** Python 3.10 grammar parsing passed. Runtime execution used
  the installed Python 3.13.11; a separate Python 3.10 runtime was not exercised.
- **System:** skipped as approved; no deployment, malware, or persistence scan.
- **Real credential validation:** not run. The actual machine run was offline;
  current GitHub authorization and VS Code session validity remain unverified.
  No graphical application path exists for this shell-invoked utility.

The lateral and causal discovery checks above remain valid: the implemented
sections cover independent local access paths, while the incident's root cause
has not been established. Findings describe evidence or exposure, not an attacker
or a malware verdict. No credential was revoked and no user repository content
was changed by the audit run.

## Reference material

- [GitHub CLI auth status](https://cli.github.com/manual/gh_auth_status)
- [Installed CLI auth implementation, v2.93.0](https://github.com/cli/cli/blob/v2.93.0/pkg/cmd/auth/status/status.go)
- [Installed CLI token read implementation, v2.93.0](https://github.com/cli/cli/blob/v2.93.0/pkg/cmd/auth/token/token.go)
- [OpenSSH key utility](https://man.openbsd.org/ssh-keygen)
- [VS Code GitHub authentication](https://github.com/microsoft/vscode/blob/main/extensions/github-authentication/README.md)
- [VS Code account usage storage](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/services/authentication/browser/authenticationUsageService.ts)
- [Git configuration](https://git-scm.com/docs/git-config)
- [Git index listing](https://git-scm.com/docs/git-ls-files)
