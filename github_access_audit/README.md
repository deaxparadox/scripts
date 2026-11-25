# GitHub access audit

Read-only Linux checks for SSH credentials, GitHub CLI accounts, VS Code account
evidence, Git access configuration, ignored files, and credential-file permissions.
Results appear live in seven numbered sections, including when output is piped.
Malware scanning and system-persistence checks are outside this tool's scope.

## Run

Requires Bash and Python 3.10+ with its standard library. Git, OpenSSH tools, and
`gh` are optional: unavailable checks are clearly marked. Nothing is installed.
Run as your normal desktop user; `sudo` would inspect a different account.

```sh
# Inspect your standard user locations and the current working repository.
bash github_access_audit/audit.sh

# Inspect one or several working repositories (no recursive repository discovery).
bash github_access_audit/audit.sh --repo /path/to/project
bash github_access_audit/audit.sh --repo /path/to/project-a --repo /path/to/project-b

# Also verify GitHub CLI identities against GitHub.com, without refreshing tokens.
bash github_access_audit/audit.sh --repo /path/to/project --online

# Save the same sanitized output to a NEW private file outside your repository.
bash github_access_audit/audit.sh --report /private/path/access-audit.txt

# Include nonstandard SSH-key and VS Code user-data directories.
bash github_access_audit/audit.sh --key-dir /path/to/keys --code-dir /path/to/Code

# Inspect another home locally; caller's agent and environment credentials excluded.
bash github_access_audit/audit.sh --home /path/to/home --repo /path/to/project
```

`--report` creates a file with mode `0600` and refuses existing files or symlinks.
Its parent directory must already exist. Account names, paths, extension IDs,
remote repository names, and fingerprints remain in the report: keep it private.
Credential values and key bodies are withheld. Do not put reports in source control.

`--timeout SECONDS` bounds each subprocess; default 10, maximum 60. File sizes,
captured output, include depth, and inventory counts are bounded. Limits and
unavailable coverage appear as findings. The whole audit can take longer than
one subprocess timeout when there are many files or account checks.
The editor inventory inspects at most 1,000 databases, prioritizing application
and profile storage before workspace storage.

## Sections

| Section | What it establishes |
| --- | --- |
| 1. Tools and coverage | Available tools, selected mode/home, versions and coverage limitations |
| 2. SSH keys and agent | Private-key encryption metadata, empty-passphrase loading where possible, permissions, fingerprints, loaded agent identities, static SSH configuration |
| 3. GitHub CLI accounts | Saved accounts, active selection, environment overrides, optional verified account identities |
| 4. VS Code accounts and extensions | Cached account preferences, extension usage/access associations, profile/workspace sources, extension inventory and manual account checks |
| 5. Git access and configuration | Fetch/push destinations, rewrites, helpers, includes, custom commands and hook locations |
| 6. Hidden changes and credential storage | Ignore sources and history hashes/times, index flags, missing tracked paths, selected credential-file permissions |
| 7. Summary and manual GitHub checks | Counts and section references, plus personal-account/repository checks to do on GitHub |

The script does not launch VS Code or run discovered helpers, hooks, aliases,
workspace tasks, SSH configuration commands, Git fetch/pull/push, or checkout.
It does not modify credentials, revoke access, change passphrases, or clear agents.
Underlying tools and the OS still need to be trusted.

## Reading results

- `CHECK`: the named check has started; output is flushed immediately.
- `INFO`: context or an inventory item.
- `VERIFIED`: the exact stated fact was confirmed. In online mode, GitHub's
  `/user` endpoint confirmed an account identity for a credential.
- `EVIDENCE`: saved configuration or historical metadata. It can be stale.
- `REVIEW`: a setting or exposure deserves attention; this is not proof of an attack.
- `MANUAL`: confirmation requires GitHub, VS Code, or another account interface.
- `UNKNOWN`: the check could not establish a result, with its reason.
- `SKIPPED`: a tool, location, mode, or supported capability was unavailable.
- `DONE`: processing finished within the reported coverage; it does not certify security.

Successful account authentication does not prove repository write permission.
An SSH fingerprint identifies a key, not the GitHub account accepting it. No SSH
connections or write tests are attempted. An encrypted key may still be loaded
in an agent, and encryption metadata does not establish passphrase strength.
For hardware-backed keys, device presence/PIN/touch policies require manual review.

### GitHub CLI verification

Local mode reads only recognized fields from `gh`'s generated hosts metadata.
Complex YAML is reported as unsupported. Environment token variables are
reported by name; their values are never shown. Merely having saved `gh`
credentials does not establish whether they survived server-side revocation.

`--online` checks GitHub.com accounts with `gh auth status --json hosts`. Each
account's JSON state is inspected, because JSON mode can exit successfully even
when authentication failed. Accepted credentials are then checked against the
fixed HTTPS endpoint `https://api.github.com/user` to confirm the actual identity.
This catches a saved account label that differs from the credential's identity.
Where needed, a credential is captured from `gh auth token` into process memory;
it is never printed in the report, put in command arguments, or written to disk.
Environment overrides take precedence for the active credential.

New CLI versions must support `--no-refresh` for both status and credential reads.
Version 2.93.0 uses its reviewed, non-refreshing implementations. Other versions
without that capability are skipped rather than guessing. Debug/proxy/Unix-socket
overrides and non-GitHub.com hosts need manual review before live checks. Online
mode never logs in, changes accounts, renews tokens, or tests a repository push.

### VS Code identities

Account evidence is read from allowlisted metadata in SQLite `state.vscdb`
files: account preferences, historical extension usage, and saved access choices.
Secret-storage values are not selected or decrypted. Application, profile, and
workspace sources are shown separately because a workspace can override a
default preference. Saved access marked "allowed" does not establish a current
session or selection.

Built-in Settings Sync session metadata often contains an opaque session ID
rather than an account name. The script reports that limitation and directs you
to **Accounts → Manage Extension Account Preferences** and the Settings Sync
account UI. Extensions with independent sign-in storage need their own account UI.

Databases are opened read-only/immutable. A database with an active WAL is
marked `UNKNOWN`; close VS Code and rerun for a consistent view. No source
database or journal is changed. Portable/custom/remote environments outside the
reported roots need explicit directories or a separate run in that environment.

### Coverage and exit codes

SSH discovery covers the selected key directories to depth three; symlinks are
not intentionally traversed. Keys elsewhere require `--key-dir`. SSH conditions
are inspected statically rather than evaluated. Git inspection excludes
process-level `GIT_*` overrides and reports their presence for manual review.
Custom credential stores, keyring contents, and full filesystem secret searches
are outside coverage. Ignore-file contents and commit subjects are withheld;
hashes and commit timestamps support comparison without dumping source data.

Exit code `0` means the audit finished, including any stated unknown/skipped
checks. It does not mean all findings passed. `2` indicates invalid input or a
fatal operation error; `130` indicates interruption. Partial reports remain
clearly marked incomplete after interruption. A closed output pipe returns `1`.

## Verification

```sh
python3 -m unittest discover -s github_access_audit/tests -v
bash -n github_access_audit/audit.sh
bash github_access_audit/audit.sh --help
```

Tests generate temporary repositories/SSH keys and synthetic editor/account
storage, including failure cases and live-output checks. Online service responses
are faked; the suite does not validate your real GitHub credentials.
