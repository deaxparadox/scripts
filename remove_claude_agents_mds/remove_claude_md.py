#!/usr/bin/env python3
"""
find_agent_mds.py - find (and optionally delete) CLAUDE.md / AGENTS.md files.

Live display (interactive terminal):
    line 1      : the directory currently being scanned (refreshes in place)
    below it    : every match, as soon as it is found
At the end the full result is reprinted, grouped by directory, because the
live view only has room for the most recent matches.

Never scanned (and therefore never listed or deleted):
    * node_modules
    * .bun, .claude, .codex, .cache (by name, at any depth)
    * anything passed with --exclude NAME
    * Python virtual environments: .venv / venv / site-packages, and any
      directory that contains pyvenv.cfg (venv/virtualenv) or conda-meta (conda)

Usage:
    python find_agent_mds.py [ROOT]                 # scan, list, then ask what to delete
    python find_agent_mds.py [ROOT] --delete        # scan, then delete everything found, no prompt
    python find_agent_mds.py [ROOT] --dry-run       # with --delete: show what would be deleted
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path

try:  # line editing (arrow keys) at the delete prompt; not available on every platform
    import readline  # noqa: F401
except ImportError:
    pass

TARGETS = ("CLAUDE.md", "AGENTS.md")
SKIP_DIR_NAMES = {"node_modules", "site-packages", "venv", ".venv"}
# Tool-managed locations: never scanned, so never listed or deleted.
# Matched by directory NAME at any depth (so a project's own .claude/ is skipped too).
TOOL_DIR_NAMES = {".bun", ".claude", ".codex", ".cache"}


def _enable_ansi() -> None:
    if os.name == "nt":
        os.system("")  # turns on VT/ANSI processing in Windows 10+ consoles


def _is_env_root(dirnames: list[str], filenames: list[str]) -> bool:
    """True for venv/virtualenv roots (pyvenv.cfg) and conda envs (conda-meta)."""
    return "pyvenv.cfg" in filenames or "conda-meta" in dirnames


def _clip(text: str, width: int, keep_end: bool = False) -> str:
    if width <= 1 or len(text) <= width:
        return text
    return ("…" + text[-(width - 1):]) if keep_end else (text[: width - 1] + "…")


class LiveView:
    """Line 1 = status, lines below = matches. Redraws the whole block in place."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdout.isatty()
        self._height = 0
        self._last_draw = 0.0

    def draw(self, status: str, matches: list[Path], force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and now - self._last_draw < 0.05:  # ~20 fps cap
            return
        self._last_draw = now

        cols, rows = shutil.get_terminal_size((100, 30))
        room = max(rows - 4, 0)  # keep the block shorter than the screen
        shown = matches[-room:] if room else []
        hidden = len(matches) - len(shown)

        lines = [_clip(status, cols - 1, keep_end=True)]
        if hidden:
            lines.append(_clip(f"  … {hidden} earlier match(es) not shown live", cols - 1))
        lines += [_clip(f"  FOUND  {m}", cols - 1, keep_end=True) for m in shown]

        self._erase()
        sys.stdout.write("\n".join(lines))
        sys.stdout.flush()
        self._height = len(lines)

    def _erase(self) -> None:
        if self._height > 1:
            sys.stdout.write(f"\x1b[{self._height - 1}F")  # up to column 0 of line 1
        else:
            sys.stdout.write("\r")
        sys.stdout.write("\x1b[J")  # clear from cursor to end of screen

    def close(self) -> None:
        if self.enabled and self._height:
            self._erase()
            sys.stdout.flush()
            self._height = 0


def find_agent_mds(
    root: str | os.PathLike = ".",
    *,
    verbose: bool = True,
    ignore_case: bool = False,
    exclude: list[str] | tuple[str, ...] = (),
) -> list[Path]:
    """Walk `root` and return every CLAUDE.md / AGENTS.md found (sorted)."""
    _enable_ansi()
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_path}")

    skip_names = SKIP_DIR_NAMES | TOOL_DIR_NAMES | set(exclude)
    wanted = {t.lower() for t in TARGETS} if ignore_case else set(TARGETS)
    view = LiveView(enabled=verbose)
    plain_progress = verbose and not view.enabled  # piped output: matches only
    matches: list[Path] = []
    dirs_scanned = 0
    skipped = 0

    try:
        # followlinks=False: symlinked directories are not entered (no loops, no escaping root)
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            if _is_env_root(dirnames, filenames):
                dirnames[:] = []
                skipped += 1
                continue
            before = len(dirnames)
            dirnames[:] = [d for d in dirnames if d not in skip_names]
            skipped += before - len(dirnames)

            dirs_scanned += 1
            view.draw(f"Scanning [{dirs_scanned} dirs | {len(matches)} found] {dirpath}", matches)

            for name in filenames:
                key = name.lower() if ignore_case else name
                if key in wanted:
                    found = Path(dirpath) / name
                    matches.append(found)
                    if plain_progress:
                        print(f"FOUND  {found}", flush=True)
                    view.draw(f"Scanning [{dirs_scanned} dirs | {len(matches)} found] {dirpath}",
                              matches, force=True)
    except KeyboardInterrupt:
        view.close()
        print("\nScan interrupted - showing what was found so far.")
    finally:
        view.close()

    matches.sort()
    if verbose:
        print(f"Scanned {dirs_scanned} directories under {root_path} "
              f"(skipped {skipped} venv/node_modules dirs).")
    return matches


def print_grouped(matches: list[Path], root: Path) -> None:
    if not matches:
        print("No CLAUDE.md / AGENTS.md files found.")
        return
    groups: dict[Path, list[Path]] = defaultdict(list)
    for m in matches:
        groups[m.parent].append(m)
    print(f"\nFound {len(matches)} file(s) in {len(groups)} director{'y' if len(groups) == 1 else 'ies'}:\n")
    n = 0
    for folder in sorted(groups):
        try:
            label = str(folder.relative_to(root)) or "."
        except ValueError:
            label = str(folder)
        print(f"{label}/")
        for f in sorted(groups[folder]):
            n += 1
            tag = "  (symlink)" if f.is_symlink() else ""
            print(f"  [{n:>3}] {f.name}{tag}")
    print()


def _parse_selection(text: str, count: int) -> list[int] | None:
    """'a' -> all, '' / 'n' -> none, '1,3,5-7' -> those. Returns 0-based indexes or None if invalid."""
    text = text.strip().lower()
    if text in ("", "n", "no"):
        return []
    if text in ("a", "all"):
        return list(range(count))
    picked: set[int] = set()
    try:
        for part in text.replace(" ", "").split(","):
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                picked.update(range(lo, hi + 1))
            else:
                picked.add(int(part))
    except ValueError:
        return None
    if any(i < 1 or i > count for i in picked):
        return None
    return sorted(i - 1 for i in picked)


def delete_files(paths: list[Path], *, dry_run: bool = False) -> int:
    deleted = 0
    for p in paths:
        # Defensive: only ever remove files/symlinks with an expected name, never directories.
        if p.name.lower() not in {t.lower() for t in TARGETS} or p.is_dir() and not p.is_symlink():
            print(f"  skipped (unexpected target): {p}")
            continue
        if dry_run:
            print(f"  would delete: {p}")
            deleted += 1
            continue
        try:
            os.remove(p)  # for a symlink this removes the link, not its target
            print(f"  deleted: {p}")
            deleted += 1
        except OSError as exc:
            print(f"  FAILED: {p} ({exc})")
    return deleted


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find (and optionally delete) CLAUDE.md / AGENTS.md files.")
    ap.add_argument("root", nargs="?", default=".", help="directory to scan (default: current directory)")
    ap.add_argument("--delete", action="store_true",
                    help="delete everything found after the scan, without prompting")
    ap.add_argument("--dry-run", action="store_true", help="show what would be deleted, delete nothing")
    ap.add_argument("--ignore-case", action="store_true", help="also match claude.md, Agents.md, etc.")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIRNAME",
                    help="extra directory name to skip at any depth (repeatable)")
    ap.add_argument("-q", "--quiet", action="store_true", help="no live output, only the final summary")
    args = ap.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    matches = find_agent_mds(root, verbose=not args.quiet, ignore_case=args.ignore_case,
                            exclude=args.exclude)
    print_grouped(matches, root)
    if not matches:
        return 0

    if args.delete:  # automatic mode
        count = delete_files(matches, dry_run=args.dry_run)
        print(f"\n{'Would delete' if args.dry_run else 'Deleted'} {count} file(s).")
        return 0

    if not sys.stdin.isatty():
        print("Not an interactive terminal; nothing deleted (use --delete to delete automatically).")
        return 0

    while True:
        answer = input("Delete which? [a]ll / numbers like 1,3,5-7 / [n]one (default none): ")
        chosen = _parse_selection(answer, len(matches))
        if chosen is None:
            print("Invalid selection, try again.")
            continue
        break
    if not chosen:
        print("Nothing deleted.")
        return 0
    targets = [matches[i] for i in chosen]
    confirm = input(f"{'Dry-run: ' if args.dry_run else ''}Delete {len(targets)} file(s)? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("Nothing deleted.")
        return 0
    count = delete_files(targets, dry_run=args.dry_run)
    print(f"\n{'Would delete' if args.dry_run else 'Deleted'} {count} file(s).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled (anything printed as 'deleted' above was already removed).")
        raise SystemExit(130)
