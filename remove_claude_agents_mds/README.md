# remove_claude_agents_mds

Finds (and optionally deletes) `CLAUDE.md` / `AGENTS.md` files under a directory.

```
python3 remove_claude_md.py [ROOT]            # scan, list, then choose what to delete
python3 remove_claude_md.py [ROOT] --delete   # delete everything found, no prompt
python3 remove_claude_md.py [ROOT] --delete --dry-run   # preview only
```

Options: `--ignore-case`, `--exclude DIRNAME` (repeatable), `-q/--quiet`.

Never scanned: `node_modules`, `.bun`, `.claude`, `.codex`, `.cache`, Python virtualenvs / conda envs.
