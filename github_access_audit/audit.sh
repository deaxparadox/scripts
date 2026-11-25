#!/usr/bin/env bash
# No startup files are sourced. Python runs isolated from PYTHONPATH and user site.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: Python 3.10+ is required; nothing was installed.' >&2
    exit 2
fi
audit_script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -I -B "$audit_script_dir/audit.py" "$@"
