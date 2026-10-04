#!/usr/bin/env bash
# Read-only diagnostics for the findings in docs/security-ietf-audit-2026-10-04.md.
# PASS means the measurement completed; it is not an IETF conformance result.
set -euo pipefail

audit_root=$(cd "$(dirname "$0")/.." && pwd)
audit_work=$(mktemp -d "${TMPDIR:-/tmp}/caddy-masque-audit.XXXXXX")
trap 'rm -rf "$audit_work"' EXIT

command -v go >/dev/null
command -v python3 >/dev/null
python3 - "$audit_root" "$audit_work" <<'PY'
import json
import pathlib
import sys

root, work = map(pathlib.Path, sys.argv[1:])
replacements = {}
for package, name in (("", "h2"), ("", "scale"), ("", "config"), ("internal/auth", "auth")):
    source = root / "tests/audit" / f"{name}.go.txt"
    target = work / f"audit_{name}_test.go"
    target.write_bytes(source.read_bytes())
    replacements[str(root / package / target.name)] = str(target)
(work / "overlay.json").write_text(json.dumps({"Replace": replacements}))
PY

export XDG_CONFIG_HOME="$audit_work/config"
export XDG_DATA_HOME="$audit_work/data"
cd "$audit_root"
echo 'Diagnostic run: PASS reports completed measurements, not standards compliance.'
go test -overlay "$audit_work/overlay.json" -count=1 -run '^TestAudit' -v . ./internal/auth
