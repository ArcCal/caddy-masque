#!/usr/bin/env python3
"""Verify that the shipped HTTP/2 dependency has only the documented patch."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
version = "v0.59.0"
if f"golang.org/x/net {version}" not in (root / "go.mod").read_text():
    raise SystemExit("Update the pinned HTTP/2 fork when updating x/net")
module = json.loads(subprocess.check_output(
    ["go", "mod", "download", "-json", "golang.org/x/net@" + version], cwd=root))
expected_sum = next(line.split()[2] for line in (root / "go.sum").read_text().splitlines()
                    if line.startswith("golang.org/x/net " + version + " "))
if module["Sum"] != expected_sum:
    raise SystemExit("Pinned upstream module checksum mismatch")
with tempfile.TemporaryDirectory(prefix="masque-http2-") as temp:
    upstream = Path(temp) / "xnet"
    shutil.copytree(module["Dir"], upstream)
    upstream.chmod(upstream.stat().st_mode | 0o200)
    for path in upstream.rglob("*"):
        path.chmod(path.stat().st_mode | 0o200)
    with (root / "third_party/http2-reset.patch").open("rb") as patch:
        subprocess.run(["patch", "--batch", "-p1"], cwd=upstream, stdin=patch, check=True,
                       stdout=subprocess.DEVNULL)
    def files(directory):
        return {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    if files(upstream) != files(root / "third_party/xnet"):
        raise SystemExit("HTTP/2 fork differs from pinned upstream plus documented patch")
print("HTTP/2 fork matches verified upstream v0.59.0 plus documented reset API patch")
