#!/usr/bin/env python3
"""Verify that the HTTP/3 dependency differs only by its documented patch."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
version = "v0.63.0"
if f"github.com/quic-go/quic-go {version}" not in (root / "go.mod").read_text():
    raise SystemExit("Update the pinned HTTP/3 fork when updating quic-go")
module = json.loads(subprocess.check_output(
    ["go", "mod", "download", "-json", "github.com/quic-go/quic-go@" + version], cwd=root))
expected_sum = next(line.split()[2] for line in (root / "go.sum").read_text().splitlines()
                    if line.startswith("github.com/quic-go/quic-go " + version + " "))
if module["Sum"] != expected_sum:
    raise SystemExit("Pinned upstream module checksum mismatch")
with tempfile.TemporaryDirectory(prefix="masque-http3-") as temp:
    upstream = Path(temp) / "quic-go"
    shutil.copytree(module["Dir"], upstream)
    upstream.chmod(upstream.stat().st_mode | 0o200)
    for path in upstream.rglob("*"):
        path.chmod(path.stat().st_mode | 0o200)
    with (root / "third_party/http3-datagram-rejection.patch").open("rb") as patch:
        subprocess.run(["patch", "--batch", "-p1"], cwd=upstream, stdin=patch, check=True,
                       stdout=subprocess.DEVNULL)
    def files(directory):
        return {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    if files(upstream) != files(root / "third_party/quic-go"):
        raise SystemExit("HTTP/3 fork differs from pinned upstream plus documented patch")
print("HTTP/3 fork matches verified upstream v0.63.0 plus documented Datagram rejection patch")
