#!/usr/bin/env python3
"""Check the upstream versions behind local transport replacements."""

import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = (root / "go.mod").read_text()
    queries = []
    replacements = {}
    for module, directory in (
        ("golang.org/x/net", "xnet"),
        ("github.com/quic-go/quic-go", "quic-go"),
    ):
        versions = re.findall(r"(?m)^\s*" + re.escape(module) + r"\s+(v\S+)\s*$", manifest)
        if len(versions) != 1:
            raise SystemExit(f"Expected one required version for {module}")
        selected = subprocess.run(
            ["go", "list", "-m", "-json", module],
            cwd=root, capture_output=True, text=True,
        )
        if selected.returncode:
            sys.stderr.write(selected.stderr)
            raise SystemExit(selected.returncode)
        metadata = json.loads(selected.stdout)
        expected = root / "third_party" / directory
        actual = metadata.get("Replace", {}).get("Dir")
        if (
            metadata.get("Path") != module
            or metadata.get("Version") != versions[0]
            or expected.is_symlink()
            or not actual
            or not Path(actual).is_absolute()
            or Path(actual).resolve() != expected.resolve()
            or metadata.get("Dir") != actual
        ):
            raise SystemExit(f"Selected source for {module} is not its pinned, verified transport fork")
        replacements[module] = f"third_party/{directory}"
        queries.append(f"{module}@{versions[0]}")

    result = subprocess.run(
        ["go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.8.0",
         "-mode=query", "-json", *queries],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)

    decoder = json.JSONDecoder()
    records = []
    position = 0
    while position < len(result.stdout):
        while position < len(result.stdout) and result.stdout[position].isspace():
            position += 1
        if position == len(result.stdout):
            break
        record, position = decoder.raw_decode(result.stdout, position)
        records.append(record)
    if not records or not any("config" in record for record in records):
        raise SystemExit("Vulnerability query returned no valid report")
    advisories = sorted({record["osv"]["id"] for record in records if "osv" in record})
    print(json.dumps({"queried_versions": queries, "selected_replacements": replacements,
                      "advisories": advisories}))
    if advisories:
        raise SystemExit("Pinned transport vulnerability gate failed; review the actual fork and update its verified source")


if __name__ == "__main__":
    main()
