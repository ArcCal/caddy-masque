"""Reconstruct the documented fork baseline and compare every shipped byte.

Notice removal is applied only to checksum-verified upstream, before the patch.
The shipped fork is never normalized: a changed comment, literal, extra file,
or missing file therefore still fails verification.
"""

import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


NOTICE_NAME = re.compile(
    r"^(?:licen[cs]e(?:[.-].*)?|copying(?:[.-].*)?|copyright(?:[.-].*)?|third_party_notices\.md)$",
    re.IGNORECASE,
)
NOTICE_TEXT = re.compile(
    r"copyright|SPDX-License-Identifier|permission is hereby granted|redistribution and use|"
    r"licensed under|license can be found|use of this source code is governed",
    re.IGNORECASE,
)
SOURCE_SUFFIXES = {".go", ".rs", ".swift", ".c", ".h", ".cc", ".cpp", ".js", ".ts", ".css", ".m"}


def verify_module_directory(directory, name, version, expected_sum):
    """Verify extracted bytes with Go's documented sumdb/dirhash Hash1 format.

    A cached download can report its stored Sum even if its extracted sources
    were subsequently edited. Hash the sources actually used as our baseline.
    """
    directory = Path(directory)
    summary = hashlib.sha256()
    for path in sorted(directory.rglob("*"), key=lambda item: item.relative_to(directory).as_posix()):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise SystemExit(f"Unexpected upstream module entry: {relative}")
        if path.is_dir():
            continue
        canonical = f"{name}@{version}/{relative}"
        if "\n" in canonical:
            raise SystemExit("Upstream module file name contains a newline")
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        summary.update(f"{digest}  {canonical}\n".encode())
    actual_sum = "h1:" + base64.b64encode(summary.digest()).decode("ascii")
    if actual_sum != expected_sum:
        raise SystemExit("Extracted upstream module checksum mismatch")


def download_verified_module(root, name, version):
    """Keep the upstream download pinned to the repository's existing checksum."""
    sums = [line.split()[2] for line in (root / "go.sum").read_text().splitlines()
            if line.startswith(f"{name} {version} ")]
    if len(sums) != 1:
        raise SystemExit(f"Expected one pinned checksum for {name} {version}")
    module = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", f"{name}@{version}"], cwd=root))
    if module.get("Sum") != sums[0]:
        raise SystemExit("Pinned upstream module checksum mismatch")
    directory = Path(module["Dir"])
    verify_module_directory(directory, name, version, sums[0])
    return directory


def strip_notices(directory):
    """Replay the exact, previously authorized notice-removal transformation.

    Return each affected path and the specific transformations made. This is
    deliberately not a generic comment filter, nor a normalization of the fork.
    """
    changes = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if NOTICE_NAME.search(path.name):
            path.unlink()
            changes[relative] = {"dedicated_notice_file": 1}
            continue
        try:
            source = path.read_text()
        except UnicodeError:
            continue
        original = source
        actions = {}
        if path.suffix in SOURCE_SUFFIXES:
            def clean_block(match):
                if not NOTICE_TEXT.search(match[0]):
                    return match[0]
                actions["notice_comment_blocks"] = actions.get("notice_comment_blocks", 0) + 1
                return ""

            source = re.sub(r"/\*.*?\*/", clean_block, source, flags=re.DOTALL)

            def clean_lines(match):
                if not NOTICE_TEXT.search(match[0]):
                    return match[0]
                actions["notice_line_groups"] = actions.get("notice_line_groups", 0) + 1
                return "".join(line for line in match[0].splitlines(keepends=True)
                               if re.match(r"//(?:go:| \+build)", line))

            source = re.sub(r"(?m)^(?://[^\n]*(?:\n|$))+", clean_lines, source)
        if path.name == "Cargo.toml":
            source, count = re.subn(r"(?m)^license(?:-file)?\s*=.*\n", "", source)
            if count:
                actions["manifest_notice_fields"] = count
        if path.name in {"package.json", "package-lock.json"}:
            try:
                document = json.loads(source)

                def clean_json(value):
                    if isinstance(value, dict):
                        for key in ("license", "licenses", "copyright"):
                            if key in value:
                                del value[key]
                                actions["manifest_notice_fields"] = actions.get("manifest_notice_fields", 0) + 1
                        for nested in value.values():
                            clean_json(nested)
                    elif isinstance(value, list):
                        for nested in value:
                            clean_json(nested)

                clean_json(document)
                source = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
                actions["json_serialization"] = 1
            except ValueError:
                pass
        if path.suffix == ".md":
            source, count = re.subn(
                r"(?ims)^#{1,6} (?:Licen[cs]e(?:s| and copyright)?|Copyright(?: and licen[cs]e)?|Licensing)\s*\n.*?(?=^#{1,6} |\Z)",
                "", source,
            )
            if count:
                actions["notice_documentation_sections"] = count
                trimmed = source.rstrip() + "\n" if source.strip() else source
                if trimmed != source:
                    actions["markdown_final_newline"] = 1
                    source = trimmed
        if source != original:
            path.write_text(source)
            changes[relative] = actions
    return changes


def prepare_upstream(source, destination):
    """Copy the verified upstream, strip notices, then format its Go sources."""
    source = Path(source)
    destination = Path(destination)
    shutil.copytree(source, destination, symlinks=True)
    for path in [destination, *destination.rglob("*")]:
        if path.is_symlink():
            raise SystemExit(f"Unexpected upstream symbolic link: {path.relative_to(destination)}")
        path.chmod(path.stat().st_mode | 0o200)
    changes = strip_notices(destination)
    go_files = sorted(destination.rglob("*.go"))
    # Batch the formatter to stay below command-line size limits. The fork is
    # compared as shipped and receives no such formatting during verification.
    for start in range(0, len(go_files), 100):
        subprocess.run(["gofmt", "-w", *map(str, go_files[start:start + 100])], check=True)
    return changes


def apply_patch(directory, patch_path):
    """Apply the recorded patch without fuzzy contexts or offset matching."""
    with Path(patch_path).open("rb") as patch:
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "--no-backup-if-mismatch", "-p1"],
            cwd=directory, stdin=patch, capture_output=True,
        )
    output = (result.stdout + result.stderr).decode(errors="replace")
    if result.returncode or re.search(r"\b(?:offset|fuzz)\b", output, re.IGNORECASE):
        raise SystemExit(f"Documented fork patch did not apply exactly:\n{output}")


def tree_files(directory):
    """Reject nonregular entries and include all file bytes and directories."""
    entries = {}
    for path in sorted(Path(directory).rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise SystemExit(f"Unexpected fork symbolic link: {relative}")
        if path.is_file():
            entries[relative] = path.read_bytes()
        elif path.is_dir():
            entries[relative + "/"] = None
        else:
            raise SystemExit(f"Unexpected nonregular fork entry: {relative}")
    return entries


def compare_tree(expected, actual, label):
    """Compare full path sets and exact bytes, including comments and fixtures."""
    expected_files = tree_files(expected)
    actual_files = tree_files(actual)
    missing = sorted(expected_files.keys() - actual_files.keys())
    unexpected = sorted(actual_files.keys() - expected_files.keys())
    changed = sorted(path for path in expected_files.keys() & actual_files.keys()
                     if expected_files[path] != actual_files[path])
    if missing or unexpected or changed:
        details = []
        for kind, paths in (("missing", missing), ("unexpected", unexpected), ("changed", changed)):
            if paths:
                details.append(f"{kind} ({len(paths)}): {', '.join(paths[:20])}")
        raise SystemExit(f"{label} fork differs from verified upstream plus documented transformations:\n" + "\n".join(details))


def summarize_notices(changes):
    removed = sum("dedicated_notice_file" in actions for actions in changes.values())
    return f"{len(changes)} upstream notice paths normalized, {removed} dedicated notice files removed"
