#!/usr/bin/env python3
"""Test current Mac/Killswitch APIs and NF protocols against real Caddy transports."""

import argparse
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib


TEST_NAME = "TestInteropCurrentMacAndKillswitch"
NF_TEST_NAME = "TestInteropCurrentNF"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--masque-vpn-root", type=Path,
        help="Current masque-vpn checkout; defaults to the sibling of caddy-masque.",
    )
    parser.add_argument("--release", action="store_true", help="Build the Rust harness with --release.")
    parser.add_argument(
        "--compile-only", action="store_true",
        help="Compile the Rust harness and Go overlay without running interoperability cases.",
    )
    return parser.parse_args()


def registry_versions(lockfile):
    versions = {}
    for package in tomllib.loads(lockfile.read_text(encoding="utf-8")).get("package", []):
        if package.get("source", "").startswith("registry+"):
            versions.setdefault(package["name"], set()).add(package["version"])
    return versions


def compatible(version):
    """Cargo's semver-compatible line: major, 0.minor, or 0.0.patch."""
    parts = version.split("+")[0].split("-")[0].split(".")
    if parts[0] != "0":
        return parts[:1]
    return parts[:2] if parts[1] != "0" else parts[:3]


def client_versions(lockfiles):
    targets = {}
    for lockfile in lockfiles:
        for name, versions in registry_versions(lockfile).items():
            for version in versions:
                key = (name, *compatible(version))
                if targets.setdefault(key, version) != version:
                    raise SystemExit(f"Client lockfiles disagree on {name}: {targets[key]} and {version}; align them first.")
    return targets


def align_lock(workspace, environment, lockfiles):
    """Pin every registry crate shared with the clients to the clients' locked version.

    The committed lock only seeds crates that the clients do not lock themselves,
    so the harness always tests the dependency versions the clients ship.
    """
    targets = client_versions(lockfiles)
    attempted = set()
    while True:
        stale = sorted(
            (name, version, targets[(name, *compatible(version))])
            for name, versions in registry_versions(workspace / "Cargo.lock").items()
            for version in versions
            if targets.get((name, *compatible(version)), version) != version
        )
        if not stale:
            return
        if stale[0] in attempted:
            raise SystemExit(f"Cannot align {stale[0][0]} {stale[0][1]} with the clients' {stale[0][2]}.")
        attempted.add(stale[0])
        name, old, new = stale[0]
        subprocess.run(
            ["cargo", "update", "--quiet", "--manifest-path", str(workspace / "Cargo.toml"),
             "-p", f"{name}@{old}", "--precise", new],
            cwd=workspace, env=environment, check=True,
        )


def main():
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    assets = repo / "tests" / "clients"
    vpn = (args.masque_vpn_root or repo.parent / "masque-vpn").resolve()
    paths = {
        "__MASQUE_CORE_PATH__": vpn / "crates" / "masque-vpn",
        "__MASQUE_MAC_PATH__": vpn / "masque-vpn-mac",
        "__MASQUE_KILLSWITCH_PATH__": vpn / "masque-vpn-killswitch",
        "__MASQUE_H3_PATH__": vpn / "vendor" / "h3",
        "__MASQUE_H3_QUINN_PATH__": vpn / "vendor" / "h3-quinn",
        "__MASQUE_NF_PATH__": vpn / "masque-nf" / "Core",
    }
    for dependency in paths.values():
        if not (dependency / "Cargo.toml").is_file():
            raise SystemExit(f"Required current Rust project is missing: {dependency}")

    environment = os.environ.copy()
    target = environment.get("CARGO_TARGET_DIR")
    if target:
        # Interpret a caller's relative shared cache before changing directory.
        environment["CARGO_TARGET_DIR"] = str(Path(target).resolve())

    with tempfile.TemporaryDirectory(prefix="caddy-masque-wrapper-interop-") as temporary:
        workspace = Path(temporary)
        (workspace / "src").mkdir()
        template = (assets / "Cargo.toml.in").read_text(encoding="utf-8")
        for marker, dependency in paths.items():
            template = template.replace(marker, json.dumps(str(dependency)))
        (workspace / "Cargo.toml").write_text(template, encoding="utf-8")
        shutil.copyfile(assets / "Cargo.lock", workspace / "Cargo.lock")
        shutil.copyfile(assets / "main.rs", workspace / "src" / "main.rs")
        shutil.copyfile(assets / "nf.rs", workspace / "src" / "nf.rs")
        support = paths["__MASQUE_NF_PATH__"] / "tests" / "support" / "mod.rs"
        (workspace / "src" / "nf_support.rs").write_text(
            support.read_text(encoding="utf-8") + (assets / "nf_support-extension.rs").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        align_lock(workspace, environment, [
            paths[marker].joinpath("Cargo.lock")
            for marker in ("__MASQUE_MAC_PATH__", "__MASQUE_KILLSWITCH_PATH__", "__MASQUE_NF_PATH__")
        ])

        metadata = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version=1", "--manifest-path", str(workspace / "Cargo.toml")],
            cwd=workspace, env=environment, capture_output=True, text=True,
        )
        if metadata.returncode:
            sys.stderr.write(metadata.stderr)
            return metadata.returncode
        packages = json.loads(metadata.stdout)["packages"]
        for name, marker in (("h3", "__MASQUE_H3_PATH__"), ("h3-quinn", "__MASQUE_H3_QUINN_PATH__")):
            selected = [package for package in packages if package["name"] == name]
            expected_manifest = paths[marker] / "Cargo.toml"
            if len(selected) != 1 or selected[0]["source"] is not None or Path(selected[0]["manifest_path"]).resolve() != expected_manifest.resolve():
                raise SystemExit(f"Current client transport patch was not selected: {name} ({expected_manifest})")

        cargo = ["cargo", "build", "--locked", "--manifest-path", str(workspace / "Cargo.toml")]
        if args.release:
            cargo.append("--release")
        built = subprocess.run(cargo, cwd=workspace, env=environment)
        if built.returncode:
            return built.returncode
        target = Path(environment.get("CARGO_TARGET_DIR", workspace / "target"))
        profile = "release" if args.release else "debug"
        binary = target / profile / "caddy-wrapper-compat"
        if not binary.is_file():
            raise SystemExit(f"The built Rust interoperability harness is missing: {binary}")
        environment["MASQUE_WRAPPER_COMPAT"] = str(binary)
        nf_binary = target / profile / "caddy-nf-compat"
        if not nf_binary.is_file():
            raise SystemExit(f"The built NF interoperability harness is missing: {nf_binary}")
        environment["MASQUE_NF_COMPAT"] = str(nf_binary)

        overlay = workspace / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(repo / "zz_current_wrapper_compat_test.go"):
                str(assets / "caddy_wrapper_compat_test.go.in"),
        }}), encoding="utf-8")
        pattern = "^$" if args.compile_only else f"^({TEST_NAME}|{NF_TEST_NAME})$"
        command = [
            "go", "test", "-race", f"-overlay={overlay}", "-count=1",
            "-timeout=10m", "-run", pattern, "-v", ".",
        ]
        process = subprocess.Popen(
            command, cwd=repo, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        lines = []
        for line in process.stdout:
            lines.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
        code = process.wait()
        if code:
            return code
        output = "".join(lines)
        if "--- SKIP:" in output:
            raise SystemExit("Interoperability validation cannot succeed with skipped cases.")
        if args.compile_only:
            print("Build-only check passed; zero interoperability cases were run.")
            return 0
        expected = set(itertools.product(
            ("mac", "killswitch"), ("ipv4-only", "dual-stack"),
            ("h3", "h2", "http1.1", "h3-capsules"),
        ))
        passed = re.findall(
            rf"^\s*--- PASS: {TEST_NAME}/(mac|killswitch)/(ipv4-only|dual-stack)/(h3|h2|http1\.1|h3-capsules)(?=\s|$)",
            output, re.MULTILINE,
        )
        if len(passed) != 16 or set(passed) != expected:
            raise SystemExit(f"Expected all 16 distinct interoperability cases; observed {len(passed)}.")
        print("All 16 current Mac/Killswitch Caddy interoperability cases passed under Go race checking.")
        expected_nf = set(itertools.product(
            ("ipv4-only", "dual-stack"), ("h3", "h2", "http1.1", "h3-capsules"),
        ))
        passed_nf = re.findall(
            rf"^\s*--- PASS: {NF_TEST_NAME}/(ipv4-only|dual-stack)/(h3|h2|http1\.1|h3-capsules)(?=\s|$)",
            output, re.MULTILINE,
        )
        if len(passed_nf) != 8 or set(passed_nf) != expected_nf:
            raise SystemExit(f"Expected all 8 distinct NF interoperability cases; observed {len(passed_nf)}.")
        print("All 8 current NF portable-core Caddy interoperability cases passed under Go race checking.")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as error:
        raise SystemExit(f"Required build tool or test asset is missing: {error.filename}")
