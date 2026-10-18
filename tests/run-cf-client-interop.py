#!/usr/bin/env python3
"""Test the CF gateway's unchanged generic client fixture against real Caddy."""

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


TEST_NAME = "TestInteropCFGenericFrontend"


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


def main():
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    assets = repo / "tests" / "cf-clients"
    vpn = (args.masque_vpn_root or repo.parent / "masque-vpn").resolve()
    paths = {
        "__CF_FRONTEND_PATH__": vpn / "masque-vpn-cf-masque" / "vendor" / "masque-frontend",
    }
    for dependency in paths.values():
        if not (dependency / "Cargo.toml").is_file():
            raise SystemExit(f"Required current Rust project is missing: {dependency}")

    environment = os.environ.copy()
    target = environment.get("CARGO_TARGET_DIR")
    if target:
        # Interpret a caller's relative shared cache before changing directory.
        environment["CARGO_TARGET_DIR"] = str(Path(target).resolve())

    with tempfile.TemporaryDirectory(prefix="caddy-masque-cf-interop-") as temporary:
        workspace = Path(temporary)
        (workspace / "src").mkdir()
        template = (assets / "Cargo.toml.in").read_text(encoding="utf-8")
        for marker, dependency in paths.items():
            template = template.replace(marker, json.dumps(str(dependency)))
        (workspace / "Cargo.toml").write_text(template, encoding="utf-8")
        shutil.copyfile(assets / "Cargo.lock", workspace / "Cargo.lock")
        shutil.copyfile(assets / "main.rs", workspace / "src" / "main.rs")
        metadata = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version=1", "--manifest-path", str(workspace / "Cargo.toml")],
            cwd=workspace, env=environment, capture_output=True, text=True,
        )
        if metadata.returncode:
            sys.stderr.write(metadata.stderr)
            return metadata.returncode
        packages = json.loads(metadata.stdout)["packages"]
        # Preserve the registry dependency versions of the upstream CF snapshot,
        # as well as its distinct local protocol/transport forks.
        upstream_lock = tomllib.loads((vpn / "masque-vpn-cf-masque" / "Cargo.lock").read_text(encoding="utf-8"))
        upstream_versions = {(package["name"], package["version"], package.get("source"))
                             for package in upstream_lock["package"]}
        drift = [(package["name"], package["version"]) for package in packages
                 if package["source"] is not None and
                 (package["name"], package["version"], package["source"]) not in upstream_versions]
        if drift:
            raise SystemExit(f"Harness dependencies differ from the current CF lockfile; review/refresh the server-owned lock: {drift}")
        # These are distinct source snapshots from the main client. Do not
        # replace them with the main workspace's transport patches.
        cf_vendor = vpn / "masque-vpn-cf-masque" / "vendor"
        for name in ("masque-frontend", "masque-proto", "h3", "h3-quinn", "h3-datagram"):
            selected = [package for package in packages if package["name"] == name]
            expected_manifest = cf_vendor / name / "Cargo.toml"
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
        binary = target / profile / "caddy-cf-frontend-compat"
        if not binary.is_file():
            raise SystemExit(f"The built Rust interoperability harness is missing: {binary}")
        environment["MASQUE_CF_FRONTEND_COMPAT"] = str(binary)
        overlay = workspace / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(repo / "zz_cf_frontend_compat_test.go"):
                str(assets / "caddy_cf_compat_test.go.in"),
        }}), encoding="utf-8")
        pattern = "^$" if args.compile_only else f"^{TEST_NAME}$"
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
            ("ipv4-only", "dual-stack"),
            ("h3", "h2", "http1.1", "h3-capsules"),
        ))
        passed = re.findall(
            rf"^\s*--- PASS: {TEST_NAME}/(ipv4-only|dual-stack)/(h3|h2|http1\.1|h3-capsules)(?=\s|$)",
            output, re.MULTILINE,
        )
        if len(passed) != 8 or set(passed) != expected:
            raise SystemExit(f"Expected all 8 distinct interoperability cases; observed {len(passed)}.")
        print("All 8 CF generic frontend Caddy interoperability cases passed under Go race checking.")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as error:
        raise SystemExit(f"Required build tool or test asset is missing: {error.filename}")
