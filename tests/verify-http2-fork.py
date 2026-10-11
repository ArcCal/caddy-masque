#!/usr/bin/env python3
"""Verify that the shipped HTTP/2 dependency has only the documented patch."""
from pathlib import Path
import tempfile

from fork_verification import apply_patch, compare_tree, download_verified_module, prepare_upstream, summarize_notices

root = Path(__file__).resolve().parents[1]
version = "v0.60.0"
if f"golang.org/x/net {version}" not in (root / "go.mod").read_text():
    raise SystemExit("Update the pinned HTTP/2 fork when updating x/net")
module = download_verified_module(root, "golang.org/x/net", version)
with tempfile.TemporaryDirectory(prefix="masque-http2-") as temp:
    upstream = Path(temp) / "xnet"
    notices = prepare_upstream(module, upstream)
    apply_patch(upstream, root / "third_party/http2-reset.patch")
    compare_tree(upstream, root / "third_party/xnet", "HTTP/2")
print("HTTP/2 fork matches verified upstream v0.60.0 plus documented patch; " + summarize_notices(notices))
