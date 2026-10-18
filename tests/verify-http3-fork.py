#!/usr/bin/env python3
"""Verify that the HTTP/3 dependency differs only by its documented patches."""
from pathlib import Path
import tempfile

from fork_verification import apply_patch, compare_tree, download_verified_module, prepare_upstream, summarize_notices

root = Path(__file__).resolve().parents[1]
version = "v0.63.0"
if f"github.com/quic-go/quic-go {version}" not in (root / "go.mod").read_text():
    raise SystemExit("Update the pinned HTTP/3 fork when updating quic-go")
module = download_verified_module(root, "github.com/quic-go/quic-go", version)
with tempfile.TemporaryDirectory(prefix="masque-http3-") as temp:
    upstream = Path(temp) / "quic-go"
    notices = prepare_upstream(module, upstream)
    apply_patch(upstream, root / "third_party/http3-datagram-rejection.patch")
    apply_patch(upstream, root / "third_party/http3-push-frames.patch")
    apply_patch(upstream, root / "third_party/quic-conformance.patch")
    apply_patch(upstream, root / "third_party/http3-conformance.patch")
    compare_tree(upstream, root / "third_party/quic-go", "HTTP/3")
print("HTTP/3 fork matches verified upstream v0.63.0 plus documented patches; " + summarize_notices(notices))
