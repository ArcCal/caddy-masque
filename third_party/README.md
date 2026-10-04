# HTTP/2 stream reset patch

`xnet` is the complete, pinned `golang.org/x/net v0.59.0` source, with its
upstream license. The only implementation change adds an explicit stream
reset API to `http2.ResponseWriter`; `http2/reset.go` unwraps middleware.
`http2-reset.patch` records the exact difference from the upstream module.

RFC 9113 §8.1.1 requires PROTOCOL_ERROR for malformed HTTP/2 messages.
RFC 9297 §3.3 applies that requirement to malformed capsules. Go's existing
write-deadline workaround sends INTERNAL_ERROR. This patch preserves Caddy's
HTTP/2 server and frame serialization while exposing the missing control.

The main go.mod applies the replacement automatically. External main modules,
including xcaddy, must explicitly replace `golang.org/x/net` with this tree:
Go does not inherit dependency replacements. The handler calls the added API
directly, so a build missing the replacement fails at compile time instead
of silently shipping incorrect error codes.

Validation uses Go 1.26.8, the complete upstream HTTP/2 and HPACK tests with
the race detector, frame-level MASQUE regression tests, and the Rust client.
Run `python3 tests/verify-http2-fork.py` from this repository to compare the
entire fork against the pinned upstream source plus the recorded patch.
When updating x/net or Go, refresh this patch and run both sets of tests.
