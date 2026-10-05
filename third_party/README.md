# Pinned HTTP protocol patches

## HTTP/2 stream reset

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

## HTTP/3 Datagram rejection

`quic-go` is the complete, pinned `github.com/quic-go/quic-go v0.63.0`
source with its upstream license. `http3-datagram-rejection.patch` records
the only changes: an explicit `http3.RejectDatagrams` API, request-scoped
Datagram rejection state, and regression tests.

RFC 9297 §2 requires requests with no HTTP Datagram semantics to abort
with H3_DATAGRAM_ERROR (0x33) on receiving a Datagram. The upstream
`HTTPStream` accessor hijacks the stream and flushes the response, which
would bypass normal body and trailer handling for an ordinary website.
This patch enforces the error in the existing Datagram queue without
hijacking, flushing, reading the body, or starting a goroutine. Queued
Datagrams are checked when the policy is applied; later Datagrams are
silently dropped after the receive side closes, as required by §2.1.

The app applies this policy to ordinary HTTP methods and classic CONNECT
on every HTTP/3 site it serves. Extended CONNECT stays with its owning
handler. This preserves CONNECT-IP's permitted optimistic Datagrams
before authentication or a response (RFC 9484 §7.1), including refused
requests, and the semantics of extensions provided by other Caddy modules.

External main modules, including xcaddy, must explicitly replace both
dependencies with the trees in this repository. For example, with this
repository at `/path/to/caddy-masque`:

```sh
go mod edit -replace=golang.org/x/net=/path/to/caddy-masque/third_party/xnet
go mod edit -replace=github.com/quic-go/quic-go=/path/to/caddy-masque/third_party/quic-go
```

The app calls the added HTTP/3 API directly, so missing the replacement
fails at compile time. Run `python3 tests/verify-http3-fork.py` to compare
the entire fork against the checksummed upstream source plus the patch.
Run `go test -race ./http3` from `third_party/quic-go`, and run the main
module's race and interoperability suites. Regression tests check queued
Datagrams, concurrent classification, closed receive-side drops, exact
wire errors, website bodies and trailers, and other streams on the same
connection. Refresh and verify the patch when updating quic-go or Go.
