# Pinned HTTP protocol patches

## HTTP/2 stream reset

`xnet` is the pinned `golang.org/x/net v0.60.0` source. It adds an explicit
stream reset API to `http2.ResponseWriter`; `http2/reset.go` unwraps middleware.
`http2-reset.patch` records the protocol and build-selection changes.
Verification checks the pinned upstream checksum, reconstructs the documented
notice cleanup and Go formatting, applies the patch without fuzzy or offset
matching, then compares every shipped file byte. Unexpected files, missing
files, or other edits fail verification.

The v0.60.0 baseline includes the upstream HTTP/2 security fixes for trailer
allocation limits (GO-2026-6603), response-header normalization
(GO-2026-6610), lazy flow-window accounting (GO-2026-6611), closed-stream
receive-credit accounting (GO-2026-6612), and synchronized HPACK table-size
updates (GO-2026-6617). These fixes and their upstream regression tests
are retained; the MASQUE reset API adds no independent credit refund.

The fork selects that server and transport on both Go 1.26 and Go 1.27.
The upstream Go 1.27 wrappers delegate to `net/http`, which does not expose
the required stream reset method and rejects the extended-CONNECT client
pseudo-header on this path. Their source is retained for review behind an
unsatisfiable build constraint. No additional build tag is required. The
reset API has a compile-time check that the selected writer implements it,
so future updates cannot silently bypass the protocol patch.

RFC 9113 §8.1.1 requires PROTOCOL_ERROR for malformed HTTP/2 messages.
RFC 9297 §3.3 applies that requirement to malformed capsules. Go's existing
write-deadline workaround sends INTERNAL_ERROR. This patch preserves Caddy's
HTTP/2 server and frame serialization while exposing the missing control.

The main go.mod applies the replacement automatically. External main modules,
including xcaddy, must explicitly replace `golang.org/x/net` with this tree:
Go does not inherit dependency replacements. The handler calls the added API
directly, so a build missing the replacement fails at compile time instead
of silently shipping incorrect error codes.

Validation covers Go 1.26 and Go 1.27, the upstream HTTP/2 and HPACK tests with
the race detector, frame-level MASQUE regression tests, and the Rust client.
Run `python3 tests/verify-http2-fork.py` from this repository to compare the
entire fork against the pinned upstream source plus the recorded patch.
When updating x/net or Go, refresh this patch and run both sets of tests.

The HTTP/1-response diagnostic regression test also synchronizes response
reads with request-header writes. The upstream test otherwise sometimes
observes an already-closed unused connection instead of its intended active
request error. The original diagnostic assertion and production retry logic
are unchanged.

## HTTP/3 Datagram rejection

`quic-go` is the pinned `github.com/quic-go/quic-go v0.63.0`
source. `http3-datagram-rejection.patch` records
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

CONNECT-IP is the only Datagram-capable protocol in the bundled builds.
The app applies the rejection policy to every other request, including
unsupported extended-CONNECT tokens, on every HTTP/3 site it serves.
Requests without Datagrams retain normal Caddy routing. Recognized
CONNECT-IP requests preserve permitted optimistic Datagrams before
authentication or a response (RFC 9484 §7.1), including refused requests.

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

## HTTP/3 push frames

`http3-push-frames.patch`, applied after the Datagram patch, makes the frame
parser return CANCEL_PUSH, PUSH_PROMISE and MAX_PUSH_ID instead of skipping
them, so they are rejected as RFC 9114 requires. Push is not supported, so on
the server's control stream a CANCEL_PUSH names a push ID never mentioned by a
PUSH_PROMISE (section 7.2.3) and is H3_ID_ERROR, as is a MAX_PUSH_ID smaller
than one received before (section 7.2.7). PUSH_PROMISE (section 7.2.5) and push
frames on a request stream are H3_FRAME_UNEXPECTED. The client, which never
sends MAX_PUSH_ID, treats CANCEL_PUSH and a PUSH_PROMISE on a request stream
as H3_ID_ERROR. The upstream parser test that required these frames to be
skipped is replaced by one for this behavior; `h3_push_frames_test.go` checks
the wire errors against the server.

## English source presentation

`english-unicode-fixtures.json` records the ASCII presentation changes separately
from protocol patches. Its JSON strings escape Unicode, including removed text,
so the record itself contains no Chinese literals. Exact baseline/output hashes
and strict patch application remain part of fork verification. Unicode strings
in Go source use escapes with identical runtime bytes. In the HTML parser
fixture, U+00BA replaces U+41BA while retaining four hexadecimal digits, greedy
character-reference consumption, and the missing-semicolon condition.
