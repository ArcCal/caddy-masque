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

`http2-conformance.patch` is applied after the reset patch and before the
conformance fixtures. It validates extended-CONNECT pseudo-headers, the OPTIONS
asterisk target, forbidden connection fields, TE lists and field-edge
whitespace, including undeclared trailers. Malformed messages reset only the
affected stream with PROTOCOL_ERROR (RFC 9113 §§8.1.1, 8.2.1, 8.3 and
RFC 8441 §4). Ordinary CONNECT and permitted Host fallback remain supported.
Outbound field whitespace is normalized before framing. Raw HPACK regression
cases verify both the error code and continued use of the same connection.

The HTTP/1-response diagnostic regression test also synchronizes response
reads with request-header writes. The upstream test otherwise sometimes
observes an already-closed unused connection instead of its intended active
request error. The original diagnostic assertion and production retry logic
are unchanged.

## HTTP/3 Datagram rejection

`quic-go` is the pinned `github.com/quic-go/quic-go v0.63.0`
source. `http3-datagram-rejection.patch` records
an explicit `http3.RejectDatagrams` API, request-scoped
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

`http3-push-frames.patch`, applied after the Datagram patch, stops the frame
parser from skipping push frames, so they are rejected as RFC 9114 requires.
Push is not supported, so on the server's control stream a CANCEL_PUSH names a
push ID never mentioned by a PUSH_PROMISE (section 7.2.3) and is H3_ID_ERROR,
as is a MAX_PUSH_ID smaller than one received before (section 7.2.7). The
parser closes the connection with H3_FRAME_UNEXPECTED as soon as it reads the
type of a PUSH_PROMISE received by a server or on a control stream (section
7.2.5), or of CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID or PRIORITY_UPDATE on
a request stream (sections 4.1, 7.2.3, 7.2.4, 7.2.6 and 7.2.7), whatever the
payload. The client, which never sends MAX_PUSH_ID, treats CANCEL_PUSH and a
PUSH_PROMISE on a request stream as H3_ID_ERROR. The single-integer payloads of
CANCEL_PUSH, GOAWAY and MAX_PUSH_ID are read only within their declared length;
an empty, shorter or longer payload is H3_FRAME_ERROR (section 7.1). The
upstream parser test that required push frames to be skipped is replaced by one
for this behavior; `h3_push_frames_test.go` checks the wire errors against the
server and the fork's client.

## HTTP/3 and QUIC conformance repairs

The [independent reassessment](../docs/ietf-reassessment-2026-10-18.md) checks
the interpretation against original RFCs, verified errata and pinned peers.
The same patch records also include the subsequent method/scheme validation,
post-success HTTP/2 CONNECT framing, client GOAWAY ordering and QUIC packet-type
corrections. Exact-code regression checks select this implementation's behavior;
they do not deny permitted generic protocol errors or connection escalation.

After the two HTTP/3 patches above, verification applies
`quic-conformance.patch` and `http3-conformance.patch`. It still reconstructs
the entire dependency and compares every shipped byte; these records do not
permit untracked downstream edits.

The HTTP/3 patch enforces reserved SETTINGS identifiers, QPACK critical-stream
lifetime and zero-capacity instruction rules, connection-scoped decompression
errors, required request fields, Content-Length consistency, frame ordering
and truncated payload errors. Successful CONNECT streams carry tunnel DATA
rather than HTTP trailers; ordinary responses, including HEAD and 304, retain
their HTTP semantics. Regressions exercise both server and client paths and
the exact wire error codes from RFC 9114 and RFC 9204.

Incoming fields also enforce RFC 9114 §10.3 and RFC 9110's field-content
grammar: no leading or trailing SP/HTAB. TE is permitted only in request
headers; its case-insensitive list accepts only trailers and ignored empty
members. Outgoing regular fields normalize edge whitespace without mutating
the caller's header map. Raw request, response and trailer tests verify
H3_MESSAGE_ERROR and valid list controls. Successful CONNECT responses retain
Content-Length metadata for stricter Capsule Protocol validation, while the
HTTP framing layer still ignores its value as RFC 9110 §9.3.6 requires.
Responses and outgoing trailers omit connection-specific fields and valid
field names nominated by Connection values. This also keeps Caddy's supported
`static_response close: true` pages and CONNECT refusals valid over HTTP/3;
ordinary end-to-end headers, bodies and trailers remain covered by regressions.

The narrow `Server.GetConnectionConfig` callback returns `ConnectionConfig`
with the header limit and HTTP idle timeout for each new connection. The
snapshot supplies both enforcement and advertised SETTINGS and is never
mutated after connection creation. Caddy's HTTP/3 takeover uses it on reload;
no new global QUIC setting or change to existing tunnels is required.

The QUIC patch accounts for the actual remaining anti-amplification byte
budget on normal, ACK, PTO, coalesced and close paths (RFC 9000 §8.1), honors
the peer's UDP payload limit, reserves sufficient congestion-window credit
for ordinary packets, and sizes PMTU probes against actual available credit
(RFC 9002 §7). DATAGRAM payload estimates include the maximum packet overhead;
receipt of an unnegotiated DATAGRAM reports PROTOCOL_VIOLATION (RFC 9221).
Unvalidated close packets are not retained for retransmission by the handler
that lacks access to the connection's byte budget.

Run the affected transport packages, the HTTP/3 race suite, real UDP
handshake/loss/migration/DATAGRAM/PMTU integration tests, and the main client
matrix when refreshing these patches. The upstream allocation-count STREAM
parser assertion is instrument-sensitive under `-race`; run it normally and
retain race coverage of all functional parser cases. Do not use that exception
to skip an ordinary functional or protocol assertion.

## Conformance fixtures

`fixture-patches.json` defines additional fixture patches applied during upstream
verification. Exact input and output hashes and strict patch application are
required. Go string values retain identical runtime bytes. The HTML parser
fixture uses U+00BA and exercises four hexadecimal digits, greedy
character-reference consumption, and a missing semicolon.
