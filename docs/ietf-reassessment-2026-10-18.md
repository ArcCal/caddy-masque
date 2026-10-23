# IETF interpretation reassessment and minimal follow-up repairs

Date: 18 October 2026. Baseline server commit:
`538a22a9ee6d237fa1b697cb693848dd992ffb86`.
Protected client commit: `e10a6ec9fcf0e005d36572830539802df36f6638`.

## Outcome and standard of proof

The earlier findings were re-examined as hypotheses, rather than treated as
authority. Most of the substantive HTTP/3, QPACK, Capsule and QUIC obligations
survive that review. Some explanatory claims were too strong: a named specific
HTTP error is not always the only lawful error, and a conservative local
scheduling policy is not necessarily the algorithm prescribed by an RFC.
The original CONNECT-IP wildcard examples also have a verified correction.

The follow-up changes only confirmed, reproducible gaps in request syntax,
CONNECT framing, GOAWAY ordering, QUIC packet-type handling and an internal
URI-template expansion helper. It preserves existing client source, production
dependency versions, authentication, the four carriers, default endpoint,
address policy and mandatory Cloudflare inclusion. The findings below distinguish
an interoperability failure from incorrect error attribution and from a helper
that does not generate production server requests.

Evidence was assessed in this order:

1. Applicable published RFC text, including its surrounding conditions and
   verified RFC Editor errata. MUST, SHOULD, MAY, sender obligations and receiver
   obligations are kept distinct. Reported, rejected or held errata do not
   silently replace the published rules.
2. Source from independent implementations pinned to commits, including
   disagreements and missing checks. Agreement is corroboration, not a vote
   that can override an explicit normative requirement.
3. A concrete current-code counterexample and meaningful positive controls,
   followed by before/after regression and compatibility tests. A failed
   diagnostic establishes only the layer actually executed.

This is a targeted reassessment of the earlier interpretations and relevant
implementation paths, not certification of every dependency or proof that no
undiscovered issue remains.

## Corrections to earlier interpretation and wording

### Specific HTTP error codes are not universally exclusive

[RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1)
defines `H3_GENERAL_PROTOCOL_ERROR` (0x101) for a protocol violation where the
endpoint “declines to use the more specific error code”. Section 8 permits
stream errors to be escalated to connection errors. [RFC 9113 §5.4](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.4)
also permits applicable generic error substitution and escalation for HTTP/2.

Consequently, a conformance assessment must not reject a deliberate permitted
generic protocol error solely because a test expected the more specific code.
Exact-code assertions remain useful for this server's chosen behavior, as do
tests that preserve other streams; they are implementation contracts rather
than the only lawful behavior of every implementation. Required connection
scope still matters: silently accepting malformed input is not a substitute.
Request cancellation or ordinary cleanup is not automatically a protocol error.

This reading is also directly corroborated by the HTTP/3 working-group
discussion of exact-code testing: [Lucas Pardue](https://github.com/quicwg/base-drafts/issues/4842#issuecomment-802137827),
[Martin Thomson](https://github.com/quicwg/base-drafts/issues/4842#issuecomment-802386417)
and [editor Mike Bishop](https://github.com/quicwg/base-drafts/issues/4336#issuecomment-723160439).
Those comments explain the text; they are not substituted for normative RFCs.

QUIC has a similar qualification in [RFC 9000 §11](https://www.rfc-editor.org/rfc/rfc9000.html#section-11):
applicable errors and generic `PROTOCOL_VIOLATION` or `INTERNAL_ERROR` can be
used instead of a more specific error. This does not make an encoding error
an appropriate generic substitute for a well-formed known frame in a forbidden
packet type; the S5 repair retains that distinction.

The earlier client C1–C7 observations remain materially supported. Their
observed cancellation/no-error paths did not select a general protocol error.
Duplicate `:status` retains its explicitly qualified singleton interpretation;
request-only response pseudo-fields and connection fields have separate,
explicit MUST clauses. Portable native-ABI commands remain distinct from
captured Apple QUIC packets. The earlier reports now link this clarification.

### Conservative transport policy is not uniquely mandated

[RFC 9002 §7](https://www.rfc-editor.org/rfc/rfc9002.html#section-7)
contains the congestion-window MUST NOT, with recovery/PTO exceptions.
Reserving the maximum next datagram size is this fork's conservative way of
obeying it; reserving the actual counted packet bytes could also comply.
The RFC does not mandate this exact scheduler. PTO remains exempt, whereas
PMTU probes consume congestion credit ([RFC 9000 §14.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.4)).
No reproduced starvation justifies another scheduler rewrite.

Likewise, RFC 9000 §14.1's 1200-byte requirement distinguishes client Initials
from server ack-eliciting Initials. A conservative guard on all Initial
construction is not a verbatim requirement that every server ACK-only Initial
be that large. No demonstrated failure warrants changing that guard here.

### Wildcard examples require the verified erratum

The original RFC 9484 examples used raw `*`. Verified technical
[erratum 8444](https://www.rfc-editor.org/errata/eid8444) adds to §4.6:

> If the "target" or "ipproto" variable is set to the wildcard value "*", it MUST be percent-encoded. It will therefore be transmitted as "%2A".

That agrees with RFC 6570 simple expansion and RFC 3986's unreserved set.
The current [client already implements this correction](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-proto/src/uri_template.rs#L189-L191).
It is not a client defect. Our stale internal helper, not the client, needed
correction. The production server matcher already accepts encoded wildcards.

## Confirmed current-server gaps and narrowly scoped changes

### S1: invalid HTTP/2 methods reached the application

A raw HTTP/2 request with `:method: BAD METHOD` reached the application and
received an ordinary response. RFC 9113 §8.3.1 requires a valid method;
[RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1)
defines `method = token`. Embedded whitespace, slash, colon and non-ASCII
bytes do not satisfy that grammar.

The repair uses the existing token validator. It does not introduce a known
method whitelist, uppercase conversion or a new dependency. Tests preserve
lowercase and extension methods, including permitted token punctuation, and
require the selected stream error for malformed methods. HTTP/3 already
validated method tokens and needs no equivalent change.

### S2: invalid schemes passed, while valid custom HTTP/2 schemes failed

The HTTP/2 extended-CONNECT path and HTTP/3 accepted malformed nonempty scheme strings, including
`1https`, `ht tps`, `https/path` and `https:`. A Unicode character could also
be case-folded before its validity was established. Conversely, the inherited
ordinary HTTP/2 path accepted only `http`/`https`, rejecting a syntactically
valid custom scheme before the application could decide how to handle it.

RFC 9113 §8.3.1 and RFC 9114 §4.3.1 require a valid scheme and do not restrict
the scheme to `http`/`https`. [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1)
defines `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
The small validators apply that ASCII grammar before lowercasing. Ordinary
CONNECT still omits `:scheme`; extended CONNECT still requires it.

Tests include malformed ASCII/Unicode, single-letter schemes, uppercase and
custom schemes, ordinary and extended requests, and another usable request
on the same connection after a stream error. Accepting a syntactically valid
scheme is not a promise to implement every URI scheme or its resource semantics.
Custom-scheme acceptance here is verified for the tested nonempty paths; an
inherited generic empty-path restriction is not claimed to have been repaired.

### S3: HTTP/2 HEADERS after successful CONNECT were treated as trailers

After a successful CONNECT response, the old receiver accepted a later
HEADERS block as ordinary request trailers/EOF. [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5)
requires frames other than DATA or stream-management frames on that established
stream to be treated as a stream error. RFC 9297 §3.2 adopts those CONNECT
frame rules when the Capsule Protocol is agreed.

The repair records CONNECT establishment on the connection's serve goroutine
when a successful response starts writing, before its bytes can reach the
peer. Trailer processing consults that state on the same goroutine. It does
not add a shared unsynchronized handler flag.

The frame matrix covers ordinary requests, classic CONNECT and CONNECT-IP;
success 200/299, refusal, no final response and interim 103; nonempty/empty
HEADERS and empty DATA with END_STREAM. It rejects prohibited post-success
HEADERS while preserving the other cases and another request on the connection.
This does not invent a prohibition on all pre-success or refused requests.

### S4: increasing client HTTP/3 GOAWAY identifiers were ignored

The server ignored GOAWAY because it does not implement push. But lack of
push state does not remove [RFC 9114 §5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2):
successive identifiers MUST NOT increase and receipt of an increase requires
a connection error. A client sequence `5 → 6` previously left the connection
active.

The control-stream loop now retains the previous identifier and selects
`H3_ID_ERROR` on an increase. Equal/decreasing identifiers and the maximum
initial value remain accepted. Positive controls still serve a GET; subsequently
closing the control stream establishes that all earlier frames were processed
without an earlier ID error. No push implementation or unrelated lifecycle
behavior is added.

### S5: QUIC packet-type handling selected the wrong error and rejected a permitted close

For a known frame in a forbidden packet type, the parser selected
`FRAME_ENCODING_ERROR` (0x7). [RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)
expressly selects connection `PROTOCOL_VIOLATION` (0xa) for that condition,
while distinguishing unknown frame types. The repair changes the enum at that
specific branch. Unknown types and malformed/truncated encodings retain their
separate handling. Tests cover both DATAGRAM encodings and the existing
packet-type matrix, including error frame attribution.

A second matrix check found that transport `CONNECTION_CLOSE` (0x1c) was
rejected in 0-RTT. Table 3 and §12.5 permit it; §10.2.3 explicitly discusses
client 0-RTT closes. The packet-type predicate must not reject that valid frame
just because Initial is a more reliable way of delivering a pre-handshake close.
Application close remains forbidden in Initial/Handshake; other prohibited
0-RTT frame restrictions remain. This is a parser-level acceptance correction,
not evidence that an unchanged VPN client had exercised this rare path.

### S6: internal URI expansion followed an erroneous raw-wildcard example

The correction deletes the literal-`*` special case in the internal expander
and updates its expectations to `%2A`. Comparison with the independent
`yosida95/uritemplate/v3` implementation now checks expansion itself, in
addition to matching. Compatibility tests preserve `%2A`, lowercase `%2a`
and historical raw `*`, and ensure `%252A` is decoded exactly once.

The production server invokes `Match`, not `Expand`. This fixes a helper and
its specification claim; it is not a demonstrated prior tunnel-establishment
failure. No client repair or stricter raw-star refusal is introduced.

## Independent implementation comparisons

The compared revisions are review snapshots, not a statement that all were
rebuilt or wire-tested here. Full source pointers and observation limits are
retained in the evidence package.

| Project and pinned revision | Relevant comparison and limit |
| --- | --- |
| [nghttp2 v1.64.0](https://github.com/nghttp2/nghttp2/blob/526ff38e0249acbcc4d0e8958c12cdeae9960cfe/lib/nghttp2_http.c) | Validates method tokens and ASCII scheme grammar. It corroborates syntax rules; its acceptance of other cases does not replace RFC text. |
| [hyperium/h2 v0.4.12](https://github.com/hyperium/h2/blob/41a0f805c833666a68a293641b0979362e411b5f/src/server.rs#L1569-L1590) | Uses typed HTTP method/URI conversion. Individual dependency parsers can have their own gaps, so typed conversion is not proof of every grammar boundary. |
| [nghttp3 v1.12.0](https://github.com/ngtcp2/nghttp3/blob/8e3523d04bec12cc1fbfd6018d2dc0ef4210148d/lib/nghttp3_http.c) | Independently checks scheme grammar. Its connection code enforces GOAWAY ordering. |
| [hyperium/h3 snapshot](https://github.com/hyperium/h3/blob/43745ad87e95b0c035ac9c547aad467303213425/h3/src/connection.rs#L663-L709) | Separately enforces nonincreasing GOAWAY identifiers. Its typed scheme parser is not used as proof of every ASCII-grammar edge. |
| [nghttp3 newer snapshot](https://github.com/ngtcp2/nghttp3/blob/d29ceea176cebc1f41c9d818c3b1825143d3f813/lib/nghttp3_conn.c#L697-L707) | QPACK critical-stream FIN handling; its QPACK implementation also rejects impossible instructions. No static-only lifetime exemption. |
| [Cloudflare quiche 0.24.0](https://github.com/cloudflare/quiche/blob/12d2af7dd19046eebfa8c14b409a31a0c38fbe48/quiche/src/frame.rs#L337-L365) | Distinguishes invalid packet-type use from malformed frame encoding. Its transport-close 0-RTT restriction disagrees with the RFC/ngtcp2; it is explicitly not copied. |
| [ngtcp2 v1.12.0](https://github.com/ngtcp2/ngtcp2/blob/697d5530238525a7d560e0bc2ea01efe4fe17581/lib/ngtcp2_conn.c#L8945-L8990) | Packet-type checks, including acceptance of both close forms in 0-RTT, and protocol-error attribution. |
| [aioquic snapshot](https://github.com/aiortc/aioquic/blob/8c5c6b49ee8c0d19b310c9b9e6a3b6301360dbb0/src/aioquic/h3/connection.py#L886-L926) | Informational-response state handling, malformed response checks and empty-DATA behavior corroborate client-report distinctions. Its own incomplete checks cannot waive explicit RFC requirements. |
| [connect-ip-go v0.4.0](https://github.com/quic-go/connect-ip-go/blob/a0c35faf2dabddae0833ee5d5f399a9d962ace3e/conn.go) | Context/IP/Capsule handling and userspace TTL decrement. Its stricter Capsule header requirement and unsupported flow-scoping templates are implementation choices, not new server MUSTs. |
| [Google quiche TUN example](https://github.com/google/quiche/blob/c7ee5a065faf3f4eb08182e12dc29b8342f8eb8c/quiche/quic/masque/masque_server_session.cc#L1187-L1277) | Direct TUN integration illustrates external routing; its supported subset cannot certify every RFC 9484 feature. |
| [yosida95/uritemplate v3.0.2](https://github.com/yosida95/uritemplate/blob/c583dbd90f8e47c667d62f787133950bb8e5bfa5/escape.go#L159-L173) | Independent RFC 6570 wildcard escaping, used as an existing test dependency without a version change. |

## Retained behavior and rejected overbroad conclusions

- **QPACK:** static-only compression is permitted. Already opened peer critical
  streams must still be monitored. A capacity-zero instruction at advertised
  maximum zero violates the sender's §3.2.3 obligation, but there is no explicit
  receiver MUST to reject that harmless zero instruction. Receiver tolerance
  must not be described as standards-valid sender behavior. No QPACK runtime
  rewrite is justified.
- **Capsules and ordinary CONNECT:** forbidden content fields and final 204–206
  are real Capsule restrictions. They must not be generalized to every generic
  CONNECT response, where RFC 9110 §9.3.6 accepts any successful 2xx and ignores
  content-length framing. Informational 100/103 before final success remain
  separate messages. Missing Capsule-Protocol is not itself a new mandatory
  refusal rule for the known `connect-ip` token.
- **TTL and routing:** RFC 9484 §7.2's encapsulation wording must be read with
  its explicit external-routing caveat. This server delegates routing to Linux.
  Without privileged path measurements, a userspace TTL compensation would
  risk double handling, local-delivery changes and checksum errors. No such
  speculative packet rewrite is introduced.
- **Resource and scope policy:** a local Capsule bound is not an RFC wire-size
  maximum. Its existence does not require unbounded buffering. Generic URI
  reg-name grammar alone also does not establish an obligation to resolve
  every string as a DNS hostname; RFC 3986 §3.2.2 delegates registered-name
  syntax to the resolver context. Neither candidate justifies a broad parser
  or memory-policy rewrite on the present evidence.
- **Private profiles:** WARP's private bare-IP format is not automatically a
  violation of generic DATAGRAM Capsule framing. mTLS, key pinning and
  out-of-band addresses are allowed choices. SOCKS GSSAPI absence remains a
  disclosed completeness limit, not a remote VPN authentication vulnerability.
- **Errata status:** verified 8444 changes wildcard guidance; verified 7365
  corrects RETIRE_CONNECTION_ID's 0-RTT table entry; verified 8240 marks close
  packets' congestion exemption. Already-correct behavior is retained.
  Reported 8999/9175/9176 are not silently adopted as approved changes.

## Validation and remaining limits

Final checks use Go 1.26.9 and 1.27.2, `-mod=readonly`, serialized test cases
where required, and bounded build parallelism. The compiled Go/fixture source
manifest remains unchanged during each final run. Counts distinguish top-level
tests from nested tests; they must not be added to client matrix cases as
independent coverage.

| Check | Go 1.26.9 | Go 1.27.2 |
| --- | --- | --- |
| Full main race suite, unchanged current CLI enabled | 179 top-level + 145 nested passes | 179 top-level + 145 nested passes |
| Full HTTP/2, HPACK and httpcommon race suites | 517 top-level + 342 nested passes | 517 top-level + 342 nested passes |
| Full HTTP/3 and qlog race suites | 175 top-level + 385 nested passes | 175 top-level + 385 nested passes |
| Four affected QUIC packages, ordinary execution | 703 top-level + 684 nested passes | 703 top-level + 684 nested passes |
| Four affected QUIC packages, functional race execution | 702 top-level + 682 nested passes | 702 top-level + 682 nested passes |
| Unchanged Mac/Killswitch/NF portable client matrix | 24/24 cases | 24/24 cases |
| Independent CF generic-client matrix | 8/8 cases | 8/8 cases |
| `go vet`, optimized CGO-disabled build, MASQUE/Cloudflare registration | Passed | Passed |

All final commands above return success, with zero failed tests. Each toolchain
passes all 41 required client cases: nine real CLI/process cases in the main
suite, 24 portable Mac/Killswitch/NF cases and eight independent CF cases.
No client matrix case is skipped. New regressions
establish baseline failures and preserve legal-input controls. Client tests use
the unchanged audited checkout and real Caddy listeners; portable bridges
remain distinct from native Apple runtime acceptance. An additional Go 1.26.9
Linux ARM64 static cross-build passes; it is not native ARM64 execution.

The first full HTTP/2 run caught `TestNoUnicodeStrings`: the new scheme path
used a Unicode case-conversion API despite already validating ASCII. It was
changed to the package's existing `asciiToLower`, preserving the test's
constraint, and final validation restarted. Superseded failures/incomplete runs
are retained separately. One inherited malformed-scheme fixture now uses
`1bogus` instead of `bogus`, since `bogus` itself is a valid scheme; its error
assertion remains, alongside new legal-custom-scheme controls.

Existing skips are explicit: three privileged nft ruleset subcases; the normal
invocation of a subprocess-only lifecycle helper, executed by its parent tests;
HTTP/2 `TestTransportExternal` and `TestSlowIncrementalDecode`; and QUIC's two
socket-buffer capability tests. Packages without test files are not executed
tests. The QUIC allocation-count assertion runs and passes normally; only that
previously diagnosed instrument-sensitive assertion is excluded from race mode.
Functional parser/conformance tests remain enabled. No failed protocol
assertion is reclassified as a pass.

No native macOS/Network.framework, live WARP, privileged TUN/nftables or native
Linux arm64 acceptance is claimed by this Linux amd64 reassessment. A cross-build
is not a native execution test. Build metadata and hashes identify local
working-tree validation artifacts, not promoted CI release artifacts.
The earlier GitHub Actions budget failure is
not relabeled as a passing CI result, and no CI requirement is disabled.

Evidence directory: `/workspace/reassessment`. The archive
`/workspace/caddy-masque-ietf-reassessment-2026-10-18.tar.gz` contains original
RFC/errata identities, pinned source comparisons, baseline and repaired test
logs, final source hashes, and the validation summary.
