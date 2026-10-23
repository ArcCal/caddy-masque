# Client IETF conformance audit: findings, affected implementations and evidence

Date: 18 October 2026.

**Audited client repository:** ArcCal/masque-vpn, commit
`e10a6ec9fcf0e005d36572830539802df36f6638`.
**Related repaired server:** caddy-masque commit
`100e5094c39f111a9240326baa4ee81f63008234`.

This is a standalone client report. It explains what is wrong, which actual
client or embedded component contains the path, what the tests observed, what
the published IETF text requires, and the limits of each conclusion. The client
repository was read and imported without modification. No client repair was
applied or proposed as a hidden dependency of the server fixes.

**Reassessment:** the [independent RFC/source review](ietf-reassessment-2026-10-18.md)
checks the conclusions against verified errata and other implementations.
The specific HTTP/3 codes below identify the tested implementation contract,
not the only permitted error choice: RFC 9114 §8.1 expressly allows an endpoint
to decline a more specific code and select `H3_GENERAL_PROTOCOL_ERROR` (0x101).
Section 8 also permits stream errors to be escalated to connection errors.
Neither flexibility excuses accepting malformed messages, silently continuing
after a required connection error, or substituting arbitrary cancellation for
a detected protocol error. None of the reported cancellation/no-error paths
requested the generic protocol error. Native ABI observations remain distinct
from packet captures.

## 1. Findings and practical significance

Seven HTTP/3 finding groups are substantiated below. C6 and C7 reject legal
peer behavior and can break a forced-H3 attempt against a conforming endpoint.
C1–C5 concern mandatory handling of malformed peer input or critical-stream
closure. A conforming server normally avoids generating those inputs, but a
receiver still has the stated protocol obligations. No memory-safety exploit,
credential bypass or native Apple incident cause is established by these tests.

The findings apply to **HTTP/3 sessions**, including an Auto attempt that
actually selects H3. They do not automatically establish an HTTP/2 or HTTP/1.1
fault. An application's retry/fallback policy can change the user-visible
result without making the defective H3 path conformant.

The CF gateway requires two separate entries: its reusable generic frontend
client component, and its actual `warp-packet` outbound client. Their callers
and some Datagram/response checks differ. Source sharing is established
explicitly; ordinary generic-client tests are not WARP-service tests.

There are also separately disclosed local SOCKS5 limitations and private WARP
profile differences. These are discussed after C1–C7 rather than silently
counted as new direct HTTP/3 measurements.

## 2. Inventory and why findings propagate to particular clients

All source links in this report pin the audited commit, rather than `main`.
A product name alone is not evidence that two implementations share a defect.

| Client/artifact | Actual implementation and source evidence |
| --- | --- |
| `masque-client`, including Linux system/SOCKS/LAN-gateway and macOS CLI roles | The [CLI entry point](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/bin/masque-client.rs#L25-L36) delegates to the shared Rust client. The [root workspace patches](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/Cargo.toml#L26-L33) select root `vendor/h3` and `vendor/h3-quinn`. |
| IETF Masque GUI | It packages and launches that CLI; it is not another HTTP/3 implementation. The [build script](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/macos/build-app.sh#L30-L49) embeds it, [settings](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/macos/IETFMasque/Sources/IETFMasqueCore/Settings.swift#L190-L205) choose `masque-client --config -`, and the [process contract](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/macos/IETFMasque/Sources/IETFMasqueCore/ClientProcess.swift#L43-L48) uses held stdin. |
| Mac | Its [manifest](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-mac/Cargo.toml#L14-L37) selects the shared library/root h3; its [client wrapper](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-mac/src/client.rs#L22-L36) delegates `run` to it. |
| Killswitch | Its [manifest](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-killswitch/Cargo.toml#L14-L37) and [client wrapper](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-killswitch/src/client.rs#L22-L36) select/delegate to the same protocol core. PF/native lifecycle behavior is additional platform code. |
| Masque NF | It has an independent production Client, tunnel and native adapter, but selects root h3. Its [manifest](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/Cargo.toml#L13-L50) separates production h3/H2/Hyper from development-only Quinn/rustls. Production socket/TLS/QUIC I/O uses Apple Network.framework. NF does not run `masque_vpn::Client` or production Quinn merely because the portable test host uses them. |
| CF embedded generic client component | The [frontend manifest](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-frontend/Cargo.toml#L14-L30) selects CF-local protocol/h3/h3-quinn/h3-datagram snapshots. This reusable client was exercised against Caddy separately; the shipping gateway uses the frontend's server role. |
| Actual CF WARP egress client | [`warp-packet` dependencies](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/Cargo.toml#L17-L22) select the same CF h3 fork. Its [production H3 construction](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L455-L475) invokes it, but response and Datagram processing use different caller code. Its production profile is a Cloudflare service contract, not the Caddy generic-client fixture. |

The current macOS build inventory is IETF Masque, Mac, Killswitch and NF. A
retired standalone Swift transport is not counted as a current additional
client implementation.

## 3. Evidence levels and affected-client matrix

**P** means direct execution of the unchanged h3 protocol layer through NF's
production native adapter. **F** means direct execution of unchanged NF
`Client::run`, with a synthetic host implementing its native ABI. **S** means
the affected dependency and caller path were established from pinned source.
**R** means that inspected source handles or explicitly guards the particular
counterexample; it does not certify every runtime error path. **I** marks an
interpretive standards conclusion, described explicitly under C2.

Neither P nor F executes Swift/Network.framework, constructs QUIC packets or
captures native wire traffic. S is not a claim that the corresponding complete
application was run against an adversarial peer.

| Finding/subcase | CLI | IETF GUI | Mac | Killswitch | NF | CF generic component | Actual WARP H3 path |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1: QPACK stream lifetime/instructions | S | S | S | S | P | S | S |
| C2: response contains request-only `:path` | S | S | S | S | P | R | R |
| C2: response contains `connection: close` | S | S | S | S | P | S | S |
| C2: duplicate `:status` acceptance | S/I | S/I | S/I | S/I | P/I | R | R |
| C3a: parser returns message error but requests cancellation | S | S | S | S | P | S | S |
| C3b/c: application detects forbidden Capsule fields but omits message-error signaling | R | R | R | R | F | R | S, separate caller |
| C4: HEADERS after successful CONNECT | S | S | S | S | P | S | S |
| C5: malformed Quarter Stream ID silently dropped | R, distinct decoder | R, distinct decoder | R, distinct decoder | R, distinct decoder | F | R, distinct decoder | S, separate manual decoder |
| C6: interim 100/103 mistaken for final refusal | S | S | S | S | F | S | S |
| C7: empty DATA mistaken for stream EOF | S | S | S | S | F | R, fixed loop | R, fixed loop |

In C5, R records recognition/error construction in a distinct decoder, not a
new observation of its final on-wire close. In C3, whole-connection termination
is permitted by RFC 9114 §8; the issue is wrong or absent prescribed error
signaling. In C2, the duplicate-status observation is definite, while its
single-status normative interpretation is qualified rather than presented as
an explicit duplicate-response MUST sentence.

## 4. Detailed HTTP/3 findings

### C1: peer QPACK critical streams are retained without lifecycle/instruction processing

**Affected:** all client/component rows above, on H3. Root and CF forks contain the same receive-stream storage pattern. A search for `encoder_recv`/`decoder_recv` finds only declarations, initialization, and replacement/duplicate detection; there is no subsequent consumer.

Sources: [root declarations](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/connection.rs#L61-L70), [root acceptance](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/connection.rs#L447-L462); [CF declarations](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/connection.rs#L61-L70), [CF acceptance](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/connection.rs#L447-L462).

The NF-host proofs send a resolved QPACK stream type first, and deliver FIN as a separate native ABI event. They observe an active driver and no corresponding parent CLOSE after a bounded wait for each of:

| Input | Specific connection error used by these proofs | Proof function |
| --- | --- | --- |
| Encoder stream `02`, then FIN | H3_CLOSED_CRITICAL_STREAM, 0x104 | `qpack_encoder_fin_is_not_enforced` |
| Decoder stream `03`, then FIN | H3_CLOSED_CRITICAL_STREAM, 0x104 | `qpack_decoder_fin_is_not_enforced` |
| Encoder stream `02 21` (capacity 1), while local maximum is 0 | QPACK_ENCODER_STREAM_ERROR, 0x201 | `qpack_encoder_capacity_is_not_enforced` |
| Decoder stream `03 80` (Section Acknowledgment for stream 0), with no dynamically encoded section | QPACK_DECODER_STREAM_ERROR, 0x202 | `qpack_decoder_invalid_ack_is_not_enforced` |

A second encoder stream produces parent CLOSE 0x103 in `duplicate_qpack_stream_control_is_enforced`, showing that stream acceptance and the h3 connection driver are active. The absence observations are bounded; the stronger support is the source's missing reader, not a claim to have watched forever.

Normative basis:

- [RFC 9204 §4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2): “Closure of either unidirectional stream type MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.”
- [RFC 9204 §4.3.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1): “The decoder MUST treat a new dynamic table capacity value that exceeds this limit as a connection error of type QPACK_ENCODER_STREAM_ERROR.”
- [RFC 9204 §4.4.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1): an acknowledgment for a stream whose nonzero-Required-Insert-Count sections are all acknowledged “MUST be treated as a connection error of type QPACK_DECODER_STREAM_ERROR.” There are no such sections in the test.
- [RFC 9204 §3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3) and §5 establish the zero default; root settings conversion [does not advertise a nonzero QPACK capacity](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/config.rs#L72-L134).

Static-only QPACK is permitted. The defect is failure to monitor streams that the peer has actually opened and to validate received instructions, not absence of dynamic compression.

### C2: malformed response fields are accepted, with an important CF exception

| Input | Canonical core, Mac, kill-switch, NF | CF fork |
| --- | --- | --- |
| Two `:status: 200` fields | Accepted; the later assignment overwrites the earlier one | Rejected by explicit duplicate-pseudo guards |
| `:status: 200` and request-only `:path: /` | Accepted; request-only pseudo-field is discarded when forming the response | Rejected by response-context checks |
| `:status: 200` and `connection: close` | Accepted and retained | Source confirms the same unchecked response path; its connection-field check is confined to request conversion |

Direct portable proofs: `duplicate_status_is_accepted` and `other_malformed_response_fields_are_accepted`. They call the unchanged h3 response parser over the NF adapter and receive `Ok(Response)` with status 200. They are not full NF session-establishment proofs; an empty assignment stream would not complete a tunnel. However, NF's later `check_response` only adds status/Capsule-content checks and does not reconstruct discarded pseudo-headers or reject `connection`.

Root-fork sources:

- [Pseudo-field assignments without duplicate guards](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/proto/headers.rs#L228-L255).
- [Response conversion requires status but does not reject request pseudo-fields](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/proto/headers.rs#L107-L118).
- [Regular-field parsing lacks hop-field restrictions](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/proto/headers.rs#L299-L304).
- [NF's later application checks](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/client.rs#L522-L540), [canonical checks](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L674-L686).

CF's different handling is proven by [duplicate guards](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/proto/headers.rs#L334-L347), [response pseudo-field rejection](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/proto/headers.rs#L200-L222), and [request-only placement of hop-field checks](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/proto/headers.rs#L136-L152). Do not label CF as accepting duplicate status or response `:path`.

Normative basis:

- [RFC 9114 §4.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3): “Pseudo-header fields defined for requests MUST NOT appear in responses”; “Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed.”
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): “any message containing connection-specific fields MUST be treated as malformed.”
- [RFC 9114 §4.1.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2): “Clients MUST NOT accept a malformed response.”
- [RFC 9114 §4.3.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2): “For responses, a single ":status" pseudo-header field is defined that carries the HTTP status code”. **Precision:** this is the textual basis for the single-status interpretation; it is not an explicit “MUST NOT duplicate :status” sentence. The two-status acceptance fact is certain, but its normative discussion should preserve this distinction. The request-only pseudo-field and connection-field violations have direct explicit MUST text.

Uppercase ordinary field names are rejected by `HeaderName::from_lowercase`; do not include them among the demonstrated accepted inputs.

### C3: detected malformed responses do not consistently request H3_MESSAGE_ERROR

#### C3a: h3 parser requests cancellation while returning message error

**Affected source:** canonical/Mac/kill-switch/NF and the CF gateway's actual WARP H3 client (plus its copied frontend client component), because both h3 forks have the same error-signaling mismatch. The WARP dependency and invocation are linked above.

- [Root fork](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/client/stream.rs#L169-L192).
- [CF fork](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/client/stream.rs#L176-L199).

Both malformed-header conversion failures return a Rust `StreamError` carrying H3_MESSAGE_ERROR (0x10e), but call the transport's `stop_sending(H3_REQUEST_CANCELLED)` (0x10c). The missing-status counterexample is unambiguously malformed under RFC 9114 §4.3.2, regardless of the duplicate-status interpretation above.

`malformed_headers_emit_cancel_instead_of_message_error` observes the production NF adapter request native ABI CLOSE flags 268 (0x10c), with no 270 (0x10e), while the returned Rust error says H3_MESSAGE_ERROR. The NF mapping is [Core/src/quic.rs:38–40](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/quic.rs#L38-L40). Quinn's source mapping likewise passes the requested code to the receive stream's stop operation: [root](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3-quinn/src/lib.rs#L416-L420), [CF](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3-quinn/src/lib.rs#L454-L458). Those adapter calls are source evidence, not a new Quinn packet-capture test.

Caller follow-through was also checked, so the returned Rust error must not be assumed to repair the earlier cancellation automatically. Canonical [recv_response failure handling](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L472-L498) returns before its separate invalid-success-header branch. Its [connection-error flush helper](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L792-L801) only polls pending connection errors; the malformed-header closures return a plain StreamError without calling [handle_connection_error_on_stream](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/error/connection_error_creators.rs#L107-L116). The CF copied frontend [also propagates recv_response errors before its semantic-header reset branch](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs#L448-L468), and WARP [propagates the recv_response error directly](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L526-L529). Canonical and CF frontend outer run loops log/retry, without selecting a corrective message error: [canonical](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L215-L233), [CF frontend](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs#L197-L215). This is source evidence, not proof of final packet ordering in those complete applications.

#### C3b: full NF Capsule-header rejection omits a message-error request

**Affected direct proof:** NF only. Canonical/Mac/kill-switch and the copied CF frontend client explicitly request message-error termination for invalid successful Capsule responses. The actual WARP H3 client has a separate source-only signaling gap described below; do not confuse that caller with the copied CF frontend client.

The full NF Client correctly identifies a `200` CONNECT-IP response containing `Content-Type: text/plain` as malformed. It returns from [the unchecked propagation site](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/client.rs#L250-L264) after [the correct semantic rejection](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/client.rs#L530-L540), without requesting H3_MESSAGE_ERROR on that stream or connection. The diagnostic `nf_malformed_capsule_headers_do_not_send_message_error` observes the malformed diagnostic and only code-zero ABI CLOSE events during teardown.

Resource drop reaches [Lease::drop](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/native.rs#L320-L325) and [Bridge::release, which requests CLOSE flags 0](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/native.rs#L258-L271). The production Swift host [dispatches CLOSE to close(id, code)](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/App/Sources/MasqueNF/NativeClient.swift#L212-L216), [sets a group applicationError only for nonzero codes](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/App/Sources/MasqueNF/NativeClient.swift#L591-L596), and [sets streamApplicationErrorCode only for nonzero codes before cancelling a stream](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/App/Sources/MasqueNF/NativeClient.swift#L613-L620).

Positive source contrasts: [canonical invalid-success response termination](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L489-L498), [CF equivalent](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs#L459-L468).

#### C3c: actual WARP H3 semantic-header rejection chooses connection close 0 (source only)

The actual WARP client calls its own [check_response](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L943-L958), which rejects content-related response fields. For a successful 200 Capsule response containing a forbidden Content-Type
(or another forbidden content field), it explicitly [calls Quinn conn.close(0)](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L530-L535), without selecting H3_MESSAGE_ERROR. This is separate from NF's ABI evidence and separate from the copied CF frontend client's correct invalid-success termination. Ordinary non-2xx refusals also use that error branch, but are outside this
malformed-message criticism. No malicious-peer WARP test was executed for this path. The WARP check also does not catch `Connection` after CF h3 accepts it, establishing C2's source-level applicability to actual WARP H3.

Normative basis for C3:

- [RFC 9297 §3.2](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2): “The Capsule Protocol MUST NOT be used with messages that contain Content-Length, Content-Type, or Transfer-Encoding header fields”; a receiver observing a violation “MUST treat the HTTP message as malformed.”
- [RFC 9114 §4.1.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2): “Malformed requests or responses that are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.”
- [RFC 9114 §8](https://www.rfc-editor.org/rfc/rfc9114.html#section-8): “An endpoint MAY choose to treat a stream error as a connection error under certain circumstances”. **Do not report whole-connection termination by itself as forbidden.** The issue is the selected/missing message-error signaling, not the choice to tear down the entire connection.
- [RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1) also permits deliberate `H3_GENERAL_PROTOCOL_ERROR` when the endpoint declines a more specific code. A general protocol error is not a demonstrated defect merely because a proof expects `H3_MESSAGE_ERROR`; the observed paths request cancellation or ordinary cleanup instead.

#### Required evidence wording limits

The synthetic host records native ABI commands. It performs no TLS handshake or QUIC packet construction and does not execute Swift/Network.framework. Therefore:

- Write “requested ABI CLOSE flags 0x10c” or “teardown emitted only code-zero ABI CLOSE commands”, not “captured STOP_SENDING/CONNECTION_CLOSE on the native wire”.
- Do not equate ABI flags 0 with H3_NO_ERROR: the registered H3_NO_ERROR value is 0x100. On Swift's code-zero path, no explicit QUIC error code is assigned by the client before cancellation; actual wire behavior remains platform-dependent and unmeasured here.
- It is supported to say that the detected malformed message does not cause this production NF path to request H3_MESSAGE_ERROR. It is not supported to claim the platform demonstrably emits a particular connection-close frame/code.
- Returning `StreamError::H3_MESSAGE_ERROR` to a caller is not the same operation as requesting that error from the transport.
- Keep the valid semantic rejection of forbidden Capsule Content-Type separate from the defective error-signaling path. A server must continue to obey Capsule restrictions.

### C4: HEADERS after successful CONNECT becomes ordinary EOF

**Requirement.** [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4) says: “Once the CONNECT method has completed, only
DATA frames are permitted”; receipt of another known frame type “MUST be treated
as a connection error of type H3_FRAME_UNEXPECTED.” The exception for an
extension expressly permitting another frame type does not make ordinary
trailing HEADERS legal. RFC 9297 §3.2 explicitly adopts HTTP/3 §4.4 frame usage
when both endpoints agree to the Capsule Protocol.

**Source.** `vendor/h3/src/connection.rs:874` stores HEADERS as trailers and returns
`Ok(None)` at line 877, without considering successful CONNECT. The NF H3 reader
breaks on that value at `masque-nf/Core/src/tunnel.rs:140`. The main generic reader
does the same at `crates/masque-vpn/src/tunnel.rs:159`. The NF manifest explicitly
selects the root H3 fork at `masque-nf/Core/Cargo.toml:48`; the root workspace does
so at `Cargo.toml:31`. Mac and Killswitch depend on this main core at their
respective `Cargo.toml:16`; this is source attribution to shared Rust protocol
paths, not direct native-application execution.

**Direct diagnostic.**
`connect_trailer_headers_are_treated_as_body_eof` sends a CONNECT-IP request,
receives final 200, then supplies a validly encoded empty HEADERS field section.
The unchanged H3 RequestStream returns ordinary `recv_data() -> Ok(None)` and
there is no parent native-ABI CLOSE request with code `0x105`
(`H3_FRAME_UNEXPECTED`). Importantly,
this test directly exercises the H3 library through the NF native adapter; it
does **not** invoke the whole NF `Client::run` loop. The successful final-200 parse
is the local positive control; the separate duplicate-QPACK-stream diagnostic
does produce the expected parent native-ABI CLOSE request (`0x103`), showing that the synthetic
host can observe such error requests.

**CF scope.** The CF fork adds an opt-in guard but defaults it to false at
`masque-vpn-cf-masque/vendor/h3/src/connection.rs:845`. Its setter is at line 850;
the HEADERS guard is at line 884, while the unguarded default still returns EOF
at line 894. Neither the embedded generic frontend nor warp-packet calls
`forbid_trailers` (`rg` over both source directories returns no matches). Thus
the generic CF caller's gap is source-confirmed, not independently reproduced
with a malicious CF peer. Merely having the unused guard is insufficient to
claim that caller complies.

The actual WARP [Capsule receive loop](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L546-L575)
also treats `recv_data() -> Ok(None)` as stream termination and calls
`conn2.close(0)`. It does not enable that guard. This extends C4 to its actual
caller by source inspection, without claiming a live WARP or native-wire test.

### C5: NF silently discards malformed HTTP Datagram prefixes

**Requirement.** [RFC 9297 §2.1](https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1) says a Quarter Stream ID greater than `2^60−1`
“MUST be treated as an HTTP/3 connection error of type H3_DATAGRAM_ERROR (0x33).”
It separately requires the same error for a QUIC DATAGRAM payload too short to
parse its Quarter Stream ID.

**Source.** `masque-nf/Core/src/client.rs:269` consumes incoming native datagrams.
Lines 270–273 forward a datagram only if decoding succeeds and equals this
request's Quarter Stream ID. Both parse failures and impossible, oversized
Quarter Stream IDs simply fail that equality test and disappear. There is no
error branch or connection-error request. Silently ignoring a valid datagram
belonging to another request does not excuse malformed framing: the malformed
prefix must be rejected before request association.

**Direct diagnostic.**
`nf_malformed_http_datagram_prefixes_are_silently_dropped` invokes unchanged NF
`Client::run`. It injects an empty payload and the eight-byte value
`d0 00 00 00 00 00 00 00`, which encodes `2^60`. In each case, queue capacity
returns to 128, proving that production demultiplexing consumed the payload;
the task remains active and CLOSE events remain empty, including no `0x33`.
This occurs after final 200 while awaiting address capsules, with the request
stream open. It does not depend on completing host address configuration.
Working real-Caddy NF Datagram controls are recorded separately in
`wrapper-summary.json` and `wrapper-go126.log` / `wrapper-go127.log`; those are
valid-input interoperability evidence, not malicious-prefix tests.

**CF and main generic scope.** Do not transfer the NF-specific hand-written
demultiplexer finding to these distinct paths. The CF generic frontend reads
through its `h3-datagram` decoder at
`masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs:477`.
Its decoder creates `H3_DATAGRAM_ERROR` for a truncated prefix at
`vendor/h3-datagram/src/datagram.rs:36` and an oversized prefix at line 48;
`datagram_handler.rs:89` feeds that error into connection-error handling.
These references are relative to the CF subtree. They show recognition of the
malformation, not a direct CF malicious-wire test or proof of every subsequent
transport-close behavior. The private WARP module has a separate manual decoder;
see its distinct profile observations below.

### C6: legal informational H3 responses abort tunnel setup

**Requirement.** [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): “A client MUST be able to parse one or more 1xx
responses received prior to a final response, even if the client does not expect
one.” A user agent may ignore an unexpected interim response, which means
continuing to the final response, not treating the interim status as final.
RFC 9114 §4.1 explicitly permits interim response messages followed by one final
response on the same stream.

**Source.** The root H3 `recv_response` returns the first HEADERS response at
`vendor/h3/src/client/stream.rs:99`. NF calls it exactly once at
`masque-nf/Core/src/client.rs:252`, then checks the returned status at line 263.
Its final-status helper rejects 100/103 at lines 559–582. The main generic client
has the same one-call setup at `crates/masque-vpn/src/client.rs:476` and immediate
status validation at line 489. The CF generic client's own copy does so at
`masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs:452` and line 459.

**Direct diagnostic and control.**
`informational_100_and_103_before_final200_are_rejected_by_actual_nf_client`
invokes unchanged NF `Client::run`. Final 200 plus valid ADDRESS_ASSIGN and
ROUTE_ADVERTISEMENT capsules produces connected status `HTTP/3`. Prefixing that
same successful sequence with valid 100 Continue produces “the server refused
the CONNECT-IP request: 100 Continue”; prefixing 103 Early Hints produces the
equivalent 103 refusal. Neither prefixed case reaches connected state. This
directly establishes the NF behavior; main/Mac/Killswitch/CF attribution is by
the source paths above, not by running their native apps against this peer.

The actual WARP client likewise [receives one response and immediately checks
it](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L522-L535).
Its [status helper](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L943-L958)
rejects 100/103 as non-success. This is source-level attribution to WARP's own
caller, rather than an inference from its copied frontend component.

**Status-code distinction.** RFC 9297 §3.2 prohibits **final Capsule responses**
204, 205 and 206. The tested 100/103 are separate informational messages before
final 200, not Capsule data or a final Capsule response. The main, NF and CF
generic clients correctly contain an explicit 204–206 rejection; that does not
justify rejecting an earlier legal informational message. Do not characterize
the generic 204–206 rejection as a defect.

### C7: zero-length DATA is confused with stream closure

**Requirement.** [RFC 9114 §7.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1) defines DATA as “arbitrary, variable-length
sequences of bytes” with no positive minimum length. Section 4.1 says stream
closure indicates the end of the final message. RFC 9297 §3.1 defines the data
stream as “all bytes sent in DATA frames with the corresponding stream ID.”
An empty DATA frame contributes zero bytes; it does not close that stream.
This is a framing/byte-stream handling defect. There is no special error code
which a peer must send merely because it receives legal empty DATA.

**Source.** `vendor/h3/src/connection.rs:866` reads at most one frame header with
an `if`; an empty DATA frame then reaches `poll_data` at line 928.
`vendor/h3/src/frame.rs:111` returns `None` when that frame's remaining length is
zero. The H3 API propagates frame-local `None` as stream EOF. NF and the main
generic reader break at the source lines cited under C4.

**Direct diagnostic and control.**
`empty_data_before_valid_address_capsules_ends_actual_nf_client_tunnel` invokes
unchanged NF `Client::run`. Final 200 plus valid assignment/routes connects.
Inserting exactly `00 00` (DATA, length zero) after final HEADERS and before the
identical capsules instead produces “tunnel ended before an address was
assigned”. The synthetic peer never sends FIN. This proves a valid-input
interoperability failure, rather than only failure to reject malformed input.

**CF exclusion.** CF has already changed that `if` to a `while` at
`masque-vpn-cf-masque/vendor/h3/src/connection.rs:875`, explicitly to skip empty
DATA until actual bytes or transport FIN. Do **not** attribute C7 to CF. No
separate malicious/empty-DATA CF runtime test was performed. The ordinary CF
8-case matrices are a different category of evidence.


## 5. Actual CF WARP egress: additional source findings and private-profile limits

The actual gateway egress must be distinguished from the reusable generic
frontend client. The [production options](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/config.rs#L197-L210)
select device-key authentication, pinned endpoint SPKI, `cf-connect-ip` and
`rfc: false`. The following conclusions are **source-confirmed**, with no live
Cloudflare enrollment, malicious-peer WARP session or WARP packet capture.

### W1. Extended CONNECT is sent without requiring peer permission

The [H3 setting check and request](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L501-L529)
log the peer's Extended CONNECT setting, require its Datagram setting, and
then send `:protocol` regardless of the Extended CONNECT flag.

The selected CF fork's [lower-level request sender](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/client/connection.rs#L161-L190)
also constructs and sends the request without checking peer Extended CONNECT
permission. The caller's omitted gate is therefore not supplied at that layer.

[RFC 8441 §3](https://www.rfc-editor.org/rfc/rfc8441.html#section-3) permits
Extended CONNECT upon receipt of `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` and
explains that using it without first receiving that setting is an incompatible
protocol change. [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3)
says the pseudo-header/setting semantics are identical in HTTP/3.
The absent gate concerns **the server's permission**. A client's own decision
not to advertise Extended CONNECT does not supply or revoke that permission.

The source comments describe a service accommodation. They establish the
client's intended behavior, not that a live Cloudflare endpoint currently
requires or exhibits it. The private token alone is not an applicable
negotiated extension overriding these HTTP/3 rules.

### W2. Private H2 mode accepts absent TLS ALPN

The [ALPN match](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L625-L637)
accepts `None` when `rfc` is false, then starts HTTP/2. Its standard-server
branch requires `h2` and it rejects an explicitly different negotiated value.

[RFC 9113 §3.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-3.3) states:
“HTTP/2 connections over TLS MUST use protocol negotiation in TLS”. The same
section confines prior-knowledge startup to cleartext TCP. The private branch
therefore departs from that TLS requirement. No present-day service behavior
was measured, and a different explicit ALPN value is not falsely reported as
accepted.

### W3. Its manual H3 Datagram decoder silently drops malformed prefixes

The actual egress [receive loop](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L333-L342)
calls a different [manual decoder](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L895-L907).
A truncated Quarter Stream ID returns `None`; an oversized value cannot equal
the valid expected ID and also returns `None`. The caller continues without
requesting `H3_DATAGRAM_ERROR`.

This is the same **category** of RFC 9297 §2.1 failure as C5, established
independently from WARP's own source. It is not evidence that CF's generic
`h3-datagram` decoder has NF's implementation. The connection advertises and
requires standard `SETTINGS_H3_DATAGRAM`; a changed inner IP payload format
does not, by itself, change the outer Quarter Stream ID requirements.

### W4. Capsule response checking omits the final 204–206 prohibition

The [request](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L513-L529)
advertises Capsule Protocol support. The separate
[`check_response`](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L943-L958)
rejects content-related fields but accepts any remaining 2xx, including 204,
205 and 206. Its comment explicitly cites RFC 9484 §4.5 and RFC 9297 §3.2.

RFC 9297 §3.2 explicitly forbids those final statuses for Capsule responses
and requires receivers to treat them as malformed. Thus the stated response
validation contract is incomplete. This conclusion is based on source, not a
new WARP response-injection test. The generic frontend, main client and NF
contain explicit prohibitions; their rejection of these statuses is correct.
This finding is separate from C6's legal informational messages before final
200.

### W5. Private H2 bare-IP Capsules differ from standard CONNECT-IP payloads

The [profile description](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L1-L18),
[H2 mode selection](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L743-L766),
and [Capsule encoder](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L970-L982)
show that private H2 DATAGRAM Capsules carry bare IP without a Context ID.

The precise standards basis is **RFC 9484 §§5–6**, combined with the generic
Capsule mapping in RFC 9297 §3.5. [RFC 9484 §5](https://www.rfc-editor.org/rfc/rfc9484.html#section-5)
says all HTTP Datagrams associated with IP proxying request streams start with
a Context ID; [§6](https://www.rfc-editor.org/rfc/rfc9484.html#section-6)
sets Context ID zero for IP packets. **RFC 9297 §3.5 alone does not require a
Context ID**: it leaves HTTP Datagram Payload semantics to the extension.

Accordingly, this is a documented difference from standard RFC 9484 IP
proxying, and a reason not to count the profile as a generic Caddy CONNECT-IP
client. A private extension can define other payload semantics; omitting this
field is not, by itself, proof of violating generic RFC 9297. No evidence was
provided of a negotiated extension changing the separate QPACK, HTTP/3 error
or ALPN requirements discussed above.

### Standards-compatible choices that are not findings

Device mTLS, endpoint key pinning and out-of-band assigned addresses do not
alone establish nonconformance. [RFC 9484 §11](https://www.rfc-editor.org/rfc/rfc9484.html#section-11)
expressly lists mutual TLS as a possible authentication mechanism.
[§4.7.1](https://www.rfc-editor.org/rfc/rfc9484.html#section-4.7.1) permits an
endpoint to be configured out-of-band with static addresses. A validated
pinned-key trust model is not equivalent to simply disabling all authentication.
The private protocol token itself proves a service-contract difference, not
all of the specific HTTP/3 violations in this report.

## 6. Additional local SOCKS5 limitation: GSSAPI is absent

This concerns the VPN applications' **local SOCKS-server role**, not the
remote CONNECT-IP server's account authentication.

[RFC 1928 §3](https://www.rfc-editor.org/rfc/rfc1928.html#section-3) states:
“Compliant implementations MUST support GSSAPI and SHOULD support
USERNAME/PASSWORD authentication methods.” Method `0x01` is GSSAPI.

The source-supported behavior is:

| Actual local listener | Evidence and consequence |
| --- | --- |
| CLI and IETF GUI | The shared [method selection and rejection](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/socks.rs#L259-L283) choose only no-authentication `0x00`, or username/password `0x02` when configured. An [existing client test](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/socks.rs#L1049-L1058) explicitly expects a GSSAPI-only offer to receive `0xff`. The IETF GUI launches this CLI. |
| Mac | Its [proxy module](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-mac/src/proxy.rs#L9-L12) includes the shared SOCKS source; the [app call](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-mac/src/proxy.rs#L196-L201) passes no local credentials, selecting `0x00`. |
| Killswitch | Its adapted [SOCKS method selection](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-killswitch/src/socks.rs#L296-L307) has the same `0x00`/`0x02` policy; the [app call](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-killswitch/src/proxy.rs#L225-L230) supplies no credentials. |
| NF | Its [method selector and handshake](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/socks.rs#L261-L278) select only `0x00` or internal `0x02`; the [production call](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/lib.rs#L161-L167) uses no credentials. Its [specification explicitly discloses](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/SPEC.md#L60-L65) removal of Kerberos/GSSAPI and disclaims full RFC 1928 conformance. |

A local application offering only GSSAPI therefore cannot negotiate the
supported methods. This is a known bounded-profile limitation, not evidence
of a remote VPN-authentication bypass or a hidden native QUIC failure. The
existing source/unit-test evidence was inspected; no fresh GSSAPI network
negotiation was claimed. The CF packet-client fixture does not activate these
local listeners and is not assigned this finding merely because a copied
SOCKS module exists elsewhere in its tree.

Unsupported BIND and fragmented SOCKS UDP are not automatically additional
mandatory violations: RFC 1928 defines command-refusal responses and expressly
allows implementations without UDP fragmentation support to drop nonzero-FRAG
Datagrams (§7). The explicit GSSAPI MUST requirement is the basis here.

## 7. Reproduction and evidence package

The report's fresh replay uses one external combined project with **13 test
functions**, an isolated Cargo target directory and serialized test execution.
All 13 diagnostic assertions reproduced their observations. That result means
successful **characterization**, not that the client passed 13 conformance tests.
No production client source, manifest or lockfile was changed.

| Diagnostic test function | What it establishes |
| --- | --- |
| `qpack_encoder_fin_is_not_enforced` | C1 encoder FIN is not acted on. |
| `qpack_decoder_fin_is_not_enforced` | C1 decoder FIN is not acted on. |
| `qpack_encoder_capacity_is_not_enforced` | C1 capacity-one instruction is ignored at maximum zero. |
| `qpack_decoder_invalid_ack_is_not_enforced` | C1 impossible dynamic-section acknowledgment is ignored. |
| `duplicate_qpack_stream_control_is_enforced` | Positive driver/ABI control: the duplicate stream requests `0x103`. |
| `duplicate_status_is_accepted` | C2's two-status acceptance observation, with its normative interpretation qualified. |
| `other_malformed_response_fields_are_accepted` | C2 request-only pseudo-field and connection-field counterexamples. |
| `malformed_headers_emit_cancel_instead_of_message_error` | C3a mismatched local error and transport/ABI request. |
| `nf_malformed_capsule_headers_do_not_send_message_error` | C3b full NF core rejects forbidden content fields but does not request `0x10e`. |
| `connect_trailer_headers_are_treated_as_body_eof` | C4 h3/NF-adapter HEADERS-to-EOF behavior after CONNECT. |
| `nf_malformed_http_datagram_prefixes_are_silently_dropped` | C5 full NF core consumes malformed association prefixes. |
| `informational_100_and_103_before_final200_are_rejected_by_actual_nf_client` | C6 final-200 success control and both interim-response failures. |
| `empty_data_before_valid_address_capsules_ends_actual_nf_client_tunnel` | C7 success control and premature EOF caused solely by empty DATA, without FIN. |

The synthetic host presents READY metadata, valid peer SETTINGS and response
bytes, acknowledges local writes, delivers receive bytes separately from FIN,
and records statuses/CLOSE commands. It does not provide native TLS, QUIC
packet construction, OS routes, PF, utun or GUI runtime. C1's no-error-event
observations are bounded waits supported by the missing source reader; they
are not a claim of observing an infinite execution.

The evidence package is
`/workspace/caddy-masque-client-ietf-evidence-2026-10-18.tar.gz`. It contains this
report, the exact external diagnostic source/lockfile, pinned source identities,
the new `confirmed-thirteen.log`, command/result metadata and cited RFC text.
The report's GitHub permalinks provide reviewable source independently of the
local workspace. The prior ordinary-Caddy acceptance is documented in
[the server follow-up](all-client-compatibility-2026-10-18.md); its positive
matrices do not negate these different-input counterexamples.

To reproduce, extract the evidence package, obtain the client at the exact
commit above, and adjust only the external diagnostic manifest's absolute path
to that checkout if necessary. Verify the recorded client source identities.
Run with Rust 1.99.0 and the lockfile:

```sh
cargo test --locked --offline \
  --target-dir /tmp/client-ietf-proof-target \
  --manifest-path /path/to/evidence/proofs/Cargo.toml \
  -- --nocapture --test-threads=1
```

`--offline` requires the locked registry dependencies to be cached first;
otherwise fetch those locked dependencies normally before the offline run.
Keep the target outside the protected client checkout and use one diagnostic
project per isolated target directory. Do not count superseded or intentionally
failing characterization runs as a successful native conformance suite.

## 8. Repair ownership and acceptance criteria

No client change is applied by this report. Client-side remediation belongs
in that repository under its owner's control. The following criteria make
future fixes reviewable without weakening Caddy's mandatory IETF behavior:

| Finding | Required repair and useful acceptance checks |
| --- | --- |
| C1 | Poll each opened QPACK critical receive stream for lifetime and instructions; preserve valid type-only/open streams and capacity-zero operation. Require connection-error signaling for FIN, excess capacity and invalid acknowledgment, with duplicate-stream and permitted-instruction controls. Our tests may enforce chosen specific codes; general conformance assessment must also allow deliberate `H3_GENERAL_PROTOCOL_ERROR`. Static-only compression remains permitted. |
| C2 | Validate pseudo-fields in response context and reject connection-specific fields. Preserve duplicate multiplicity until explicit singleton policy is enforced; test same/different repeated statuses and retain the stated normative interpretation. Exercise the complete client after valid assignment/routes, plus permitted ordinary headers. |
| C3 | Propagate the detected malformed-message classification to transport termination. Test both the returned application error and the requested stream/connection error; capture native wire behavior separately. Escalating to a connection error and deliberately selecting the general protocol error are permitted. Normal cleanup or request cancellation alone does not provide that protocol-error signal. |
| C4 | Activate CONNECT framing rules after the final success response in each actual caller. Require a connection error for prohibited HEADERS, using specific `0x105` or an intentional general protocol error, while continuing to allow ordinary non-CONNECT trailers and applicable negotiated extension frames. |
| C5 | Parse and range-check the Quarter Stream ID before routing by request ID. Require a connection error for malformed prefixes (`0x33` is the specific code; intentional general protocol errors remain allowed); retain permitted drops/buffering for valid not-yet-created streams and mandatory dropping for closed receive sides. Cover NF and WARP's separate manual decoders independently. |
| C6 | Consume permitted informational responses until a final response arrives, keeping existing setup bounds. Test `200`, `100→200`, `103→200`, multiple permitted interim messages, final refusal, and rejection of unsupported HTTP/3 status 101 (RFC 9114 §4.5). No success may be inferred from 1xx alone. |
| C7 | Keep reading past empty DATA until bytes, a permitted ordinary trailer section or actual stream closure arrives. Test empty frames before and between Capsule bytes, multiple empty frames, FIN, resets and cancellation. Do not use a positive DATA length as a requirement. |
| WARP profile and SOCKS limits | Distinguish standard mode from documented private service behavior; validate each actual caller rather than only a reusable frontend component. Retain an explicit limited-SOCKS conformance statement unless GSSAPI is implemented. |

C6/C7 deserve priority for interoperability because the peer input is valid.
C1–C5 remain mandatory receiver obligations even when a trusted normal server
never triggers them. No blanket security severity or CVSS score is assigned
without an exploit/impact assessment beyond these protocol counterexamples.

## 9. Conclusions and explicit limits

The evidence supports seven HTTP/3 finding groups, the case-specific client
matrix, additional source-confirmed WARP paths/profile observations, and a
disclosed SOCKS5 limitation. It does not establish that every ordinary tunnel
fails, that an Apple API caused these Rust-level behaviors, or that the client's
recorded native H3 incident has this particular cause.

The following distinctions are part of the conclusion:

- Verified [RFC 9484 erratum 8444](https://www.rfc-editor.org/errata/eid8444) corrects the original wildcard examples to `%2A`. The audited shared/root client's URI-template implementation already follows it. The separate CF-local copy at the audited revision still emitted raw `*`; the late-revision addendum below records that historical defect and its upstream repair. The server's stale internal expansion helper is corrected by the reassessment, while its tolerant matcher continues to accept existing request forms.
- Legal stream 4 behind an unwritten lower stream, and selecting H3 Capsules
  because native usable Datagram capacity is small, are compatibility cases
  rather than client RFC violations by themselves.
- Capsule response rejection for forbidden content fields or final 204–206
  statuses is correct. C3 concerns the subsequent error signal; C6 concerns
  earlier legal informational messages.
- Duplicate-status acceptance is directly observed, with an interpretive
  singleton-status argument. The report does not fabricate an explicit
  duplicate-response MUST sentence from RFC 9114.
- P/F observations are portable protocol/ABI evidence. Other application paths
  marked S are source-confirmed. Actual native wire codes, live WARP behavior,
  macOS GUI/network lifecycle and different installed binary versions require
  their own measurements.
- IETF conformance takes precedence over a server workaround. The protected
  client repository remains unchanged; no permissive Caddy behavior is used
  to disguise these client limitations.

## Late-revision addendum: CF wildcard encoding, fixed upstream

A final remote check found client `main` at
`906352c346f6ec2b0b6b5bd5713fca1e0f187b6e`, four commits after the diagnostic
revision `e10a6ec9fcf0e005d36572830539802df36f6638`. The immutable
[comparison](https://github.com/ArcCal/masque-vpn/compare/e10a6ec9fcf0e005d36572830539802df36f6638...906352c346f6ec2b0b6b5bd5713fca1e0f187b6e)
changes only the CF gateway subtree. This addendum corrects the earlier broad
wildcard statement without changing the seven HTTP/3 finding groups.

**Historical C8: the CF-local URI helper emitted unencoded wildcard variables.**
At e10, the separate
[CF helper](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-proto/src/uri_template.rs#L381-L391)
returned literal `*` before ordinary percent encoding. Its
[default-template test](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-proto/src/uri_template.rs#L465-L470)
expected `/.well-known/masque/ip/*/*/`. This affects requests expanded by the
CF-local reusable generic client and the corresponding local template helper;
it is not a defect of the canonical/root helper, Mac, Killswitch or NF, nor
proof that the distinct WARP caller uses this expansion path. Caddy's tolerant
matcher accepted the old form, so this is a source-confirmed encoding violation
rather than a demonstrated ordinary Caddy connection failure.

The normative basis is explicit. Verified
[erratum 8444](https://www.rfc-editor.org/errata/eid8444) adds to RFC 9484 §4.6:
“If the "target" or "ipproto" variable is set to the wildcard value "*", it
MUST be percent-encoded. It will therefore be transmitted as "%2A".”
[RFC 6570 §3.2.1](https://www.rfc-editor.org/rfc/rfc6570.html#section-3.2.1)
already restricts passthrough in ordinary expansion to unreserved characters;
`*` is outside the
[RFC 3986 §2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3)
unreserved set. RFC 9484 §3 forbids reserved and fragment expansion, so those
operators cannot justify the special case. Erratum 8444 also corrects the
misleading original examples; raw examples alone are insufficient evidence
that the implementation conforms.

This issue was repaired **in the client project upstream**, by
[commit 1e32d636](https://github.com/ArcCal/masque-vpn/commit/1e32d636fa37314563bd5161a62abf99a6d78bdb),
before this addendum. The
[906 helper](https://github.com/ArcCal/masque-vpn/blob/906352c346f6ec2b0b6b5bd5713fca1e0f187b6e/masque-vpn-cf-masque/vendor/masque-proto/src/uri_template.rs#L381-L390)
removes the special case, and its
[regression](https://github.com/ArcCal/masque-vpn/blob/906352c346f6ec2b0b6b5bd5713fca1e0f187b6e/masque-vpn-cf-masque/vendor/masque-proto/src/uri_template.rs#L556-L576)
covers `%2A` in paths and queries, decoding once and preserving literal escape
data as `%252A`. No client repair was made by this caddy-masque review.

The latest delta also adds cooperative receive-loop yielding in the CF frontend,
bounded executable logging and scoped-name DNS failover. Root H3, all NF code,
canonical/Mac/Killswitch callers, CF H3/Datagram forks, CF tunnel code and the
WARP caller are byte-identical to the diagnostic revision. The one CF frontend
client production-line change wraps the existing Datagram read future; its
response/error/CONNECT handling is unchanged. Consequently C1–C7 retain their
existing source attribution and qualifications, including CF's C2 exceptions
and C7 exclusion. The thirteen replayed diagnostic assertions remain actual e10
executions of the unchanged relevant source; they are not relabeled as a fresh
latest-HEAD malicious-peer or native Apple run. Supplemental 906 CF-to-Caddy
acceptance subsequently passed all eight carrier/family cases with each of Go
1.26.9 and 1.27.2 under race checking. Fourteen URI-template tests and seven
buffered HTTP/3 scheduling regressions also passed. The complete 492 regular
files plus one symlink remained unchanged. Commands, the initial offline cache
miss and successful locked retry, hashes and coverage limits are recorded
separately in the comprehensive review; these ordinary acceptance results do
not constitute a fresh C1–C7 adversarial-peer test.

## Appendix: pinned source index for C4–C7 and the distinct Datagram decoders

The detailed findings above use client-tree-relative paths. These links anchor
the relevant implementation fragments to the audited revision:

- [Root HEADERS-to-EOF and single-frame receive logic](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/connection.rs#L860-L929).
- [Frame-local `poll_data` empty-length result](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/vendor/h3/src/frame.rs#L95-L120).
- [Shared tunnel receive pump](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/tunnel.rs#L143-L164) and [NF receive pump](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/tunnel.rs#L126-L144).
- [NF response acquisition, status check and manual Datagram demultiplexer](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-nf/Core/src/client.rs#L250-L279).
- [Main client response acquisition/status check](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/src/client.rs#L472-L498).
- [CF generic response acquisition/status check and Datagram setup](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs#L448-L486).
- [CF default trailer guard and corrected empty-DATA receive loop](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3/src/connection.rs#L838-L896).
- [Shared client upstream Datagram decoder](https://github.com/hyperium/h3/blob/43745ad87e95b0c035ac9c547aad467303213425/h3-datagram/src/datagram.rs#L30-L57) and [error propagation](https://github.com/hyperium/h3/blob/43745ad87e95b0c035ac9c547aad467303213425/h3-datagram/src/datagram_handler.rs#L80-L94), selected by the [pinned dependency](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/crates/masque-vpn/Cargo.toml#L30-L34). Unlike h3 itself, this dependency is not a root `vendor/h3-datagram` directory.
- [CF Datagram framing decoder](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3-datagram/src/datagram.rs#L30-L57) and [error propagation](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/vendor/h3-datagram/src/datagram_handler.rs#L80-L94).
- [Actual WARP response and Capsule pump](https://github.com/ArcCal/masque-vpn/blob/e10a6ec9fcf0e005d36572830539802df36f6638/masque-vpn-cf-masque/crates/warp-packet/src/masque.rs#L522-L575).
