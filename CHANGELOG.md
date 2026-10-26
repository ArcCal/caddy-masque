# Changelog

Each version is tagged with its number; CI attaches Caddy builds to its release on GitHub after required validation passes.

## Unreleased

- Every published release gets its Caddy builds, whatever its tag: the tag no longer has to appear in this changelog. `RELEASE-MANIFEST.txt` records the tag, source commit and checksums. Uploads still wait for every required test.
- Extend the RFC-based review with bounded HTTP/2 SETTINGS acknowledgments, request-length/flow-control errors and priority validation; prevent malformed HTTP/3 fields/status syntax and unsupported HTTP/2–HTTP/3 switching responses. Preserve valid website and CONNECT behavior.
- Validate signed QPACK field-section Base values while accepting legal positive static-only Base encodings, including the required 62-bit range. Apply the same check to requests, responses and trailers without enabling dynamic compression or changing dependencies.
- Enforce new-address QUIC amplification budgets, complete undersized-probe MTU validation, answer current-path and multiple challenges, and validate the previous path during migration. Preserve response routes, congestion credit and CID lifetime across deferred sends; select the highest non-probing path and promote its reserved CID.
- Keep queued QUIC packets bound to their original destination/local metadata across migration, and credit buffered/coalesced packet receipts only once during decryption retries. Extend required QUIC package and actual-UDP migration gates for versions 1 and 2.
- Preserve QUIC zero idle-timeout semantics and safely bound large timeout values. Suppress ICMPv6 errors in response to Redirect as RFC 4443 requires. Detailed evidence and validation limits are in the [comprehensive follow-up report](docs/comprehensive-recheck-2026-10-18.md).
- Recheck earlier conformance judgments against original RFCs, verified errata and pinned independent implementations. Clarify permitted generic HTTP/QUIC errors and distinguish implementation policy from mandatory behavior.
- Validate HTTP/2 method tokens and HTTP/2–HTTP/3 URI schemes, retaining valid custom schemes and extension methods. Reject HEADERS after successful HTTP/2 CONNECT and increasing client HTTP/3 GOAWAY identifiers.
- Correct QUIC forbidden-packet error attribution and allow transport CONNECTION_CLOSE in 0-RTT. Correct internal wildcard expansion to `%2A` per verified RFC 9484 erratum 8444 while preserving tolerant request matching.
- Wait for delayed HTTP/3 SETTINGS rather than permanently disabling negotiated QUIC Datagrams after three seconds. Pending admissions remain cancellable and release their lease on user revocation or shutdown; failures before a response use a non-2xx status.
- Preserve ignored CONNECT response Content-Length fields for Capsule Protocol validation without using them to delimit tunnel DATA.
- Reject malformed HTTP/3 field-edge whitespace and response/trailer TE fields, accept valid request TE lists, and normalize outgoing header whitespace without changing the caller's header map.
- Keep Caddy `close: true` website and refusal responses valid over HTTP/3 by omitting connection-specific fields and Connection-nominated fields, including trailers.
- Expand unchanged-client acceptance to Masque NF, IETF Masque's stdin/EOF process contract and the experimental gateway's separate generic client fixture. Record client-side HTTP/3 conformance limitations separately; retain mandatory Cloudflare in every build.
- **Cloudflare DNS is bundled in every build**, pinned at v0.2.4: normal `go build`, custom mains importing MASQUE, the installer and CI artifacts. Rebuilding no longer removes the provider. Module-registration checks require `dns.providers.cloudflare`.
- **IETF behavior takes priority over response camouflage.** Refused HTTP/2 and HTTP/3 CONNECT-IP requests retain website bodies but use a non-2xx status; malformed anonymous upgrades receive protocol errors. HTTP/1.1 Upgrade refusals and ordinary web traffic retain their normal behavior.
- Repair inherited HTTP/3 SETTINGS, QPACK critical-stream/error scope, required headers, content lengths, frame truncation and CONNECT/trailer validation, with independent wire regressions and valid website/tunnel controls.
- Enforce QUIC pre-validation byte budgets, peer UDP receive limits, conservative DATAGRAM payload capacity, unnegotiated-DATAGRAM error codes and congestion-window credit. Exact amplification tests check actual UDP output.
- Complete HTTP/2 extended-CONNECT and field/trailer validation, prescribed stream resets and safe outbound whitespace normalization, preserving unrelated streams.
- Correct explicit ADDRESS_REQUEST rejection and omitted optional query scoping; validate IPv4 checksums before local ICMP generation; preserve unconditional link-local isolation and bound large-pool reuse history without dropping conntrack safety.
- New HTTP/3 connections use reloaded Caddy header/idle limits. User/route changes are staged until Caddy commits a reload, so a failed candidate cannot revoke existing sessions.
- Refresh the current-client wrapper lock and select the actual clients' vendored H3 patches without modifying masque-vpn. Standard and manual Cloudflare releases promote the exact checksum-verified executable that passed kernel/wire validation.

- Update bundled Caddy to 2.11.7, including its HTTP/2 request-body deadline and idle streaming fixes. The pinned MASQUE HTTP/2 and HTTP/3 patches remain in use.
- **Go 1.27 preserves CONNECT-IP over HTTP/2.** The pinned x/net fork continues to use its patched HTTP/2 server and transport instead of switching to Go 1.27's standard-library wrappers. Ordinary builds and xcaddy builds with the documented dependency replacements need no extra build tag. A compile-time check requires the selected response writer to provide the stream-reset API. CI runs protocol and client interoperability gates with Go 1.26 and 1.27.
- **Tunnels ended for reasons other than a malformed message are cancelled.** An unanswered IPv6 MTU probe (RFC 9484 §7.2), a path that cannot carry 1280-byte IPv6 packets (§7.1) and an internal route-advertisement error ended the request stream with `H3_MESSAGE_ERROR` (or HTTP/2 `PROTOCOL_ERROR`), which tells the client its message was malformed (RFC 9114 §8.1). They now use `H3_REQUEST_CANCELLED` (RFC 9114 §4.1.1) or HTTP/2 `CANCEL`; malformed capsules and requests keep `H3_MESSAGE_ERROR` / `PROTOCOL_ERROR`, and other session ends still close the stream normally. masque-vpn's server does the same.
- **HTTP/3 push frames are rejected as RFC 9114 requires.** The pinned quic-go skipped CANCEL_PUSH, PUSH_PROMISE and MAX_PUSH_ID. Push is not supported, so a client's CANCEL_PUSH names a push ID never promised (§7.2.3) and a MAX_PUSH_ID smaller than an earlier one (§7.2.7) now close the connection with `H3_ID_ERROR`; PUSH_PROMISE (§7.2.5) and push frames on a request stream close it with `H3_FRAME_UNEXPECTED`, however malformed their payload, as do SETTINGS, GOAWAY and PRIORITY_UPDATE on a request stream. CANCEL_PUSH, GOAWAY and MAX_PUSH_ID payloads are read only within their declared length: an empty, shorter or longer payload closes the connection with `H3_FRAME_ERROR` (§7.1) instead of consuming the next frame's bytes or waiting for them. The fork's HTTP/3 client applies the same rules to frames from a server.
- The validation job also runs masque-vpn's wire-level conformance probe (`tests/conformance.sh` with `SERVER_KIND=caddy`), which builds CONNECT-IP requests, capsules and datagrams itself over HTTP/3, HTTP/2 and HTTP/1.1 and checks the answers against RFC 9484 and RFC 9297, and `TestInteropMasqueClient`, which runs masque-client against Caddy in process over IPv4 and IPv6, on every transport and HTTP/3 datagram mode.
- Release builds run on native runners for each architecture and must start, list the MASQUE app and handler, and carry a tag the changelog documents.

## 1.2.0

Tag: **`v1.2.0`**

- **HTTP/3 Datagrams require defined request semantics.** On the module's HTTP/3 server, Datagrams on ordinary requests and unsupported extended-CONNECT tokens abort the request with H3_DATAGRAM_ERROR (0x33), as RFC 9297 requires, including on sites without the `masque` directive. Malformed HTTP Datagram framing closes the connection with that error. Recognized CONNECT-IP requests retain permitted optimistic Datagrams, including authentication refusals.
- **Ordinary HTTP/3 website behavior is preserved.** The pinned quic-go patch rejects unsupported Datagrams without taking over the request stream or changing request bodies, response status codes or trailers. Custom builds must include both the quic-go and x/net replacements in [third_party/README.md](third_party/README.md).
- **HTTP/1.0 ignores Upgrade.** Even requests with valid CONNECT-IP credentials follow the ordinary site's routes, as RFC 9110 §7.8 requires. HTTP/1.1 Upgrade tunnels remain supported.
- **Open tunnels no longer prevent graceful process exit after a reload.** Shutdown ends retained HTTP/2 tunnels, including when the replacement configuration removes the MASQUE handler or all current HTTP servers, and HTTP/3 capsule tunnels with `http3 off`, before Caddy waits for HTTP shutdown. Successful reloads that retain the user and its permitted routes continue to preserve active tunnels.
- Shutdown rejects new and delayed session acquisitions, and waits for an in-progress host-network repair before closing the TUN device and removing forwarding/NAT state.
- Changing the TUN interface now enforces the documented restart requirement instead of opening a second network with the same nftables table. A rejected interface-change reload preserves the original tunnel; the new interface can be used after a genuine stop and restart.
- Removed verified unused internal fields and helpers; compatibility paths and supported transports are retained.
- **Missing interoperability validation now blocks artifacts and release uploads.** Unlike the 1.1 behavior recorded below, missing `MASQUE_VPN_TOKEN` access fails the required job. Unit/race, protocol and strict optimized-client end-to-end tests must pass on native Linux x86_64 and arm64. End-to-end validation requires a positive passing count with zero failures and zero skips; fork pull requests need validation from a trusted repository branch.
- The manual Cloudflare variant reuses the required gates, scans its actual custom build for reachable vulnerabilities, and runs strict interoperability tests against that binary on the selected native architecture before uploading an artifact.

HTTP/3, HTTP/2 and HTTP/1.1 CONNECT-IP, existing client configurations and interchangeable password hashes remain supported. Linux x86_64 and arm64 remain the release platforms; native validation and deployment-specific certificate, DNS, firewall, forwarding and MTU checks are still required.

## 1.1

Tag: **`1.1`**

- Reachable dependency vulnerability scanning is now part of the required release test job.

- Release artifacts support Linux x86_64 and arm64 only. Optimized-client end-to-end tests run on both native architectures before release uploads whenever the `MASQUE_VPN_TOKEN` secret can read masque-vpn; without it they are skipped with a visible warning instead of silently, and the builds are still attached.
- **Every published release gets its builds.** The 1.0 release run had failed at the build-provenance attestation, which GitHub offers to public repositories only, so no archives were attached; the attestation is now made only for a public repository. A run of the `ci` workflow started by hand with the tag of an existing release builds that tag and attaches the archives, for a release whose own run failed.
- Before uploading, CI checks that each `caddy` is a static ELF executable for the architecture in its archive's name, built for Linux from the tagged commit (`caddy build-info` shows it), and that both archives match their SHA-256 files.

- The default capsule decoding limit includes the full IPv6 header and an eight-byte context ID.
- Capsule parsing gains segmentation fuzzing. End-to-end CI uses the optimized Rust client and explicitly supplies the network simulator, whose bandwidth limiter works without kernel traffic-shaping modules and is checked before testing transfers.

- **Malformed HTTP/2 requests and capsules reset their stream with `PROTOCOL_ERROR`.** A pinned `golang.org/x/net` patch exposes the reset API through Caddy's existing HTTP/2 server. Other streams remain usable; HTTP/3, HTTP/2 and HTTP/1.1 remain supported. Custom builds must include the replacement documented in [third_party/README.md](third_party/README.md).
- **IPv6 all-nodes MTU probes receive a local unicast reply.** A peer can verify the 1280-byte tunnel MTU without knowing the server's address; multicast packets are never forwarded into the host network.
- **The service no longer logs its entire environment at startup.** This keeps environment-based DNS API credentials out of the journal.

## 1.0

The first stable version. The code is that of 0.99, which has every fix of the pre-production audit
([docs/review-2026-10-03.md](docs/review-2026-10-03.md)):

- **C1**: checking the route ranges a client advertises takes O(n log n), not O(n²), so an authenticated client can no
  longer tie up the server's CPU with large ROUTE_ADVERTISEMENT capsules.
- **C2**: one source (an IPv4 address or an IPv6 /64) may have at most 4 password verifications waiting or running, and
  credentials verified in the last 12 hours are remembered, so a flood of made-up credentials does not keep out users
  who connected before.
- **C3**: the systemd service puts Caddy's admin API on a socket only root can use, `/run/caddy-masque/admin.sock`,
  instead of `localhost:2019`, which every local user could use.
- **C4**: the installer and the examples add `:443` to the site addresses, so clients that name the server by IP address
  (such as the Mac app's optional IP field) connect.
- **C5**: tunnels over HTTP/1.1 and HTTP/2 get TCP keepalive and a 30-second `TCP_USER_TIMEOUT`, so a client that is
  gone is noticed in about 30 seconds rather than 2.5 minutes.
- **C6**: IPv6 pools smaller than a /64 clear the old connection tracking entries before reusing an address.

It works with masque-vpn 1.0.0's `masque-client` and with MasqueVPN 1.0 on the Mac, and its password hashes are
interchangeable with masque-vpn's `masque-passwd`.
