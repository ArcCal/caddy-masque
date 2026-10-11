# Design and Caddy update maintenance

## Goals

Serve CONNECT-IP according to RFC 9484, with HTTP Datagrams and Capsules
(RFC 9297) and extended CONNECT over HTTP/2 and HTTP/3 (RFC 8441, RFC 9220).
Keep HTTP/1.1 Upgrade support and all four client modes: HTTP/3 Datagrams,
HTTP/2, HTTP/1.1 and HTTP/3 DATAGRAM Capsules.

The required clients are masque-client, masque-vpn-mac and
masque-vpn-killswitch. Existing configuration, authentication, certificate
verification, packet framing, address assignment and reconnect behavior must
remain compatible. NF and Swift are outside this acceptance scope.

The VPN and ordinary Caddy websites share TCP/UDP port 443. Unauthenticated
requests follow the configured website behavior. Website routing, bodies,
trailers, TLS and reverse proxies must continue to work.

## Integration

The MASQUE app owns the Linux TUN device, address pool and sessions. The handler
recognizes authenticated CONNECT-IP requests and passes other traffic to Caddy.
HTTP/1.1 and HTTP/2 use Caddy's TCP listeners. The app serves HTTP/3 with
Datagrams using Caddy's certificates and routes; disabling that takeover uses
Caddy's HTTP/3 with Capsule transport instead.

The pinned x/net fork supplies exact HTTP/2 stream resets. The pinned quic-go
fork rejects HTTP Datagrams on ordinary requests without hijacking website
streams. Main-module replacements are mandatory, including in xcaddy builds;
see [the patch contracts and verification](../third_party/README.md).
Go 1.26 and Go 1.27 select the patched HTTP/2 implementation without an extra
build tag. Tunnel deadlines and lifecycle must remain independent of website
idle timeouts, while normal requests retain Caddy's protections.

## Caddy update maintenance

Check [official Caddy releases](https://github.com/caddyserver/caddy/releases)
from time to time and before changing Caddy, Go, either transport fork or the
build pipeline. Identify the latest stable release and compare it with the
pinned version; discovering a release does not establish its compatibility.
Every proposed upgrade requires these checks:

1. Review release notes and relevant source changes, especially HTTP server
   setup, response-writer `Unwrap`, request-body wrappers, deadlines, TLS,
   HTTP/3 takeover and reload/shutdown. Record the candidate and baseline
   versions. Rebase required transport patches when their dependencies change;
   do not drop them or bypass checksum verification.
2. Build the exact final server artifact on both supported Go lines, currently
   1.26 and 1.27, using their current patch releases and the documented
   replacements. Verify its Caddy version and module registrations, including
   custom-main or xcaddy variants being shipped. A supported-toolchain change
   must be reviewed explicitly.
3. Run strict fork verification, module verification, vet and the main and
   patched HTTP/2, HPACK and HTTP/3 race suites. Retain frame-level RFC checks:
   malformed messages use the prescribed PROTOCOL_ERROR/H3_MESSAGE_ERROR,
   cancellation uses CANCEL/H3_REQUEST_CANCELLED, and Datagram faults use
   H3_DATAGRAM_ERROR with the required stream/connection distinction. Check
   other-stream isolation, Capsule negotiation and IPv6 MTU behavior.
4. Run real masque-client interoperability and the current Mac/Killswitch
   protocol-core matrix over all four modes. Run strict Linux kernel and wire
   conformance checks against the final artifact. Cover TLS trust and refusal,
   authentication, idle survival, reload/revocation, failure recovery and
   reconnect, plus ordinary website bodies, trailers and routing. Release
   checks use optimized client builds and native supported server architectures.
5. Record exact versions, source revisions, artifact hashes, build/test commands
   and passed/failed/skipped counts. Require actual passing cases; zero-case
   runs and skipped required cases do not establish compatibility. Keep old
   baseline results separate from results for the candidate artifact. Do not
   weaken protocol assertions or certificate verification to make an upgrade
   pass; fix the incompatibility or retain the verified dependency version.

Protocol-core tests do not prove native Mac behavior. Record macOS utun,
routes/DNS restoration, PF protection, GUI lifecycle and sleep/wake checks
separately, and identify native Mac or arm64 execution that remains unrun.
Neither cross-compilation nor Linux kernel tests substitute for those checks.
Test evidence is not a claim of formal IETF or Apple certification. See the
[current compatibility report](compatibility-2026-10-11.md) and
[wrapper harness scope](../tests/clients/README.md).
