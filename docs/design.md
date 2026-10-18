# Design and Caddy update maintenance

## Goals

Serve CONNECT-IP according to RFC 9484, with HTTP Datagrams and Capsules
(RFC 9297) and extended CONNECT over HTTP/2 and HTTP/3 (RFC 8441, RFC 9220).
Mandatory IETF requirements take precedence when they conflict with camouflage or other design goals.
A refused extended CONNECT must never become a successful website 2xx response. Ordinary website bodies and
error pages may be reused within those protocol rules; exact endpoint indistinguishability is not a goal.

Keep HTTP/1.1 Upgrade support and all four client modes: HTTP/3 Datagrams,
HTTP/2, HTTP/1.1 and HTTP/3 DATAGRAM Capsules.

All current clients in ArcCal/masque-vpn are in scope: masque-client (including
its Linux system/LAN-gateway/SOCKS modes and macOS CLI), the IETF Masque GUI
that launches that executable, masque-vpn-mac, masque-vpn-killswitch and
Masque NF. NF has an independent protocol core with Network.framework I/O;
the retired standalone Swift transport is no longer a current client.
Existing configuration, authentication, certificate verification, packet
framing, address assignment and reconnect behavior must remain compatible.
Client-side RFC violations must be identified explicitly rather than hidden
by a server workaround that violates mandatory IETF behavior. The client
repository must remain unchanged.

The experimental CF-MASQUE project is a Linux gateway server. Its embedded
generic CONNECT-IP client fixture is also checked independently. Its outbound
Cloudflare-device-authenticated WARP dialect is a separate service contract,
not the authentication or wire protocol offered by this Caddy module.

The VPN and ordinary Caddy websites share TCP/UDP port 443. Unauthenticated requests use the configured website response where protocol rules allow it;
refused HTTP/2 and HTTP/3 CONNECT-IP responses use non-2xx status codes. Website routing, bodies,
trailers, TLS and reverse proxies must continue to work.

Every build must include the pinned `github.com/caddy-dns/cloudflare` module, currently v0.2.4.
The MASQUE package registers the provider so normal builds, custom mains, the installer and all CI artifacts
include it. Build validation must require `dns.providers.cloudflare`, `masque` and `http.handlers.masque`.
Cloudflare DNS credentials remain an optional deployment setting, not a build prerequisite.

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
idle timeouts, while normal requests retain Caddy's protections. HTTP/3 header limits and HTTP idle lifetime are snapshotted
from the current Caddy configuration for each new connection, without mutating settings of existing tunnels.
Changes to shared authentication and routing policy are staged while a candidate configuration starts.
They apply after Caddy publishes the new active context, before the old MASQUE app is cleaned up;
failed startup must leave the previous configuration's live sessions intact.

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
   custom-main or xcaddy variants being shipped. Require the bundled Cloudflare provider in each artifact. A supported-toolchain change
   must be reviewed explicitly.
3. Run strict fork verification, module verification, vet and the main and
   patched HTTP/2, HPACK and HTTP/3 race suites. Retain frame-level RFC checks:
   malformed messages use the prescribed PROTOCOL_ERROR/H3_MESSAGE_ERROR,
   cancellation uses CANCEL/H3_REQUEST_CANCELLED, and Datagram faults use
   H3_DATAGRAM_ERROR with the required stream/connection distinction. Check
   other-stream isolation, Capsule negotiation and IPv6 MTU behavior.
   Run the named security regressions and both reachability-based vulnerability
   scanning and the recorded transport-version advisory query. Local
   replacements can hide their upstream version from the source scan. Updating
   Go's standard library does not patch the separately vendored HTTP/2 server
   and transport; verify the actual source against a security-fixed snapshot.
4. Run real masque-client interoperability, the current Mac/Killswitch and NF
   protocol-core matrices, and the independent embedded frontend client over
   all four modes. Check auto selection, small native Datagram capacities and
   legal later request streams behind an idle lower-numbered stream. Run strict Linux kernel and wire
   conformance checks against the final artifact. Cover TLS trust and refusal,
   authentication, idle survival, reload/revocation, failure recovery and
   reconnect, plus ordinary website bodies, trailers and routing. Release
   checks use optimized client builds and native supported server architectures. Package the exact checksum-bound executable that passed these checks;
   do not rebuild a different executable between validation and upload.
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
[HTTP/2 security repair](http2-security-2026-10-11.md), plus the
[wrapper harness scope](../tests/clients/README.md). The
[October 18 conformance repair report](conformance-repair-2026-10-18.md)
records the subsequent standards audit, fixes and validation boundaries.
