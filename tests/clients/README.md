# Current Mac, Killswitch and NF interoperability

Run the current app APIs against Caddy's real TLS, authentication, CONNECT-IP and
HTTP transports from the Caddy repository:

```sh
python3 tests/run-client-wrapper-interop.py --masque-vpn-root ../masque-vpn
```

The runner creates a temporary Rust workspace from these assets, uses the tested
lockfile, and builds with `cargo build --locked`. It honors `CARGO_TARGET_DIR` for
a shared cache. Its top-level Cargo patches select the current client's vendored
`h3` and `h3-quinn`; locked Cargo metadata must confirm both paths before building.
The lockfile was refreshed against client commit
`e10a6ec9fcf0e005d36572830539802df36f6638`. When client dependencies change, review
and refresh this harness lockfile without modifying the client repository.
`--release` selects an optimized Rust build; the default uses the
debug profile. Go runs the test through an overlay so normal `go test ./...` does
not depend on a Rust checkout or run this longer matrix. Go build tags are not
added. The runner requires all 16 Mac/Killswitch and all 8 NF distinct cases and rejects skipped cases.
`--compile-only` checks build and overlay wiring, and runs no interoperability
cases.

The 16 cases cover both wrappers, IPv4-only and dual-stack Caddy configurations,
and HTTP/3 Datagrams, HTTP/2, HTTP/1.1 and HTTP/3 DATAGRAM Capsules. H3 SETTINGS are
checked independently to confirm the selected datagram/capsule path. Caddy's
default session quota and MTU probing remain enabled.

Every case verifies:

- The current app settings produce the IPv4-only client configuration.
- A DNS candidate probe travels through the real Caddy tunnel and returns.
- Wrong credentials receive a refusal and never configure the client's host,
  while the authenticated session remains usable. The website's cover response
  uses 404 for HTTP/2 and HTTP/3 CONNECT refusals; HTTP/1.1 Upgrade refusals retain
  its ordinary 200 response.
- VPN and the app's counted SOCKS implementation work concurrently, receive
  distinct IPv4 tunnel addresses, and preserve packet framing and byte accounting.
- 512 complete 1350-byte IPv4 packets echo in both directions without corruption.
- The original session survives beyond the 10-second IPv6 MTU-probe deadline,
  including when IPv6 is assigned by Caddy but unused by the IPv4-only app.
- Cancelling SOCKS releases its control and listening sockets while VPN keeps
  forwarding; final shutdown releases all Caddy sessions.

The primary VPN uses the real shared `masque_vpn::Client` with the app's current
public settings and packet framing. Each app's private VPN counting adapter is
not an external public API; this harness does not claim to exercise that adapter.
The SOCKS adapter and its counters are the actual app implementations.

The server TUN and the client's native host setup use packet channels. These tests
do not validate native macOS utun, system routes, PF, DNS store, GUI lifecycle,
sleep/wake or physical-network forwarding. Dual-stack describes the server
configuration; these apps continue to configure IPv4 only.

## NF's independent protocol core

The eight NF cases use the actual `masque-nf/Core` HTTP/CONNECT-IP/SOCKS code,
with IPv4-only and dual-stack Caddy configurations over the same four transports.
They reuse a temporary copy of the client's unchanged test bridge, appending
only an external-Caddy fixture constructor and an accessor for its DNS fixture.
The host bridge uses verified Rust TLS/QUIC; it does not execute Apple's
Network.framework implementation. Rust 2024 is needed by this current test host.

A Unix datagram channel connects Caddy's fake TUN to a deterministic destination
IP stack. Every NF case checks tunneled DNS, TCP half-close with 100,013 bytes,
UDP carrying complete 1,280-byte IP packets, appropriate IPv6 availability,
authentication refusal, survival beyond the MTU-probe deadline and cancellation.
The H3 cases additionally check Auto, native DATAGRAM limits 0/1168/1172/1288/1289,
and a request behind the native group's emulated idle stream zero. Small limits
must select Capsules without TCP fallback; sufficient capacity must actually
send DATAGRAMs. Each extra control prints its own PASS marker.

This validates independent NF protocol behavior against Caddy, while native
TLS/QUIC behavior, Swift/C bridge execution and the documented physical-Mac
HTTP/3 incident require Apple-runtime acceptance separately.
