# Current Mac and Killswitch interoperability

Run the current app APIs against Caddy's real TLS, authentication, CONNECT-IP and
HTTP transports from the Caddy repository:

```sh
python3 tests/run-client-wrapper-interop.py --masque-vpn-root ../masque-vpn
```

The runner creates a temporary Rust workspace from these assets, uses the tested
lockfile, and builds with `cargo build --locked`. It honors `CARGO_TARGET_DIR` for
a shared cache. `--release` selects an optimized Rust build; the default uses the
debug profile. Go runs the test through an overlay so normal `go test ./...` does
not depend on a Rust checkout or run this longer matrix. Go build tags are not
added. The runner requires all 16 distinct cases and rejects skipped cases.
`--compile-only` checks build and overlay wiring, and runs no interoperability
cases.

The 16 cases cover both wrappers, IPv4-only and dual-stack Caddy configurations,
and HTTP/3 Datagrams, HTTP/2, HTTP/1.1 and HTTP/3 DATAGRAM Capsules. H3 SETTINGS are
checked independently to confirm the selected datagram/capsule path. Caddy's
default session quota and MTU probing remain enabled.

Every case verifies:

- The current app settings produce the IPv4-only client configuration.
- A DNS candidate probe travels through the real Caddy tunnel and returns.
- Wrong credentials receive the configured website response and never configure
  the client's host, while the authenticated session remains usable.
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
