# CF gateway generic client compatibility

Run the unchanged generic client library retained inside the current
`masque-vpn-cf-masque` project against Caddy:

```sh
python3 tests/run-cf-client-interop.py --masque-vpn-root ../masque-vpn
```

This is a separate temporary Cargo workspace. The server-owned lockfile was
seeded from the CF workspace at client revision
`e10a6ec9fcf0e005d36572830539802df36f6638`. Builds use `cargo build --locked`.
Cargo metadata must select that checkout's CF-local `masque-frontend`,
`masque-proto`, `h3`, `h3-quinn`, and `h3-datagram` snapshots, and every selected
registry package/version must appear in the upstream CF lockfile. The main
client's H3 patches are not substituted. When upstream dependencies change,
review and refresh only this server-owned harness lockfile. The client checkout
is read-only throughout the run. `CARGO_TARGET_DIR` selects an optional build
cache; `--release` selects optimized builds. `--compile-only` checks compilation
and the Go overlay while running zero interoperability cases.

The runner requires eight distinct passing cases and rejects skipped cases:
IPv4-only and dual-stack client/server configurations, each over H3 QUIC
DATAGRAM, H2, HTTP/1.1 Upgrade, and H3 DATAGRAM Capsules. The Go fixture checks H3
SETTINGS independently to confirm the selected carrier.

Each case uses the real `masque_frontend::client::Client`, certificate validation,
Basic authentication, address assignment and route processing. It checks:

- A trusted CA succeeds and an unrelated CA fails before host configuration.
- Wrong credentials are refused while the authenticated tunnel keeps working.
- 512 complete 1350-byte IPv4 UDP packets echo without corruption.
- Dual-stack cases also echo a 1280-byte IPv6 packet and 256 complete 1350-byte
  IPv6 packets, with payloads and addressing checked in both directions.
- The original session survives beyond the default ten-second IPv6 MTU-probe
  deadline without reconnecting.
- Revoking then restoring the user's credential causes the unchanged reconnect
  loop to establish a new usable session; shutdown releases Caddy sessions.

The server's destination network is a deterministic IP echo fixture, and the
client's native host configuration is represented by its public `Host` trait and
packet channels. This does not execute Linux TUN/routing, native Apple APIs, real
Internet forwarding or a Cloudflare service.

`masque-vpn-cf-masque` itself is an experimental Linux gateway server. Its
production outbound `warp-masque-packet` client uses a separate Cloudflare
profile: enrolled device mTLS, endpoint SPKI pinning, `cf-connect-ip`, and a
private H2 capsule format. It is not a generic Caddy client and is not what this
harness claims to test. No Cloudflare enrollment is requested or used here.
