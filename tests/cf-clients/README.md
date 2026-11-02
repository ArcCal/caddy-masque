# CF gateway generic client compatibility

Run the unchanged generic client library retained inside the current
`masque-vpn-cf-masque` project against Caddy:

```sh
python3 tests/run-cf-client-interop.py --masque-vpn-root ../masque-vpn
```

This is a separate temporary Cargo workspace. Its lockfile is seeded from the
current CF workspace's `Cargo.lock` on every run; builds then use
`cargo build --locked`, and every selected registry or git package/version must
appear in that CF lockfile. Cargo metadata must select the CF frontend crate
(`masque-vpn-cf-masque/crates/frontend`, package `masque-frontend`), the CF
workspace's own `vendor/h3` and `vendor/h3-quinn` snapshots (patched in as the CF
workspace patches them), and the parent `crates/masque-vpn` client library and
`crates/masque-proto` wire-format crate that the frontend reuses. The main
client's H3 patches are not substituted. The client checkout is read-only
throughout the run. `CARGO_TARGET_DIR` selects an optional build
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
