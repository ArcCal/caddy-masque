# Changelog

Each version is tagged with its number; CI attaches Caddy builds to its release on GitHub.

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
