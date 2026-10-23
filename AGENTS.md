# Agent instructions for caddy-masque

## Project context

- This is a Caddy CONNECT-IP server module, not an Apple Network Relay plugin.
  Its Linux host networking creates TUN, forwarding and NAT state.
- Start with `docs/USER_GUIDE.md`, `app.go`, `caddyfile.go` and `go.mod`.
  Preserve the local patched QUIC/x/net dependency replacements when building.
- Every normal, custom-main, xcaddy and cross-compiled build must include
  `github.com/caddy-dns/cloudflare`. Preserve its unconditional package import
  and pinned dependency; do not make it optional through tags or build variants.
- Check the exact final executable for `masque`, `http.handlers.masque` and
  `dns.providers.cloudflare` before installation, packaging or publication.
  Cross-built executables need the check on the target or a suitable runner.
  A failed check must not replace a working installed binary. Using Cloudflare
  DNS challenges is optional; bundling the provider is mandatory.
- Maintain client interoperability, authentication, certificate handling and
  the protocol-specific distinctions between H3 Datagrams and Capsules.
- Preserve ownership and cleanup boundaries for listeners, sessions, routing
  and firewall objects; do not reset unrelated host networking.
- Protect Caddy's administration endpoint separately from tunnel credentials.
  Check actual release attachments and published tags before promising binaries.
- Separate local protocol/client fixtures from native systemd, WAN and actual
  client-device acceptance. Use the retained validation records accurately.

## Repository-wide contribution rules

The following six rules apply to this repository and all its subdirectories.

### 1. Anonymity and English

- Maintain complete anonymity in contributions and change metadata.
- Use exactly `Anonymous <anonymous@example.invalid>` as both the raw Git
  author and committer of every new commit, and as the tagger of annotated tags.
  Keep commits and tags unsigned. Do not add personal attribution, identity
  trailers, agent session identifiers or personal account details. Preserve
  required legal attribution.
- Keep repository text and change metadata in English. Do not introduce Chinese,
  Korean or Russian content, Han, Hangul or Cyrillic characters, or dedicated
  CJK/fullwidth punctuation. Use ASCII punctuation for new prose. Preserve
  protocol data, existing test semantics and required legal notices.

### 2. Read before editing and preserve design objectives

Before making any change, read the project's design objectives, commit history,
change history and entire codebase. No change may violate the design objectives
unless the user explicitly requests changing those objectives.

### 3. Minimal necessary changes

- Every change must be minimal and necessary for the requested task.
- Do not perform large refactors unless the user explicitly requests them.

### 4. Server requirements

All MASQUE-related servers must have no violations of applicable IETF
specifications, no known performance or security issues, and no regressions.

All network-relay-related servers must have no violations of applicable IETF
specifications and Apple's specifications, no known performance or security
issues, and no regressions.

### 5. Client requirements

Clients are not required to strictly follow IETF or Apple specifications, but
must remain fully compatible and interoperable with their corresponding
servers, with no serious performance or security issues and no regressions.

### 6. Test before committing

- No change may introduce new problems or regressions.
- Test changes before committing. Commit only after the tests appropriate to
  the change pass and no new issues are found.
- Failed, skipped, unavailable or interrupted tests do not count as passes.
  Do not commit changes whose required validation is incomplete.
