#!/usr/bin/env bash
# Validate a Caddy build before atomically replacing the installed binary.
# Usage: bash deploy/install-binary.sh CANDIDATE [CONFIG [DESTINATION]]
# No service is restarted here. The caller owns restart and rollback.
set -euo pipefail

CANDIDATE=${1:?usage: install-binary.sh CANDIDATE [CONFIG [DESTINATION]]}
CONFIG=${2:-/etc/caddy/Caddyfile}
DESTINATION=${3:-/usr/local/bin/caddy}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[ -x "$CANDIDATE" ] || die "$CANDIDATE is not executable"
modules=$("$CANDIDATE" list-modules --skip-standard) || die "cannot run the candidate binary"
for module in masque http.handlers.masque; do
    grep -qxF "$module" <<<"$modules" || die "the candidate lacks $module"
done

# Keep custom modules even when the current Caddyfile does not use them.
# Re-running the basic installer must not silently remove the DNS plugin.
if [ -e "$DESTINATION" ]; then
    existing=$("$DESTINATION" list-modules --skip-standard) || die "cannot inspect the installed binary; it was left unchanged"
    while IFS= read -r module; do
        [[ "$module" =~ ^[a-z0-9_]+([.][a-z0-9_-]+)*$ ]] || continue
        grep -qxF "$module" <<<"$modules" || die "the candidate would remove $module; supply a build containing all installed custom modules"
    done <<<"$existing"
fi
if [ -f "$CONFIG" ]; then
    "$CANDIDATE" validate --config "$CONFIG" --adapter caddyfile || die "configuration validation failed; the installed binary was left unchanged"
fi

# Stage on the destination filesystem: rename is atomic, and readers never
# see a partially copied binary. Set execute permissions before publication.
directory=$(dirname -- "$DESTINATION")
staged=$(mktemp "$directory/.caddy-install.XXXXXX")
trap 'rm -f -- "$staged"' EXIT
install -m 755 -- "$CANDIDATE" "$staged"
mv -f -- "$staged" "$DESTINATION"
