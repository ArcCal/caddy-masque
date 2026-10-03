#!/usr/bin/env bash
# Offline provisioning smoke test of the combined Caddy binary. No Cloudflare
# credentials or DNS writes; this does not claim live ACME issuance works.
set -euo pipefail
CADDY=$(realpath -- "${1:?usage: cloudflare-config.sh CADDY}")
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
printf '%s' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$WORK/token"
HASH='$argon2id$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8'
cat > "$WORK/Caddyfile" <<EOF
{
    email admin@example.com
    masque {
        ipv4 10.89.0.1/24
        user smoke $HASH
    }
}
example.com, *.example.com, :443 {
    tls {
        dns cloudflare {file.$WORK/token}
    }
    masque
    respond "cover website"
}
EOF
XDG_CONFIG_HOME="$WORK/config" XDG_DATA_HOME="$WORK/data" \
    "$CADDY" adapt --config "$WORK/Caddyfile" --adapter caddyfile --validate > "$WORK/config.json"
python3 - "$WORK/config.json" <<'PY'
import json, sys
apps = json.load(open(sys.argv[1]))['apps']
assert 'masque' in apps and 'http' in apps
providers = [issuer['challenges']['dns']['provider']
             for policy in apps['tls']['automation']['policies']
             for issuer in policy.get('issuers', [])
             if 'dns' in issuer.get('challenges', {})]
assert providers and all(p['name'] == 'cloudflare' for p in providers)
assert all(p['api_token'].startswith('{file.') for p in providers)
print('MASQUE + Cloudflare DNS configuration provisioned successfully (offline)')
PY
