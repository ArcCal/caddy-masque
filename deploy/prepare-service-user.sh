#!/usr/bin/env bash
# Provision the non-login account used by both systemd installers.
set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || die "service account preparation requires root"
systemd-sysusers --inline 'u caddy-masque - "Caddy MASQUE service" /var/lib/caddy-masque /usr/sbin/nologin'

account_entry=$(getent passwd caddy-masque)
group_entry=$(getent group caddy-masque)
[[ $account_entry == "$(getent -s files passwd caddy-masque)" &&
    $group_entry == "$(getent -s files group caddy-masque)" ]] ||
    die "caddy-masque must resolve to its local system account and group"
IFS=: read -r account _ account_uid account_gid _ account_home account_shell <<<"$account_entry"
IFS=: read -r group _ group_gid group_members <<<"$group_entry"
[[ $account == caddy-masque && $group == caddy-masque && $account_uid =~ ^[1-9][0-9]*$ && $group_gid =~ ^[1-9][0-9]*$ &&
    $account_gid == "$group_gid" && $account_home == /var/lib/caddy-masque &&
    ( $account_shell == /usr/sbin/nologin || $account_shell == /sbin/nologin || $account_shell == /bin/false ) &&
    ( -z $group_members || $group_members == caddy-masque ) && $(id -G caddy-masque) == "$account_gid" ]] ||
    die "caddy-masque must be a dedicated non-root, non-login account with its own group and no supplementary groups"

# Refuse shared numeric identities, including other users with this primary GID.
[[ $(getent passwd | awk -F: -v uid="$account_uid" -v gid="$account_gid" '$3 == uid || $4 == gid { n++ } END { print n+0 }') == 1 &&
    $(getent group | awk -F: -v gid="$account_gid" '$3 == gid { n++ } END { print n+0 }') == 1 ]] ||
    die "the caddy-masque UID and GID must not be shared with other accounts"
