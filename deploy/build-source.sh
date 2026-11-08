#!/usr/bin/env bash
# Source-only helper: installation paths and compiler flags belong to callers.
caddy_build_prepare() {
    local available filesystem rule tmp_size_kb
    CADDY_BUILD_SESSION=$(mktemp -d "/tmp/caddy-masque-source-$(date +%Y%m%d-%H%M%S).XXXXXX") || return
    if [[ -z $(trap -p EXIT) ]]; then trap 'caddy_build_cleanup' EXIT; fi
    available=$(df -Pk /tmp | awk 'END {print $4}') || return
    filesystem=$(df -PT /tmp | awk 'END {print $2}') || return
    if [[ $filesystem == tmpfs || $available -lt 5242880 ]]; then
        CADDY_BUILD_WORK=$(mktemp -d "/var/tmp/caddy-masque-build-$(date +%Y%m%d-%H%M%S).XXXXXX") || return
    else
        CADDY_BUILD_WORK="$CADDY_BUILD_SESSION/work"
        mkdir -m 700 -- "$CADDY_BUILD_WORK" || return
    fi
    command -v systemd-tmpfiles >/dev/null || { echo 'systemd-tmpfiles is required for reboot cleanup.' >&2; return 1; }
    CADDY_BUILD_BOOT_RULE="/etc/tmpfiles.d/${CADDY_BUILD_SESSION##*/}.conf"
    rule="$CADDY_BUILD_SESSION/cleanup.conf"
    printf 'R! %s - - - -\nR! %s - - - -\nr! %s - - - -\n' \
        "$CADDY_BUILD_SESSION" "$CADDY_BUILD_WORK" "$CADDY_BUILD_BOOT_RULE" > "$rule"
    install -m 600 -- "$rule" "$CADDY_BUILD_BOOT_RULE" || return
    if (( available < 262144 )); then
        if [[ $filesystem == tmpfs && $(findmnt -n -o TARGET -T /tmp) == /tmp ]]; then
            CADDY_BUILD_TMP_SIZE_KB=$(df -Pk /tmp | awk 'END {print $2}') || return
            tmp_size_kb=$((CADDY_BUILD_TMP_SIZE_KB + 262144 - available))
            (( tmp_size_kb >= 524288 )) || tmp_size_kb=524288
            mount -o "remount,size=${tmp_size_kb}K" /tmp || return
        else
            echo 'Need at least 256 MiB free in /tmp for complete source downloads.' >&2; return 1
        fi
    fi
    mkdir -p "$CADDY_BUILD_WORK/cache/build" "$CADDY_BUILD_WORK/cache/mod" "$CADDY_BUILD_WORK/tmp" || return
    export GOCACHE="$CADDY_BUILD_WORK/cache/build" GOMODCACHE="$CADDY_BUILD_WORK/cache/mod"
    export TMPDIR="$CADDY_BUILD_WORK/tmp" GOTMPDIR="$CADDY_BUILD_WORK/tmp" GOWORK=off
}

caddy_build_cleanup() {
    [[ ${BASH_SUBSHELL:-0} == 0 ]] || return 0
    if [[ ${CADDY_BUILD_SWAP_RETAINED:-0} == 1 ]]; then
        rm -rf -- "$CADDY_BUILD_WORK/cache" "$CADDY_BUILD_WORK/toolchains" "$CADDY_BUILD_WORK/tmp" "$CADDY_BUILD_WORK/go-tmp"
        echo 'Temporary swap and its boot-only cleanup rule will be removed after reboot.' >&2
    elif [[ -n ${CADDY_BUILD_WORK:-} ]]; then
        rm -rf -- "$CADDY_BUILD_WORK" || return
    fi
    [[ -z ${CADDY_BUILD_SESSION:-} ]] || rm -rf -- "$CADDY_BUILD_SESSION" || return
    if [[ -n ${CADDY_BUILD_TMP_SIZE_KB:-} ]]; then
        mount -o "remount,size=${CADDY_BUILD_TMP_SIZE_KB}K" /tmp ||
            echo 'The temporary /tmp size setting will reset after reboot.' >&2
    fi
    if [[ ${CADDY_BUILD_SWAP_RETAINED:-0} != 1 && -n ${CADDY_BUILD_BOOT_RULE:-} ]]; then
        rm -f -- "$CADDY_BUILD_BOOT_RULE"
    fi
}

caddy_build_source() {
    local work
    caddy_build_prepare || return
    work=$CADDY_BUILD_SESSION
    printf 'Downloading latest complete caddy-masque main into %s\n' "$work/source"
    if ! git -c protocol.file.allow=never clone --no-local --recurse-submodules \
        --branch main -- https://github.com/ArcCal/caddy-masque.git "$work/source"; then
        printf 'Source download failed; no local checkout will be built. Work: %s\n' "$work" >&2
        return 1
    fi
    CADDY_BUILD_SOURCE=$(cd -- "$work/source" && pwd -P) || return
    git -C "$CADDY_BUILD_SOURCE" log -1 --oneline
}
