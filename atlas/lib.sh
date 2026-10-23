# Shared bash helpers for every Atlas/Sentinel entrypoint. Source it; it defines functions only.
#
#   atlas_load_env <state dir>   read <state dir>/sentinel.env (KEY=VALUE lines, no shell code);
#                                a variable already set in the environment wins (so cron needs only
#                                SENTINEL_ATLAS, and systemd's EnvironmentFile= gives the same result)
#   i18n_load                    load the message catalog for SENTINEL_LANG (en default) into I18N
#   t <key> [name=value ...]     print the message <key> with {name} placeholders filled in
ATLAS_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

atlas_load_env() {
    local f="${1:-.}/sentinel.env" line k v
    [ -r "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        [[ $line =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        k=${BASH_REMATCH[2]}
        v=${BASH_REMATCH[3]}
        if [[ $v =~ ^\"(.*)\"$ ]] || [[ $v =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
        [ -n "${!k+x}" ] && continue      # the environment wins
        export "$k=$v"
    done < "$f"
}

declare -gA I18N=()
i18n_load() {
    local k v
    I18N=()
    while IFS= read -r -d '' k && IFS= read -r -d '' v; do
        I18N[$k]=$v
    done < <(python3 "$ATLAS_LIB_DIR/i18n.py" --dump 2>/dev/null)
}

t() {
    local key=$1 tmpl a name
    shift
    [ "${#I18N[@]}" -gt 0 ] || i18n_load
    tmpl=${I18N[$key]:-$key}
    # bash 5.2 treats & in a substitution replacement as the match; values must stay literal
    shopt -u patsub_replacement 2>/dev/null || true
    for a in "$@"; do
        name=${a%%=*}
        tmpl=${tmpl//"{$name}"/"${a#*=}"}
    done
    printf '%s' "$tmpl"
}
