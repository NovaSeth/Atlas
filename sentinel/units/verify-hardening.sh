#!/bin/bash
# Offline unit analysis and opt-in, root-only transient probes. --print changes nothing.
set -uo pipefail

usage() {
    echo 'Usage: verify-hardening.sh --code DIR --state DIR --user NAME [--mail-to LOCALUSER] [--print]' >&2
    exit 2
}
CODE='' STATE='' AUSER='' MAIL_TO='' PRINT=0
while (($#)); do
    case "$1" in
        --code|--state|--user|--mail-to)
            (($# >= 2)) || usage
            case "$1" in
                --code) CODE=$2 ;;
                --state) STATE=$2 ;;
                --user) AUSER=$2 ;;
                --mail-to) MAIL_TO=$2 ;;
            esac
            shift 2 ;;
        --print) PRINT=1; shift ;;
        *) usage ;;
    esac
done
# Keep template substitutions literal and prevent systemd specifier expansion.
[[ $CODE =~ ^/[A-Za-z0-9._/@+-]+$ && $STATE =~ ^/[A-Za-z0-9._/@+-]+$ ]] || usage
[[ $AUSER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || usage
[[ -z $MAIL_TO || $MAIL_TO =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || usage
if (( ! PRINT && EUID != 0 )); then
    echo 'verify-hardening: root required for transient probes (use --print to inspect)' >&2
    exit 1
fi
run() {
    if ((PRINT)); then
        printf '%q ' "$@"; printf '\n'
    else
        "$@"
    fi
}
fail() { echo "verify-hardening: $*" >&2; exit 1; }
UNITS=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
TMP=/tmp/atlas-hardening-preview
if ((PRINT)); then
    run mktemp -d || exit 1
else
    TMP=$(run mktemp -d) || fail 'temporary directory creation failed'
    trap 'run rm -rf -- "$TMP"' EXIT
fi
# Render without shell evaluation. The same commands are displayed in print mode.
for name in sentinel-stream.service sentinel-escalation.service; do
    run python3 -c '
import pathlib, sys
source, dest, code, state, user = sys.argv[1:]
text = pathlib.Path(source).read_text()
for key, value in (("@ATLAS_CODE@", code), ("@ATLAS_STATE@", state), ("@ATLAS_USER@", user)):
    text = text.replace(key, value)
pathlib.Path(dest).write_text(text)
' "$UNITS/$name" "$TMP/$name" "$CODE" "$STATE" "$AUSER" || fail "rendering $name failed"
    run systemd-analyze security --offline=true --no-pager "$TMP/$name" || fail "offline analysis of $name failed"
done

# Read hardening from the templates so probes cannot silently diverge from the units.
for role in stream escalation; do
    props=()
    while IFS= read -r line; do
        case "$line" in
            NoNewPrivileges=*|Protect*=*|ReadWritePaths=*|Private*=*|CapabilityBoundingSet=*|SystemCall*=*|Restrict*=*|LockPersonality=*|MemoryDenyWriteExecute=*|UMask=*)
                props+=(-p "${line//@ATLAS_STATE@/$STATE}") ;;
        esac
    done < "$UNITS/sentinel-$role.service"
    # mktemp uses a unique name and never overwrites an existing runtime file.
    # Expanded by the transient shell, not by this verifier.
    # shellcheck disable=SC2016
    probe='f=$(mktemp "$1/runtime/hardening-XXXXXXXX") || exit 1; rm -- "$f"'
    if [[ $role == stream ]]; then
        probe='journalctl -n 1 -q --no-pager || exit 1; '"$probe"
    fi
    run systemd-run --wait --pipe --collect --unit="atlas-hardening-$role-$$" \
        -p "User=$AUSER" "${props[@]}" /bin/sh -c "$probe" sh "$STATE" || fail "$role runtime probe failed"
    if [[ $role == escalation && -n $MAIL_TO ]]; then
        # Display MTA verbose output for queue identification; leave deletion to the operator.
        run printf '%s\n' 'Queued mail probe: record the message id below and remove it from the local MTA queue.'
        # Expanded by the transient shell.
        # shellcheck disable=SC2016
        run systemd-run --wait --pipe --collect --unit="atlas-hardening-escalation-mail-$$" \
            -p "User=$AUSER" "${props[@]}" /bin/sh -c \
            'printf "Subject: Atlas hardening probe\n\nLocal queued probe.\n" | /usr/sbin/sendmail -v -odq "$1"' \
            sh "$MAIL_TO" || fail 'escalation queued mail probe failed'
    fi
done
