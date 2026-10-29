#!/usr/bin/env bash
# uninstall.sh - reverse install.sh: units (the AI resident unit and /etc/atlas/resident.env too), Apache snippet, sudoers drop-in, managed crontab lines.
#
#   ./uninstall.sh [--state DIR] [--user NAME] [--purge] [--dry-run]
#
# The state directory (baseline, config, logs, runtime/) is kept unless --purge is given. The code directory
# and the user account are left alone (remove them by hand if you want to).
set -uo pipefail

STATE=/var/lib/atlas
AUSER=atlas
DRY=0 PURGE=0
SYSTEMD_DIR=${ATLAS_SYSTEMD_DIR:-/etc/systemd/system}
ETC_DIR=${ATLAS_ETC_DIR:-/etc/atlas}
SUDOERS_DIR=${ATLAS_SUDOERS_DIR:-/etc/sudoers.d}
APACHE_CONF_DIR=${ATLAS_APACHE_CONF_DIR:-/etc/apache2/conf-available}
UNITS=(sentinel-stream.service sentinel-escalation.service sentinel-escalation.timer)
export PATH="$PATH:/usr/sbin:/sbin"

while [ $# -gt 0 ]; do
    case $1 in
        --state) STATE=${2:?--state needs a directory}; shift 2 ;;
        --user) AUSER=${2:?--user needs a name}; shift 2 ;;
        --purge) PURGE=1; shift ;;
        --dry-run|-n) DRY=1; shift ;;
        -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "uninstall.sh: unknown option: $1" >&2; exit 2 ;;
    esac
done

run() {
    if [ "$DRY" -eq 1 ]; then
        printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}
say() { printf '==> %s\n' "$*"; }
present() { [ "$DRY" -eq 1 ] || [ -e "$1" ]; }   # a dry run shows every step

if [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: run as root, or use --dry-run" >&2
    exit 1
fi

if present "$SYSTEMD_DIR/atlas-resident.service"; then
    say "stopping and removing the AI resident unit and its env file"
    run systemctl disable --now atlas-resident.service || true
    run rm -f "$SYSTEMD_DIR/atlas-resident.service"
    run rm -f "$ETC_DIR/resident.env"
    run rmdir "$ETC_DIR" 2>/dev/null || true
fi

say "stopping and removing the units"
run systemctl disable --now sentinel-stream.service sentinel-escalation.timer sentinel-escalation.service || true
for u in "${UNITS[@]}"; do
    present "$SYSTEMD_DIR/$u" && run rm -f "$SYSTEMD_DIR/$u"
done
run systemctl daemon-reload
# a removed unit that last ended in error stays listed by `systemctl --failed` until reset
run systemctl reset-failed sentinel-stream.service sentinel-escalation.service atlas-resident.service 2>/dev/null || true

if present "$APACHE_CONF_DIR/sentinel-sensitive.conf"; then
    say "removing the Apache snippet"
    run a2disconf -q sentinel-sensitive || true
    run rm -f "$APACHE_CONF_DIR/sentinel-sensitive.conf"
    run apache2ctl configtest && run systemctl reload apache2
fi

present "$SUDOERS_DIR/atlas" && run rm -f "$SUDOERS_DIR/atlas"

if [ "$DRY" -eq 1 ]; then
    printf '[dry-run] crontab -u %q -  (atlas-managed lines removed)\n' "$AUSER"
elif crontab -u "$AUSER" -l 2>/dev/null | grep -q 'atlas-managed'; then
    crontab -u "$AUSER" -l 2>/dev/null | grep -v 'atlas-managed' | crontab -u "$AUSER" -
    say "removed the atlas-managed crontab lines of $AUSER"
fi

if [ "$PURGE" -eq 1 ]; then
    say "purging the state directory $STATE"
    run rm -rf --one-file-system "$STATE"
else
    say "state kept in $STATE (use --purge to delete it)"
fi
say "done$([ "$DRY" -eq 1 ] && echo ' (dry run: nothing was changed)')"
