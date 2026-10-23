#!/usr/bin/env bash
# install.sh - install Atlas + Sentinel on a Debian/Ubuntu host with systemd (Apache optional).
#
#   ./install.sh [--code DIR] [--state DIR] [--user NAME] [--with-apache] [--install-cron] [--yes] [--dry-run]
#
# Idempotent: run it again after an update. It never overwrites an existing sentinel.env (or any other
# file in the state directory). --dry-run prints every action instead of doing it; every system
# command goes through run(), which is what makes the dry run honest (and testable).
# Defaults: code /opt/atlas, state /var/lib/atlas, user atlas. Reverse: uninstall.sh.
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CODE=/opt/atlas
STATE=/var/lib/atlas
AUSER=atlas
DRY=0 APACHE=0 CRON=0 YES=0
SYSTEMD_DIR=${ATLAS_SYSTEMD_DIR:-/etc/systemd/system}
SUDOERS_DIR=${ATLAS_SUDOERS_DIR:-/etc/sudoers.d}
APACHE_CONF_DIR=${ATLAS_APACHE_CONF_DIR:-/etc/apache2/conf-available}
UNITS=(sentinel-stream.service sentinel-escalation.service sentinel-escalation.timer)
export PATH="$PATH:/usr/sbin:/sbin"

usage() {
    sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --code DIR       where the code lives (copied there from this checkout if different); default /opt/atlas
  --state DIR      state directory (SENTINEL_ATLAS): config, baseline, logs; default /var/lib/atlas
  --user NAME      unprivileged account that runs Atlas (created if missing); default atlas
  --with-apache    also install the Apache sensitive-path log snippet (a2enconf + reload)
  --install-cron   install the crontab lines for the Atlas user (otherwise they are only printed)
  --yes            do not ask before accepting the first snapshot as the baseline
  --dry-run        print every action, change nothing
EOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --code) CODE=${2:?--code needs a directory}; shift 2 ;;
        --state) STATE=${2:?--state needs a directory}; shift 2 ;;
        --user) AUSER=${2:?--user needs a name}; shift 2 ;;
        --with-apache) APACHE=1; shift ;;
        --install-cron) CRON=1; shift ;;
        --yes|-y) YES=1; shift ;;
        --dry-run|-n) DRY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
case $CODE in /*) ;; *) echo "install.sh: --code must be an absolute path" >&2; exit 2 ;; esac
case $STATE in /*) ;; *) echo "install.sh: --state must be an absolute path" >&2; exit 2 ;; esac
CODE=${CODE%/}; STATE=${STATE%/}

run() {   # every action that changes the system goes through here
    if [ "$DRY" -eq 1 ]; then
        printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}
say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

# --- 1. Prerequisites ---------------------------------------------------------------------------
say "checking prerequisites"
missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$1 (package: $2)"); }
need systemctl systemd
need journalctl systemd
need python3 python3
need sudo sudo
need visudo sudo
need ss iproute2
need crontab cron
need timeout coreutils
if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    missing+=("python3 >= 3.11 (found $(python3 -c 'import platform; print(platform.python_version())'))")
fi
if [ "$APACHE" -eq 1 ]; then
    need apache2ctl apache2
    need a2enconf apache2
fi
command -v mail >/dev/null 2>&1 || warn "no 'mail' command: escalation cannot mail anyone (install bsd-mailx or mailutils and an MTA)"
for opt in certbot ufw fail2ban-client docker screen; do
    command -v "$opt" >/dev/null 2>&1 || say "optional tool not installed (fine, Atlas skips it): $opt"
done
if [ "${#missing[@]}" -gt 0 ]; then
    printf 'MISSING: %s\n' "${missing[@]}" >&2
    if [ "$DRY" -eq 1 ]; then
        warn "continuing because this is a dry run"
    else
        exit 1
    fi
fi
if [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo ./install.sh ...), or use --dry-run" >&2
    exit 1
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/atlas-install.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT
render() {   # $1 template  $2 output
    sed -e "s|@ATLAS_CODE@|$CODE|g" -e "s|@ATLAS_STATE@|$STATE|g" -e "s|@ATLAS_USER@|$AUSER|g" "$1" > "$2"
}

# --- 2. The Atlas user --------------------------------------------------------------------------
if id -u "$AUSER" >/dev/null 2>&1; then
    say "user $AUSER exists"
    AGROUP=$(id -gn "$AUSER")
else
    say "creating system user $AUSER"
    run useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$AUSER"
    AGROUP=$AUSER
fi
if [ "$AUSER" != root ]; then
    # read access to the system journal and to /var/log/apache2 (root:adm 0640)
    for g in adm systemd-journal; do
        getent group "$g" >/dev/null 2>&1 && run usermod -a -G "$g" "$AUSER"
    done
fi

# --- 3. Code ------------------------------------------------------------------------------------
if [ "$(realpath -m "$CODE")" = "$REPO" ]; then
    say "code already in place: $CODE"
else
    say "copying the code to $CODE"
    run install -d -m 0755 "$CODE"
    run cp -a "$REPO/atlas" "$REPO/sentinel" "$REPO/i18n" "$REPO/examples" "$REPO/docs" \
        "$REPO/README.md" "$REPO/install.sh" "$REPO/uninstall.sh" "$CODE/"
fi

# --- 4. State directory and the one config file --------------------------------------------------
say "state directory $STATE"
for d in "$STATE" "$STATE/jobs.d" "$STATE/bridges.d" "$STATE/pauses" "$STATE/snapshots"; do
    run install -d -m 0750 -o "$AUSER" -g "$AGROUP" "$d"
done
install_if_absent() {   # $1 source  $2 destination  $3 mode
    if [ -e "$2" ]; then
        say "keeping existing $2"
    else
        run install -m "$3" -o "$AUSER" -g "$AGROUP" "$1" "$2"
    fi
}
install_if_absent "$REPO/examples/sentinel.env" "$STATE/sentinel.env" 0640
install_if_absent "$REPO/examples/known-ips.txt" "$STATE/known-ips.txt" 0640
install_if_absent "$REPO/examples/http-expected.json" "$STATE/http-expected.json" 0640
install_if_absent "$REPO/atlas/pauses/README.md" "$STATE/pauses/README.md" 0640

# --- 5. systemd units ---------------------------------------------------------------------------
say "systemd units -> $SYSTEMD_DIR"
for u in "${UNITS[@]}"; do
    render "$REPO/sentinel/units/$u" "$TMP/$u"
    run install -m 0644 "$TMP/$u" "$SYSTEMD_DIR/$u"
done
run systemctl daemon-reload
run systemctl enable --now sentinel-stream.service sentinel-escalation.timer

# --- 6. Apache snippet (optional) ---------------------------------------------------------------
if [ "$APACHE" -eq 1 ]; then
    say "Apache sensitive-path log snippet"
    run install -m 0644 "$REPO/sentinel/apache/sentinel-sensitive.conf" "$APACHE_CONF_DIR/sentinel-sensitive.conf"
    run a2enconf -q sentinel-sensitive
    run apache2ctl configtest
    run systemctl reload apache2
else
    say "skipping the Apache snippet (use --with-apache)"
fi

# --- 7. sudoers drop-in: exactly the read-only commands Atlas runs -------------------------------
if [ "$AUSER" = root ]; then
    say "user is root: no sudoers drop-in needed"
else
    render "$REPO/examples/sudoers.d/atlas" "$TMP/sudoers-atlas"
    if command -v visudo >/dev/null 2>&1; then
        # a check of a temp file, harmless, so it runs in a dry run too
        if ! visudo -cf "$TMP/sudoers-atlas" >/dev/null; then
            echo "install.sh: the rendered sudoers file does not parse (sudo >= 1.9.10 needed); nothing installed" >&2
            exit 1
        fi
        say "sudoers drop-in parses (visudo -cf)"
    fi
    run install -m 0440 -o root -g root "$TMP/sudoers-atlas" "$SUDOERS_DIR/atlas"
fi

# --- 8. crontab ---------------------------------------------------------------------------------
render "$REPO/sentinel/units/crontab.example" "$TMP/crontab"
say "crontab lines for user $AUSER:"
grep -v '^#' "$TMP/crontab" | sed 's/^/    /'
if [ "$CRON" -eq 1 ]; then
    if [ "$DRY" -eq 1 ]; then
        printf '[dry-run] crontab -u %q -  (existing atlas-managed lines replaced by the lines above)\n' "$AUSER"
    else
        { crontab -u "$AUSER" -l 2>/dev/null | grep -v 'atlas-managed'; grep -v '^#' "$TMP/crontab"; } | crontab -u "$AUSER" -
        say "crontab installed"
    fi
else
    say "not installed: add them with 'crontab -u $AUSER -e', or rerun with --install-cron"
fi

# --- 9. First snapshot and baseline -------------------------------------------------------------
as_user() {
    if [ "$AUSER" = "$(id -un)" ]; then
        run env SENTINEL_ATLAS="$STATE" "$@"
    else
        run sudo -u "$AUSER" env SENTINEL_ATLAS="$STATE" "$@"
    fi
}
say "first snapshot"
as_user python3 "$CODE/atlas/atlas.py" snap
if [ "$YES" -eq 1 ]; then
    as_user python3 "$CODE/atlas/atlas.py" bless
elif [ "$DRY" -eq 1 ]; then
    say "would ask before accepting the snapshot as the baseline (bless); --yes skips the question"
    as_user python3 "$CODE/atlas/atlas.py" bless
else
    read -r -p "Accept this snapshot as the baseline now (atlas.py bless)? [y/N] " answer
    case $answer in
        [yY]*) as_user python3 "$CODE/atlas/atlas.py" bless ;;
        *) say "later: sudo -u $AUSER env SENTINEL_ATLAS=$STATE python3 $CODE/atlas/atlas.py bless" ;;
    esac
fi

if [ ! -e "$STATE/sentinel.env" ] || ! grep -qE '^SENTINEL_EMAIL=.+' "$STATE/sentinel.env" 2>/dev/null; then
    say "NEXT: set SENTINEL_EMAIL in $STATE/sentinel.env - until then escalation reports UNKNOWN (no recipient)"
fi
say "done$([ "$DRY" -eq 1 ] && echo ' (dry run: nothing was changed)')"
