#!/usr/bin/env bash
#
# Point THIS SERVER's own DNS at a NextDNS profile over DNS-over-HTTPS.
# The Linux equivalent of NextDNS's "DNS over HTTPS / Windows 11" setup page.
# Ubuntu 22.04 / 24.04 / 26.04+. Safe to re-run — idempotent at every step.
#
#   sudo bash deploy/nextdns-server-doh.sh 7a2783        # set it up
#   sudo bash deploy/nextdns-server-doh.sh --status      # what's in effect now
#   sudo bash deploy/nextdns-server-doh.sh --uninstall   # put it back
#
# This changes how the SERVER resolves names — nothing about the routers
# mikromon manages, and nothing about the machine you browse from. Those are
# separate resolvers; see the header notes in --status output.
#
set -euo pipefail

log()  { echo "  $*"; }
step() { echo; echo ">> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

RESOLV=/etc/resolv.conf
BACKUP_DIR=/var/backups/mikromon-dns

[[ "${EUID}" -eq 0 ]] || die "Must be run as root. Use: sudo bash $0 $*"

# ---------------------------------------------------------------------------
# Status / uninstall
# ---------------------------------------------------------------------------
show_status() {
    step "Resolver in effect on this server"
    log "${RESOLV} ->"
    sed 's/^/    /' "${RESOLV}" 2>/dev/null || log "    (missing)"
    echo
    if command -v nextdns &>/dev/null; then
        log "nextdns CLI: installed"
        nextdns status 2>&1 | sed 's/^/    /' || true
        echo
        log "configured profile:"
        nextdns config list 2>&1 | sed 's/^/    /' || true
    else
        log "nextdns CLI: not installed"
    fi
    echo
    step "Is this server's DNS actually going through NextDNS?"
    # NextDNS answers this specially: the TXT record names the profile that
    # resolved it, so it proves the whole path end to end rather than just
    # showing what's configured.
    if command -v dig &>/dev/null; then
        dig +short +time=5 +tries=1 test.nextdns.io TXT 2>&1 | sed 's/^/    /'
    else
        log "(install dnsutils for the live check: apt-get install -y dnsutils)"
    fi
    echo
    log "A line naming your profile id = working."
    log "'unconfigured' / no answer  = this server is NOT using NextDNS."
}

do_uninstall() {
    step "Removing the NextDNS resolver from this server"
    if command -v nextdns &>/dev/null; then
        nextdns deactivate 2>/dev/null || true
        nextdns stop       2>/dev/null || true
        nextdns uninstall  2>/dev/null || true
        log "nextdns service deactivated and removed."
    fi
    if [[ -f "${BACKUP_DIR}/resolv.conf" ]]; then
        cp -a "${BACKUP_DIR}/resolv.conf" "${RESOLV}"
        log "restored the original ${RESOLV}"
    else
        log "no saved ${RESOLV} to restore — leaving the current one alone."
    fi
    step "Done. Check name resolution still works:  getent hosts github.com"
}

case "${1:-}" in
    --status)    show_status; exit 0 ;;
    --uninstall) do_uninstall; exit 0 ;;
    "")          die "Usage: $0 <nextdns-profile-id> | --status | --uninstall" ;;
esac

PROFILE="$1"
[[ "${PROFILE}" =~ ^[a-z0-9]{6,}$ ]] \
    || die "'${PROFILE}' doesn't look like a NextDNS profile id (e.g. 7a2783)."

# ---------------------------------------------------------------------------
# 1. Pre-flight
# ---------------------------------------------------------------------------
step "Pre-flight"
command -v systemctl &>/dev/null || die "systemd is required."
log "profile to use: ${PROFILE}  (https://dns.nextdns.io/${PROFILE})"

# Keep a copy of the working resolver BEFORE touching anything. This server
# is the WireGuard hub and runs mikromon itself — if DNS breaks here, mikromon
# can't reach api.nextdns.io, SMTP, or the billing provider. --uninstall puts
# this file straight back.
mkdir -p "${BACKUP_DIR}"
if [[ ! -f "${BACKUP_DIR}/resolv.conf" ]]; then
    cp -aL "${RESOLV}" "${BACKUP_DIR}/resolv.conf"
    log "saved a rollback copy of ${RESOLV} -> ${BACKUP_DIR}/resolv.conf"
else
    log "rollback copy already saved (kept the original from the first run)"
fi

# ---------------------------------------------------------------------------
# 2. Install the NextDNS CLI
# ---------------------------------------------------------------------------
# Why the official CLI rather than systemd-resolved: resolved speaks
# DNS-over-TLS, not DNS-over-HTTPS. The CLI is what does real DoH on Linux,
# which is what the Windows 11 instructions set up and what gets through
# networks that only allow 443.
step "Installing the NextDNS CLI"
if command -v nextdns &>/dev/null; then
    log "already installed: $(nextdns version 2>/dev/null || echo present)"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg >/dev/null
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://repo.nextdns.io/nextdns.gpg \
        -o /usr/share/keyrings/nextdns.gpg
    echo "deb [signed-by=/usr/share/keyrings/nextdns.gpg] https://repo.nextdns.io/deb stable main" \
        > /etc/apt/sources.list.d/nextdns.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y nextdns >/dev/null
    log "installed: $(nextdns version 2>/dev/null || echo ok)"
fi

# ---------------------------------------------------------------------------
# 3. Configure + activate
# ---------------------------------------------------------------------------
step "Pointing this server at profile ${PROFILE}"
# Re-running `install` on an existing setup errors rather than reconfiguring,
# so tear the old service down first — that is what makes this re-runnable.
nextdns deactivate 2>/dev/null || true
nextdns stop       2>/dev/null || true
nextdns uninstall  2>/dev/null || true

# -report-client-info is deliberately OFF: this is a server, so every query in
# the log is the server itself. Leaving it on adds nothing and puts hostnames
# from this box into the profile's log.
nextdns install \
    -profile "${PROFILE}" \
    -auto-activate \
    -report-client-info=false
nextdns start
nextdns activate
log "nextdns is running and owns ${RESOLV}"

# ---------------------------------------------------------------------------
# 4. Prove it end to end
# ---------------------------------------------------------------------------
step "Verifying"
command -v dig &>/dev/null || DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends dnsutils >/dev/null 2>&1 || true

if ! getent hosts github.com >/dev/null 2>&1; then
    echo
    die "Name resolution is BROKEN after this change. Roll back now:
       sudo bash $0 --uninstall"
fi
log "ordinary name resolution still works (github.com resolved)"

VERDICT="$(dig +short +time=5 +tries=1 test.nextdns.io TXT 2>/dev/null || true)"
echo
if grep -qi "${PROFILE}" <<<"${VERDICT}"; then
    log "CONFIRMED — this server is resolving through profile ${PROFILE}:"
    sed 's/^/    /' <<<"${VERDICT}"
else
    log "NOT confirmed yet. test.nextdns.io said:"
    sed 's/^/    /' <<<"${VERDICT:-(no answer)}"
    log "Give it a few seconds and re-check with:  sudo bash $0 --status"
fi

cat <<EOF

>> Done.

   What this changed:  only how THIS SERVER resolves names.
   What it did NOT:    the routers mikromon manages (those are set from each
                       device's DNS tab), and the machine you browse from
                       (that needs its own setup — the page you were reading).

   Roll back at any time:  sudo bash $0 --uninstall
   Check at any time:      sudo bash $0 --status
EOF
