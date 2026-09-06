#!/usr/bin/env bash
# =============================================================================
#  ModSecurity Bad Bot Monitor — Installer
#  Project : ModSec_Disable_BadBots
#  Version : 2.1.0
#  GitHub  : https://github.com/ShahaB108/ModSec_Disable_BadBots
#  Stack   : DirectAdmin + LiteSpeed Enterprise + CSF Firewall
#  Run as  : root
#
#  Since v2.1.0 ALL service-owned files and directories live under
#  /opt/modsec-bot-monitor (bin/, rules/, state/, systemd/, VERSION).
#  Only thin integration points remain outside: the systemd unit is
#  symlinked from /etc/systemd/system, the rule is mirrored into
#  /etc/modsecurity.d and CustomBuild's custom dir, and the legacy
#  ServerHub version-stamp path is kept working via a symlink.
# =============================================================================

set -euo pipefail

# ── Version ───────────────────────────────────────────────────────────────────
SERVICE_VERSION="2.1.0"

# ── Source URLs ───────────────────────────────────────────────────────────────
GITHUB_RAW="https://raw.githubusercontent.com/ShahaB108/ModSec_Disable_BadBots/refs/heads/main"
URL_SCRIPT="${GITHUB_RAW}/monitor_modsec.py"
URL_SERVICE="${GITHUB_RAW}/modsec-bot-monitor.service"
URL_RULE="${GITHUB_RAW}/777007_block_badbots.conf"

# ── Destination paths (v2.1.0 layout — everything under /opt) ─────────────────
INSTALL_DIR="/opt/modsec-bot-monitor"
RULE_ID="777007"
RULE_FILE="777007_block_badbots.conf"
# Master copy of the ModSecurity rule — the source of truth, watched and
# restored by the monitor's rule watchdog (a GitHub download is only the
# last-resort fallback when the master itself cannot be recovered).
RULES_DIR="${INSTALL_DIR}/rules"
MASTER_RULE_FILE="${RULES_DIR}/${RULE_FILE}"
MODSEC_DIR="/etc/modsecurity.d"
# DirectAdmin/CustomBuild "custom" rule dir — files placed here survive
# CustomBuild rebuilds, unlike unmanaged files dropped directly in MODSEC_DIR.
DA_DIR="/usr/local/directadmin"
CUSTOMBUILD_MODSEC_DIR="${DA_DIR}/custombuild/custom/modsecurity/conf"
# DirectAdmin per-user/domain data dir — home of each domain's .modsecurity_rules toggle file.
DA_USERS_DIR="${DA_DIR}/data/users"
BIN_DIR="${INSTALL_DIR}/bin"
SCRIPT_DEST="${BIN_DIR}/monitor_modsec.py"
SERVICE_NAME="modsec-bot-monitor"
SYSTEMD_DIR="${INSTALL_DIR}/systemd"
UNIT_SOURCE="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
STATE_DIR="${INSTALL_DIR}/state"
# Version stamp written here at install time. The legacy path
# (/usr/local/share/modsec-disable-badbots-version) is kept as a symlink for
# ServerHub's agent collector, which checks that exact path first.
VERSION_FILE="${INSTALL_DIR}/VERSION"
LEGACY_VERSION_FILE="/usr/local/share/modsec-disable-badbots-version"
GITHUB_API_COMMIT="https://api.github.com/repos/ShahaB108/ModSec_Disable_BadBots/commits/main"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YLW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BLU}${BLD}── $* ${NC}"; }
ok()      { echo -e "    ${GRN}✔${NC}  $*"; }
skip()    { echo -e "    ${YLW}↷${NC}  $*"; }

banner() {
    echo -e "${CYN}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║     ModSecurity Bad Bot Monitor — Installer           ║"
    echo "  ║     Version: ${SERVICE_VERSION} │ Rule ID: 777007          ║"
    echo "  ║     LiteSpeed + CSF + DirectAdmin                     ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# =============================================================================
#  PRE-FLIGHT CHECKS
# =============================================================================
preflight() {
    section "Pre-flight checks"

    [[ $EUID -ne 0 ]] && error "Must be run as root."
    ok "Running as root"

    for bin in python3 curl csf systemctl; do
        command -v "$bin" &>/dev/null \
            || error "'$bin' not found. Install it before proceeding."
        ok "$bin found at $(command -v $bin)"
    done

    python3 -c "import sys; assert sys.version_info >= (3,9)" 2>/dev/null \
        || error "Python 3.9+ required. Found: $(python3 --version)"
    ok "Python version: $(python3 --version)"

    [[ -d "$MODSEC_DIR" ]] \
        || error "ModSecurity directory not found: $MODSEC_DIR — is ModSecurity installed?"
    ok "ModSecurity directory: $MODSEC_DIR"

    [[ -f "/etc/csf/csf.deny" ]] \
        || warn "/etc/csf/csf.deny not found — CSF may not be active."
}

# =============================================================================
#  DETECT SYSTEMD NAMESPACE SUPPORT
#  Some KVM/container environments reject PrivateTmp / ProtectSystem.
#  We test it and patch the service file automatically if needed.
# =============================================================================
detect_namespace_support() {
    section "Detecting systemd namespace support"

    local virt
    virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    info "Virtualization: ${virt}"

    # Quick test: try PrivateTmp in a transient unit
    if systemd-run --quiet --wait --property=PrivateTmp=yes \
        -- /bin/true 2>/dev/null; then
        ok "Namespace sandboxing is supported — hardening will be enabled"
        NAMESPACE_OK=true
    else
        warn "Namespace sandboxing NOT supported on this host"
        warn "PrivateTmp / ProtectSystem will be disabled in the service file"
        NAMESPACE_OK=false
    fi
}

# =============================================================================
#  DOWNLOAD FILES
# =============================================================================
download_files() {
    section "Downloading files from GitHub"

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Fetching monitor_modsec.py ..."
    curl -fsSL "$URL_SCRIPT"  -o "${TMP_DIR}/monitor_modsec.py"  || error "Download failed: $URL_SCRIPT"
    ok "monitor_modsec.py"

    info "Fetching modsec-bot-monitor.service ..."
    curl -fsSL "$URL_SERVICE" -o "${TMP_DIR}/modsec-bot-monitor.service" || error "Download failed: $URL_SERVICE"
    ok "modsec-bot-monitor.service"

    info "Fetching 777007_block_badbots.conf ..."
    curl -fsSL "$URL_RULE"    -o "${TMP_DIR}/${RULE_FILE}"        || error "Download failed: $URL_RULE"
    ok "777007_block_badbots.conf"

    # Patch service file if namespaces are not supported
    if [[ "${NAMESPACE_OK}" == false ]]; then
        info "Patching service file — disabling namespace directives..."
        sed -i \
            -e 's/^PrivateTmp=yes/PrivateTmp=no/' \
            -e 's/^NoNewPrivileges=yes/NoNewPrivileges=no/' \
            -e 's/^ProtectSystem=strict/ProtectSystem=false/' \
            "${TMP_DIR}/modsec-bot-monitor.service"
        ok "Service file patched for namespace-restricted environment"
    fi
}

# =============================================================================
#  CLEANUP / MIGRATION — clear previous install, migrate v2.0.x state
# =============================================================================
# The Python script, unit file and rule master are always freshly
# downloaded, so reinstalling them guarantees an update actually lands.
# Since v2.1.0 the runtime state (blocked-IP history + hit stats) is
# MIGRATED from the legacy /var/lib/modsec_bot_monitor instead of wiped,
# so a reinstall no longer loses tracking history.
cleanup_previous_install() {
    section "Cleanup / migration — previous install (if any)"

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping running service before cleanup..."
        systemctl stop "$SERVICE_NAME"
    fi

    # Legacy v2.0.x script location (/usr/local/bin) — superseded by /opt
    if [[ -e "/usr/local/bin/monitor_modsec.py" && ! -L "/usr/local/bin/monitor_modsec.py" ]]; then
        rm -f "/usr/local/bin/monitor_modsec.py"
        ok "Removed legacy script: /usr/local/bin/monitor_modsec.py"
    else
        skip "No legacy script at /usr/local/bin/monitor_modsec.py"
    fi

    # Migrate state from the legacy /var/lib/modsec_bot_monitor (v2.0.x)
    if [[ -d "/var/lib/modsec_bot_monitor" ]]; then
        mkdir -p "$STATE_DIR"
        local f
        for f in state.json modsec_bad_bots.txt blocked_ips.txt; do
            if [[ -f "/var/lib/modsec_bot_monitor/$f" && ! -e "$STATE_DIR/$f" ]]; then
                mv "/var/lib/modsec_bot_monitor/$f" "$STATE_DIR/$f"
            fi
        done
        rm -rf "/var/lib/modsec_bot_monitor"
        ok "Migrated state to $STATE_DIR — blocked-IP history and hit stats preserved"
    else
        skip "No legacy state dir at /var/lib/modsec_bot_monitor"
    fi

    # Old unit file (v2.0.x regular file or stale symlink) — recreated as
    # a symlink into /opt by install_service()
    if [[ -e "$SERVICE_DEST" || -L "$SERVICE_DEST" ]]; then
        rm -f "$SERVICE_DEST"
        systemctl daemon-reload
        ok "Removed old service unit: $SERVICE_DEST"
    else
        skip "No existing service unit at $SERVICE_DEST"
    fi

    # Legacy version stamp (v2.0.x regular file) — recreated as a symlink
    # to $VERSION_FILE by install_version_stamp()
    if [[ -e "$LEGACY_VERSION_FILE" && ! -L "$LEGACY_VERSION_FILE" ]]; then
        rm -f "$LEGACY_VERSION_FILE"
        ok "Removed legacy version stamp: $LEGACY_VERSION_FILE"
    else
        skip "No legacy version stamp file at $LEGACY_VERSION_FILE"
    fi
}

# =============================================================================
#  STEP 1 — ModSecurity Rule
# =============================================================================
install_rule() {
    section "Step 1 — ModSecurity Rule ${RULE_ID} (v${SERVICE_VERSION})"

    # Master copy under /opt — ALWAYS refreshed. It is the source of truth
    # the service's rule watchdog mirrors from; GitHub is only the fallback
    # if the master itself goes missing.
    mkdir -p "$RULES_DIR"
    cp "${TMP_DIR}/${RULE_FILE}" "$MASTER_RULE_FILE"
    chmod 644 "$MASTER_RULE_FILE"
    ok "Rule master installed: $MASTER_RULE_FILE"

    # Active copy included by ModSecurity
    local dest="${MODSEC_DIR}/${RULE_FILE}"

    if [[ -f "$dest" ]] && grep -q "id:${RULE_ID}" "$dest" 2>/dev/null; then
        skip "Rule ${RULE_ID} already active at $dest — the service watchdog re-syncs it from the master on startup"
        RULE_INSTALLED=false
    else
        cp "${TMP_DIR}/${RULE_FILE}" "$dest"
        chmod 644 "$dest"
        ok "Rule installed: $dest"
        RULE_INSTALLED=true

        info "Reloading LiteSpeed..."
        local lswsctrl
        lswsctrl=$(command -v lswsctrl 2>/dev/null \
            || echo "/usr/local/lsws/bin/lswsctrl")
        if [[ -x "$lswsctrl" ]]; then
            "$lswsctrl" restart &>/dev/null \
                && ok "LiteSpeed reloaded" \
                || warn "lswsctrl restart failed — reload LiteSpeed manually to activate the rule"
        else
            warn "lswsctrl not found — reload LiteSpeed manually"
        fi
    fi

    # Verify rule is readable
    grep -r "id:${RULE_ID}" "$MODSEC_DIR" &>/dev/null \
        && ok "Rule ${RULE_ID} confirmed in ${MODSEC_DIR}" \
        || error "Rule ${RULE_ID} not found after install — check ModSecurity configuration"

    # Mirror into the DirectAdmin/CustomBuild "custom" dir so a CustomBuild
    # rebuild doesn't silently remove/disable the rule. Only attempted when
    # DirectAdmin is actually present on this host.
    if [[ -d "$DA_DIR" ]]; then
        mkdir -p "$CUSTOMBUILD_MODSEC_DIR" \
            && cp "${TMP_DIR}/${RULE_FILE}" "${CUSTOMBUILD_MODSEC_DIR}/${RULE_FILE}" \
            && chmod 644 "${CUSTOMBUILD_MODSEC_DIR}/${RULE_FILE}" \
            && ok "Rule mirrored to CustomBuild custom dir: ${CUSTOMBUILD_MODSEC_DIR}/${RULE_FILE}" \
            || warn "Could not mirror rule to ${CUSTOMBUILD_MODSEC_DIR} — CustomBuild rebuilds may drop the rule"
    else
        skip "DirectAdmin not detected — skipping CustomBuild mirror"
    fi
}

# =============================================================================
#  STEP 2 — Python Script
# =============================================================================
install_script() {
    section "Step 2 — Python monitor script"

    mkdir -p "$BIN_DIR"
    cp "${TMP_DIR}/monitor_modsec.py" "$SCRIPT_DEST"
    chmod 750 "$SCRIPT_DEST"
    chown root:root "$SCRIPT_DEST"
    ok "Script installed: $SCRIPT_DEST"

    python3 -c "import ast; ast.parse(open('$SCRIPT_DEST').read())" \
        && ok "Python syntax check passed" \
        || error "Python syntax error in $SCRIPT_DEST"
}

# =============================================================================
#  STEP 3 — Version stamp
#  Records the installed service version + commit in
#  /opt/modsec-bot-monitor/VERSION. The legacy path used by ServerHub's
#  agent collector (/usr/local/share/modsec-disable-badbots-version) is
#  kept working via a symlink. Best effort: if the GitHub API is
#  unreachable the install date is stamped instead, and this step never
#  fails the install.
# =============================================================================
install_version_stamp() {
    section "Step 3 — Version stamp (${SERVICE_VERSION})"

    local sha
    sha=$(curl -fsSL --max-time 10 "$GITHUB_API_COMMIT" 2>/dev/null \
        | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("sha",""))[:12])' 2>/dev/null) \
        || sha=""
    if [[ -z "${sha:-}" ]]; then
        sha="unknown"
        warn "Could not resolve latest commit SHA (GitHub API unreachable?) — stamping date only"
    fi

    local stamp="${SERVICE_VERSION} main@${sha} installed $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$(dirname "$VERSION_FILE")"
    echo "$stamp" > "$VERSION_FILE"
    chmod 644 "$VERSION_FILE"
    ok "Version stamp written: $(cat "$VERSION_FILE")"

    # Keep the legacy ServerHub collector path working via a symlink
    mkdir -p "$(dirname "$LEGACY_VERSION_FILE")"
    if [[ -e "$LEGACY_VERSION_FILE" || -L "$LEGACY_VERSION_FILE" ]]; then
        rm -f "$LEGACY_VERSION_FILE"
    fi
    if ln -sfn "$VERSION_FILE" "$LEGACY_VERSION_FILE"; then
        ok "Legacy stamp path linked: $LEGACY_VERSION_FILE -> $VERSION_FILE"
    else
        warn "Could not create legacy stamp symlink at $LEGACY_VERSION_FILE"
    fi
}

# =============================================================================
#  STEP 4 — State Directory
# =============================================================================
install_statedir() {
    section "Step 4 — State/data directory"

    mkdir -p "$STATE_DIR"
    chmod 750 "$STATE_DIR"
    ok "Directory ready: $STATE_DIR"

    if [[ -n "$(ls -A "$STATE_DIR" 2>/dev/null)" ]]; then
        info "Existing state detected — blocked-IP history and hit stats preserved"
    fi

    info "Files that live here:"
    echo -e "    ${CYN}state.json${NC}         — log offset + inode (for log rotation detection)"
    echo -e "    ${CYN}modsec_bad_bots.txt${NC} — cumulative IP/bot hit counts"
    echo -e "    ${CYN}blocked_ips.txt${NC}     — IPs already blocked via CSF (dedup guard)"
}

# =============================================================================
#  STEP 5 — Systemd Service
#  The unit file's home is /opt/modsec-bot-monitor/systemd/; a symlink from
#  /etc/systemd/system points at it, so the unit lives with the rest of the
#  service while systemd still finds it in its normal search path.
# =============================================================================
install_service() {
    section "Step 5 — Systemd service"

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
    fi

    mkdir -p "$SYSTEMD_DIR"
    cp "${TMP_DIR}/modsec-bot-monitor.service" "$UNIT_SOURCE"
    chmod 644 "$UNIT_SOURCE"
    ok "Service unit installed: $UNIT_SOURCE"

    ln -sfn "$UNIT_SOURCE" "$SERVICE_DEST"
    if [[ "$(readlink -f "$SERVICE_DEST")" == "$UNIT_SOURCE" ]]; then
        ok "Unit linked: $SERVICE_DEST -> $UNIT_SOURCE"
    else
        error "Failed to link $SERVICE_DEST -> $UNIT_SOURCE"
    fi

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" &>/dev/null
    ok "Service enabled (will start on boot)"

    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service is running"
        info "On startup, the service scans every domain's .modsecurity_rules file"
        info "under ${DA_USERS_DIR}/*/domains/ and re-enables"
        info "ModSecurity ('SecRuleEngine On') wherever it was disabled. Check"
        info "'journalctl -u ${SERVICE_NAME}' for a report of anything it fixed."
    else
        warn "Service did not start cleanly. Check logs with:"
        warn "  journalctl -u ${SERVICE_NAME} -n 30 --no-pager"
    fi
}

# =============================================================================
#  SUMMARY
# =============================================================================
print_summary() {
    echo ""
    echo -e "${GRN}${BLD}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║        Installation Complete — v${SERVICE_VERSION}                 ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${BLD}Service home (v2.1.0 layout):${NC} ${INSTALL_DIR}/"
    echo -e "  ${CYN}bin/${NC}        ${SCRIPT_DEST}"
    echo -e "  ${CYN}rules/${NC}      ${MASTER_RULE_FILE}  (rule master, source of truth)"
    echo -e "  ${CYN}systemd/${NC}    ${UNIT_SOURCE}"
    echo -e "  ${CYN}state/${NC}      ${STATE_DIR}/ (state.json, modsec_bad_bots.txt, blocked_ips.txt)"
    echo -e "  ${CYN}VERSION${NC}     ${VERSION_FILE} ($(cat "$VERSION_FILE" 2>/dev/null || echo 'n/a'))"
    echo ""
    echo -e "${BLD}Integration points outside /opt:${NC}"
    echo -e "  ${CYN}ModSec rule${NC}    ${MODSEC_DIR}/${RULE_FILE} (mirrored from rules/)"
    if [[ -d "$DA_DIR" ]]; then
        echo -e "  ${CYN}CustomBuild mirror${NC} ${CUSTOMBUILD_MODSEC_DIR}/${RULE_FILE}"
    fi
    echo -e "  ${CYN}Systemd unit${NC}   ${SERVICE_DEST} -> ${UNIT_SOURCE}"
    echo -e "  ${CYN}Legacy stamp${NC}   ${LEGACY_VERSION_FILE} -> ${VERSION_FILE}"
    echo ""

    echo -e "${BLD}Service management:${NC}"
    echo -e "  systemctl status  ${SERVICE_NAME}"
    echo -e "  systemctl stop    ${SERVICE_NAME}"
    echo -e "  systemctl restart ${SERVICE_NAME}"
    echo ""

    echo -e "${BLD}View live logs:${NC}"
    echo -e "  journalctl -u ${SERVICE_NAME} -f"
    echo -e "  journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    echo ""

    echo -e "${BLD}View bot statistics:${NC}"
    echo -e "  cat ${STATE_DIR}/modsec_bad_bots.txt"
    echo -e "  sort -t$'\\t' -k3 -rn ${STATE_DIR}/modsec_bad_bots.txt | head -20"
    echo ""

    echo -e "${BLD}View blocked IPs (by this service):${NC}"
    echo -e "  cat ${STATE_DIR}/blocked_ips.txt"
    echo -e "  wc -l ${STATE_DIR}/blocked_ips.txt"
    echo ""

    echo -e "${BLD}View CSF deny list:${NC}"
    echo -e "  grep 'modsec-bot-monitor' /etc/csf/csf.deny"
    echo -e "  csf -l | grep 777007"
    echo ""

    echo -e "${BLD}Test the ModSecurity rule:${NC}"
    echo -e "  curl -s -o /dev/null -w '%{http_code}' -A 'ClaudeBot/1.0' https://yourdomain.com"
    echo -e "  # Expected: 403"
    echo ""

    echo -e "${BLD}Verify rule is loaded in ModSecurity:${NC}"
    echo -e "  grep -r 'id:777007' ${MODSEC_DIR}"
    echo ""

    echo -e "${BLD}Reset service state (start tracking from scratch):${NC}"
    echo -e "  systemctl stop ${SERVICE_NAME}"
    echo -e "  rm -f ${STATE_DIR}/state.json"
    echo -e "  systemctl start ${SERVICE_NAME}"
    echo ""

    echo -e "${YLW}Note:${NC} On first start the service positions itself at the"
    echo -e "current log EOF and begins tracking new hits from that point."
    echo -e "It does NOT backfill historical log data."
    echo ""
}

# =============================================================================
#  MAIN
# =============================================================================
NAMESPACE_OK=true
RULE_INSTALLED=false

banner
preflight
detect_namespace_support
download_files
cleanup_previous_install
install_rule
install_script
install_version_stamp
install_statedir
install_service
print_summary
