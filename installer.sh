#!/usr/bin/env bash
# =============================================================================
#  ModSecurity Bad Bot Monitor — Installer
#  Project : ModSec_Disable_BadBots
#  GitHub  : https://github.com/ShahaB108/ModSec_Disable_BadBots
#  Stack   : DirectAdmin + LiteSpeed Enterprise + CSF Firewall
#  Run as  : root
# =============================================================================

set -euo pipefail

# ── Source URLs ───────────────────────────────────────────────────────────────
GITHUB_RAW="https://raw.githubusercontent.com/ShahaB108/ModSec_Disable_BadBots/refs/heads/main"
URL_SCRIPT="${GITHUB_RAW}/monitor_modsec.py"
URL_SERVICE="${GITHUB_RAW}/modsec-bot-monitor.service"
URL_RULE="${GITHUB_RAW}/777007_block_badbots.conf"

# ── Destination paths ─────────────────────────────────────────────────────────
RULE_ID="777007"
RULE_FILE="777007_block_badbots.conf"
MODSEC_DIR="/etc/modsecurity.d"
SCRIPT_DEST="/usr/local/bin/monitor_modsec.py"
SERVICE_NAME="modsec-bot-monitor"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
STATE_DIR="/var/lib/modsec_bot_monitor"

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
    echo "  ║     Rule ID: 777007 │ LiteSpeed + CSF + DirectAdmin   ║"
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

    python3 -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null \
        || error "Python 3.11+ required. Found: $(python3 --version)"
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
#  STEP 1 — ModSecurity Rule
# =============================================================================
install_rule() {
    section "Step 1 — ModSecurity Rule ${RULE_ID}"

    local dest="${MODSEC_DIR}/${RULE_FILE}"

    if grep -r --include="*.conf" "id:${RULE_ID}" "$MODSEC_DIR" &>/dev/null; then
        skip "Rule ${RULE_ID} already exists — skipping. To reinstall, remove existing file first."
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
}

# =============================================================================
#  STEP 2 — Python Script
# =============================================================================
install_script() {
    section "Step 2 — Python monitor script"

    cp "${TMP_DIR}/monitor_modsec.py" "$SCRIPT_DEST"
    chmod 750 "$SCRIPT_DEST"
    chown root:root "$SCRIPT_DEST"
    ok "Script installed: $SCRIPT_DEST"

    python3 -c "import ast; ast.parse(open('$SCRIPT_DEST').read())" \
        && ok "Python syntax check passed" \
        || error "Python syntax error in $SCRIPT_DEST"
}

# =============================================================================
#  STEP 3 — State Directory
# =============================================================================
install_statedir() {
    section "Step 3 — State/data directory"

    mkdir -p "$STATE_DIR"
    chmod 750 "$STATE_DIR"
    ok "Directory ready: $STATE_DIR"

    info "Files that will be created here at runtime:"
    echo -e "    ${CYN}state.json${NC}         — log offset + inode (for log rotation detection)"
    echo -e "    ${CYN}modsec_bad_bots.txt${NC} — cumulative IP/bot hit counts"
    echo -e "    ${CYN}blocked_ips.txt${NC}     — IPs already blocked via CSF (dedup guard)"
}

# =============================================================================
#  STEP 4 — Systemd Service
# =============================================================================
install_service() {
    section "Step 4 — Systemd service"

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
    fi

    cp "${TMP_DIR}/modsec-bot-monitor.service" "$SERVICE_DEST"
    chmod 644 "$SERVICE_DEST"
    ok "Service file installed: $SERVICE_DEST"

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" &>/dev/null
    ok "Service enabled (will start on boot)"

    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service is running"
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
    echo "  ║               Installation Complete                   ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${BLD}Installed files:${NC}"
    echo -e "  ${CYN}ModSec rule${NC}   ${MODSEC_DIR}/${RULE_FILE}"
    echo -e "  ${CYN}Python script${NC} ${SCRIPT_DEST}"
    echo -e "  ${CYN}Systemd unit${NC}  ${SERVICE_DEST}"
    echo -e "  ${CYN}State dir${NC}     ${STATE_DIR}/"
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
install_rule
install_script
install_statedir
install_service
print_summary
