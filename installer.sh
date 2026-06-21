#!/usr/bin/env bash
# install.sh — ModSecurity Bad Bot Monitor installer
# Environment: DirectAdmin + LiteSpeed Enterprise + CSF
# Run as root

set -euo pipefail

RULE_ID="777007"
RULE_FILE="777007_block_badbots.conf"
MODSEC_DIR="/etc/modsecurity.d"
SCRIPT_SRC="monitor_modsec.py"
SCRIPT_DEST="/usr/local/bin/monitor_modsec.py"
SERVICE_SRC="modsec-bot-monitor.service"
SERVICE_DEST="/etc/systemd/system/modsec-bot-monitor.service"
STATE_DIR="/var/lib/modsec_bot_monitor"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Pre-flight checks ──────────────────────────────────────────

[[ $EUID -ne 0 ]] && error "Must be run as root."

for bin in python3 csf; do
    command -v "$bin" &>/dev/null || error "'$bin' not found in PATH."
done

python3 -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null \
    || error "Python 3.11+ required. Found: $(python3 --version)"

[[ -d "$MODSEC_DIR" ]] || error "ModSecurity directory not found: $MODSEC_DIR"

for f in "$RULE_FILE" "$SCRIPT_SRC" "$SERVICE_SRC"; do
    [[ -f "./$f" ]] || error "Required file not found in current directory: $f"
done

# ── Step 1: ModSecurity rule ───────────────────────────────────

info "Checking ModSecurity rule $RULE_ID..."

DEST_RULE="$MODSEC_DIR/$RULE_FILE"
RULE_EXISTS=false

if grep -r --include="*.conf" "id:${RULE_ID}" "$MODSEC_DIR" &>/dev/null; then
    RULE_EXISTS=true
fi

if [[ "$RULE_EXISTS" == true ]]; then
    warn "Rule $RULE_ID already exists in $MODSEC_DIR — skipping rule installation."
    warn "To force reinstall, remove existing rule file and re-run."
else
    cp "./$RULE_FILE" "$DEST_RULE"
    chmod 644 "$DEST_RULE"
    info "Rule $RULE_ID installed at $DEST_RULE"

    info "Reloading LiteSpeed..."
    if command -v lswsctrl &>/dev/null; then
        lswsctrl restart && info "LiteSpeed reloaded." || warn "lswsctrl restart failed — reload manually."
    elif [[ -x /usr/local/lsws/bin/lswsctrl ]]; then
        /usr/local/lsws/bin/lswsctrl restart && info "LiteSpeed reloaded." || warn "lswsctrl restart failed."
    else
        warn "lswsctrl not found — reload LiteSpeed manually to activate the rule."
    fi
fi

# Verify rule is active
if grep -r "id:${RULE_ID}" "$MODSEC_DIR" &>/dev/null; then
    info "Rule $RULE_ID confirmed active in $MODSEC_DIR"
else
    error "Rule $RULE_ID not found after install — check ModSecurity config."
fi

# ── Step 2: Python monitor script ─────────────────────────────

info "Installing monitor script to $SCRIPT_DEST..."
cp "./$SCRIPT_SRC" "$SCRIPT_DEST"
chmod 750 "$SCRIPT_DEST"
chown root:root "$SCRIPT_DEST"
info "Script installed."

# ── Step 3: State directory ────────────────────────────────────

info "Creating state directory $STATE_DIR..."
mkdir -p "$STATE_DIR"
chmod 750 "$STATE_DIR"
info "State directory ready."

# ── Step 4: Systemd service ────────────────────────────────────

info "Installing systemd service..."

EXISTING_ACTIVE=false
if systemctl is-active --quiet modsec-bot-monitor 2>/dev/null; then
    EXISTING_ACTIVE=true
    info "Stopping existing service before update..."
    systemctl stop modsec-bot-monitor
fi

cp "./$SERVICE_SRC" "$SERVICE_DEST"
chmod 644 "$SERVICE_DEST"

systemctl daemon-reload
systemctl enable modsec-bot-monitor
systemctl start modsec-bot-monitor

sleep 2
if systemctl is-active --quiet modsec-bot-monitor; then
    info "Service modsec-bot-monitor is running."
else
    warn "Service may have failed to start. Check with:"
    warn "  journalctl -u modsec-bot-monitor -n 50"
fi

# ── Summary ────────────────────────────────────────────────────

echo ""
echo -e "${GRN}═══════════════════════════════════════════════════${NC}"
echo -e "${GRN} Installation complete${NC}"
echo -e "${GRN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "  Rule file  : $DEST_RULE"
echo "  Script     : $SCRIPT_DEST"
echo "  Service    : $SERVICE_DEST"
echo "  State dir  : $STATE_DIR"
echo ""
echo "  Useful commands:"
echo "    systemctl status modsec-bot-monitor"
echo "    journalctl -u modsec-bot-monitor -f"
echo "    cat $STATE_DIR/modsec_bad_bots.txt"
echo "    cat $STATE_DIR/blocked_ips.txt"
echo ""
