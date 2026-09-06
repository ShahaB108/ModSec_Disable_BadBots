#!/usr/bin/env python3
"""
ModSecurity Rule 777007 - Bad Bot Monitor & CSF Blocker
Production-grade | DirectAdmin + LiteSpeed + CSF

Version : 2.1.0
Layout  : since v2.1.0 all service-owned files live under
          /opt/modsec-bot-monitor (bin/, rules/, state/, systemd/, VERSION).
          Only integration points remain outside: the active rule mirror in
          /etc/modsecurity.d (+ CustomBuild custom dir on DirectAdmin hosts)
          and the symlinked systemd unit in /etc/systemd/system.
"""

import glob
import json
import logging
import logging.handlers
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# ===================== Configuration =====================
# All tunables live here. Edit this block to customize behavior —
# nothing below this section should need to change for normal use.

# ── Version ────────────────────────────────────────────────
VERSION = "2.1.0"

# ── Paths: service home (v2.1.0 layout) ────────────────────
# Every file this service owns lives under INSTALL_DIR: the script
# (bin/), the rule master copy (rules/), runtime state (state/) and
# the systemd unit (systemd/, symlinked into /etc/systemd/system).
INSTALL_DIR     = "/opt/modsec-bot-monitor"

# ── Paths: ModSecurity audit log ──────────────────────────
# Path to the ModSecurity JSON audit log this service tails.
LOG_FILE        = "/var/log/httpd/modsec_audit.log"

# ── Paths: local state / data directory ───────────────────
# Directory where this service persists its own state and stats.
STATE_DIR       = f"{INSTALL_DIR}/state"
# Tracks last-read log offset + inode (for log rotation detection).
STATE_FILE      = f"{STATE_DIR}/state.json"
# Cumulative "IP + bot name -> hit count" table, written each cycle.
DATA_FILE       = f"{STATE_DIR}/modsec_bad_bots.txt"
# List of IPs already blocked via CSF by this service (dedup guard).
BLOCKED_FILE    = f"{STATE_DIR}/blocked_ips.txt"

# ── CSF (ConfigServer Security & Firewall) integration ────
# CSF's deny list, read directly to check if an IP is already blocked.
CSF_DENY_FILE   = "/etc/csf/csf.deny"

# ── Monitoring cycle behavior ─────────────────────────────
# Seconds between each log-parsing / blocking cycle.
CHECK_INTERVAL  = 600
# ModSecurity rule ID this service watches for in the audit log.
RULE_ID         = "777007"
# Cumulative hit count (per IP+bot) required before CSF blocks the IP.
BLOCK_THRESHOLD = 30
# Memory guard: max unique IP+bot combos kept in the stats table.
MAX_STATS_KEYS  = 50000

# ── Rule file watchdog ─────────────────────────────────────
# Master copy of the rule — the source of truth for this service.
MASTER_RULE_DIR      = f"{INSTALL_DIR}/rules"
MASTER_RULE_FILE     = f"{MASTER_RULE_DIR}/777007_block_badbots.conf"
# Active copy actually included by ModSecurity.
RULE_FILE            = "/etc/modsecurity.d/777007_block_badbots.conf"
# DirectAdmin installation root — when present, the rule is also
# mirrored into CustomBuild's "custom" rule directory. CustomBuild
# rebuilds can wipe unmanaged files from /etc/modsecurity.d, but they
# preserve and reapply anything placed here, keeping the rule safe
# across DirectAdmin/CustomBuild updates.
DA_DIR                = "/usr/local/directadmin"
CUSTOMBUILD_RULE_DIR  = f"{DA_DIR}/custombuild/custom/modsecurity/conf"
CUSTOMBUILD_RULE_FILE = f"{CUSTOMBUILD_RULE_DIR}/777007_block_badbots.conf"
# Source URL used to re-download the rule file — only as a last-resort
# fallback when the master copy is missing and cannot be recovered
# locally from the active copy.
RULE_URL              = (
    "https://raw.githubusercontent.com/ShahaB108/"
    "ModSec_Disable_BadBots/refs/heads/main/777007_block_badbots.conf"
)
# LiteSpeed control binary, used to reload the webserver after a restore.
LSWS_CTL              = "/usr/local/lsws/bin/lswsctrl"
# How often (seconds) to re-verify all rule file locations.
RULE_CHECK_INTERVAL   = 21600   # 6 hours

# ── Per-domain ModSecurity enforcement ──────────────────────
# DirectAdmin per-user data directory. Each domain has its own
# <domain>.modsecurity_rules file under <user>/domains/ that can turn
# ModSecurity (and therefore rule 777007) off for that domain alone.
DA_USERS_DIR             = "/usr/local/directadmin/data/users"
# Glob pattern (relative to DA_USERS_DIR) matching every domain's
# per-domain ModSecurity toggle file.
DOMAIN_MODSEC_RULES_GLOB = "*/domains/*.modsecurity_rules"
# NOTE: ModSecurity is force-enabled on all domains only ONCE, on service
# startup (i.e. effectively at install time). After that, this service
# never flips a domain back on by itself — if an admin or DirectAdmin
# user turns it off later, that's respected. Every monitoring cycle just
# logs a warning for any domain currently found disabled, so it's visible
# without being silently overridden.
# =========================================================

_shutdown = False


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("modsec-bot-monitor")
    logger.setLevel(logging.INFO)
    try:
        syslog = logging.handlers.SysLogHandler(address="/dev/log")
        syslog.setFormatter(logging.Formatter(
            "modsec-bot-monitor[%(process)d]: %(levelname)s %(message)s"
        ))
        logger.addHandler(syslog)
    except Exception:
        pass
    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(stdout)
    return logger


log = setup_logging()


def signal_handler(sig, frame):
    global _shutdown
    _shutdown = True
    log.info(f"Received signal {sig}, shutting down cleanly...")


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)


def ensure_dirs():
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)


# ──────────────────── State / persistence ────────────────────

def load_state() -> dict:
    default = {"offset": None, "inode": None}
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                return {**default, **json.load(f)}
    except Exception as e:
        log.warning(f"Could not load state file: {e}")
    return default


def save_state(offset: int, inode: int):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"offset": offset, "inode": inode}, f)
    except Exception as e:
        log.error(f"Could not save state: {e}")


def load_blocked_ips() -> set:
    blocked = set()
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE) as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        blocked.add(ip)
    except Exception as e:
        log.warning(f"Could not load blocked IPs: {e}")
    return blocked


def save_blocked_ips(blocked: set):
    try:
        with open(BLOCKED_FILE, "w") as f:
            for ip in sorted(blocked):
                f.write(f"{ip}\n")
    except Exception as e:
        log.error(f"Could not save blocked IPs: {e}")


def load_existing_stats() -> dict:
    stats = {}
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        key = f"{parts[0]}\t{parts[1]}"
                        try:
                            stats[key] = int(parts[2])
                        except ValueError:
                            pass
    except Exception as e:
        log.warning(f"Could not load existing stats: {e}")
    return stats


def save_stats(stats: dict):
    try:
        with open(DATA_FILE, "w") as f:
            for key, count in sorted(stats.items(), key=lambda x: -x[1]):
                f.write(f"{key}\t{count}\n")
    except Exception as e:
        log.error(f"Could not save stats: {e}")


# ──────────────────── Bot name extraction ────────────────────

_KNOWN_BOTS = re.compile(
    r"(ahrefsbot|baiduspider|blexbot|barkrowler|semrushbot|claudebot|yandexbot|bytespider"
    r"|aliyunsecbot|bingbot|mb2345browser|liebaofast|micromessenger|kinza|datanyze"
    r"|serpstatbot|spaziodati|aspiegelbot|petalbot|meta-externalagent|meta-webindexer"
    r"|imagesiftbot|amazonbot|dotbot|gptbot|mj12bot|ccbot|duckduckbot|facebot|facebookbot"
    r"|twitterbot|slackbot|discordbot|sogou.*?spider|exabot|applebot|linkedinbot|siteimprove"
    r"|zoominfobot|scrapy|dataforseobot|mauibot|neevabot|perplexitybot|anthropic-ai"
    r"|cohere-ai|pinterestbot|timpibot|magpie-crawler|python-requests|python-httpx"
    r"|go-http-client|libwww-perl)",
    re.IGNORECASE,
)
_GENERIC_BOT = re.compile(r"([a-z0-9.\-]+bot)", re.IGNORECASE)
_CRAWLER     = re.compile(r"(bot|crawler|spider|scraper)", re.IGNORECASE)

_IP_RE = re.compile(r'"client_ip"\s*:\s*"([^"]+)"')
_UA_RE = re.compile(r'"user-agent"\s*:\s*"([^"]*)"', re.IGNORECASE)


def extract_bot_name(user_agent: str) -> str:
    for pat in (_KNOWN_BOTS, _GENERIC_BOT, _CRAWLER):
        m = pat.search(user_agent)
        if m:
            name = re.sub(r"[^a-zA-Z0-9.\-]", "", m.group(1))
            if len(name) > 2:
                return name[:30]
    return "unknown"



# ──────────────────── Rule file watchdog ─────────────────────

def _copy_into_place(src: str, dest: str) -> bool:
    """
    Copy src -> dest, creating dest's parent directory if needed and
    forcing 0644 permissions (rule files must stay world-readable for
    the webserver, even when restored from a 0600 /tmp download).
    """
    import shutil
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        os.chmod(dest, 0o644)
        return True
    except Exception as e:
        log.error(f"Failed to copy rule file to {dest}: {e}")
        return False


def _files_identical(path_a: str, path_b: str) -> bool:
    """True when both files exist and have byte-identical content."""
    try:
        with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
            return fa.read() == fb.read()
    except Exception:
        return False


def _download_rule_file():
    """
    Download the rule file from GitHub into /tmp. Returns the temp
    path on success, or None on any failure (already logged).
    """
    tmp_path = "/tmp/777007_block_badbots.conf.tmp"
    try:
        result = subprocess.run(
            ["wget", "-q", "-O", tmp_path, RULE_URL],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            log.error(f"wget failed (exit {result.returncode}): {result.stderr.strip()}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return None

        size = os.path.getsize(tmp_path)
        if size < 50:
            log.error(f"Downloaded file too small ({size} bytes), removing")
            os.remove(tmp_path)
            return None

        return tmp_path

    except FileNotFoundError:
        log.error("wget not found — install wget or check PATH")
        return None
    except subprocess.TimeoutExpired:
        log.error("wget timed out after 60s")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return None
    except Exception as e:
        log.error(f"Unexpected error during download: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return None


def _reload_litespeed():
    try:
        result = subprocess.run(
            [LSWS_CTL, "restart"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info("LiteSpeed reloaded successfully after rule restore")
        else:
            log.warning(f"LiteSpeed reload returned non-zero: {result.stderr.strip()}")
    except FileNotFoundError:
        log.error(f"lswsctrl not found at {LSWS_CTL} — rule restored but LiteSpeed NOT reloaded")
    except subprocess.TimeoutExpired:
        log.error("LiteSpeed reload timed out")
    except Exception as e:
        log.error(f"Unexpected error reloading LiteSpeed: {e}")


def check_rule_file():
    """
    Keep the rule file present and consistent in all locations:

      MASTER_RULE_FILE       /opt/modsec-bot-monitor/rules/...  (source of truth)
      RULE_FILE              /etc/modsecurity.d/...             (active copy included by ModSecurity)
      CUSTOMBUILD_RULE_FILE  DirectAdmin/CustomBuild custom dir (DirectAdmin hosts only)

    Recovery order:
      1. Master missing, active copy present         -> recover master from the active copy
      2. Master missing everywhere                   -> download from GitHub into master
      3. Master present, active copy missing/drifted -> re-mirror master -> active (+ LiteSpeed reload)
      4. Master present, DA mirror missing/drifted   -> re-mirror master -> CustomBuild dir
    """
    master_ok = os.path.exists(MASTER_RULE_FILE)
    active_ok = os.path.exists(RULE_FILE)

    # 1) Establish/recover the master copy first.
    if not master_ok:
        if active_ok:
            log.warning(
                f"Master rule missing: {MASTER_RULE_FILE} — recovering from {RULE_FILE}"
            )
            if _copy_into_place(RULE_FILE, MASTER_RULE_FILE):
                master_ok = True
                log.info(f"Master rule recovered -> {MASTER_RULE_FILE}")
        if not master_ok:
            log.warning("Rule file missing everywhere — downloading from GitHub as last resort")
            tmp_path = _download_rule_file()
            if tmp_path is None:
                log.error("Could not restore master rule copy — existing copies left untouched")
                return
            size = os.path.getsize(tmp_path)
            master_ok = _copy_into_place(tmp_path, MASTER_RULE_FILE)
            os.remove(tmp_path)
            if not master_ok:
                log.error("Failed to restore master rule copy — see error above")
                return
            log.info(f"Master rule restored ({size} bytes) -> {MASTER_RULE_FILE}")

    reload_needed = False

    # 2) Active copy: restore if missing, re-sync if drifted.
    if not active_ok:
        log.warning(f"Active rule missing: {RULE_FILE} — re-mirroring from master")
        if _copy_into_place(MASTER_RULE_FILE, RULE_FILE):
            log.info(f"Active rule restored -> {RULE_FILE}")
            reload_needed = True
    elif not _files_identical(MASTER_RULE_FILE, RULE_FILE):
        log.warning(
            f"Active rule drifted from master — re-syncing {MASTER_RULE_FILE} -> {RULE_FILE}"
        )
        if _copy_into_place(MASTER_RULE_FILE, RULE_FILE):
            log.info(f"Active rule re-synced -> {RULE_FILE}")
            reload_needed = True

    # 3) CustomBuild mirror: only on DirectAdmin hosts (kept in sync so a
    #    CustomBuild rebuild can't drop the rule).
    if os.path.isdir(DA_DIR):
        if not os.path.exists(CUSTOMBUILD_RULE_FILE):
            log.warning(
                f"CustomBuild copy missing: {CUSTOMBUILD_RULE_FILE} — re-mirroring from master"
            )
            if _copy_into_place(MASTER_RULE_FILE, CUSTOMBUILD_RULE_FILE):
                log.info(f"CustomBuild copy restored -> {CUSTOMBUILD_RULE_FILE}")
        elif not _files_identical(MASTER_RULE_FILE, CUSTOMBUILD_RULE_FILE):
            log.warning(
                f"CustomBuild copy drifted from master — re-syncing -> {CUSTOMBUILD_RULE_FILE}"
            )
            _copy_into_place(MASTER_RULE_FILE, CUSTOMBUILD_RULE_FILE)

    if reload_needed:
        _reload_litespeed()


# ── Per-domain ModSecurity enforcement ──────────────────────

_SEC_RULE_ENGINE_OFF_RE = re.compile(r"^(\s*SecRuleEngine\s+)Off\b", re.IGNORECASE | re.MULTILINE)


def _enable_modsecurity_in_file(path: str) -> bool:
    """
    Flip 'SecRuleEngine Off' -> 'SecRuleEngine On' in a single
    .modsecurity_rules file. Returns True if the file was changed.
    Writes via a tmp file + os.replace in the same directory for an
    atomic, permission-safe update (same pattern as the rule watchdog).
    """
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception as e:
        log.error(f"Failed to read {path}: {e}")
        return False

    if not _SEC_RULE_ENGINE_OFF_RE.search(content):
        return False

    new_content = _SEC_RULE_ENGINE_OFF_RE.sub(r"\1On", content)

    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w") as f:
            f.write(new_content)
        os.replace(tmp_path, path)
        return True
    except Exception as e:
        log.error(f"Failed to write {path}: {e}")
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return False


def enforce_modsecurity_enabled():
    """
    Scan every domain's DirectAdmin .modsecurity_rules file and
    re-enable ModSecurity ('SecRuleEngine On') wherever it's been
    switched off, so rule 777007 (and every other rule) stays active
    site-wide. Reloads LiteSpeed once at the end if anything changed.
    """
    pattern = os.path.join(DA_USERS_DIR, DOMAIN_MODSEC_RULES_GLOB)
    try:
        matches = glob.glob(pattern)
    except Exception as e:
        log.error(f"Failed to glob {pattern}: {e}")
        return

    if not matches:
        log.debug(f"No domain ModSecurity rule files found under {DA_USERS_DIR}")
        return

    fixed = []
    for path in matches:
        try:
            if _enable_modsecurity_in_file(path):
                fixed.append(path)
        except Exception as e:
            log.error(f"Unexpected error processing {path}: {e}")

    if not fixed:
        log.debug(f"Checked {len(matches)} domain(s) — ModSecurity already enabled everywhere")
        return

    log.warning(f"ModSecurity was disabled on {len(fixed)} domain(s), re-enabled:")
    for path in fixed:
        log.warning(f"  -> {path}")

    _reload_litespeed()


def check_domain_modsec_status():
    """
    Read-only check: scan every domain's .modsecurity_rules file and log
    a warning for any domain currently disabled ('SecRuleEngine Off').
    Unlike enforce_modsecurity_enabled(), this NEVER modifies files or
    reloads LiteSpeed — it only reports. Intended to run on every
    monitoring cycle so a disabled domain stays visible in the logs
    without this service silently flipping it back on behind an admin's
    or user's back after the one-time startup enforcement.
    """
    pattern = os.path.join(DA_USERS_DIR, DOMAIN_MODSEC_RULES_GLOB)
    try:
        matches = glob.glob(pattern)
    except Exception as e:
        log.error(f"Failed to glob {pattern}: {e}")
        return

    if not matches:
        return

    disabled = []
    for path in matches:
        try:
            with open(path, "r") as f:
                content = f.read()
        except Exception as e:
            log.error(f"Failed to read {path}: {e}")
            continue

        if _SEC_RULE_ENGINE_OFF_RE.search(content):
            disabled.append(path)

    for path in disabled:
        log.warning(f"ModSecurity is disabled for domain: {path}")


# ──────────────────── CSF integration ────────────────────────

def is_ip_in_csf_deny(ip: str) -> bool:
    """
    Read /etc/csf/csf.deny directly instead of spawning csf -g.
    Much faster, no subprocess overhead, and non-destructive.
    """
    try:
        with open(CSF_DENY_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: "1.2.3.4 # comment" or "1.2.3.4/32 # comment"
                entry = line.split()[0].split("/")[0]
                if entry == ip:
                    return True
    except FileNotFoundError:
        log.warning(f"CSF deny file not found: {CSF_DENY_FILE}")
    except Exception as e:
        log.warning(f"Error reading CSF deny file: {e}")
    return False


def block_ip(ip: str, bot_name: str, count: int, blocked: set) -> bool:
    """
    Attempt to block an IP via CSF. Returns True only on a new successful block.
    Uses in-memory set + csf.deny file as dual guard against duplicate blocks.
    """
    if ip in blocked:
        return False

    if is_ip_in_csf_deny(ip):
        log.debug(f"IP {ip} already in csf.deny, skipping")
        blocked.add(ip)
        return False

    # comment = f"ModSec-777007 BadBot {bot_name} ({count} hits)"
    comment = f"modsec-bot-monitor: Rule 777007 BadBot {bot_name} ({count} hits) - {time.strftime('%a %b %d %H:%M:%S')}"
    try:
        result = subprocess.run(
            ["csf", "-d", ip, comment],
            capture_output=True, text=True, timeout=15,
        )
        output_combined = (result.stdout + result.stderr).lower()
        if result.returncode == 0:
            log.info(f"Blocked {ip} via CSF — {bot_name}, {count} hits")
            blocked.add(ip)
            return True
        elif "already" in output_combined:
            log.debug(f"IP {ip} already blocked in CSF (reported by csf)")
            blocked.add(ip)
            return False
        else:
            log.warning(f"CSF block failed for {ip}: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        log.error(f"csf -d timed out for IP {ip}")
        return False
    except FileNotFoundError:
        log.error("csf binary not found — is CSF installed?")
        return False
    except Exception as e:
        log.error(f"Unexpected error blocking {ip}: {e}")
        return False


# ──────────────────── Main processing cycle ──────────────────

def run_cycle(blocked: set) -> bool:
    """
    Read new log entries since last offset, merge with cumulative stats,
    block IPs above threshold. Returns True if any new IPs were blocked.
    """
    state = load_state()
    saved_inode = state["inode"]
    saved_offset = state["offset"]

    try:
        stat = os.stat(LOG_FILE)
        current_inode = stat.st_ino
        current_size  = stat.st_size
    except FileNotFoundError:
        log.warning(f"Log file not found: {LOG_FILE}")
        return False

    # First run ever: start tracking from current EOF, don't re-read old log
    if saved_offset is None:
        log.info("First run — positioning at current log EOF, no historical backfill")
        save_state(current_size, current_inode)
        return False

    # Log rotation detected via inode change
    if saved_inode and current_inode != saved_inode:
        log.info(f"Log rotation detected (inode {saved_inode} → {current_inode}), resetting offset")
        saved_offset = 0

    new_hits: dict[str, int] = defaultdict(int)
    new_offset = saved_offset

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(saved_offset)
            while True:
                line = f.readline()
                if not line:
                    break
                if RULE_ID in line:
                    ip_m = _IP_RE.search(line)
                    ua_m = _UA_RE.search(line)
                    if ip_m and ua_m:
                        ip  = ip_m.group(1).strip()
                        bot = extract_bot_name(ua_m.group(1))
                        key = f"{ip}\t#{bot}"
                        new_hits[key] += 1
                new_offset = f.tell()
    except Exception as e:
        log.error(f"Error reading log: {e}")
        return False

    save_state(new_offset, current_inode)
    log.info(f"Parsed {len(new_hits)} new IP/bot pairs from log")

    if not new_hits:
        return False

    # Merge new hits with historical cumulative totals
    all_stats = load_existing_stats()
    for key, cnt in new_hits.items():
        all_stats[key] = all_stats.get(key, 0) + cnt

    # Memory guard — trim to top N entries
    if len(all_stats) > MAX_STATS_KEYS:
        log.warning(f"Stats map hit {len(all_stats)} entries, trimming to {MAX_STATS_KEYS}")
        all_stats = dict(sorted(all_stats.items(), key=lambda x: -x[1])[:MAX_STATS_KEYS])

    save_stats(all_stats)

    # Block IPs above threshold
    newly_blocked = 0
    for key, count in all_stats.items():
        if count < BLOCK_THRESHOLD:
            continue
        parts = key.split("\t")
        ip       = parts[0]
        bot_name = parts[1].lstrip("#") if len(parts) > 1 else "unknown"
        if block_ip(ip, bot_name, count, blocked):
            newly_blocked += 1

    if newly_blocked:
        log.info(f"Blocked {newly_blocked} new IPs via CSF this cycle")
        save_blocked_ips(blocked)

    return newly_blocked > 0


def main():
    if "--version" in sys.argv[1:]:
        print(f"modsec-bot-monitor {VERSION}")
        return

    ensure_dirs()
    blocked = load_blocked_ips()
    log.info(
        f"modsec-bot-monitor v{VERSION} started — interval={CHECK_INTERVAL}s, "
        f"threshold={BLOCK_THRESHOLD} hits, {len(blocked)} IPs pre-loaded from history"
    )

    # Rule file watchdog: check immediately on startup, then every RULE_CHECK_INTERVAL
    try:
        check_rule_file()
    except Exception as e:
        log.error(f"Unhandled error in rule file check: {e}", exc_info=True)
    last_rule_check = time.monotonic()

    # Per-domain ModSecurity enforcement: force-enable ONCE on startup only
    # (effectively "at install time"). After this, the service never
    # re-enables a domain on its own — see check_domain_modsec_status()
    # in the main loop below, which only warns.
    try:
        enforce_modsecurity_enabled()
    except Exception as e:
        log.error(f"Unhandled error in domain ModSecurity enforcement: {e}", exc_info=True)

    while not _shutdown:
        try:
            run_cycle(blocked)
        except Exception as e:
            log.error(f"Unhandled error in cycle: {e}", exc_info=True)

        if time.monotonic() - last_rule_check >= RULE_CHECK_INTERVAL:
            try:
                check_rule_file()
            except Exception as e:
                log.error(f"Unhandled error in rule file check: {e}", exc_info=True)
            last_rule_check = time.monotonic()

        # Read-only: warn (don't re-enable) if a domain currently has
        # ModSecurity switched off.
        try:
            check_domain_modsec_status()
        except Exception as e:
            log.error(f"Unhandled error in domain ModSecurity status check: {e}", exc_info=True)

        # Sleep in short chunks so SIGTERM is handled quickly
        for _ in range(CHECK_INTERVAL // 5):
            if _shutdown:
                break
            time.sleep(5)

    log.info("modsec-bot-monitor stopped gracefully")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
