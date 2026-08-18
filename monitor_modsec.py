#!/usr/bin/env python3
"""
ModSecurity Rule 777007 - Bad Bot Monitor & CSF Blocker
Production-grade | DirectAdmin + LiteSpeed + CSF
"""

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

# ── Paths: ModSecurity audit log ──────────────────────────
# Path to the ModSecurity JSON audit log this service tails.
LOG_FILE        = "/var/log/httpd/modsec_audit.log"

# ── Paths: local state / data directory ───────────────────
# Directory where this service persists its own state and stats.
STATE_DIR       = "/var/lib/modsec_bot_monitor"
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
CHECK_INTERVAL  = 300
# ModSecurity rule ID this service watches for in the audit log.
RULE_ID         = "777007"
# Cumulative hit count (per IP+bot) required before CSF blocks the IP.
BLOCK_THRESHOLD = 5
# Memory guard: max unique IP+bot combos kept in the stats table.
MAX_STATS_KEYS  = 50000

# ── Rule file watchdog ─────────────────────────────────────
# Primary ModSecurity rule file location (used by ModSecurity itself).
RULE_FILE            = "/etc/modsecurity.d/777007_block_badbots.conf"
# DirectAdmin/CustomBuild "custom" rule directory. CustomBuild rebuilds
# can wipe unmanaged files from /etc/modsecurity.d, but it preserves and
# reapplies anything placed here — so we mirror the rule file into this
# path too, keeping it safe across DirectAdmin/CustomBuild updates.
CUSTOMBUILD_RULE_DIR  = "/usr/local/directadmin/custombuild/custom/modsecurity/conf"
CUSTOMBUILD_RULE_FILE = f"{CUSTOMBUILD_RULE_DIR}/777007_block_badbots.conf"
# Source URL used to re-download the rule file if it goes missing.
RULE_URL              = (
    "https://raw.githubusercontent.com/ShahaB108/"
    "ModSec_Disable_BadBots/refs/heads/main/777007_block_badbots.conf"
)
# LiteSpeed control binary, used to reload the webserver after a restore.
LSWS_CTL              = "/usr/local/lsws/bin/lswsctrl"
# How often (seconds) to re-verify both rule file locations exist.
RULE_CHECK_INTERVAL   = 7200   # 2 hours
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
    Copy src -> dest via /tmp staging, avoiding direct writes to
    guarded directories (e.g. Imunify360's real-time file guard on
    /etc/modsecurity.d). Creates dest's parent directory if needed.
    """
    import shutil
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        return True
    except Exception as e:
        log.error(f"Failed to copy rule file to {dest}: {e}")
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
    Verify the rule file exists in BOTH locations:
      - RULE_FILE            (active ModSecurity config)
      - CUSTOMBUILD_RULE_FILE (DirectAdmin/CustomBuild "custom" dir,
                                so a CustomBuild rebuild won't drop it)

    If RULE_FILE is missing, download fresh from GitHub and place it
    in both locations, then reload LiteSpeed. If only the CustomBuild
    copy is missing, just re-mirror the existing RULE_FILE — no
    download needed.
    """
    modsec_ok      = os.path.exists(RULE_FILE)
    custombuild_ok = os.path.exists(CUSTOMBUILD_RULE_FILE)

    if modsec_ok and custombuild_ok:
        log.debug(f"Rule file OK in both locations: {RULE_FILE}, {CUSTOMBUILD_RULE_FILE}")
        return

    if modsec_ok and not custombuild_ok:
        log.warning(
            f"CustomBuild copy missing: {CUSTOMBUILD_RULE_FILE} — "
            f"re-mirroring from {RULE_FILE}"
        )
        if _copy_into_place(RULE_FILE, CUSTOMBUILD_RULE_FILE):
            log.info(f"CustomBuild copy restored -> {CUSTOMBUILD_RULE_FILE}")
        return

    log.warning(f"Rule file missing: {RULE_FILE} — downloading from GitHub")

    tmp_path = _download_rule_file()
    if tmp_path is None:
        return

    size = os.path.getsize(tmp_path)
    ok_main = _copy_into_place(tmp_path, RULE_FILE)
    ok_custombuild = _copy_into_place(tmp_path, CUSTOMBUILD_RULE_FILE)
    os.remove(tmp_path)

    if not ok_main:
        log.error("Failed to restore rule file to primary ModSecurity path")
        return

    log.info(f"Rule file restored ({size} bytes) -> {RULE_FILE}")
    if ok_custombuild:
        log.info(f"Rule file mirrored -> {CUSTOMBUILD_RULE_FILE}")
    else:
        log.warning(
            f"Primary rule file restored, but mirroring to "
            f"{CUSTOMBUILD_RULE_FILE} failed — see error above"
        )

    _reload_litespeed()


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
    ensure_dirs()
    blocked = load_blocked_ips()
    log.info(
        f"modsec-bot-monitor started — interval={CHECK_INTERVAL}s, "
        f"threshold={BLOCK_THRESHOLD} hits, {len(blocked)} IPs pre-loaded from history"
    )

    # Rule file watchdog: check immediately on startup, then every 12 hours
    try:
        check_rule_file()
    except Exception as e:
        log.error(f"Unhandled error in rule file check: {e}", exc_info=True)
    last_rule_check = time.monotonic()

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

        # Sleep in short chunks so SIGTERM is handled quickly
        for _ in range(CHECK_INTERVAL // 5):
            if _shutdown:
                break
            time.sleep(5)

    log.info("modsec-bot-monitor stopped gracefully")
    sys.stdout.flush()


if __name__ == "__main__":
    main()