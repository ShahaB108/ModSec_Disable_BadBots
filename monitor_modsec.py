#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import subprocess
import signal
import sys
from collections import defaultdict

# ===================== Configuration =====================
LOG_FILE = "/var/log/httpd/modsec_audit.log"
STATE_FILE = "/var/log/modsec_bot_monitor.state"
DATA_FILE = "/var/log/modsec_bad_bots.txt"
CHECK_INTERVAL = 600  # 10 minutes
RULE_ID = "777007"
BLOCK_THRESHOLD = 5   # Minimum hits before blocking via CSF
# ======================================================

running = True

def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    global running
    running = False
    print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received signal {sig}. Stopping service...")
    # Force exit after a short delay to allow systemd to detect stop
    sys.stdout.flush()
    time.sleep(1)
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

def extract_bot_name(user_agent):
    """Extract short bot name from User-Agent string"""
    ua = user_agent.lower()
    
    bot_patterns = [
        r'(ahrefsbot|baiduspider|blexbot|barkrowler|semrushbot|claudebot|yandexbot|bytespider|aliyunsecbot|bingbot|mb2345browser|liebaofast|micromessenger|kinza|datanyze|serpstatbot|spaziodati|aspiegelbot|petalbot|meta-externalagent|meta-webindexer|imagesiftbot|amazonbot|dotbot|gptbot|mj12bot|ccbot|duckduckbot|facebot|facebookbot|twitterbot|slackbot|discordbot|sogou.*spider|exabot|applebot|linkedinbot|siteimprove|zoominfobot|scrapy|python-requests|python-httpx|go-http-client|dataforseobot|mauibot|neevabot|perplexitybot|anthropic-ai|cohere-ai|pinterestbot|timpibot|magpie-crawler)',
        r'([a-z0-9.-]+bot)',
        r'(bot|crawler|spider|scraper)',
    ]
    
    for pattern in bot_patterns:
        match = re.search(pattern, ua)
        if match:
            name = match.group(1).strip()
            name = re.sub(r'[^a-z0-9.-]', '', name)
            if len(name) > 2:
                return name[:30]
    return "unknown"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            pass
    return 0

def save_state(position):
    with open(STATE_FILE, 'w') as f:
        f.write(str(position))

def is_already_blocked(ip):
    try:
        result = subprocess.run(['csf', '-d', ip], capture_output=True, text=True, timeout=10)
        return "already in deny list" in result.stdout.lower() or "is already blocked" in result.stdout.lower()
    except:
        return False

def block_ip_csf(ip, bot_name, count):
    comment = f"ModSec-777007 BadBot {bot_name} ({count} hits)"
    try:
        result = subprocess.run(['csf', '-d', ip, comment], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print(f"✅ Blocked IP {ip} via CSF ({bot_name}, {count} hits)")
            return True
        else:
            print(f"⚠️ CSF block failed for {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"❌ Error blocking IP {ip}: {e}")
        return False

def process_log():
    stats = defaultdict(int)
    current_pos = load_state()
    new_pos = current_pos
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(current_pos)
            
            for line in f:
                if RULE_ID in line:
                    try:
                        ip_match = re.search(r'"client_ip":"([^"]+)"', line)
                        ua_match = re.search(r'"user-agent":"([^"]+)"', line)
                        
                        if ip_match and ua_match:
                            client_ip = ip_match.group(1)
                            user_agent = ua_match.group(1)
                            bot_name = extract_bot_name(user_agent)
                            key = f"{client_ip}\t#{bot_name}"
                            stats[key] += 1
                    except:
                        continue
                
                new_pos = f.tell()
                
    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
        return
    except Exception as e:
        print(f"Error reading log: {e}")
        return

    # Merge with previous data
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            key = f"{parts[0]}\t{parts[1]}"
                            count = int(parts[2]) if len(parts) > 2 else 0
                            stats[key] = stats.get(key, 0) + count
        except:
            pass

    # Save updated stats
    with open(DATA_FILE, 'w') as f:
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for key, count in sorted_stats:
            f.write(f"{key}\t{count}\n")

    save_state(new_pos)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Processed — {len(stats)} records updated")

    # Block via CSF
    blocked_count = 0
    for key, count in list(stats.items()):
        if count >= BLOCK_THRESHOLD:
            ip = key.split('\t')[0]
            bot_name = key.split('\t')[1].replace('#', '') if '\t' in key else "unknown"
            if not is_already_blocked(ip):
                if block_ip_csf(ip, bot_name, count):
                    blocked_count += 1

    if blocked_count > 0:
        print(f"🔒 Blocked {blocked_count} new bad bot IPs via CSF")

if __name__ == "__main__":
    print("🚀 ModSecurity Bad Bot Blocker + CSF Integration Started")
    print(f"Log File: {LOG_FILE}")
    print(f"Interval: {CHECK_INTERVAL//60} minutes | Block Threshold: {BLOCK_THRESHOLD} hits")
    
    while running:
        process_log()
        if not running:
            break
        
        # Use shorter sleep with check to make shutdown faster
        for _ in range(CHECK_INTERVAL // 10):
            if not running:
                break
            time.sleep(10)
    
    print("✅ Service Stopped Gracefully.")
    sys.stdout.flush()
