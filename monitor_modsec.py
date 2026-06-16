#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
from collections import defaultdict
import signal

# ===================== Configuration =====================
LOG_FILE = "/var/log/httpd/modsec_audit.log"
STATE_FILE = "/var/log/modsec_bot_monitor.state"
DATA_FILE = "/var/log/modsec_bad_bots.txt"
CHECK_INTERVAL = 300  # 5 minutes
RULE_ID = "777007"
# ======================================================

running = True

def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    global running
    running = False
    print("\nStopping service...")

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def extract_bot_name(user_agent):
    """Extract short bot name from User-Agent string"""
    ua = user_agent.lower()
    
    # Strong regex patterns for common bots (based on your ModSecurity rule)
    bot_patterns = [
        r'(ahrefsbot|baiduspider|blexbot|barkrowler|semrushbot|claudebot|yandexbot|bytespider|aliyunsecbot|bingbot|mb2345browser|liebaofast|micromessenger|kinza|datanyze|serpstatbot|spaziodati|aspiegelbot|petalbot|meta-externalagent|meta-webindexer|imagesiftbot|amazonbot|dotbot|gptbot|mj12bot|ccbot|duckduckbot|facebot|facebookbot|twitterbot|slackbot|discordbot|sogou.*spider|exabot|applebot|linkedinbot|siteimprove|zoominfobot|scrapy|python-requests|python-httpx|go-http-client|dataforseobot|mauibot|neevabot|perplexitybot|anthropic-ai|cohere-ai|pinterestbot|timpibot|magpie-crawler)',
        r'([a-z0-9.-]+bot)',           # Catch anything ending with "bot"
        r'(bot|crawler|spider|scraper)', # General fallback
    ]
    
    for pattern in bot_patterns:
        match = re.search(pattern, ua)
        if match:
            name = match.group(1).strip()
            # Clean the name
            name = re.sub(r'[^a-z0-9.-]', '', name)
            if len(name) > 2:
                return name[:30]  # Limit length
    return "unknown"


def load_state():
    """Load last read position from state file"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            pass
    return 0


def save_state(position):
    """Save current read position"""
    with open(STATE_FILE, 'w') as f:
        f.write(str(position))


def process_log():
    """Process the ModSecurity audit log"""
    stats = defaultdict(int)
    current_pos = load_state()
    new_pos = current_pos
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(current_pos)
            
            for line in f:
                if RULE_ID in line:
                    try:
                        # Extract client_ip and user-agent
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

    # Merge with previous statistics
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            key = f"{parts[0]}\t{parts[1]}"
                            count = int(parts[2]) if len(parts) > 2 else 0
                            if key in stats:
                                stats[key] += count
                            else:
                                stats[key] = count
        except:
            pass

    # Save sorted results
    with open(DATA_FILE, 'w') as f:
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for key, count in sorted_stats:
            f.write(f"{key}\t{count}\n")

    save_state(new_pos)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Processed — {len(stats)} records updated")


if __name__ == "__main__":
    print("🚀 ModSecurity Rule 777007 Bot Monitor Started")
    print(f"Log File: {LOG_FILE}")
    print(f"Checking every {CHECK_INTERVAL//60} minutes")
    
    while running:
        process_log()
        if not running:
            break
        time.sleep(CHECK_INTERVAL)
    
    print("✅ Service Stopped.")
