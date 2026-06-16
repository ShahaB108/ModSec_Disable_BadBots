#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import json
from collections import defaultdict
import signal
import sys

# ===================== Setting =====================
LOG_FILE = "/var/log/httpd/modsec_audit.log"
STATE_FILE = "/var/log/modsec_bot_monitor.state"
DATA_FILE = "/var/log/modsec_bad_bots.txt"
CHECK_INTERVAL = 300  # 5 min
RULE_ID = "777007"
# ====================================================

# for graceful shutdown
running = True

def signal_handler(sig, frame):
    global running
    running = False
    print("\nStoping...")

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def extract_bot_name(user_agent):
    """Get Bot shortname"""
    match = re.search(r'(?i)([a-z0-9]+bot|bingbot|semrush|ahrefs|mj12bot|python-requests|scrapy)', user_agent)
    if match:
        return match.group(1).lower()
    return "unknown"

def load_state():
    """Load last read"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            pass
    return 0

def save_state(position):
    """Saving"""
    with open(STATE_FILE, 'w') as f:
        f.write(str(position))

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
                        # finding client_ip and user-agent
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
        print(f"File Not Found: {LOG_FILE}")
        return
    except Exception as e:
        print(f"Fail to Read: {e}")
        return

    # Loading old data
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            key = f"{parts[0]}\t{parts[1]}"
                            if key in stats:
                                stats[key] += int(parts[2]) if len(parts) > 2 else 0
        except:
            pass

    # Save new data
    with open(DATA_FILE, 'w') as f:
        # sort by repeat
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for key, count in sorted_stats:
            f.write(f"{key}\t{count}\n")

    save_state(new_pos)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] processed - {len(stats)} update")

if __name__ == "__main__":
    print("Started to Monitor RuleID.")
    print(f"Log File: {LOG_FILE}")
    print(f"Checking every {CHECK_INTERVAL//60} min")
    
    while running:
        process_log()
        if not running:
            break
        time.sleep(CHECK_INTERVAL)
    
    print("Service Stopped.")
