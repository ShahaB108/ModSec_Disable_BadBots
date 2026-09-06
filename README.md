# ModSec Disable BadBots

**Current version: 2.1.0**

A lightweight ModSecurity and CSF integration project designed to identify, monitor, and block unwanted bots and crawlers on LiteSpeed and DirectAdmin servers.

## Features

* Blocks known AI bots, crawlers, scrapers, and indexing bots using ModSecurity.
* Uses a dedicated ModSecurity Rule ID (`777007`) for tracking and filtering requests.
* Monitors ModSecurity audit logs automatically.
* Generates a list of detected bot IPs and User-Agents.
* Integrates with CSF Firewall to automatically block offending IP addresses.
* Prevents duplicate firewall entries.
* Supports DirectAdmin + LiteSpeed environments.
* Includes a systemd service for continuous monitoring.
* Mirrors the rule file into DirectAdmin/CustomBuild's `custom` config dir so a CustomBuild rebuild can't silently drop it.
* All service-owned files and directories consolidated under `/opt/modsec-bot-monitor` (v2.1.0+).
* Watchdog keeps the active rule copies in sync from a local master under `/opt` — GitHub is only a last-resort fallback.
* Lightweight and production-ready.

## Included Files

| File                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| `777007_block_badbots.conf`  | ModSecurity rule for blocking known bots and crawlers             |
| `monitor_modsec.py`          | Monitors ModSecurity audit logs and processes Rule ID 777007 hits |
| `modsec-bot-monitor.service` | Systemd service for automatic monitoring                          |
| `installer.sh`               | Automated installation and deployment script                      |
| `modsec_bad_bots.txt`        | Sample of the generated list of detected bot IPs and hit counts   |

Once installed, all service files live under `/opt/modsec-bot-monitor` — see [Installed Layout](#installed-layout-v210).

## Requirements

* DirectAdmin
* LiteSpeed Enterprise
* ModSecurity enabled
* CSF Firewall
* Python 3.9+
* Linux (CloudLinux, AlmaLinux, Rocky Linux, CentOS)

## Installation

```bash
git clone https://github.com/ShahaB108/ModSec_Disable_BadBots.git
cd ModSec_Disable_BadBots

chmod +x installer.sh
./installer.sh
```

Re-running `installer.sh` on a host that already has the service installed does a **full clean reinstall**: it stops the running service and freshly downloads + reinstalls the script, the systemd unit and the rule master — so an update always actually lands, and you're not left running stale code.

Upgrading from v2.0.x (old paths: `/usr/local/bin/monitor_modsec.py`, `/var/lib/modsec_bot_monitor/`) is automatic: the installer migrates `state.json`, `modsec_bad_bots.txt` and `blocked_ips.txt` into `/opt/modsec-bot-monitor/state/`, removes the legacy locations, and replaces the old unit file with a symlink into `/opt` — blocked-IP history and hit stats are preserved. The active rule copy in `/etc/modsecurity.d` is left in place during cleanup, then re-synced from the new master copy the first time the service starts.

## Installed Layout (v2.1.0+)

Everything the service owns lives under a single directory:

```text
/opt/modsec-bot-monitor/
├── bin/
│   └── monitor_modsec.py           # monitor script (formerly /usr/local/bin/)
├── rules/
│   └── 777007_block_badbots.conf   # rule MASTER copy — source of truth
├── state/                          # runtime state (formerly /var/lib/modsec_bot_monitor/)
│   ├── state.json                  #   log offset + inode (rotation detection)
│   ├── modsec_bad_bots.txt         #   cumulative IP/bot hit counts
│   └── blocked_ips.txt             #   IPs blocked by this service (dedup guard)
├── systemd/
│   └── modsec-bot-monitor.service  # unit file (symlinked from /etc/systemd/system/)
└── VERSION                         # installed version + commit stamp
```

A few managed integration points must live outside `/opt`, where systemd, ModSecurity and ServerHub expect them:

| Path | Purpose |
| ---- | ------- |
| `/etc/systemd/system/modsec-bot-monitor.service` | Symlink → `/opt/modsec-bot-monitor/systemd/modsec-bot-monitor.service` |
| `/etc/modsecurity.d/777007_block_badbots.conf` | Active rule copy included by ModSecurity — re-mirrored from the master by the watchdog |
| `/usr/local/directadmin/custombuild/custom/modsecurity/conf/777007_block_badbots.conf` | CustomBuild-safe mirror (DirectAdmin hosts only) |
| `/usr/local/share/modsec-disable-badbots-version` | Symlink → `/opt/modsec-bot-monitor/VERSION`, keeps the ServerHub agent collector working |

## How It Works

1. ModSecurity Rule `777007` detects requests from known crawlers and bots.
2. Matching requests are logged into the ModSecurity audit log.
3. `monitor_modsec.py` parses the audit log periodically.
4. Detected IP addresses are recorded in `/opt/modsec-bot-monitor/state/modsec_bad_bots.txt`.
5. New IPs are automatically blocked using CSF:

```bash
csf -d IP_ADDRESS "ModSecurity Rule 777007 Bad Bot"
```

## Example Output

```text
147.160.138.19    # bingbot/2.0      513
45.134.88.74      # MJ12bot          248
216.73.216.51     # ClaudeBot/1.0    200
118.91.186.70     # DotBot/1.2       148
```

## Service Management

Start service:

```bash
systemctl start modsec-bot-monitor
```

Enable on boot:

```bash
systemctl enable modsec-bot-monitor
```

Check status:

```bash
systemctl status modsec-bot-monitor
```

View logs:

```bash
journalctl -u modsec-bot-monitor -f
```

Check the installed version:

```bash
cat /opt/modsec-bot-monitor/VERSION
/opt/modsec-bot-monitor/bin/monitor_modsec.py --version
```

## Customization

To add or remove bots, edit the **rule master copy**:

```text
/opt/modsec-bot-monitor/rules/777007_block_badbots.conf
```

Then restart the monitor — its watchdog re-mirrors the master to the active locations and reloads LiteSpeed for you:

```bash
systemctl restart modsec-bot-monitor
```

> **Note:** manual edits to the active copies (`/etc/modsecurity.d/777007_block_badbots.conf` or the CustomBuild mirror) are detected as drift and reverted from the master on the next watchdog run — always edit the master.

All tunables (paths, thresholds, intervals, URLs) are grouped at the top of `monitor_modsec.py` in a single configuration block, each with an explanatory comment — edit them there.

## Domain-Level ModSecurity Enforcement

[#domain-level-modsecurity-enforcement](#domain-level-modsecurity-enforcement)

DirectAdmin lets a domain owner (or a support tech) switch ModSecurity off per-domain, which silently disables rule 777007 — and every other rule — for that domain, regardless of the server-wide config. Each domain's toggle lives in its own file:

```
/usr/local/directadmin/data/users/<user>/domains/<domain>.modsecurity_rules
```

containing a single line, `SecRuleEngine Off` when disabled.

Every `DOMAIN_MODSEC_CHECK_INTERVAL` (default 2h, plus once on service startup), `monitor_modsec.py`:

1. Globs `/usr/local/directadmin/data/users/*/domains/*.modsecurity_rules`.
2. Flips any `SecRuleEngine Off` line to `SecRuleEngine On` (case/whitespace-insensitive match, everything else in the file left untouched).
3. Reloads LiteSpeed once at the end, only if at least one domain was changed.
4. Logs every domain it had to fix, so you have an audit trail of who/what turned it off.

This keeps ModSecurity mandatory site-wide — nobody can leave a domain unprotected for more than one check cycle. Adjust `DOMAIN_MODSEC_CHECK_INTERVAL` in the config block if you want it checked more or less often.

## DirectAdmin / CustomBuild Persistence

[#directadmin--custombuild-persistence](#directadmin--custombuild-persistence)

DirectAdmin's CustomBuild can rebuild ModSecurity's config and remove unmanaged files from `/etc/modsecurity.d`. To prevent the rule from being silently dropped:

- Since v2.1.0 the rule's **master copy lives at `/opt/modsec-bot-monitor/rules/777007_block_badbots.conf`** — safe from CustomBuild rebuilds by construction.
- The installer mirrors it into `/etc/modsecurity.d` **and** `/usr/local/directadmin/custombuild/custom/modsecurity/conf` (CustomBuild's designated "custom" rule directory, which it preserves across rebuilds).
- The `monitor_modsec.py` watchdog verifies **all three** copies on startup and every `RULE_CHECK_INTERVAL` (default 6h) — including content drift, not just existence. Missing or drifted copies are re-mirrored from the master (with a LiteSpeed reload when the active copy changes); if the master itself is missing it is first recovered from the active copy, and only as a last resort re-downloaded from GitHub.
- This step is skipped automatically on non-DirectAdmin hosts.

## Disclaimer

This project intentionally blocks a wide range of crawlers, AI agents, scrapers, and indexing bots. Review the rule set carefully before deploying in production environments, especially if you rely on search engine indexing or third-party monitoring services.
