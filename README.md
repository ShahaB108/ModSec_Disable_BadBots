# ModSec Disable BadBots

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
* Lightweight and production-ready.

## Included Files

| File                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| `777007_block_badbots.conf`  | ModSecurity rule for blocking known bots and crawlers             |
| `monitor_modsec.py`          | Monitors ModSecurity audit logs and processes Rule ID 777007 hits |
| `modsec-bot-monitor.service` | Systemd service for automatic monitoring                          |
| `installer.sh`               | Automated installation and deployment script                      |
| `modsec_bad_bots.txt`        | Generated list of detected bot IPs and hit counts                 |

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

## How It Works

1. ModSecurity Rule `777007` detects requests from known crawlers and bots.
2. Matching requests are logged into the ModSecurity audit log.
3. `monitor_modsec.py` parses the audit log periodically.
4. Detected IP addresses are recorded in `modsec_bad_bots.txt`.
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

## Customization

To add or remove bots, edit:

```text
777007_block_badbots.conf
```

After making changes, reload LiteSpeed:

```bash
systemctl reload lsws
```

## Disclaimer

This project intentionally blocks a wide range of crawlers, AI agents, scrapers, and indexing bots. Review the rule set carefully before deploying in production environments, especially if you rely on search engine indexing or third-party monitoring services.

