# Network Abuse Monitoring

A tool for monitoring internal networks for various types of attacks and abuse. Automatically detects port scanning, bruteforce attacks, DDoS patterns, and checks IP addresses through the AbuseIPDB API.

## Features

- **Port Scan Detection** - Monitoring suspicious port scanning activity
- **Bruteforce Attack Detection** - Detecting password brute-force attempts on SSH, Telnet, RDP, MySQL, PostgreSQL and other services
- **DDoS Pattern Detection** - Identifying signs of distributed attacks
- **AbuseIPDB Integration** - Automatic checking of IP addresses for recent abuse
- **Detailed Reports** - Getting detailed information about abuse through AbuseIPDB Reports API
- **Discord Notifications** - Sending webhooks to Discord when suspicious activity is detected
- **External IP Lists** - Support for fetching IP address lists from external sources via API
- **API Rate Limiting** - Automatic compliance with AbuseIPDB limits (1000 IPs per day)

## Requirements

- Python 3.7+
- Linux (uses ss/netstat for connection monitoring)
- AbuseIPDB account with API key
- Discord webhook (optional)

## Installation

### Automatic Setup (Recommended)

Run the setup script to automatically install dependencies and create a systemd service:

```bash
git clone <repository-url>
cd network-abuse-monitoring
chmod +x setup.sh
sudo ./setup.sh
```

The script will:
- Install Python dependencies
- Create `.env` file from `env.example`
- Create and enable systemd service
- Configure automatic startup on boot

After running setup, edit the `.env` file with your configuration and start the service:
```bash
sudo systemctl start network-abuse-monitor
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/ccoin27/network-abuse-monitoring
cd network-abuse-monitoring
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Copy the configuration file:
```bash
cp env.example .env
```

4. Edit the `.env` file and specify your settings:
```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url
SCAN_THRESHOLD=10
BRUTEFORCE_THRESHOLD=5
CHECK_INTERVAL=60
ABUSEIPDB_CHECK_ENABLED=true
EXTERNAL_IP_LIST_URL=
EXTERNAL_IP_LIST_KEY=
```

## Configuration

### Environment Variables

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Required |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL for notifications | Optional |
| `SCAN_THRESHOLD` | Threshold for port scan detection (number of ports) | 10 |
| `BRUTEFORCE_THRESHOLD` | Threshold for bruteforce attack detection (number of attempts) | 5 |
| `CHECK_INTERVAL` | Check interval in seconds | 60 |
| `ABUSEIPDB_CHECK_ENABLED` | Enable AbuseIPDB checking | true |
| `EXTERNAL_IP_LIST_URL` | URL for fetching IP address list | Optional |
| `EXTERNAL_IP_LIST_KEY` | Key for accessing external API | Optional |

### Getting AbuseIPDB API Key

1. Register at [AbuseIPDB](https://www.abuseipdb.com/)
2. Go to the [API](https://www.abuseipdb.com/account/api) section
3. Create a new API key
4. Copy the key to the `.env` file

### Creating Discord Webhook

1. Open Discord server settings
2. Go to "Integrations" → "Webhooks"
3. Create a new webhook
4. Copy the webhook URL to the `.env` file

## Usage

### Running as a Service (Recommended)

If you used the setup script, the service is already configured. Manage it with:

```bash
# Start the service
sudo systemctl start network-abuse-monitor

# Stop the service
sudo systemctl stop network-abuse-monitor

# Check service status
sudo systemctl status network-abuse-monitor

# View logs
sudo journalctl -u network-abuse-monitor -f

# Restart the service
sudo systemctl restart network-abuse-monitor

# Disable auto-start on boot
sudo systemctl disable network-abuse-monitor
```

### Running Manually

Start monitoring:
```bash
python network_monitor.py
```

The tool will:
- Monitor outgoing connections every 60 seconds (or specified interval)
- Detect suspicious activity
- Check IP addresses through AbuseIPDB (with rate limiting)
- Send notifications to Discord when attacks are detected

Press `Ctrl+C` to stop.

## Project Structure

```
network-abuse-monitoring/
├── config/
│   └── __init__.py          # Configuration and environment variables
├── services/
│   ├── __init__.py
│   ├── abuseipdb.py         # AbuseIPDB API integration
│   ├── discord.py            # Discord notification sending
│   └── ip_fetcher.py         # Fetching IP list from external source
├── detectors/
│   ├── __init__.py
│   └── detector.py           # Attack detectors
├── core/
│   ├── __init__.py
│   └── monitor.py            # Main monitoring module
├── network_monitor.py        # Entry point
├── setup.sh                  # Automatic setup script
├── requirements.txt          # Dependencies
├── env.example               # Configuration example
└── README.md                 # Documentation
```

## Detected Attacks

### Port Scanning
Detected when attempting to connect to a large number of ports on a single IP address. Threshold is configurable via `SCAN_THRESHOLD`.

### Bruteforce Attacks
Detected when multiple connection attempts are made to protected services:
- SSH (22)
- Telnet (23)
- RDP (3389)
- MySQL (3306)
- PostgreSQL (5432)
- SQL Server (1433)
- Oracle (1521)
- Redis (6379)

Threshold is configurable via `BRUTEFORCE_THRESHOLD`.

### DDoS Patterns
Detected when simultaneously scanning a large number of ports (>50) and multiple connection attempts (>20).

## API Response Examples

### AbuseIPDB Check API

**Request:**
```http
GET https://api.abuseipdb.com/api/v2/check?ipAddress=176.111.173.242&maxAgeInDays=90&verbose=
Headers:
  Key: YOUR_API_KEY
  Accept: application/json
```

**Response:**
```json
{
  "data": {
    "ipAddress": "176.111.173.242",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidencePercentage": 75,
    "countryCode": "RU",
    "usageType": "hosting",
    "isp": "Example ISP",
    "domain": "example.com",
    "hostnames": [
      "example.hostname.com"
    ],
    "isTor": false,
    "totalReports": 2840,
    "numDistinctUsers": 1250,
    "lastReportedAt": "2024-03-01T12:00:00+00:00"
  }
}
```

**Response Fields:**
- `ipAddress` - IP address
- `isPublic` - Whether the IP is public
- `abuseConfidencePercentage` - Abuse confidence percentage (0-100)
- `countryCode` - Country code (ISO 3166-1 alpha-2)
- `usageType` - Usage type (hosting, isp, etc.)
- `totalReports` - Total number of reports
- `numDistinctUsers` - Number of unique users who reported the IP
- `lastReportedAt` - Date of last report

### AbuseIPDB Reports API

**Request:**
```http
GET https://api.abuseipdb.com/api/v2/reports?ipAddress=176.111.173.242&maxAgeInDays=30&perPage=25&page=1
Headers:
  Key: YOUR_API_KEY
  Accept: application/json
```

**Response:**
```json
{
  "data": {
    "total": 2840,
    "page": 1,
    "count": 25,
    "perPage": 25,
    "lastPage": 114,
    "nextPageUrl": "https://api.abuseipdb.com/api/v2/reports?ipAddress=176.111.173.242&maxAgeInDays=30&perPage=25&page=2",
    "previousPageUrl": null,
    "results": [
      {
        "reportedAt": "2024-03-01T21:00:03+00:00",
        "comment": "Invalid user joseph from 176.111.173.242 port 53860",
        "categories": [
          18,
          22
        ],
        "reporterId": 43121,
        "reporterCountryCode": "DE",
        "reporterCountryName": "Germany"
      },
      {
        "reportedAt": "2024-03-01T13:27:47+00:00",
        "comment": "Apr 17 18:19:28 roki2 sshd[29767]: Invalid user gituser from 176.111.173.242\nApr 17 18:19:28 roki2 sshd[29767]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=176.111.173.242\nApr 17 18:19:29 roki2 sshd[29767]: Failed password for invalid user gituser from 176.111.173.242 port 54766 ssh2",
        "categories": [
          18,
          22
        ],
        "reporterId": 35071,
        "reporterCountryCode": "US",
        "reporterCountryName": "United States of America"
      }
    ]
  }
}
```

**Response Fields:**
- `total` - Total number of reports
- `page` - Current page
- `count` - Number of results on current page
- `perPage` - Number of results per page
- `lastPage` - Last page number
- `results` - Array of reports

**Abuse Categories:**
- `3` - Fraud Orders
- `4` - DDoS Attack
- `5` - FTP Brute-Force
- `6` - Ping of Death
- `7` - Phishing
- `8` - Fraud VoIP
- `9` - Open Proxy
- `10` - Web Spam
- `11` - Email Spam
- `12` - Blog Spam
- `13` - VPN IP
- `14` - Port Scan
- `15` - Hacking
- `16` - SQL Injection
- `17` - Spoofing
- `18` - Brute-Force
- `19` - Bad Web Bot
- `20` - Exploited Host
- `21` - Web App Attack
- `22` - SSH
- `23` - IoT Targeted

## External IP List

The tool supports fetching IP address lists from external sources. Configure `EXTERNAL_IP_LIST_URL` and optionally `EXTERNAL_IP_LIST_KEY`.

**API Response Format:**

The following JSON formats are supported:

1. Array of IP addresses:
```json
["192.168.1.1", "10.0.0.1", "172.16.0.1"]
```

2. Object with `ips` key:
```json
{
  "ips": ["192.168.1.1", "10.0.0.1"]
}
```

3. Object with `ip` key:
```json
{
  "ip": "192.168.1.1"
}
```

4. Object with `ipAddress` key:
```json
{
  "ipAddress": "192.168.1.1"
}
```

5. Object with `addresses` key:
```json
{
  "addresses": ["192.168.1.1", "10.0.0.1"]
}
```

If `EXTERNAL_IP_LIST_KEY` is specified, it will be passed as the `key` parameter in the GET request.

## API Limits

The tool automatically complies with AbuseIPDB's limit of 1000 IP checks per day. The minimum interval between checks of the same IP is ~86.4 seconds. Results are cached for 1 hour.

## Discord Notifications

When suspicious activity is detected, notifications are sent to Discord with information:
- Attack type
- IP address
- Attack details (ports, attempts, etc.)
- AbuseIPDB information (if available)
- Detection time

## Development

### Dependencies

- `python-dotenv` - Loading environment variables from .env file
- `requests` - HTTP requests to APIs

### Architecture

The project is divided into modules:
- **config** - Configuration and settings
- **services** - External services (AbuseIPDB, Discord, IP fetcher)
- **detectors** - Detectors for various attack types
- **core** - Main monitoring logic

## License

MIT

## Support

If you encounter any issues, please create an issue in the repository.

## Credits

Created specially for https://satx.cloud