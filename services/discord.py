import requests
from datetime import datetime
from config import DISCORD_WEBHOOK_URL
from services.database import ReportDatabase

class DiscordNotifier:
    def __init__(self):
        self.webhook_url = DISCORD_WEBHOOK_URL
        self.db = ReportDatabase()
    
    def send_webhook(self, title, description, fields, color=16711680):
        if not self.webhook_url:
            return
        
        embed = {
            'title': title,
            'description': description,
            'color': color,
            'fields': fields,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        payload = {
            'embeds': [embed]
        }
        
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception:
            pass
    
    def report_port_scan(self, ip, ports, abuse_info=None, reports_info=None):
        if self.db.is_reported(ip, 'port_scan'):
            return
        
        fields = [
            {'name': 'IP Address', 'value': ip, 'inline': True},
            {'name': 'Ports Scanned', 'value': str(len(ports)), 'inline': True},
            {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': False}
        ]
        
        if abuse_info:
            fields.append({'name': 'AbuseIPDB Confidence', 'value': f"{abuse_info['abuseConfidencePercentage']}%", 'inline': True})
            fields.append({'name': 'Total Reports', 'value': str(abuse_info['totalReports']), 'inline': True})
            fields.append({'name': 'Country', 'value': abuse_info.get('countryCode', 'N/A'), 'inline': True})
        
        if reports_info and reports_info.get('data', {}).get('total', 0) > 0:
            total_reports = reports_info['data']['total']
            fields.append({'name': 'Total Reports (Detailed)', 'value': str(total_reports), 'inline': True})
            
            if reports_info['data'].get('results'):
                recent_reports = reports_info['data']['results'][:3]
                categories_map = {
                    3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
                    6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
                    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam',
                    12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan',
                    15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
                    18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
                    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
                }
                report_text = []
                for report in recent_reports:
                    cats = [categories_map.get(c, str(c)) for c in report.get('categories', [])]
                    report_text.append(f"**{report.get('reportedAt', '')[:10]}**: {', '.join(cats)}")
                if report_text:
                    fields.append({'name': 'Recent Reports', 'value': '\n'.join(report_text), 'inline': False})
        
        ports_list = sorted(list(ports))[:20]
        ports_str = ', '.join(map(str, ports_list))
        if len(ports) > 20:
            ports_str += f' ... (+{len(ports) - 20} more)'
        
        fields.append({'name': 'Ports', 'value': ports_str, 'inline': False})
        
        self.send_webhook(
            'Port Scan Detected',
            'Potential port scanning activity detected from internal network',
            fields
        )
        
        details = f"Ports: {ports_str}"
        self.db.add_report(ip, 'port_scan', None, details)
    
    def report_bruteforce(self, ip, port, attempts, abuse_info=None, reports_info=None):
        if self.db.is_reported(ip, 'bruteforce', port):
            return
        
        port_names = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL'}
        port_name = port_names.get(port, f'Port {port}')
        
        fields = [
            {'name': 'IP Address', 'value': ip, 'inline': True},
            {'name': 'Service', 'value': port_name, 'inline': True},
            {'name': 'Attempts', 'value': str(attempts), 'inline': True},
            {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': False}
        ]
        
        if abuse_info:
            fields.append({'name': 'AbuseIPDB Confidence', 'value': f"{abuse_info['abuseConfidencePercentage']}%", 'inline': True})
            fields.append({'name': 'Total Reports', 'value': str(abuse_info['totalReports']), 'inline': True})
            fields.append({'name': 'Country', 'value': abuse_info.get('countryCode', 'N/A'), 'inline': True})
        
        if reports_info and reports_info.get('data', {}).get('total', 0) > 0:
            total_reports = reports_info['data']['total']
            fields.append({'name': 'Total Reports (Detailed)', 'value': str(total_reports), 'inline': True})
            
            if reports_info['data'].get('results'):
                recent_reports = reports_info['data']['results'][:3]
                categories_map = {
                    3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
                    6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
                    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam',
                    12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan',
                    15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
                    18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
                    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
                }
                report_text = []
                for report in recent_reports:
                    cats = [categories_map.get(c, str(c)) for c in report.get('categories', [])]
                    report_text.append(f"**{report.get('reportedAt', '')[:10]}**: {', '.join(cats)}")
                if report_text:
                    fields.append({'name': 'Recent Reports', 'value': '\n'.join(report_text), 'inline': False})
        
        self.send_webhook(
            'Bruteforce Attack Detected',
            f'Potential {port_name} bruteforce attack detected',
            fields,
            color=16753920
        )
        
        details = f"Service: {port_name}, Attempts: {attempts}"
        self.db.add_report(ip, 'bruteforce', port, details)
    
    def report_ddos(self, ip, abuse_info=None):
        if self.db.is_reported(ip, 'ddos'):
            return
        
        fields = [
            {'name': 'IP Address', 'value': ip, 'inline': True},
            {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': False}
        ]
        if abuse_info:
            fields.append({'name': 'AbuseIPDB Confidence', 'value': f"{abuse_info['abuseConfidencePercentage']}%", 'inline': True})
        self.send_webhook(
            'DDoS Pattern Detected',
            'Potential DDoS attack pattern detected',
            fields,
            color=8388608
        )
        
        details = f"DDoS pattern detected"
        if abuse_info:
            details += f", Confidence: {abuse_info['abuseConfidencePercentage']}%"
        self.db.add_report(ip, 'ddos', None, details)
