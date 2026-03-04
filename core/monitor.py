import time
from datetime import datetime
from detectors.detector import AttackDetector
from services.abuseipdb import AbuseIPDB
from services.discord import DiscordNotifier
from services.ip_fetcher import IPFetcher
from services.database import ReportDatabase
from config import CHECK_INTERVAL, ABUSEIPDB_CHECK_ENABLED

class NetworkMonitor:
    def __init__(self):
        self.detector = AttackDetector()
        self.abuseipdb = AbuseIPDB()
        self.discord = DiscordNotifier()
        self.ip_fetcher = IPFetcher()
        self.db = ReportDatabase()
        self.suspicious_ips = set()
        self.external_ips_to_check = set()
    
    def update_external_ips(self):
        try:
            ips = self.ip_fetcher.fetch_ips()
            self.external_ips_to_check = set(ips)
            if ips:
                print(f"Loaded {len(ips)} IPs from external source")
        except Exception as e:
            print(f"Error fetching external IPs: {e}")
    
    def check_external_ips(self):
        if not self.external_ips_to_check:
            return
        
        for ip in list(self.external_ips_to_check):
            if self.abuseipdb.can_check(ip):
                abuse_info = self.abuseipdb.check_ip(ip)
                if abuse_info and abuse_info.get('abuseConfidencePercentage', 0) > 25:
                    reports_info = self.abuseipdb.get_reports(ip)
                    fields = [
                        {'name': 'IP Address', 'value': ip, 'inline': True},
                        {'name': 'Abuse Confidence', 'value': f"{abuse_info['abuseConfidencePercentage']}%", 'inline': True},
                        {'name': 'Total Reports', 'value': str(abuse_info['totalReports']), 'inline': True},
                        {'name': 'Country', 'value': abuse_info.get('countryCode', 'N/A'), 'inline': True},
                        {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': False}
                    ]
                    
                    if reports_info and reports_info.get('data', {}).get('total', 0) > 0:
                        total_reports = reports_info['data']['total']
                        fields.append({'name': 'Total Reports (Detailed)', 'value': str(total_reports), 'inline': True})
                    
                    if not self.db.is_reported(ip, 'external_suspicious'):
                        self.discord.send_webhook(
                            'Suspicious IP from External List',
                            'IP from external list has high abuse confidence',
                            fields,
                            color=16753920
                        )
                        details = f"Abuse Confidence: {abuse_info['abuseConfidencePercentage']}%, Reports: {abuse_info['totalReports']}"
                        self.db.add_report(ip, 'external_suspicious', None, details)
                    self.suspicious_ips.add(ip)
    
    def detect_suspicious_activity(self):
        connections = self.detector.get_outgoing_connections()
        
        for ip, port in connections:
            if self.detector.detect_port_scan(ip, port):
                conn_info = self.detector.get_connection_info(ip)
                ports = conn_info['ports'] if conn_info else set()
                
                abuse_info = None
                reports_info = None
                if ABUSEIPDB_CHECK_ENABLED:
                    abuse_info = self.abuseipdb.check_ip(ip)
                    if abuse_info and abuse_info.get('abuseConfidencePercentage', 0) > 25:
                        reports_info = self.abuseipdb.get_reports(ip)
                        self.suspicious_ips.add(ip)
                
                self.discord.report_port_scan(ip, ports, abuse_info, reports_info)
            
            if self.detector.detect_bruteforce(ip, port):
                conn_info = self.detector.get_connection_info(ip)
                attempts = conn_info['attempts'] if conn_info else 0
                
                abuse_info = None
                reports_info = None
                if ABUSEIPDB_CHECK_ENABLED:
                    abuse_info = self.abuseipdb.check_ip(ip)
                    if abuse_info and abuse_info.get('abuseConfidencePercentage', 0) > 25:
                        reports_info = self.abuseipdb.get_reports(ip)
                        self.suspicious_ips.add(ip)
                
                self.discord.report_bruteforce(ip, port, attempts, abuse_info, reports_info)
            
            if self.detector.detect_ddos_pattern(ip):
                abuse_info = None
                if ABUSEIPDB_CHECK_ENABLED:
                    abuse_info = self.abuseipdb.check_ip(ip)
                self.discord.report_ddos(ip, abuse_info)
        
        self.detector.cleanup_old_connections()
    
    def run(self):
        print(f"Network monitoring started at {datetime.now()}")
        print(f"Check interval: {CHECK_INTERVAL} seconds")
        print(f"AbuseIPDB enabled: {ABUSEIPDB_CHECK_ENABLED}")
        
        external_check_counter = 0
        cleanup_counter = 0
        
        while True:
            try:
                self.detect_suspicious_activity()
                
                external_check_counter += 1
                if external_check_counter >= 10:
                    self.update_external_ips()
                    self.check_external_ips()
                    external_check_counter = 0
                
                cleanup_counter += 1
                if cleanup_counter >= 1440:
                    self.db.cleanup_old_reports(30)
                    cleanup_counter = 0
                
                time.sleep(CHECK_INTERVAL)
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(CHECK_INTERVAL)
