import requests
from datetime import datetime, timedelta
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_CHECK_ENABLED, MIN_CHECK_INTERVAL

class AbuseIPDB:
    def __init__(self):
        self.api_key = ABUSEIPDB_API_KEY
        self.enabled = ABUSEIPDB_CHECK_ENABLED
        self.checked_ips = {}
        self.last_check_time = {}
        self.min_interval = MIN_CHECK_INTERVAL
    
    def can_check(self, ip):
        if ip in self.last_check_time:
            elapsed = (datetime.now() - self.last_check_time[ip]).total_seconds()
            return elapsed >= self.min_interval
        return True
    
    def check_ip(self, ip):
        if not self.enabled or not self.api_key:
            return None
        
        if not self.can_check(ip):
            if ip in self.checked_ips:
                cache_time, result = self.checked_ips[ip]
                if datetime.now() - cache_time < timedelta(hours=1):
                    return result
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                result = {
                    'isPublic': data.get('data', {}).get('isPublic', False),
                    'abuseConfidencePercentage': data.get('data', {}).get('abuseConfidencePercentage', 0),
                    'usageType': data.get('data', {}).get('usageType', ''),
                    'countryCode': data.get('data', {}).get('countryCode', ''),
                    'totalReports': data.get('data', {}).get('totalReports', 0)
                }
                self.checked_ips[ip] = (datetime.now(), result)
                self.last_check_time[ip] = datetime.now()
                return result
        except Exception:
            pass
        return None
    
    def get_reports(self, ip, max_age_days=30, per_page=25, page=1):
        if not self.enabled or not self.api_key:
            return None
        
        if not self.can_check(ip):
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/reports'
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': max_age_days,
                'perPage': per_page,
                'page': page
            }
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                self.last_check_time[ip] = datetime.now()
                return response.json()
        except Exception:
            pass
        return None
