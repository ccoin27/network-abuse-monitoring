import requests
import json
from config import EXTERNAL_IP_LIST_URL, EXTERNAL_IP_LIST_KEY

class IPFetcher:
    def __init__(self):
        self.url = EXTERNAL_IP_LIST_URL
        self.key = EXTERNAL_IP_LIST_KEY
    
    def fetch_ips(self):
        if not self.url:
            return []
        
        try:
            params = {}
            if self.key:
                params['key'] = self.key
            
            response = requests.get(self.url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    return [str(ip).strip() for ip in data if ip]
                elif isinstance(data, dict):
                    if 'ips' in data:
                        return [str(ip).strip() for ip in data['ips'] if ip]
                    elif 'ip' in data:
                        return [str(data['ip']).strip()]
                    elif 'ipAddress' in data:
                        return [str(data['ipAddress']).strip()]
                    elif 'addresses' in data:
                        return [str(ip).strip() for ip in data['addresses'] if ip]
                
                return []
        except Exception:
            pass
        return []
