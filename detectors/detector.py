import subprocess
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from config import SCAN_THRESHOLD, BRUTEFORCE_THRESHOLD

class AttackDetector:
    def __init__(self):
        self.connections = defaultdict(lambda: {'ports': set(), 'attempts': 0, 'last_seen': None})
        self.port_scan_detected = set()
        self.bruteforce_detected = set()
        self.ddos_detected = set()
        self.lock = threading.Lock()
        self.connection_cache = []
        self.cache_time = None
        self.cache_ttl = 5
        self.bruteforce_ports = {22, 23, 3389, 3306, 5432, 1433, 1521, 6379}
    
    def get_outgoing_connections(self):
        now = datetime.now()
        if self.cache_time and (now - self.cache_time).total_seconds() < self.cache_ttl:
            return self.connection_cache
        
        try:
            result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                connections = self._parse_ss_output(result.stdout)
                self.connection_cache = connections
                self.cache_time = now
                return connections
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        
        try:
            result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                connections = self._parse_netstat_output(result.stdout)
                self.connection_cache = connections
                self.cache_time = now
                return connections
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        
        return self.connection_cache if self.connection_cache else []
    
    def _parse_ss_output(self, output):
        connections = []
        for line in output.split('\n'):
            if 'ESTAB' in line or 'SYN-SENT' in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4]
                    if ':' in remote:
                        try:
                            if '[' in remote:
                                idx = remote.rindex(']')
                                ip = remote[1:idx]
                                port = int(remote[idx+2:])
                            else:
                                ip, port = remote.rsplit(':', 1)
                                port = int(port)
                            connections.append((ip, port))
                        except (ValueError, IndexError):
                            continue
        return connections
    
    def _parse_netstat_output(self, output):
        connections = []
        for line in output.split('\n'):
            if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4]
                    if ':' in remote:
                        try:
                            if '[' in remote:
                                idx = remote.rindex(']')
                                ip = remote[remote.index('[')+1:idx]
                                port = int(remote[idx+2:])
                            else:
                                ip, port = remote.rsplit(':', 1)
                                port = int(port)
                            connections.append((ip, port))
                        except (ValueError, IndexError):
                            continue
        return connections
    
    def detect_port_scan(self, ip, port):
        with self.lock:
            if ip in self.port_scan_detected:
                return False
            
            self.connections[ip]['ports'].add(port)
            self.connections[ip]['last_seen'] = datetime.now()
            
            if len(self.connections[ip]['ports']) >= SCAN_THRESHOLD:
                self.port_scan_detected.add(ip)
                return True
            return False
    
    def detect_bruteforce(self, ip, port):
        if port not in self.bruteforce_ports:
            return False
        
        with self.lock:
            if ip in self.bruteforce_detected:
                return False
            
            self.connections[ip]['attempts'] += 1
            self.connections[ip]['last_seen'] = datetime.now()
            
            if self.connections[ip]['attempts'] >= BRUTEFORCE_THRESHOLD:
                self.bruteforce_detected.add(ip)
                return True
        return False
    
    def detect_ddos_pattern(self, ip):
        with self.lock:
            if ip in self.ddos_detected:
                return False
            
            if ip in self.connections:
                conn = self.connections[ip]
                if len(conn['ports']) > 50 and conn['attempts'] > 20:
                    self.ddos_detected.add(ip)
                    return True
            return False
    
    def get_connection_info(self, ip):
        with self.lock:
            if ip in self.connections:
                return {
                    'ports': self.connections[ip]['ports'].copy(),
                    'attempts': self.connections[ip]['attempts']
                }
            return None
    
    def cleanup_old_connections(self):
        with self.lock:
            now = datetime.now()
            to_remove = []
            for ip, data in self.connections.items():
                if data['last_seen'] and now - data['last_seen'] > timedelta(minutes=30):
                    to_remove.append(ip)
            for ip in to_remove:
                del self.connections[ip]
                if ip in self.port_scan_detected:
                    self.port_scan_detected.remove(ip)
                if ip in self.bruteforce_detected:
                    self.bruteforce_detected.remove(ip)
                if ip in self.ddos_detected:
                    self.ddos_detected.remove(ip)
