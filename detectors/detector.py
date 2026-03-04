import os
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
    
    def get_outgoing_connections(self):
        try:
            result = os.popen('ss -tn').read()
            connections = []
            for line in result.split('\n'):
                if 'ESTAB' in line or 'SYN-SENT' in line or 'SYN-RECV' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote = parts[4]
                        if ':' in remote:
                            try:
                                if '[' in remote and ']' in remote:
                                    ipv6_part = remote.split(']')[0] + ']'
                                    ip = ipv6_part[1:-1]
                                    port_str = remote.split(']')[1]
                                    if port_str.startswith(':'):
                                        port = int(port_str[1:])
                                    else:
                                        continue
                                else:
                                    ip, port = remote.rsplit(':', 1)
                                    port = int(port)
                                connections.append((ip, port))
                            except:
                                pass
            return connections
        except Exception:
            try:
                result = os.popen('netstat -tn').read()
                connections = []
                for line in result.split('\n'):
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            remote = parts[4]
                            if ':' in remote:
                                try:
                                    if '[' in remote and ']' in remote:
                                        ip = remote.split(']')[0].split('[')[1]
                                        port_str = remote.split(']')[1]
                                        if port_str.startswith(':'):
                                            port = int(port_str[1:])
                                        else:
                                            continue
                                    else:
                                        ip, port = remote.rsplit(':', 1)
                                        port = int(port)
                                    connections.append((ip, port))
                                except:
                                    pass
                return connections
            except Exception:
                return []
    
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
        with self.lock:
            if ip in self.bruteforce_detected:
                return False
            
            if port in [22, 23, 3389, 3306, 5432, 1433, 1521, 6379]:
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
