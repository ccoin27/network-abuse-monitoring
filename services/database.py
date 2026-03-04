import sqlite3
import os
from datetime import datetime, timedelta
from threading import Lock

class ReportDatabase:
    def __init__(self, db_path='reports.db'):
        self.db_path = db_path
        self.lock = Lock()
        self.init_database()
    
    def init_database(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    port INTEGER,
                    reported_at TIMESTAMP NOT NULL,
                    details TEXT,
                    UNIQUE(ip_address, attack_type, port)
                )
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ip_type ON reports(ip_address, attack_type, port)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_reported_at ON reports(reported_at)
            ''')
            conn.commit()
            conn.close()
    
    def is_reported(self, ip, attack_type, port=None):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if port is not None:
                cursor.execute('''
                    SELECT id FROM reports 
                    WHERE ip_address = ? AND attack_type = ? AND port = ?
                ''', (ip, attack_type, port))
            else:
                cursor.execute('''
                    SELECT id FROM reports 
                    WHERE ip_address = ? AND attack_type = ?
                ''', (ip, attack_type))
            
            result = cursor.fetchone()
            conn.close()
            return result is not None
    
    def add_report(self, ip, attack_type, port=None, details=None):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO reports 
                    (ip_address, attack_type, port, reported_at, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, attack_type, port, datetime.now(), details))
                conn.commit()
            except sqlite3.Error:
                pass
            finally:
                conn.close()
    
    def cleanup_old_reports(self, days=30):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cutoff_date = datetime.now() - timedelta(days=days)
            cursor.execute('''
                DELETE FROM reports WHERE reported_at < ?
            ''', (cutoff_date,))
            conn.commit()
            conn.close()
