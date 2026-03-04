import sqlite3
import os
from datetime import datetime, timedelta
from threading import Lock

class ReportDatabase:
    def __init__(self, db_path='reports.db'):
        self.db_path = db_path
        self.lock = Lock()
        self.conn = None
        self.init_database()
    
    def get_connection(self):
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            self.conn.execute('PRAGMA cache_size=10000')
            self.conn.execute('PRAGMA temp_store=MEMORY')
        return self.conn
    
    def init_database(self):
        with self.lock:
            conn = self.get_connection()
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
    
    def is_reported(self, ip, attack_type, port=None):
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if port is not None:
                cursor.execute('''
                    SELECT id FROM reports 
                    WHERE ip_address = ? AND attack_type = ? AND port = ?
                    LIMIT 1
                ''', (ip, attack_type, port))
            else:
                cursor.execute('''
                    SELECT id FROM reports 
                    WHERE ip_address = ? AND attack_type = ?
                    LIMIT 1
                ''', (ip, attack_type))
            
            return cursor.fetchone() is not None
    
    def add_report(self, ip, attack_type, port=None, details=None):
        with self.lock:
            conn = self.get_connection()
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
    
    def cleanup_old_reports(self, days=30):
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cutoff_date = datetime.now() - timedelta(days=days)
            cursor.execute('''
                DELETE FROM reports WHERE reported_at < ?
            ''', (cutoff_date,))
            conn.commit()
    
    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
