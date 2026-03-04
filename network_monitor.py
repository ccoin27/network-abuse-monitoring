import signal
import sys
from core.monitor import NetworkMonitor

monitor = None

def signal_handler(sig, frame):
    if monitor:
        print("\nShutting down gracefully...")
        monitor.db.close()
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    monitor = NetworkMonitor()
    monitor.run()
