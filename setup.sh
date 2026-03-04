#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="network-abuse-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_PATH=$(which python3)

if [ -z "$PYTHON_PATH" ]; then
    PYTHON_PATH=$(which python)
fi

if [ -z "$PYTHON_PATH" ]; then
    echo "Error: Python not found. Please install Python 3.7+"
    exit 1
fi

echo "Installing dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" || pip install -r "$SCRIPT_DIR/requirements.txt"

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "Creating .env file from env.example..."
    cp "$SCRIPT_DIR/env.example" "$SCRIPT_DIR/.env"
    echo "Please edit .env file and configure your settings before starting the service"
fi

echo "Creating systemd service..."

sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Network Abuse Monitoring Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_PATH $SCRIPT_DIR/network_monitor.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling service..."
sudo systemctl enable "$SERVICE_NAME"

echo ""
echo "Setup completed!"
echo ""
echo "To start the service, run:"
echo "  sudo systemctl start $SERVICE_NAME"
echo ""
echo "To check service status:"
echo "  sudo systemctl status $SERVICE_NAME"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "Don't forget to edit $SCRIPT_DIR/.env file with your configuration!"
