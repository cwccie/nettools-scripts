#!/bin/bash
#
# nettools_fix_all.sh - All-in-One Fix Script for nettools
#
# This script performs a comprehensive fix of all common issues with nettools.
# It addresses initialization problems, missing modules, permission issues,
# and ensures the application is properly configured for external access.
#
# Usage: sudo bash nettools_fix_all.sh
#

# Exit on any error
set -e

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Base directory
BASE_DIR="/opt/nettools"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================================${NC}"
echo -e "${GREEN}     nettools All-in-One Fix Script                      ${NC}"
echo -e "${GREEN}     $(date)                                             ${NC}"
echo -e "${GREEN}=========================================================${NC}"

# Stop the service if it's running
systemctl stop nettools.service

# ---------------------------------------------------
# 1. Fix app/__init__.py
# ---------------------------------------------------
echo -e "\n${YELLOW}1. Fixing app/__init__.py${NC}"

# Create a backup of the original file
cp ${BASE_DIR}/app/__init__.py ${BASE_DIR}/app/__init__.py.backup.$(date +%Y%m%d%H%M%S)

# Update the file with a comprehensive fixed version
cat > ${BASE_DIR}/app/__init__.py << 'EOF'
import os
import logging
from flask import Flask, redirect, url_for
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_flask_exporter import PrometheusMetrics
from pythonjsonlogger import jsonlogger

# Configure logging
logger = logging.getLogger('nettools')
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Initialize extensions
socketio = SocketIO()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
metrics = None  # Will be initialized with app

def create_app(config_name=None):
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    from config import config
    app.config.from_object(config[config_name])
    
    # Ensure PCAP storage directory exists
    os.makedirs(app.config['PCAP_STORAGE_PATH'], exist_ok=True)
    
    # Initialize extensions
    socketio.init_app(app, cors_allowed_origins="*", async_mode='gevent')
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Initialize PrometheusMetrics with the app
    global metrics
    metrics = PrometheusMetrics(app)
    
    # Custom metrics
    metrics.info('app_info', 'Application info', version='1.0.0')
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        # Simple user loader for development
        from app.auth.models import User
        return User(user_id, "admin")
    
    # Root route redirects to dashboard
    @app.route('/')
    def index():
        return redirect(url_for('dashboard.index'))
    
    # Register blueprints
    try:
        from app.auth.routes import auth_bp
        app.register_blueprint(auth_bp)
    except ImportError:
        logger.warning("Auth module not fully available")
    
    try:
        from app.dashboard.routes import dashboard_bp
        app.register_blueprint(dashboard_bp)
    except ImportError:
        logger.warning("Dashboard module not fully available")
    
    try:
        from app.capture.routes import capture_bp
        app.register_blueprint(capture_bp)
    except ImportError:
        logger.warning("Capture module not fully available")
    
    try:
        from app.api.auth import api_auth_bp
        app.register_blueprint(api_auth_bp, url_prefix='/api/auth')
    except ImportError:
        logger.warning("API auth module not fully available")
    
    try:
        from app.api.dashboard import api_dashboard_bp
        app.register_blueprint(api_dashboard_bp, url_prefix='/api/dashboard')
    except ImportError:
        logger.warning("API dashboard module not fully available")
    
    try:
        from app.api.capture import api_capture_bp
        app.register_blueprint(api_capture_bp, url_prefix='/api/capture')
    except ImportError:
        logger.warning("API capture module not fully available")
    
    return app, socketio

app, socketio = create_app()
EOF

chown nettools_user:nettools_user ${BASE_DIR}/app/__init__.py

# ---------------------------------------------------
# 2. Fix run.py
# ---------------------------------------------------
echo -e "\n${YELLOW}2. Fixing run.py${NC}"

# Create a backup of the original file
cp ${BASE_DIR}/run.py ${BASE_DIR}/run.py.backup.$(date +%Y%m%d%H%M%S)

# Update the file with a robust version
cat > ${BASE_DIR}/run.py << 'EOF'
#!/usr/bin/env python3
import os
import sys
import traceback

try:
    from app import app, socketio
    
    if __name__ == '__main__':
        host = os.environ.get('HOST', '0.0.0.0')  # Default to 0.0.0.0 for external access
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        print(f"Starting nettools on http://{host}:{port}")
        print(f"Debug mode: {debug}")
        
        try:
            # First try with allow_unsafe_werkzeug (newer versions of Flask-SocketIO)
            socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
        except TypeError:
            # Fall back to old syntax if allow_unsafe_werkzeug is not supported
            socketio.run(app, host=host, port=port, debug=debug)
            
except Exception as e:
    print(f"ERROR: Failed to start nettools application: {str(e)}")
    print("Traceback:")
    traceback.print_exc()
    sys.exit(1)
EOF

chmod +x ${BASE_DIR}/run.py
chown nettools_user:nettools_user ${BASE_DIR}/run.py

# ---------------------------------------------------
# 3. Fix start_nettools.sh
# ---------------------------------------------------
echo -e "\n${YELLOW}3. Fixing start_nettools.sh${NC}"

# Create a backup of the original file if it exists
if [ -f "${BASE_DIR}/start_nettools.sh" ]; then
    cp ${BASE_DIR}/start_nettools.sh ${BASE_DIR}/start_nettools.sh.backup.$(date +%Y%m%d%H%M%S)
fi

# Create an improved version
cat > ${BASE_DIR}/start_nettools.sh << 'EOF'
#!/bin/bash
#
# nettools - Web-Based Network Packet Capture Tool
# Startup Script
#

# Change to the application directory
cd /opt/nettools

# Activate the virtual environment
source venv/bin/activate

# Set environment variables
export FLASK_APP=run.py
export FLASK_DEBUG=true
export HOST=0.0.0.0
export PORT=5000

echo "Starting nettools on http://0.0.0.0:5000"
echo "Press Ctrl+C to stop"

# Start the application
python run.py
EOF

chmod +x ${BASE_DIR}/start_nettools.sh
chown nettools_user:nettools_user ${BASE_DIR}/start_nettools.sh

# ---------------------------------------------------
# 4. Fix systemd service
# ---------------------------------------------------
echo -e "\n${YELLOW}4. Fixing systemd service${NC}"

# Create an improved service file
cat > /etc/systemd/system/nettools.service << 'EOF'
[Unit]
Description=nettools - Web-Based Network Packet Capture Tool
After=network.target

[Service]
User=nettools_user
Group=nettools_user
WorkingDirectory=/opt/nettools
ExecStart=/opt/nettools/venv/bin/python run.py
Restart=on-failure
RestartSec=10
Environment=FLASK_DEBUG=true
Environment=HOST=0.0.0.0
Environment=PORT=5000

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# ---------------------------------------------------
# 5. Ensure required directories exist
# ---------------------------------------------------
echo -e "\n${YELLOW}5. Ensuring required directories exist${NC}"

# Create app module directories
mkdir -p ${BASE_DIR}/app/templates
mkdir -p ${BASE_DIR}/app/static/css
mkdir -p ${BASE_DIR}/app/static/js
mkdir -p ${BASE_DIR}/app/static/img
mkdir -p ${BASE_DIR}/app/auth
mkdir -p ${BASE_DIR}/app/dashboard
mkdir -p ${BASE_DIR}/app/capture
mkdir -p ${BASE_DIR}/app/api
mkdir -p ${BASE_DIR}/app/utils

# Create data directories
mkdir -p ${BASE_DIR}/pcap_files
mkdir -p ${BASE_DIR}/logs

# ---------------------------------------------------
# 13. Fix permissions and ownership
# ---------------------------------------------------
echo -e "\n${YELLOW}13. Fixing file permissions${NC}"

find ${BASE_DIR} -type d -exec chmod 755 {} \;
find ${BASE_DIR} -type f -exec chmod 644 {} \;
chmod +x ${BASE_DIR}/run.py
chmod +x ${BASE_DIR}/start_nettools.sh

# Set correct ownership for all files
chown -R nettools_user:nettools_user ${BASE_DIR}

# Set special permissions for data directories
chmod 770 ${BASE_DIR}/pcap_files
chmod 770 ${BASE_DIR}/logs

# ---------------------------------------------------
# 14. Check for firewall issues
# ---------------------------------------------------
echo -e "\n${YELLOW}14. Checking firewall rules${NC}"

# Check if ufw is active
if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    echo -e "${GREEN}-> UFW firewall is active, adding rule for port 5000...${NC}"
    ufw allow 5000/tcp
fi

# Check if firewalld is active
if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
    echo -e "${GREEN}-> firewalld is active, adding rule for port 5000...${NC}"
    firewall-cmd --permanent --add-port=5000/tcp
    firewall-cmd --reload
fi

# ---------------------------------------------------
# 15. Start the service
# ---------------------------------------------------
echo -e "\n${YELLOW}15. Starting nettools service${NC}"

systemctl daemon-reload
systemctl enable nettools.service
systemctl start nettools.service

# Check status
echo -e "${GREEN}-> Service status:${NC}"
systemctl status nettools.service

# ---------------------------------------------------
# Final instructions
# ---------------------------------------------------
echo -e "${GREEN}=========================================================${NC}"
echo -e "${GREEN}     nettools All-in-One Fix Complete!                   ${NC}"
echo -e "${GREEN}=========================================================${NC}"
echo -e "\n${YELLOW}The service has been fixed and restarted.${NC}"
echo -e "\n${YELLOW}Access the application at:${NC}"
echo -e "http://$(hostname -I | awk '{print $1}'):5000"
echo -e "\n${YELLOW}If you encounter any issues, try these commands:${NC}"
echo -e "1. Check logs: sudo journalctl -u nettools.service -f"
echo -e "2. Restart service: sudo systemctl restart nettools.service"
echo -e "3. Run manually: sudo -u nettools_user ${BASE_DIR}/start_nettools.sh"
echo -e "\n${GREEN}Thank you for using nettools!${NC}"