#!/bin/bash
#
# nettools_setup_complete.sh - Complete setup script for the nettools application
#
# This script performs a complete setup of the nettools application with a professional
# dark mode UI, correct functionality, and all required dependencies. It handles system 
# updates, package installation, user creation, directory setup, and application configuration.
#
# Usage: sudo bash nettools_setup_complete.sh
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
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}     nettools Setup Script                               ${NC}"
echo -e "${BLUE}     $(date)                                             ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# ---------------------------------------------------
# 1. System Updates and Package Installation
# ---------------------------------------------------
echo -e "\n${YELLOW}1. System Updates and Package Installation${NC}"

echo -e "${GREEN}-> Updating package lists...${NC}"
apt-get update

echo -e "${GREEN}-> Upgrading packages...${NC}"
apt-get upgrade -y

echo -e "${GREEN}-> Installing core dependencies...${NC}"
apt-get install -y python3 python3-venv python3-dev python3-pip
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y net-tools tshark tcpdump wireshark
apt-get install -y nginx
apt-get install -y dos2unix

echo -e "${GREEN}-> Installing development tools...${NC}"
apt-get install -y git build-essential

# ---------------------------------------------------
# 2. User and Group Setup
# ---------------------------------------------------
echo -e "\n${YELLOW}2. User and Group Setup${NC}"

echo -e "${GREEN}-> Creating nettools_user...${NC}"
# Check if user already exists
if id "nettools_user" &>/dev/null; then
    echo -e "${YELLOW}User nettools_user already exists${NC}"
else
    adduser --system --shell /bin/bash --group --disabled-password --home ${BASE_DIR} nettools_user
    echo -e "${GREEN}User nettools_user created${NC}"
fi

echo -e "${GREEN}-> Adding nettools_user to wireshark group...${NC}"
usermod -aG wireshark nettools_user

# ---------------------------------------------------
# 3. Directory Structure Setup
# ---------------------------------------------------
echo -e "\n${YELLOW}3. Directory Structure Setup${NC}"

echo -e "${GREEN}-> Creating application directory structure...${NC}"
mkdir -p ${BASE_DIR}
mkdir -p ${BASE_DIR}/app/{auth,capture,dashboard,api,utils}
mkdir -p ${BASE_DIR}/app/templates/{auth,dashboard,capture}
mkdir -p ${BASE_DIR}/app/static/{css,js,img}
mkdir -p ${BASE_DIR}/tests/{unit,integration,fixtures}
mkdir -p ${BASE_DIR}/pcap_files
mkdir -p ${BASE_DIR}/logs

# ---------------------------------------------------
# 4. Python Virtual Environment Setup
# ---------------------------------------------------
echo -e "\n${YELLOW}4. Python Virtual Environment Setup${NC}"

echo -e "${GREEN}-> Creating and activating virtual environment...${NC}"
cd ${BASE_DIR}
python3 -m venv venv
source ${BASE_DIR}/venv/bin/activate

# ---------------------------------------------------
# 5. Install Python Dependencies
# ---------------------------------------------------
echo -e "\n${YELLOW}5. Installing Python Dependencies${NC}"

echo -e "${GREEN}-> Installing required Python packages...${NC}"
pip install --upgrade pip
pip install flask flask-login flask-wtf flask-socketio
pip install gunicorn gevent gevent-websocket
pip install bcrypt PyJWT flask-limiter
pip install dpkt pyshark scapy
pip install aiohttp aiofiles
pip install influxdb-client pandas matplotlib
pip install prometheus-flask-exporter python-json-logger
pip install pytest pytest-cov pytest-mock

# Generate requirements.txt
pip freeze > ${BASE_DIR}/requirements.txt

# Deactivate virtual environment
deactivate

# ---------------------------------------------------
# 6. Create Configuration Files
# ---------------------------------------------------
echo -e "\n${YELLOW}6. Creating Configuration Files${NC}"

# Create config.py
echo -e "${GREEN}-> Creating config.py...${NC}"
cat > ${BASE_DIR}/config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    PCAP_STORAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pcap_files')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max upload size
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    
    # InfluxDB settings
    INFLUXDB_URL = os.environ.get('INFLUXDB_URL', 'http://localhost:8086')
    INFLUXDB_TOKEN = os.environ.get('INFLUXDB_TOKEN', '')
    INFLUXDB_ORG = os.environ.get('INFLUXDB_ORG', 'packet_capture')
    INFLUXDB_BUCKET = os.environ.get('INFLUXDB_BUCKET', 'network_metrics')
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Security settings
    CSRF_ENABLED = True
    BCRYPT_LOG_ROUNDS = 13

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False
    BCRYPT_LOG_ROUNDS = 4  # Lower rounds for faster tests

class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = False
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    PCAP_STORAGE_PATH = '/tmp/pcap_test'
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    
    # In production, ensure these are set as environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Use secure cookies in production
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # Content Security Policy
    CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'"
    }

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
EOF

# Create dark mode CSS
echo -e "${GREEN}-> Creating dark mode CSS...${NC}"
cat > ${BASE_DIR}/app/static/css/dark-mode.css << 'EOF'
:root {
  /* Base colors */
  --bg-primary: #121212;       /* Main background */
  --bg-secondary: #1e1e1e;     /* Card backgrounds, sidebar */
  --bg-tertiary: #252525;      /* Input backgrounds, darker panels */
  --text-primary: #d3d3d3;     /* Main text color */
  --text-secondary: #b0b0b0;   /* Secondary text, labels */
  --accent: #0078d7;           /* Primary accent (blue) */
  --accent-hover: #0086f0;     /* Hover state for accent */
  --success: #16a34a;          /* Success actions/indicators (green) */
  --error: #dc2626;            /* Error states/destructive actions (red) */
  --warning: #f59e0b;          /* Warning states (amber) */
  --border: #444444;           /* Border color */
  
  /* Additional colors for specific components */
  --terminal-bg: #000000;      /* Terminal background */
  --terminal-text: #00ff00;    /* Terminal text */
  --highlight: rgba(255, 255, 255, 0.05); /* Hover highlight */
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, 
               Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  background-color: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
  display: flex;
}

/* Layout Structure */
.sidebar {
  width: 250px;
  height: 100vh;
  position: fixed;
  left: 0;
  top: 0;
  background-color: var(--bg-secondary);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  transition: transform 0.3s ease;
  z-index: 100;
}

.content {
  margin-left: 250px;
  width: calc(100% - 250px);
  padding: 2rem;
  min-height: 100vh;
}

/* Typography */
h1.page-title {
  font-size: 1.75rem;
  font-weight: 700;
  margin-bottom: 1rem;
}

.page-description {
  color: var(--text-secondary);
  margin-bottom: 2rem;
}

h2 {
  font-size: 1.5rem;
  font-weight: 600;
}

h3 {
  font-size: 1.2rem;
  font-weight: 600;
}

p {
  margin-bottom: 1rem;
}

.text-secondary {
  color: var(--text-secondary);
  font-size: 0.9rem;
}

.text-small {
  font-size: 0.8rem;
}

.monospace {
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
}

/* Navigation */
.sidebar-header {
  padding: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.sidebar-header h1 {
  font-size: 1.25rem;
  font-weight: 600;
}

.sidebar-header p {
  color: var(--text-secondary);
  font-size: 0.8rem;
  margin-top: 0.5rem;
}

.nav-list {
  list-style: none;
  padding: 1rem 0;
}

.nav-item {
  margin-bottom: 0.5rem;
}

.nav-link {
  display: block;
  padding: 0.75rem 1.5rem;
  color: var(--text-primary);
  text-decoration: none;
  transition: all 0.2s ease;
  border-left: 3px solid transparent;
}

.nav-link:hover, .nav-link.active {
  background-color: var(--bg-tertiary);
  border-left-color: var(--accent);
}

.icon {
  margin-right: 0.5rem;
  display: inline-block;
  width: 1.2rem;
  text-align: center;
}

.sidebar-footer {
  position: absolute;
  bottom: 0;
  left: 0;
  width: 100%;
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--border);
  font-size: 0.8rem;
  color: var(--text-secondary);
}

/* Cards */
.card {
  background-color: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}

.card-title {
  margin: 0;
  font-size: 1.2rem;
  font-weight: 600;
}

.card-body {
  margin-bottom: 1rem;
}

.card-footer {
  border-top: 1px solid var(--border);
  margin-top: 1.5rem;
  padding-top: 1rem;
  display: flex;
  justify-content: flex-end;
}

/* Buttons */
.btn {
  background-color: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  padding: 0.5rem 1rem;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s ease, transform 0.1s ease;
  text-decoration: none;
  display: inline-block;
}

.btn:hover {
  background-color: var(--accent-hover);
  transform: translateY(-1px);
}

.btn:active {
  transform: translateY(0);
}

.btn-secondary {
  background-color: var(--bg-tertiary);
  color: var(--text-primary);
}

.btn-secondary:hover {
  background-color: rgba(255, 255, 255, 0.1);
}

.btn-success {
  background-color: var(--success);
}

.btn-warning {
  background-color: var(--warning);
  color: #000;
}

.btn-danger {
  background-color: var(--error);
}

.btn-sm {
  padding: 0.25rem 0.75rem;
  font-size: 0.8rem;
}

.btn-icon {
  padding: 0.5rem;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2rem;
  height: 2rem;
}

/* Forms */
.form-group {
  margin-bottom: 1.25rem;
}

.form-label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.form-hint {
  display: block;
  margin-top: 0.25rem;
  color: var(--text-secondary);
  font-size: 0.8rem;
}

.form-control {
  width: 100%;
  padding: 0.75rem;
  border-radius: 4px;
  border: 1px solid var(--border);
  background-color: var(--bg-tertiary);
  color: var(--text-primary);
  font-size: 1rem;
}

.form-control:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px rgba(0, 120, 215, 0.25);
}

select.form-control {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23b0b0b0' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14 2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 1rem center;
  padding-right: 2.5rem;
}

/* Tables */
.table-container {
  overflow-x: auto;
  border-radius: 8px;
  border: 1px solid var(--border);
  margin-bottom: 1.5rem;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

th {
  background-color: var(--bg-tertiary);
  font-weight: 600;
  color: var(--text-secondary);
}

tbody tr:hover {
  background-color: var(--highlight);
}

/* Status Indicators */
.status-indicator {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 500;
}

.status-indicator::before {
  content: "";
  display: inline-block;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  margin-right: 0.5rem;
}

.status-success {
  background-color: rgba(22, 163, 74, 0.1);
  color: var(--success);
}

.status-success::before {
  background-color: var(--success);
}

.status-warning {
  background-color: rgba(245, 158, 11, 0.1);
  color: var(--warning);
}

.status-warning::before {
  background-color: var(--warning);
}

.status-error {
  background-color: rgba(220, 38, 38, 0.1);
  color: var(--error);
}

.status-error::before {
  background-color: var(--error);
}

/* Alerts */
.alert {
  padding: 1rem;
  border-radius: 4px;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
}

.alert-icon {
  margin-right: 0.75rem;
  font-size: 1.2rem;
}

.alert-success {
  background-color: rgba(22, 163, 74, 0.1);
  color: var(--success);
  border-left: 4px solid var(--success);
}

.alert-warning {
  background-color: rgba(245, 158, 11, 0.1);
  color: var(--warning);
  border-left: 4px solid var(--warning);
}

.alert-error {
  background-color: rgba(220, 38, 38, 0.1);
  color: var(--error);
  border-left: 4px solid var(--error);
}

/* Stats cards */
.stats-container {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  background-color: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 1rem;
}

.stat-label {
  font-size: 0.9rem;
  color: var(--text-secondary);
  margin-bottom: 0.5rem;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  margin-bottom: 0.25rem;
}

.stat-secondary {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

/* Terminal */
.terminal-container {
  background-color: var(--terminal-bg);
  border-radius: 8px;
  padding: 0.75rem;
  margin-bottom: 1.5rem;
  overflow: hidden;
}

.terminal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.terminal-title {
  color: var(--text-secondary);
  font-size: 0.9rem;
}

.terminal-content {
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  height: 300px;
  overflow-y: auto;
  padding: 0.5rem;
  color: var(--terminal-text);
  font-size: 0.9rem;
  line-height: 1.4;
}

/* Utilities */
.d-flex {
  display: flex;
}

.justify-content-between {
  justify-content: space-between;
}

.align-items-center {
  align-items: center;
}

.flex-wrap {
  flex-wrap: wrap;
}

.gap-1 {
  gap: 0.5rem;
}

.gap-2 {
  gap: 1rem;
}

.mb-1 {
  margin-bottom: 0.5rem;
}

.mb-2 {
  margin-bottom: 1rem;
}

.mb-3 {
  margin-bottom: 1.5rem;
}

.mb-4 {
  margin-bottom: 2rem;
}

.p-2 {
  padding: 1rem;
}

.p-3 {
  padding: 1.5rem;
}

.text-center {
  text-align: center;
}

/* Animations */
.status-running {
  animation: pulse-opacity 1.5s infinite;
}

@keyframes pulse-opacity {
  0% { opacity: 0.7; }
  50% { opacity: 1; }
  100% { opacity: 0.7; }
}

/* Responsive adjustments */
@media (max-width: 991px) {
  .sidebar {
    transform: translateX(-100%);
    z-index: 1000;
  }
  
  .sidebar.active {
    transform: translateX(0);
  }
  
  .content {
    margin-left: 0;
    width: 100%;
  }
  
  .menu-toggle {
    display: block;
    position: fixed;
    top: 1rem;
    left: 1rem;
    z-index: 1001;
    padding: 0.5rem;
    background-color: var(--bg-secondary);
    border-radius: 4px;
    border: 1px solid var(--border);
  }
}

@media (min-width: 992px) {
  .menu-toggle {
    display: none;
  }
}
EOF

# Create app/__init__.py
echo -e "${GREEN}-> Creating app/__init__.py...${NC}"
cat > ${BASE_DIR}/app/__init__.py << 'EOF'
import os
import logging
from flask import Flask, redirect, url_for, render_template_string
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
    try:
        from config import config
        app.config.from_object(config[config_name])
    except (ImportError, KeyError):
        # Fallback to basic configuration if config.py is missing or invalid
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-fallback')
        app.config['PCAP_STORAGE_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pcap_files')
    
    # Ensure PCAP storage directory exists
    os.makedirs(app.config.get('PCAP_STORAGE_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pcap_files')), exist_ok=True)
    
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
        try:
            from app.auth.models import User
            return User(user_id, "admin")
        except ImportError:
            # Fallback for missing User model
            from flask_login import UserMixin
            class FallbackUser(UserMixin):
                def __init__(self, id):
                    self.id = id
                def get_id(self):
                    return str(self.id)
            return FallbackUser(user_id)
    
    # Custom error handler for CSRF errors
    @app.errorhandler(400)
    def handle_csrf_error(e):
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF Error</title>
            <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-mode.css') }}">
        </head>
        <body>
            <div class="content">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">CSRF Token Error</h2>
                    </div>
                    <div class="card-body">
                        <p>There was a problem with your form submission. Please try again.</p>
                    </div>
                    <div class="card-footer">
                        <a href="{{ url_for('auth.login') }}" class="btn">Return to Login</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """), 400
    
    # Root route redirects to dashboard or fallback
    @app.route('/')
    def index():
        try:
            return redirect(url_for('dashboard.index'))
        except:
            # Fallback route if dashboard blueprint is not registered
            @app.route('/fallback')
            def fallback():
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>nettools</title>
                    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-mode.css') }}">
                </head>
                <body>
                    <div class="content">
                        <div class="card">
                            <div class="card-header">
                                <h2 class="card-title">nettools</h2>
                            </div>
                            <div class="card-body">
                                <p>nettools is running, but some components are missing. Please check installation.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """)
            return redirect(url_for('fallback'))
    
    # Register blueprints with error handling
    blueprints = [
        ('app.auth.routes', 'auth_bp', None),
        ('app.dashboard.routes', 'dashboard_bp', None),
        ('app.capture.routes', 'capture_bp', None),
        ('app.api.auth', 'api_auth_bp', '/api/auth'),
        ('app.api.dashboard', 'api_dashboard_bp', '/api/dashboard'),
        ('app.api.capture', 'api_capture_bp', '/api/capture')
    ]
    
    for module_path, blueprint_name, url_prefix in blueprints:
        try:
            module = __import__(module_path, fromlist=[blueprint_name])
            blueprint = getattr(module, blueprint_name)
            app.register_blueprint(blueprint, url_prefix=url_prefix)
            logger.info(f"Registered blueprint: {blueprint_name}")
        except (ImportError, AttributeError) as e:
            logger.warning(f"Could not register blueprint {blueprint_name}: {str(e)}")
    
    return app, socketio

# Initialize app and socketio
try:
    app, socketio = create_app()
except Exception as e:
    import sys
    logger.error(f"Error creating app: {str(e)}")
    # Create minimal fallback app that at least runs
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'fallback-key'
    socketio = SocketIO(app)
    csrf = CSRFProtect(app)
    
    @app.route('/')
    def fallback_index():
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>nettools</title>
            <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-mode.css') }}">
        </head>
        <body>
            <div class="content">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">nettools</h2>
                    </div>
                    <div class="card-body">
                        <p>nettools is running in fallback mode. Check logs for errors.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """)
EOF

# Create run.py
echo -e "${GREEN}-> Creating run.py...${NC}"
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

# ---------------------------------------------------
# 7. Create Basic Module Files
# ---------------------------------------------------
echo -e "\n${YELLOW}7. Creating Basic Module Files${NC}"

# Auth module
echo -e "${GREEN}-> Creating auth module files...${NC}"
touch ${BASE_DIR}/app/auth/__init__.py

cat > ${BASE_DIR}/app/auth/models.py << 'EOF'
from flask_login import UserMixin

class User(UserMixin):
    """Simple User model for development."""
    
    def __init__(self, id, username, email=None):
        self.id = id
        self.username = username
        self.email = email
        
    def get_id(self):
        return str(self.id)
EOF

cat > ${BASE_DIR}/app/auth/routes.py << 'EOF'
from flask import Blueprint, redirect, url_for, request, flash, render_template
from flask_login import login_user, logout_user, login_required
from app.auth.models import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Auto-login for development purposes."""
    if request.method == 'POST':
        # Create and log in a dummy user for development
        dummy_user = User("dev_user", "admin")
        login_user(dummy_user)
        
        # Redirect to requested page or default to dashboard
        next_page = request.args.get('next', url_for('dashboard.index'))
        flash('You have been automatically logged in for development purposes.', 'info')
        return redirect(next_page)
    
    # Basic page if template is missing
    try:
        return render_template('auth/login.html', title='Login')
    except:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <link rel="stylesheet" href="/static/css/dark-mode.css">
        </head>
        <body>
            <div class="content">
                <div class="card" style="max-width: 400px; margin: 100px auto;">
                    <div class="card-header">
                        <h2 class="card-title">nettools Login</h2>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="btn">Login (Development Mode)</button>
                        </form>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    return redirect(url_for('auth.login'))
EOF

# Dashboard module
echo -e "${GREEN}-> Creating dashboard module files...${NC}"
touch ${BASE_DIR}/app/dashboard/__init__.py

cat > ${BASE_DIR}/app/dashboard/routes.py << 'EOF'
from flask import Blueprint, render_template
from flask_login import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Dashboard index page."""
    try:
        return render_template('dashboard/index.html', title='Dashboard')
    except:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <link rel="stylesheet" href="/static/css/dark-mode.css">
        </head>
        <body>
            <div class="sidebar">
                <div class="sidebar-header">
                    <h1>nettools</h1>
                    <p>Network Analysis Tool</p>
                </div>
                <ul class="nav-list">
                    <li class="nav-item">
                        <a href="/dashboard" class="nav-link active">
                            <span class="icon">⧉</span> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/capture" class="nav-link">
                            <span class="icon">▶</span> Capture
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/logout" class="nav-link">
                            <span class="icon">↪</span> Logout
                        </a>
                    </li>
                </ul>
                <div class="sidebar-footer">
                    <p>nettools v1.0</p>
                </div>
            </div>
            
            <div class="content">
                <h1 class="page-title">Dashboard</h1>
                <p class="page-description">Network monitoring and packet capture tool</p>
                
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-label">Available Interfaces</div>
                        <div class="stat-value">2</div>
                        <div class="stat-secondary">eth0, lo</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Disk Space</div>
                        <div class="stat-value">32<span style="font-size: 1rem">GB</span></div>
                        <div class="stat-secondary">available space</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">PCAP Storage</div>
                        <div class="stat-value">0</div>
                        <div class="stat-secondary">files stored</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Quick Actions</h2>
                    </div>
                    <div class="card-body">
                        <div class="d-flex gap-1">
                            <a href="/capture" class="btn">Start New Capture</a>
                            <a href="#" class="btn btn-secondary">Browse Saved Captures</a>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Recent Activity</h2>
                    </div>
                    <div class="card-body">
                        <p class="text-secondary">No recent capture activity found.</p>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Interface</th>
                                        <th>Duration</th>
                                        <th>Packets</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td colspan="5" class="text-center">No data available</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
EOF

# Capture module
echo -e "${GREEN}-> Creating capture module files...${NC}"
touch ${BASE_DIR}/app/capture/__init__.py

cat > ${BASE_DIR}/app/capture/routes.py << 'EOF'
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
import os
import uuid
import subprocess
import json
from datetime import datetime

# Create blueprint
capture_bp = Blueprint('capture', __name__)

# Store active captures
active_captures = {}

@capture_bp.route('/capture')
@login_required
def index():
    """Render the capture configuration page."""
    return render_template('capture/index.html', title='Network Packet Capture')

@capture_bp.route('/api/capture/interfaces', methods=['GET'])
@login_required
def get_interfaces():
    """Get available network interfaces."""
    try:
        # Use ifconfig or ip to get interfaces
        interfaces = get_network_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        current_app.logger.error(f"Error getting interfaces: {str(e)}")
        return jsonify(['eth0', 'lo'])  # Return default interfaces on error

@capture_bp.route('/api/capture/start', methods=['POST'])
@login_required
def start_capture():
    """Start a packet capture."""
    try:
        data = request.json
        
        # Generate a unique ID for this capture
        capture_id = str(uuid.uuid4())
        
        # Store capture info (simulation)
        active_captures[capture_id] = {
            'id': capture_id,
            'interface': data.get('interface', 'eth0'),
            'filter': data.get('filter', ''),
            'started_at': datetime.now().isoformat(),
            'active': True
        }
        
        return jsonify({
            'status': 'success',
            'message': 'Capture started successfully',
            'capture_id': capture_id
        })
        
    except Exception as e:
        current_app.logger.error(f"Error starting capture: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to start capture: {str(e)}"
        }), 500

@capture_bp.route('/api/capture/stop/<capture_id>', methods=['POST'])
@login_required
def stop_capture(capture_id):
    """Stop a packet capture."""
    if capture_id not in active_captures:
        return jsonify({
            'status': 'error',
            'message': 'Capture not found'
        }), 404
    
    # Update capture info
    active_captures[capture_id]['active'] = False
    active_captures[capture_id]['ended_at'] = datetime.now().isoformat()
    
    return jsonify({
        'status': 'success',
        'message': 'Capture stopped successfully'
    })

@capture_bp.route('/api/capture/status', methods=['GET'])
@login_required
def get_status():
    """Get the status of all captures."""
    return jsonify({
        'status': 'success',
        'captures': active_captures
    })

def get_network_interfaces():
    """Get a list of available network interfaces."""
    interfaces = []
    
    try:
        # Try using 'ip' command first (more modern)
        result = subprocess.run(['ip', '-o', 'link', 'show'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE,
                             text=True)
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                # Extract interface name (first field after number)
                parts = line.strip().split(':', 2)
                if len(parts) >= 2:
                    interface = parts[1].strip()
                    if interface != 'lo':  # Skip loopback
                        interfaces.append(interface)
            
            # Always add loopback at the end
            interfaces.append('lo')
        else:
            # If 'ip' fails, try 'ifconfig'
            result = subprocess.run(['ifconfig'], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 text=True)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    if line and not line.startswith(' '):
                        interface = line.split(':')[0]
                        interfaces.append(interface)
            else:
                # If both fail, return default interfaces
                interfaces = ['eth0', 'lo']
    except Exception as e:
        # In case of any error, return default interfaces
        current_app.logger.error(f"Error getting network interfaces: {str(e)}")
        interfaces = ['eth0', 'lo']
    
    return interfaces
EOF

# API modules
echo -e "${GREEN}-> Creating API module files...${NC}"
touch ${BASE_DIR}/app/api/__init__.py

cat > ${BASE_DIR}/app/api/auth.py << 'EOF'
from flask import Blueprint, jsonify

api_auth_bp = Blueprint('api_auth', __name__)

@api_auth_bp.route('/status')
def status():
    return jsonify({"status": "ok", "message": "Auth API is working"})
EOF

cat > ${BASE_DIR}/app/api/dashboard.py << 'EOF'
from flask import Blueprint, jsonify

api_dashboard_bp = Blueprint('api_dashboard', __name__)

@api_dashboard_bp.route('/status')
def status():
    return jsonify({"status": "ok", "message": "Dashboard API is working"})

@api_dashboard_bp.route('/system-info')
def system_info():
    """Get system information."""
    return jsonify({
        'status': 'success',
        'interfaces': ['eth0', 'lo'],
        'disk_space': {
            'total': '50 GB',
            'used': '10 GB',
            'available': '40 GB',
            'percent_used': 20
        },
        'pcap_storage': {
            'count': 0,
            'size': '0 MB'
        }
    })
EOF

cat > ${BASE_DIR}/app/api/capture.py << 'EOF'
from flask import Blueprint, jsonify, request
import uuid
from datetime import datetime

api_capture_bp = Blueprint('api_capture', __name__)

# Store active captures
active_captures = {}

@api_capture_bp.route('/interfaces')
def get_interfaces():
    """Get available network interfaces."""
    return jsonify(['eth0', 'lo'])

@api_capture_bp.route('/start', methods=['POST'])
def start_capture():
    """Start a packet capture."""
    try:
        data = request.get_json()
        
        # Generate a unique ID for this capture
        capture_id = str(uuid.uuid4())
        
        # Store capture info (simulation)
        active_captures[capture_id] = {
            'id': capture_id,
            'interface': data.get('interface', 'eth0'),
            'filter': data.get('filter', ''),
            'started_at': datetime.now().isoformat(),
            'active': True
        }
        
        return jsonify({
            'status': 'success',
            'message': 'Capture started successfully',
            'capture_id': capture_id
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Failed to start capture: {str(e)}"
        }), 500

@api_capture_bp.route('/stop/<capture_id>', methods=['POST'])
def stop_capture(capture_id):
    """Stop a packet capture."""
    if capture_id not in active_captures:
        return jsonify({
            'status': 'error',
            'message': 'Capture not found'
        }), 404
    
    # Update capture info
    active_captures[capture_id]['active'] = False
    
    return jsonify({
        'status': 'success',
        'message': 'Capture stopped successfully'
    })

@api_capture_bp.route('/status')
def get_status():
    """Get the status of all captures."""
    return jsonify({
        'status': 'success',
        'captures': active_captures
    })
EOF

# Utils module
echo -e "${GREEN}-> Creating utils module files...${NC}"
mkdir -p ${BASE_DIR}/app/utils
touch ${BASE_DIR}/app/utils/__init__.py

cat > ${BASE_DIR}/app/utils/packet_parser.py << 'EOF'
def parse_packet_summary(packet):
    """
    Parse a packet JSON from tshark and return a summary.
    
    Args:
        packet (dict): The packet JSON from tshark
        
    Returns:
        dict: A summary of the packet
    """
    summary = {
        'number': None,
        'timestamp': None,
        'protocol': None,
        'length': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'info': None
    }
    
    try:
        # Parse from _source section
        source = packet.get('_source', {})
        layers = source.get('layers', {})
        
        # Get frame info
        frame = layers.get('frame', {})
        summary['number'] = int(frame.get('frame.number', ['0'])[0])
        summary['timestamp'] = frame.get('frame.time', [''])[0]
        summary['length'] = int(frame.get('frame.len', ['0'])[0])
        
        # Get IP info
        ip = layers.get('ip', {})
        if ip:
            summary['src_ip'] = ip.get('ip.src', [''])[0]
            summary['dst_ip'] = ip.get('ip.dst', [''])[0]
        
        # Get protocol info
        protocols = frame.get('frame.protocols', [''])[0].split(':')
        if protocols:
            summary['protocol'] = protocols[-1].upper()
        
        # Add a default info if none was set
        if not summary['info']:
            summary['info'] = f"Packet #{summary['number']}"
        
    except Exception as e:
        # If there's an error parsing, return a simple default
        summary['info'] = f"Error parsing packet: {str(e)}"
        
    return summary
EOF

# Create layout template
echo -e "${GREEN}-> Creating layout template...${NC}"
mkdir -p ${BASE_DIR}/app/templates

cat > ${BASE_DIR}/app/templates/layout.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title|default('nettools - Network Analysis') }}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-mode.css') }}">
    {% block styles %}{% endblock %}
</head>
<body>
    <button class="menu-toggle" id="menu-toggle">
        <span class="icon">≡</span>
    </button>
    
    <div class="sidebar">
        <div class="sidebar-header">
            <h1>nettools</h1>
            <p>Network Analysis Tool</p>
        </div>
        <ul class="nav-list">
            <li class="nav-item">
                <a href="/dashboard" class="nav-link {% if request.path == '/dashboard' %}active{% endif %}">
                    <span class="icon">⧉</span> Dashboard
                </a>
            </li>
            <li class="nav-item">
                <a href="/capture" class="nav-link {% if request.path == '/capture' %}active{% endif %}">
                    <span class="icon">▶</span> Capture
                </a>
            </li>
            <li class="nav-item">
                <a href="/logout" class="nav-link">
                    <span class="icon">↪</span> Logout
                </a>
            </li>
        </ul>
        <div class="sidebar-footer">
            <p>nettools v1.0</p>
        </div>
    </div>

    <div class="content">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        <div class="alert-icon">
                            {% if category == 'success' %}✓{% elif category == 'error' %}✗{% elif category == 'warning' %}!{% else %}ℹ{% endif %}
                        </div>
                        <div>{{ message }}</div>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Mobile menu toggle
            const menuToggle = document.getElementById('menu-toggle');
            const sidebar = document.querySelector('.sidebar');
            
            if (menuToggle && sidebar) {
                menuToggle.addEventListener('click', function() {
                    sidebar.classList.toggle('active');
                });
            }
            
            // Close sidebar when clicking outside
            document.addEventListener('click', function(event) {
                if (window.innerWidth <= 991 && sidebar.classList.contains('active') && 
                    !sidebar.contains(event.target) && event.target !== menuToggle) {
                    sidebar.classList.remove('active');
                }
            });
        });
    </script>
    
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

# Create auth templates
echo -e "${GREEN}-> Creating auth templates...${NC}"
mkdir -p ${BASE_DIR}/app/templates/auth

cat > ${BASE_DIR}/app/templates/auth/login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - nettools</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dark-mode.css') }}">
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: var(--bg-primary);
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 1rem;
        }
        .app-logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .app-logo h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        .app-logo p {
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="app-logo">
            <h1>nettools</h1>
            <p>Network Analysis Tool</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        <div class="alert-icon">
                            {% if category == 'success' %}✓{% elif category == 'error' %}✗{% elif category == 'warning' %}!{% else %}ℹ{% endif %}
                        </div>
                        <div>{{ message }}</div>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Login</h2>
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <div class="alert-icon">ℹ</div>
                    <div>This is a development version with simplified authentication.</div>
                </div>
                
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" value="admin" readonly>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password" value="password" readonly>
                    </div>
                    
                    <button type="submit" class="btn" style="width: 100%;">Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF

# Create dashboard templates
echo -e "${GREEN}-> Creating dashboard templates...${NC}"
mkdir -p ${BASE_DIR}/app/templates/dashboard

cat > ${BASE_DIR}/app/templates/dashboard/index.html << 'EOF'
{% extends "layout.html" %}

{% block content %}
<h1 class="page-title">Dashboard</h1>
<p class="page-description">Network monitoring and packet capture tool</p>

<div class="stats-container">
    <div class="stat-card">
        <div class="stat-label">Available Interfaces</div>
        <div class="stat-value">2</div>
        <div class="stat-secondary">eth0, lo</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Disk Space</div>
        <div class="stat-value">32<span style="font-size: 1rem">GB</span></div>
        <div class="stat-secondary">available space</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">PCAP Storage</div>
        <div class="stat-value">0</div>
        <div class="stat-secondary">files stored</div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Quick Actions</h2>
    </div>
    <div class="card-body">
        <div class="d-flex gap-1">
            <a href="/capture" class="btn">Start New Capture</a>
            <a href="#" class="btn btn-secondary">Browse Saved Captures</a>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Recent Activity</h2>
    </div>
    <div class="card-body">
        <p class="text-secondary">No recent capture activity found.</p>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Interface</th>
                        <th>Duration</th>
                        <th>Packets</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="5" class="text-center">No data available</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">System Information</h2>
    </div>
    <div class="card-body">
        <div class="form-group">
            <label class="form-label">CPU Usage</label>
            <div style="height: 10px; background: var(--bg-tertiary); border-radius: 5px; overflow: hidden;">
                <div style="width: 15%; height: 100%; background: var(--accent);"></div>
            </div>
            <span class="text-secondary">15%</span>
        </div>
        
        <div class="form-group">
            <label class="form-label">Memory Usage</label>
            <div style="height: 10px; background: var(--bg-tertiary); border-radius: 5px; overflow: hidden;">
                <div style="width: 40%; height: 100%; background: var(--accent);"></div>
            </div>
            <span class="text-secondary">40%</span>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Create capture templates
echo -e "${GREEN}-> Creating capture templates...${NC}"
mkdir -p ${BASE_DIR}/app/templates/capture

cat > ${BASE_DIR}/app/templates/capture/index.html << 'EOF'
{% extends "layout.html" %}

{% block content %}
<h1 class="page-title">Network Packet Capture</h1>
<p class="page-description">Configure and start a packet capture session</p>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Capture Configuration</h2>
    </div>
    <div class="card-body">
        <form id="capture-form">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <div class="form-group">
                <label class="form-label" for="interface">Network Interface</label>
                <select class="form-control" id="interface" name="interface">
                    <option value="" selected disabled>Select Interface</option>
                    <option value="eth0">eth0</option>
                    <option value="lo">lo</option>
                </select>
            </div>
            
            <div class="form-group">
                <label class="form-label" for="filter">Capture Filter (BPF Syntax)</label>
                <input type="text" class="form-control" id="filter" name="filter" placeholder="e.g., tcp port 80">
                <span class="form-hint">Examples: 'tcp port 80', 'host 192.168.1.1', 'icmp'</span>
            </div>
            
            <div class="form-group">
                <label class="form-label" for="packet-limit">Packet Limit</label>
                <input type="number" class="form-control" id="packet-limit" name="packet_limit" min="0" value="1000">
                <span class="form-hint">Maximum number of packets to capture (0 = unlimited)</span>
            </div>
            
            <div class="form-group">
                <label class="d-flex align-items-center">
                    <input type="checkbox" id="live-capture" name="live_capture" checked>
                    <span class="ml-2">Live Capture</span>
                </label>
            </div>
            
            <button type="submit" class="btn" id="start-capture">Start Capture</button>
        </form>
    </div>
</div>

<div id="capture-results" style="display: none;">
    <div class="card">
        <div class="card-header">
            <div class="d-flex justify-content-between align-items-center">
                <h2 class="card-title">Capture Results</h2>
                <button class="btn btn-danger" id="stop-capture">Stop Capture</button>
            </div>
        </div>
        <div class="card-body">
            <div class="status-indicator status-success mb-2" id="capture-status">
                Running capture on eth0
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody id="packets-tbody">
                        <tr>
                            <td colspan="7" class="text-center">No packets captured yet</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

{% endblock %}

{% block scripts %}
<script>
    // Get CSRF token for AJAX requests
    function getCsrfToken() {
        return document.querySelector('input[name="csrf_token"]').value;
    }

    let activeCapture = null;
    
    // Capture form submission 
    document.getElementById('capture-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const interfaceValue = document.getElementById('interface').value;
        const filterValue = document.getElementById('filter').value;
        const packetLimitValue = document.getElementById('packet-limit').value;
        
        // Validate form
        if (!interfaceValue) {
            alert('Please select a network interface.');
            return;
        }
        
        // Start capture via AJAX
        fetch('/api/capture/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({
                interface: interfaceValue,
                filter: filterValue,
                packet_limit: packetLimitValue
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Show capture results section
                document.getElementById('capture-results').style.display = 'block';
                activeCapture = data.capture_id;
                
                // Update UI to show active capture
                const captureStatus = document.getElementById('capture-status');
                captureStatus.textContent = `Running capture on ${interfaceValue}${filterValue ? ' with filter: ' + filterValue : ''}`;
                captureStatus.classList.add('status-running');
                
                const tbody = document.getElementById('packets-tbody');
                tbody.innerHTML = '<tr><td colspan="7" class="text-center">Capture started. Waiting for packets...</td></tr>';
                
                // Scroll to results
                document.getElementById('capture-results').scrollIntoView({ behavior: 'smooth' });
                
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to start capture. See console for details.');
        });
    });

    // Stop capture button
    document.getElementById('stop-capture').addEventListener('click', function() {
        if (!activeCapture) {
            alert('No active capture to stop.');
            return;
        }
        
        fetch(`/api/capture/stop/${activeCapture}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const captureStatus = document.getElementById('capture-status');
                captureStatus.textContent = 'Capture stopped';
                captureStatus.classList.remove('status-running');
                captureStatus.classList.remove('status-success');
                captureStatus.classList.add('status-warning');
                
                // Show success message
                const alert = document.createElement('div');
                alert.className = 'alert alert-success mb-2';
                alert.innerHTML = '<div class="alert-icon">✓</div><div>Capture stopped successfully</div>';
                
                document.getElementById('capture-results').querySelector('.card-body').insertBefore(
                    alert, 
                    document.getElementById('capture-results').querySelector('.card-body').firstChild
                );
                
                activeCapture = null;
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to stop capture. See console for details.');
        });
    });
</script>
{% endblock %}
EOF

# ---------------------------------------------------
# 8. Create Start Script and Service
# ---------------------------------------------------
echo -e "\n${YELLOW}8. Creating Start Script and Service${NC}"

# Create start script
echo -e "${GREEN}-> Creating start_nettools.sh...${NC}"
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

# Create systemd service file
echo -e "${GREEN}-> Creating systemd service file...${NC}"
cat > /etc/systemd/system/nettools.service << 'EOF'
[Unit]
Description=nettools - Web-Based Network Packet Capture Tool
After=network.target

[Service]
User=nettools_user
Group=nettools_user
WorkingDirectory=/opt/nettools
ExecStart=/opt/nettools/venv/bin/python /opt/nettools/run.py
Restart=on-failure
RestartSec=10
Environment=FLASK_DEBUG=true
Environment=HOST=0.0.0.0
Environment=PORT=5000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nettools.service

# ---------------------------------------------------
# 9. Set Permissions
# ---------------------------------------------------
echo -e "\n${YELLOW}9. Setting Permissions${NC}"

find ${BASE_DIR} -type d -exec chmod 755 {} \;
find ${BASE_DIR} -type f -exec chmod 644 {} \;
chmod +x ${BASE_DIR}/run.py
chmod +x ${BASE_DIR}/start_nettools.sh

# Special permissions for data directories
chmod 770 ${BASE_DIR}/pcap_files
chmod 770 ${BASE_DIR}/logs

# Set ownership
chown -R nettools_user:nettools_user ${BASE_DIR}

# ---------------------------------------------------
# 10. Configure Firewall (if needed)
# ---------------------------------------------------
echo -e "\n${YELLOW}10. Configuring Firewall${NC}"

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
# 11. Start the Service
# ---------------------------------------------------
echo -e "\n${YELLOW}11. Starting nettools Service${NC}"

systemctl start nettools.service
sleep 3  # Give the service a moment to start

# Check if the service is running
if systemctl is-active --quiet nettools.service; then
    echo -e "${GREEN}-> nettools service is running successfully!${NC}"
    systemctl status nettools.service
else
    echo -e "${RED}-> nettools service failed to start.${NC}"
    echo -e "${YELLOW}-> Checking service logs:${NC}"
    systemctl status nettools.service
    journalctl -u nettools.service -n 20
fi

# ---------------------------------------------------
# Final Summary and Instructions
# ---------------------------------------------------
echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}     nettools Setup Complete!                            ${NC}"
echo -e "${BLUE}=========================================================${NC}"
echo -e "\n${GREEN}The nettools application has been installed and configured with a professional dark mode UI.${NC}"
echo -e "\n${GREEN}You can access the application at:${NC}"
echo -e "  http://$(hostname -I | awk '{print $1}'):5000"
echo -e "\n${GREEN}Useful commands:${NC}"
echo -e "  - Check service status: sudo systemctl status nettools.service"
echo -e "  - View service logs: sudo journalctl -u nettools.service -f"
echo -e "  - Restart service: sudo systemctl restart nettools.service"
echo -e "  - Start manually: sudo -u nettools_user ${BASE_DIR}/start_nettools.sh"
echo -e "\n${GREEN}Thank you for using nettools!${NC}"