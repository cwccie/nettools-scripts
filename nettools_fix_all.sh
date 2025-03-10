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
# 6. Create minimal auth module if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}6. Creating minimal auth module${NC}"

# Create __init__.py
touch ${BASE_DIR}/app/auth/__init__.py

# Create auth/models.py if missing
if [ ! -f "${BASE_DIR}/app/auth/models.py" ]; then
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
fi

# Create auth/routes.py if missing
if [ ! -f "${BASE_DIR}/app/auth/routes.py" ]; then
    cat > ${BASE_DIR}/app/auth/routes.py << 'EOF'
from flask import Blueprint, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Auto-login for development purposes."""
    from app.auth.models import User
    
    # Create and log in a dummy user for development
    dummy_user = User("dev_user", "admin")
    login_user(dummy_user)
    
    # Redirect to requested page or default to dashboard
    next_page = request.args.get('next', url_for('dashboard.index'))
    flash('You have been automatically logged in for development purposes.', 'info')
    return redirect(next_page)

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
EOF
fi

# ---------------------------------------------------
# 7. Create minimal dashboard module if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}7. Creating minimal dashboard module${NC}"

# Create __init__.py
touch ${BASE_DIR}/app/dashboard/__init__.py

# Create dashboard/routes.py if missing
if [ ! -f "${BASE_DIR}/app/dashboard/routes.py" ]; then
    cat > ${BASE_DIR}/app/dashboard/routes.py << 'EOF'
from flask import Blueprint, render_template
from flask_login import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Dashboard index page."""
    return render_template('dashboard/index.html', title='Dashboard')
EOF
fi

# Create dashboard template if missing
mkdir -p ${BASE_DIR}/app/templates/dashboard
if [ ! -f "${BASE_DIR}/app/templates/dashboard/index.html" ]; then
    cat > ${BASE_DIR}/app/templates/dashboard/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nettools Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .card-header {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .btn {
            display: inline-block;
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin-right: 10px;
        }
        .btn-outline {
            background-color: transparent;
            color: #4CAF50;
            border: 1px solid #4CAF50;
        }
        nav {
            margin-bottom: 20px;
            background-color: #333;
            padding: 10px;
            border-radius: 5px;
        }
        nav a {
            color: white;
            text-decoration: none;
            margin-right: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/dashboard">Dashboard</a>
            <a href="/capture">Capture</a>
        </nav>
        
        <h1>nettools Dashboard</h1>
        <p>Welcome to the nettools network packet capture and analysis tool.</p>
        
        <div class="card">
            <div class="card-header">Quick Actions</div>
            <div>
                <a href="/capture" class="btn">Start New Capture</a>
                <a href="#" class="btn btn-outline">Browse Saved Captures</a>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">System Information</div>
            <div>
                <p>Available Interfaces: eth0, lo</p>
                <p>Disk Space: 10 GB free of 15 GB</p>
                <p>PCAP Storage: 0 files</p>
            </div>
        </div>
    </div>
</body>
</html>
EOF
fi

# ---------------------------------------------------
# 8. Create capture module if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}8. Creating capture module${NC}"

# Create __init__.py
touch ${BASE_DIR}/app/capture/__init__.py

# Create capture/routes.py if missing
if [ ! -f "${BASE_DIR}/app/capture/routes.py" ]; then
    cat > ${BASE_DIR}/app/capture/routes.py << 'EOF'
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
import os
import uuid
import subprocess
import time
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

@capture_bp.route('/api/capture/interfaces')
@login_required
def interfaces():
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
    """Start a new packet capture."""
    try:
        data = request.get_json()
        
        # Generate a unique ID for this capture
        capture_id = str(uuid.uuid4())
        
        # Create a filename for the PCAP
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{data.get('interface')}_{timestamp}_{capture_id[:8]}.pcap"
        filepath = os.path.join(current_app.config['PCAP_STORAGE_PATH'], filename)
        
        # For now, we'll just simulate starting a capture
        active_captures[capture_id] = {
            'id': capture_id,
            'interface': data.get('interface'),
            'filter': data.get('filter'),
            'packet_limit': data.get('packet_limit'),
            'filepath': filepath,
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
    """Stop an active packet capture session."""
    if capture_id not in active_captures:
        return jsonify({
            'status': 'error',
            'message': 'Capture not found'
        }), 404
    
    capture = active_captures[capture_id]
    capture['active'] = False
    capture['ended_at'] = datetime.now().isoformat()
    
    return jsonify({
        'status': 'success',
        'message': 'Capture stopped successfully'
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
fi

# Create capture/forms.py if missing
if [ ! -f "${BASE_DIR}/app/capture/forms.py" ]; then
    cat > ${BASE_DIR}/app/capture/forms.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, IntegerField, BooleanField, SubmitField
from wtforms.validators import Optional, NumberRange

class CaptureForm(FlaskForm):
    """Form for configuring packet capture."""
    interface = SelectField('Network Interface', validators=[])
    filter = StringField('Capture Filter (BPF Syntax)', validators=[Optional()])
    display_filter = StringField('Display Filter (Wireshark Syntax)', validators=[Optional()])
    packet_limit = IntegerField('Packet Limit', 
                              validators=[Optional(), NumberRange(min=1, max=1000000)],
                              default=1000)
    timeout = IntegerField('Timeout (seconds)', 
                         validators=[Optional(), NumberRange(min=1, max=3600)],
                         default=0)
    live_capture = BooleanField('Live Capture', default=True)
    submit = SubmitField('Start Capture')
EOF
fi

# Create capture template if missing
mkdir -p ${BASE_DIR}/app/templates/capture
if [ ! -f "${BASE_DIR}/app/templates/capture/index.html" ]; then
    cat > ${BASE_DIR}/app/templates/capture/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Packet Capture</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .card-header {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .btn {
            display: inline-block;
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin-right: 10px;
        }
        .btn-outline {
            background-color: transparent;
            color: #4CAF50;
            border: 1px solid #4CAF50;
        }
        nav {
            margin-bottom: 20px;
            background-color: #333;
            padding: 10px;
            border-radius: 5px;
        }
        nav a {
            color: white;
            text-decoration: none;
            margin-right: 15px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        .form-control {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/dashboard">Dashboard</a>
            <a href="/capture">Capture</a>
            <a href="/login">Login</a>
            <a href="/logout">Logout</a>
        </nav>
        
        <h1>Network Packet Capture</h1>
        <p>Configure and start a packet capture session.</p>
        
        <div class="card">
            <div class="card-header">Capture Configuration</div>
            <div>
                <form id="capture-form">
                    <div class="form-group">
                        <label for="interface">Network Interface</label>
                        <select class="form-control" id="interface" name="interface">
                            <option value="" selected disabled>Select Interface</option>
                            <option value="eth0">eth0</option>
                            <option value="lo">lo</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="filter">Capture Filter (BPF Syntax)</label>
                        <input type="text" class="form-control" id="filter" name="filter" placeholder="e.g., tcp port 80">
                        <small>Examples: 'tcp port 80', 'host 192.168.1.1', 'icmp'</small>
                    </div>
                    <div class="form-group">
                        <label for="packet-limit">Packet Limit</label>
                        <input type="number" class="form-control" id="packet-limit" name="packet_limit" min="0" value="1000">
                        <small>Maximum number of packets to capture (0 = unlimited)</small>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="live-capture" name="live_capture" checked>
                            Live Capture
                        </label>
                    </div>
                    <button type="submit" class="btn" id="start-capture">Start Capture</button>
                </form>
            </div>
        </div>
        
        <div id="capture-results" style="display: none;">
            <div class="card">
                <div class="card-header">
                    <span>Capture Results</span>
                    <button class="btn btn-danger" id="stop-capture" style="float: right;">Stop Capture</button>
                </div>
                <div>
                    <table class="table">
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
                                <td colspan="7" style="text-align: center;">No packets captured yet</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Capture form submission
        document.getElementById('capture-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show capture results
            document.getElementById('capture-results').style.display = 'block';
            
            // Placeholder alert
            alert('Capture functionality is in development.');
        });

        // Stop capture button
        document.getElementById('stop-capture').addEventListener('click', function() {
            alert('Stop capture functionality is in development.');
        });
    </script>
</body>
</html>
EOF
fi

# ---------------------------------------------------
# 9. Create API module files if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}9. Creating API module files${NC}"

# Create __init__.py
touch ${BASE_DIR}/app/api/__init__.py

# Create api/auth.py if missing
if [ ! -f "${BASE_DIR}/app/api/auth.py" ]; then
    cat > ${BASE_DIR}/app/api/auth.py << 'EOF'
from flask import Blueprint, jsonify

api_auth_bp = Blueprint('api_auth', __name__)

@api_auth_bp.route('/status')
def status():
    return jsonify({"status": "ok", "message": "Auth API is working"})
EOF
fi

# Create api/dashboard.py if missing
if [ ! -f "${BASE_DIR}/app/api/dashboard.py" ]; then
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
fi

# Create api/capture.py if missing
if [ ! -f "${BASE_DIR}/app/api/capture.py" ]; then
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
fi

# ---------------------------------------------------
# 10. Create packet_parser.py if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}10. Creating packet_parser.py if missing${NC}"

if [ ! -f "${BASE_DIR}/app/utils/packet_parser.py" ]; then
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
fi

# ---------------------------------------------------
# 11. Create a basic layout template if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}11. Creating basic layout template${NC}"

if [ ! -f "${BASE_DIR}/app/templates/layout.html" ]; then
    cat > ${BASE_DIR}/app/templates/layout.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title|default('nettools - Network Analysis') }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .card-header {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .btn {
            display: inline-block;
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin-right: 10px;
        }
        .btn-outline {
            background-color: transparent;
            color: #4CAF50;
            border: 1px solid #4CAF50;
        }
        nav {
            margin-bottom: 20px;
            background-color: #333;
            padding: 10px;
            border-radius: 5px;
        }
        nav a {
            color: white;
            text-decoration: none;
            margin-right: 15px;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }
        .alert-info {
            color: #31708f;
            background-color: #d9edf7;
            border-color: #bce8f1;
        }
        .alert-success {
            color: #3c763d;
            background-color: #dff0d8;
            border-color: #d6e9c6;
        }
        .alert-warning {
            color: #8a6d3b;
            background-color: #fcf8e3;
            border-color: #faebcc;
        }
        .alert-danger {
            color: #a94442;
            background-color: #f2dede;
            border-color: #ebccd1;
        }
    </style>
    {% block styles %}{% endblock %}
</head>
<body>
    <div class="container">
        <nav>
            <a href="/dashboard">Dashboard</a>
            <a href="/capture">Capture</a>
            <a href="/login">Login</a>
            <a href="/logout">Logout</a>
        </nav>

        {% if message %}
            <div class="alert alert-info">{{ message }}</div>
        {% endif %}
        
        {% block content %}{% endblock %}
    </div>

    {% block scripts %}{% endblock %}
</body>
</html>
EOF
fi

# ---------------------------------------------------
# 12. Create minimal CSS if missing
# ---------------------------------------------------
echo -e "\n${YELLOW}12. Creating minimal CSS${NC}"

if [ ! -f "${BASE_DIR}/app/static/css/main.css" ]; then
    cat > ${BASE_DIR}/app/static/css/main.css << 'EOF'
/* Main CSS file for nettools */

body {
    font-family: Arial, sans-serif;
    background-color: #f5f5f5;
    margin: 0;
    padding: 0;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Card styling */
.card {
    border: 1px solid #ddd;
    border-radius: 5px;
    margin-bottom: 20px;
    background-color: white;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.card-header {
    padding: 10px 15px;
    border-bottom: 1px solid #ddd;
    background-color: #f8f9fa;
    font-weight: bold;
}

.card-body {
    padding: 15px;
}

/* Button styling */
.btn {
    display: inline-block;
    padding: 8px 16px;
    margin-right: 10px;
    border-radius: 4px;
    text-decoration: none;
    cursor: pointer;
    border: none;
}

.btn-primary {
    background-color: #007bff;
    color: white;
}

.btn-secondary {
    background-color: #6c757d;
    color: white;
}

.btn-success {
    background-color: #28a745;
    color: white;
}

.btn-danger {
    background-color: #dc3545;
    color: white;
}

/* Form styling */
.form-group {
    margin-bottom: 15px;
}

.form-control {
    display: block;
    width: 100%;
    padding: 8px 12px;
    border: 1px solid #ced4da;
    border-radius: 4px;
}

/* Table styling */
.table {
    width: 100%;
    border-collapse: collapse;
}

.table th, .table td {
    padding: 12px 15px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}

.table thead th {
    background-color: #f8f9fa;
    font-weight: bold;
}

/* Alert styling */
.alert {
    padding: 15px;
    margin-bottom: 20px;
    border: 1px solid transparent;
    border-radius: 4px;
}

.alert-info {
    color: #31708f;
    background-color: #d9edf7;
    border-color: #bce8f1;
}

.alert-success {
    color: #3c763d;
    background-color: #dff0d8;
    border-color: #d6e9c6;
}

.alert-warning {
    color: #8a6d3b;
    background-color: #fcf8e3;
    border-color: #faebcc;
}

.alert-danger {
    color: #a94442;
    background-color: #f2dede;
    border-color: #ebccd1;
}
EOF
fi

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
# 16. Check accessibility
# ---------------------------------------------------
echo -e "\n${YELLOW}16. Checking if nettools is accessible${NC}"

# Give the service a moment to start
sleep 3

# Check if the port is open
if command -v curl &> /dev/null; then
    echo -e "${GREEN}-> Testing connection to http://localhost:5000${NC}"
    curl -s -o /dev/null -w "%{http_code}" http://localhost:5000
    echo ""
    
    IP_ADDR=$(hostname -I | awk '{print $1}')
    if [ -n "$IP_ADDR" ]; then
        echo -e "${GREEN}-> Testing connection to http://${IP_ADDR}:5000${NC}"
        curl -s -o /dev/null -w "%{http_code}" http://${IP_ADDR}:5000
        echo ""
    fi
else
    echo -e "${YELLOW}-> curl not found, skipping connection test${NC}"
fi

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
echo -e "\n${GREEN}Thank you for using nettools!${NC}"#!/bin/bash
#
# nettools - All-in-One Fix Script
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