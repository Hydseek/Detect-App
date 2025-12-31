"""
Vulnerability Testing Application
ARP Spoofing & SYN Flooding Detection System

Developed by: Wejdene Cherif & Maram Raboudi
Class: SSIR4E_A

This is a comprehensive network security monitoring tool that detects
ARP spoofing and SYN flood attacks in real-time.
"""

import os
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict

# Flask imports
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Scapy imports for packet capture
from scapy.all import sniff, ARP, TCP, IP, conf


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vulnerability_detector.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Detection thresholds
    SYN_FLOOD_THRESHOLD = 100  # SYN packets per second per IP
    SYN_FLOOD_TIME_WINDOW = 1  # seconds
    ARP_CACHE_TIMEOUT = 300  # seconds

    # Monitoring settings
    PACKET_CAPTURE_INTERFACE = None  # None = default interface
    PACKET_CAPTURE_FILTER = "arp or tcp"
    MAX_ALERTS_DISPLAY = 100

    # Log settings
    LOG_FILE = 'logs/detector.log'
    LOG_LEVEL = 'INFO'


# ============================================================================
# DATABASE MODELS
# ============================================================================

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash and set the user password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)


class Alert(db.Model):
    """Alert model for storing detection events"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)  # 'ARP_SPOOFING' or 'SYN_FLOOD'
    severity = db.Column(db.String(20), nullable=False)  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    source_ip = db.Column(db.String(45))  # IPv4 or IPv6
    source_mac = db.Column(db.String(17))
    destination_ip = db.Column(db.String(45))
    destination_mac = db.Column(db.String(17))
    details = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        """Convert alert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'attack_type': self.attack_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'destination_ip': self.destination_ip,
            'destination_mac': self.destination_mac,
            'details': self.details,
            'is_resolved': self.is_resolved
        }


class NetworkStats(db.Model):
    """Network statistics model"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    total_packets = db.Column(db.Integer, default=0)
    arp_packets = db.Column(db.Integer, default=0)
    tcp_packets = db.Column(db.Integer, default=0)
    syn_packets = db.Column(db.Integer, default=0)
    alerts_triggered = db.Column(db.Integer, default=0)


# ============================================================================
# NETWORK DETECTOR
# ============================================================================

class NetworkDetector:
    """Network vulnerability detector for ARP spoofing and SYN flooding"""

    def __init__(self, db, alert_model, stats_model, config):
        self.db = db
        self.Alert = alert_model
        self.NetworkStats = stats_model
        self.config = config
        self.is_running = False
        self.capture_thread = None

        # ARP spoofing detection
        self.arp_table = {}  # IP -> MAC mapping

        # SYN flood detection
        self.syn_tracker = defaultdict(list)  # IP -> list of timestamps

        # Statistics
        self.stats = {
            'total_packets': 0,
            'arp_packets': 0,
            'tcp_packets': 0,
            'syn_packets': 0,
            'alerts_triggered': 0
        }

        # Setup logging
        logging.basicConfig(
            filename=config['LOG_FILE'],
            level=getattr(logging, config['LOG_LEVEL']),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def start_monitoring(self, interface=None):
        """Start packet capture in a separate thread"""
        if self.is_running:
            self.logger.warning("Monitoring is already running")
            return False

        self.is_running = True
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,),
            daemon=True
        )
        self.capture_thread.start()
        self.logger.info(f"Started monitoring on interface: {interface or 'default'}")
        return True

    def stop_monitoring(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        self.logger.info("Stopped monitoring")
        return True

    def _capture_packets(self, interface):
        """Capture and analyze packets"""
        try:
            sniff(
                iface=interface,
                filter=self.config['PACKET_CAPTURE_FILTER'],
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
            self.is_running = False

    def _process_packet(self, packet):
        """Process each captured packet"""
        try:
            self.stats['total_packets'] += 1

            # Check for ARP packets
            if packet.haslayer(ARP):
                self.stats['arp_packets'] += 1
                self._detect_arp_spoofing(packet)

            # Check for TCP packets
            if packet.haslayer(TCP) and packet.haslayer(IP):
                self.stats['tcp_packets'] += 1
                if packet[TCP].flags & 0x02:  # SYN flag
                    self.stats['syn_packets'] += 1
                    self._detect_syn_flood(packet)

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def _detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        arp = packet[ARP]

        # Only process ARP replies
        if arp.op != 2:  # op=2 is ARP reply
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst

        # Check if IP already exists in our table with different MAC
        if src_ip in self.arp_table:
            stored_mac = self.arp_table[src_ip]['mac']
            if stored_mac != src_mac:
                # Possible ARP spoofing detected
                severity = self._calculate_arp_severity(src_ip)
                self._create_alert(
                    attack_type='ARP_SPOOFING',
                    severity=severity,
                    source_ip=src_ip,
                    source_mac=src_mac,
                    destination_ip=dst_ip,
                    details=f"MAC address changed from {stored_mac} to {src_mac} for IP {src_ip}. Possible ARP spoofing attack."
                )
                self.logger.warning(f"ARP Spoofing detected: IP {src_ip} changed MAC from {stored_mac} to {src_mac}")

        # Update ARP table
        self.arp_table[src_ip] = {
            'mac': src_mac,
            'timestamp': datetime.utcnow()
        }

    def _detect_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        ip = packet[IP]

        src_ip = ip.src
        current_time = datetime.utcnow()

        # Add timestamp to tracker
        self.syn_tracker[src_ip].append(current_time)

        # Remove old timestamps outside the time window
        cutoff_time = current_time - timedelta(seconds=self.config['SYN_FLOOD_TIME_WINDOW'])
        self.syn_tracker[src_ip] = [
            ts for ts in self.syn_tracker[src_ip] if ts > cutoff_time
        ]

        # Check if threshold exceeded
        syn_count = len(self.syn_tracker[src_ip])
        if syn_count > self.config['SYN_FLOOD_THRESHOLD']:
            severity = self._calculate_syn_severity(syn_count)
            self._create_alert(
                attack_type='SYN_FLOOD',
                severity=severity,
                source_ip=src_ip,
                destination_ip=ip.dst,
                details=f"SYN flood detected from {src_ip}: {syn_count} SYN packets in {self.config['SYN_FLOOD_TIME_WINDOW']} second(s). Threshold: {self.config['SYN_FLOOD_THRESHOLD']}"
            )
            self.logger.warning(f"SYN Flood detected from {src_ip}: {syn_count} packets/sec")

            # Clear tracker to avoid duplicate alerts
            self.syn_tracker[src_ip] = []

    def _calculate_arp_severity(self, ip):
        """Calculate severity level for ARP spoofing"""
        # Check if it's the gateway or a critical host
        try:
            gateway_ip = conf.route.route("0.0.0.0")[2]
            if ip == gateway_ip:
                return 'CRITICAL'
        except:
            pass
        return 'HIGH'

    def _calculate_syn_severity(self, syn_count):
        """Calculate severity level for SYN flood"""
        threshold = self.config['SYN_FLOOD_THRESHOLD']
        if syn_count > threshold * 5:
            return 'CRITICAL'
        elif syn_count > threshold * 3:
            return 'HIGH'
        elif syn_count > threshold * 1.5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _create_alert(self, attack_type, severity, source_ip, source_mac=None,
                     destination_ip=None, destination_mac=None, details=''):
        """Create and save an alert to the database"""
        try:
            alert = self.Alert(
                attack_type=attack_type,
                severity=severity,
                source_ip=source_ip,
                source_mac=source_mac,
                destination_ip=destination_ip,
                destination_mac=destination_mac,
                details=details
            )
            self.db.session.add(alert)
            self.db.session.commit()
            self.stats['alerts_triggered'] += 1
            self.logger.info(f"Alert created: {attack_type} - {severity} - {source_ip}")
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Error creating alert: {e}")

    def get_statistics(self):
        """Get current monitoring statistics"""
        return self.stats.copy()

    def clear_statistics(self):
        """Reset statistics"""
        self.stats = {
            'total_packets': 0,
            'arp_packets': 0,
            'tcp_packets': 0,
            'syn_packets': 0,
            'alerts_triggered': 0
        }
        self.logger.info("Statistics cleared")

    def get_recent_alerts(self, limit=100):
        """Get recent alerts from database"""
        try:
            alerts = self.Alert.query.order_by(
                self.Alert.timestamp.desc()
            ).limit(limit).all()
            return [alert.to_dict() for alert in alerts]
        except Exception as e:
            self.logger.error(f"Error fetching alerts: {e}")
            return []

    def clear_all_alerts(self):
        """Clear all alerts from database"""
        try:
            self.Alert.query.delete()
            self.db.session.commit()
            self.logger.info("All alerts cleared")
            return True
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Error clearing alerts: {e}")
            return False


# ============================================================================
# FLASK APPLICATION
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize detector (will be set up after app context)
detector = None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ============================================================================
# DASHBOARD ROUTES
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    stats = detector.get_statistics() if detector else {}
    recent_alerts = detector.get_recent_alerts(20) if detector else []
    monitoring_status = detector.is_running if detector else False

    return render_template('dashboard.html',
                         stats=stats,
                         alerts=recent_alerts,
                         monitoring_status=monitoring_status)


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    stats = detector.get_statistics() if detector else {}
    all_alerts = detector.get_recent_alerts(100) if detector else []
    monitoring_status = detector.is_running if detector else False
    users = User.query.all()

    return render_template('admin.html',
                         stats=stats,
                         alerts=all_alerts,
                         monitoring_status=monitoring_status,
                         users=users,
                         config=app.config)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/monitoring/start', methods=['POST'])
@login_required
def start_monitoring():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403

    if detector:
        success = detector.start_monitoring(app.config['PACKET_CAPTURE_INTERFACE'])
        if success:
            return jsonify({'success': True, 'message': 'Monitoring started'})
        else:
            return jsonify({'success': False, 'message': 'Monitoring already running'})
    return jsonify({'success': False, 'message': 'Detector not initialized'}), 500


@app.route('/api/monitoring/stop', methods=['POST'])
@login_required
def stop_monitoring():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403

    if detector:
        detector.stop_monitoring()
        return jsonify({'success': True, 'message': 'Monitoring stopped'})
    return jsonify({'success': False, 'message': 'Detector not initialized'}), 500


@app.route('/api/monitoring/status', methods=['GET'])
@login_required
def monitoring_status():
    if detector:
        return jsonify({
            'is_running': detector.is_running,
            'statistics': detector.get_statistics()
        })
    return jsonify({'is_running': False, 'statistics': {}})


@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    if detector:
        alerts = detector.get_recent_alerts(limit)
        return jsonify({'success': True, 'alerts': alerts})
    return jsonify({'success': False, 'alerts': []}), 500


@app.route('/api/alerts/clear', methods=['POST'])
@login_required
def clear_alerts():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403

    if detector:
        success = detector.clear_all_alerts()
        if success:
            return jsonify({'success': True, 'message': 'All alerts cleared'})
    return jsonify({'success': False, 'message': 'Failed to clear alerts'}), 500


@app.route('/api/stats/clear', methods=['POST'])
@login_required
def clear_stats():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403

    if detector:
        detector.clear_statistics()
        return jsonify({'success': True, 'message': 'Statistics cleared'})
    return jsonify({'success': False, 'message': 'Detector not initialized'}), 500


@app.route('/api/config/update', methods=['POST'])
@login_required
def update_config():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403

    data = request.get_json()

    if 'syn_threshold' in data:
        app.config['SYN_FLOOD_THRESHOLD'] = int(data['syn_threshold'])

    if 'time_window' in data:
        app.config['SYN_FLOOD_TIME_WINDOW'] = int(data['time_window'])

    return jsonify({'success': True, 'message': 'Configuration updated'})


# ============================================================================
# INITIALIZATION FUNCTIONS
# ============================================================================

def init_db():
    """Initialize database and create default admin user"""
    with app.app_context():
        db.create_all()

        # Create default admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@localhost',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)

            # Create default regular user
            user = User(
                username='user',
                email='user@localhost',
                is_admin=False
            )
            user.set_password('user123')
            db.session.add(user)

            db.session.commit()
            print("Default users created:")
            print("  Admin - username: admin, password: admin123")
            print("  User  - username: user, password: user123")


def init_detector():
    """Initialize the network detector"""
    global detector
    with app.app_context():
        detector = NetworkDetector(db, Alert, NetworkStats, app.config)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

    # Initialize database
    init_db()

    # Initialize detector
    init_detector()

    print("\n" + "="*60)
    print("Vulnerability Testing Application")
    print("ARP Spoofing & SYN Flooding Detection System")
    print("="*60)
    print("\nDeveloped by: Wejdene Cherif & Maram Raboudi")
    print("Class: SSIR4E_A")
    print("\nStarting Flask application on http://127.0.0.1:5001")
    print("\nDefault credentials:")
    print("  Admin: username='admin', password='admin123'")
    print("  User:  username='user', password='user123'")
    print("\nNote: Root/Administrator privileges required for packet capture!")
    print("="*60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5001)
