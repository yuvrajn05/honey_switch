from flask import Flask, render_template, request, jsonify
import mysql.connector
import subprocess
import json
import os
from datetime import datetime
import configparser

app = Flask(__name__)

# Read configuration from config.properties file
def load_config():
    config = configparser.ConfigParser()
    
    # Define the path to config.properties
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.properties')
    
    # Convert Java-style properties to INI format that configparser can read
    with open(config_path, 'r') as file:
        config_content = '[DEFAULT]\n' + file.read()
    
    config.read_string(config_content)
    return config['DEFAULT']

# Load configuration
CONFIG = load_config()

# Database connection configuration from config.properties
DB_CONFIG = {
    'host': CONFIG.get('db.url', 'localhost:3306').split('/')[-2].split(':')[0],
    'port': int(CONFIG.get('db.url', 'localhost:3306').split('/')[-2].split(':')[1]),
    'user': CONFIG.get('db.username', ''),
    'password': CONFIG.get('db.password', ''),
    'database': CONFIG.get('db.url', '').split('/')[-1]
}

def get_db_connection():
    """Create and return a database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/logs')
def get_logs():
    """API endpoint to fetch security logs"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    # Get query parameters for filtering
    attack_type = request.args.get('attack_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    ip_address = request.args.get('ip_address')
    
    # Build the query based on filters
    query = "SELECT * FROM security_logs WHERE 1=1"
    params = []
    
    if attack_type:
        query += " AND attack_type = %s"
        params.append(attack_type)
    
    if start_date:
        query += " AND timestamp >= %s"
        params.append(start_date)
    
    if end_date:
        query += " AND timestamp <= %s"
        params.append(end_date)
    
    if ip_address:
        query += " AND ip_address = %s"
        params.append(ip_address)
    
    query += " ORDER BY timestamp DESC LIMIT 1000"
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    
    # Convert datetime objects to string for JSON serialization
    for log in logs:
        log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.close()
    conn.close()
    
    return jsonify(logs)

@app.route('/flag-ip', methods=['POST'])
def flag_ip():
    """API endpoint to flag an IP address and add it to firewall rules"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400
    
    try:
        # For Linux systems using iptables
        # In a production environment, you would want more robust handling
        # and possibly use a more secure method to add firewall rules
        if os.name == 'posix':  # Linux/Unix
            cmd = f"sudo ip6tables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return jsonify({"error": f"Failed to block IP: {result.stderr}"}), 500
                
        # For Windows systems using Windows Firewall
        elif os.name == 'nt':  # Windows
            cmd = f'netsh advfirewall firewall add rule name="Block IP {ip_address}" dir=in action=block remoteip={ip_address}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return jsonify({"error": f"Failed to block IP: {result.stderr}"}), 500
        
        # Log the blocking action
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            query = "INSERT INTO blocked_ips (ip_address, blocked_at, reason) VALUES (%s, %s, %s)"
            cursor.execute(query, (ip_address, datetime.now(), "Flagged through web interface"))
            conn.commit()
            cursor.close()
            conn.close()
        
        return jsonify({"success": True, "message": f"IP {ip_address} has been blocked"})
        
    except Exception as e:
        return jsonify({"error": f"Failed to block IP: {str(e)}"}), 500

@app.route('/analyze', methods=['POST'])
def analyze_logs():
    """API endpoint to analyze security logs and identify potential threats"""
    data = request.get_json()
    analysis_type = data.get('type', 'basic')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    results = {}
    
    # Basic analysis - top attacking IPs
    cursor.execute("""
        SELECT ip_address, COUNT(*) as count 
        FROM security_logs 
        GROUP BY ip_address 
        ORDER BY count DESC 
        LIMIT 10
    """)
    results['top_ips'] = cursor.fetchall()
    
    # Attack types distribution
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM security_logs 
        GROUP BY attack_type 
        ORDER BY count DESC
    """)
    results['attack_distribution'] = cursor.fetchall()
    
    # Time-based analysis
    cursor.execute("""
        SELECT 
            DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour,
            COUNT(*) as count
        FROM security_logs
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY hour
        ORDER BY hour
    """)
    results['hourly_distribution'] = cursor.fetchall()
    
    # Advanced analysis if requested
    if analysis_type == 'advanced':
        # Find potential brute force attacks (multiple requests from same IP in short time)
        cursor.execute("""
            SELECT ip_address, COUNT(*) as count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
            FROM security_logs
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY ip_address
            HAVING count > 30
            ORDER BY count DESC
        """)
        results['potential_brute_force'] = cursor.fetchall()
        
        # Find IPs targeting specific vulnerable paths
        cursor.execute("""
            SELECT ip_address, request_uri, COUNT(*) as count
            FROM security_logs
            WHERE request_uri LIKE '%wp-admin%' 
               OR request_uri LIKE '%wp-login%'
               OR request_uri LIKE '%admin%'
               OR request_uri LIKE '%login%'
            GROUP BY ip_address, request_uri
            HAVING count > 5
            ORDER BY count DESC
            LIMIT 20
        """)
        results['targeted_attacks'] = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    # Convert datetime objects to string for JSON serialization
    for key in results:
        for item in results[key]:
            for field in item:
                if isinstance(item[field], datetime):
                    item[field] = item[field].strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify(results)

# Add this route to your app.py file

@app.route('/unflag-ip', methods=['POST'])
def unflag_ip():
    """API endpoint to unflag/unblock an IP address from firewall rules"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400
    
    try:
        # For Linux systems using iptables
        if os.name == 'posix':  # Linux/Unix
            cmd = f"sudo ip6tables -D INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return jsonify({"error": f"Failed to unblock IP: {result.stderr}"}), 500
                
        # For Windows systems using Windows Firewall
        elif os.name == 'nt':  # Windows
            cmd = f'netsh advfirewall firewall delete rule name="Block IP {ip_address}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return jsonify({"error": f"Failed to unblock IP: {result.stderr}"}), 500
        
        # Remove the IP from the blocked_ips table
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            query = "DELETE FROM blocked_ips WHERE ip_address = %s"
            cursor.execute(query, (ip_address,))
            conn.commit()
            cursor.close()
            conn.close()
        
        return jsonify({"success": True, "message": f"IP {ip_address} has been unblocked"})
        
    except Exception as e:
        return jsonify({"error": f"Failed to unblock IP: {str(e)}"}), 500

# Add a new route to get currently blocked IPs
@app.route('/blocked-ips')
def get_blocked_ips():
    """API endpoint to get all blocked IP addresses"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
    ips = cursor.fetchall()
    
    # Convert datetime objects to string for JSON serialization
    for ip in ips:
        ip['blocked_at'] = ip['blocked_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.close()
    conn.close()
    
    return jsonify(ips)

# Create a blocked_ips table if it doesn't exist yet
def setup_blocked_ips_table():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                blocked_at TIMESTAMP NOT NULL,
                reason VARCHAR(255) NOT NULL,
                UNIQUE KEY unique_ip (ip_address)
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()

if __name__ == '__main__':
    setup_blocked_ips_table()
    app.run(debug=True)