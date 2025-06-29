# populate_db.py
import mysql.connector
import random
from datetime import datetime, timedelta
import ipaddress
import json

# Database connection configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'reon',  # Change to your MySQL username
    'password': '$Asif@038269',  # Change to your MySQL password
    'database': 'security_logs'
}

# Sample data for generating realistic logs
ATTACK_TYPES = [
    "XSS", 
    "SQLi", 
    "Brute Force", 
    "Directory Traversal", 
    "Command Injection",
    "File Inclusion",
    "CSRF",
    "SSRF",
    "XML Injection"
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/7.79.1",
    "Wget/1.21",
    "sqlmap/1.5.12#stable",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html"
]

REQUEST_PATHS = [
    "/login.php", 
    "/admin/", 
    "/wp-login.php", 
    "/wp-admin/", 
    "/admin/login", 
    "/administrator/", 
    "/phpmyadmin/", 
    "/api/v1/users",
    "/api/v1/auth",
    "/user/profile",
    "/dashboard",
    "/checkout",
    "/cart",
    "/register",
    "/password/reset"
]

# Generate sample attack payloads for different attack types
def get_attack_payload(attack_type):
    if attack_type == "XSS":
        payloads = [
            "<script>alert(1)</script>",
            "<img src='x' onerror='alert(document.cookie)'>",
            "<svg onload='eval(atob(\"YWxlcnQoZG9jdW1lbnQuY29va2llKQ==\"))'>",
            "javascript:alert(document.domain)"
        ]
    elif attack_type == "SQLi":
        payloads = [
            "' OR 1=1 --",
            "admin' --",
            "'; DROP TABLE users; --",
            "1' UNION SELECT username,password FROM users --"
        ]
    elif attack_type == "Brute Force":
        # For brute force, we'll just use common usernames
        payloads = ["admin", "administrator", "root", "user", "test"]
    elif attack_type == "Directory Traversal":
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system.ini",
            "....//....//....//etc/shadow",
            "/var/www/html/../../etc/passwd"
        ]
    elif attack_type == "Command Injection":
        payloads = [
            "| cat /etc/passwd",
            "; ls -la",
            "& ipconfig",
            "$(whoami)"
        ]
    elif attack_type == "File Inclusion":
        payloads = [
            "/etc/passwd",
            "http://evil.com/malware.php",
            "C:\\Windows\\system.ini",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
    elif attack_type == "CSRF":
        payloads = ["csrf_token=invalid", "missing_token", "expired_token"]
    elif attack_type == "SSRF":
        payloads = [
            "http://localhost/admin",
            "http://127.0.0.1/config",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
    elif attack_type == "XML Injection":
        payloads = [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
            "<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
        ]
    else:
        payloads = ["suspicious_payload"]
    
    return random.choice(payloads)

# Generate a random IPv6 address
def random_ipv6():
    ip = ipaddress.IPv6Address(random.randint(0, 2**128-1))
    return str(ip)

# Generate attack clusters (multiple attacks from the same IPs)
def generate_attack_clusters(num_ips=20, attacks_per_ip_min=5, attacks_per_ip_max=50):
    attack_clusters = []
    
    for _ in range(num_ips):
        ip = random_ipv6()
        attack_type = random.choice(ATTACK_TYPES)
        num_attacks = random.randint(attacks_per_ip_min, attacks_per_ip_max)
        
        attack_clusters.append({
            'ip': ip,
            'attack_type': attack_type,
            'count': num_attacks
        })
    
    return attack_clusters

# Generate a random timestamp within the last 30 days
def random_timestamp():
    now = datetime.now()
    days_ago = random.randint(0, 30)
    hours_ago = random.randint(0, 23)
    minutes_ago = random.randint(0, 59)
    seconds_ago = random.randint(0, 59)
    
    timestamp = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago, seconds=seconds_ago)
    return timestamp

# Generate a single log entry
def generate_log_entry(ip=None, attack_type=None):
    if not ip:
        ip = random_ipv6()
    
    if not attack_type:
        attack_type = random.choice(ATTACK_TYPES)
    
    method = random.choice(HTTP_METHODS)
    path = random.choice(REQUEST_PATHS)
    user_agent = random.choice(USER_AGENTS)
    timestamp = random_timestamp()
    
    # Generate appropriate payload based on attack type
    payload = get_attack_payload(attack_type)
    
    # Create query string and parameters based on the attack
    if method == "GET":
        query_string = f"param={payload}&other=value"
        parameters = json.dumps({"param": payload, "other": "value"})
        request_body = ""
    else:
        query_string = ""
        if random.random() < 0.5:
            # JSON payload
            parameters = json.dumps({"param": payload, "other": "value"})
            request_body = parameters
        else:
            # Form data
            parameters = json.dumps({"param": payload, "other": "value"})
            request_body = f"param={payload}&other=value"
    
    return {
        'ip_address': ip,
        'request_uri': path,
        'method': method,
        'query_string': query_string,
        'parameters': parameters,
        'request_body': request_body,
        'user_agent': user_agent,
        'timestamp': timestamp,
        'attack_type': attack_type
    }

def populate_database(num_random_logs=500, num_clusters=15):
    # Connect to database
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        print("Connected to database. Starting data population...")
        
        # Generate attack clusters (multiple attacks from same IPs)
        attack_clusters = generate_attack_clusters(num_ips=num_clusters, attacks_per_ip_min=10, attacks_per_ip_max=50)
        
        # First, insert cluster attacks (patterns of attacks from same IPs)
        cluster_count = 0
        for cluster in attack_clusters:
            for _ in range(cluster['count']):
                entry = generate_log_entry(ip=cluster['ip'], attack_type=cluster['attack_type'])
                
                query = """
                INSERT INTO security_logs 
                (ip_address, request_uri, method, query_string, parameters, request_body, user_agent, timestamp, attack_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                cursor.execute(query, (
                    entry['ip_address'],
                    entry['request_uri'],
                    entry['method'],
                    entry['query_string'],
                    entry['parameters'],
                    entry['request_body'],
                    entry['user_agent'],
                    entry['timestamp'],
                    entry['attack_type']
                ))
                
                cluster_count += 1
                if cluster_count % 100 == 0:
                    conn.commit()
                    print(f"Inserted {cluster_count} cluster attack logs...")
        
        conn.commit()
        print(f"Inserted {cluster_count} cluster attack logs.")
        
        # Then insert random individual attacks
        random_count = 0
        for _ in range(num_random_logs):
            entry = generate_log_entry()
            
            query = """
            INSERT INTO security_logs 
            (ip_address, request_uri, method, query_string, parameters, request_body, user_agent, timestamp, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(query, (
                entry['ip_address'],
                entry['request_uri'],
                entry['method'],
                entry['query_string'],
                entry['parameters'],
                entry['request_body'],
                entry['user_agent'],
                entry['timestamp'],
                entry['attack_type']
            ))
            
            random_count += 1
            if random_count % 100 == 0:
                conn.commit()
                print(f"Inserted {random_count} random attack logs...")
        
        conn.commit()
        print(f"Inserted {random_count} random attack logs.")
        
        # Create blocked_ips table if it doesn't exist
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
        
        # Add some IPs to blocked_ips
        print("Adding some blocked IPs...")
        for i in range(5):
            if i < len(attack_clusters):
                # Block some of our cluster attackers
                ip = attack_clusters[i]['ip']
                reason = f"Blocked due to {attack_clusters[i]['attack_type']} attacks"
            else:
                # Add some random blocked IPs
                ip = random_ipv6()
                reason = "Manually blocked"
                
            try:
                cursor.execute(
                    "INSERT INTO blocked_ips (ip_address, blocked_at, reason) VALUES (%s, %s, %s)",
                    (ip, datetime.now() - timedelta(days=random.randint(0, 10)), reason)
                )
            except mysql.connector.errors.IntegrityError:
                # Ignore duplicate key errors
                pass
                
        conn.commit()
        
        cursor.close()
        conn.close()
        
        print(f"Database population complete. Total logs: {cluster_count + random_count}")
        print(f"- {cluster_count} cluster attack logs")
        print(f"- {random_count} random attack logs")
        print("- 5 blocked IPs")
        
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False
    
    return True

if __name__ == "__main__":
    # Populate with 500 random logs and 15 attack clusters
    populate_database(num_random_logs=500, num_clusters=15)