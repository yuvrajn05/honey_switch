# Security Middleware

A robust Java-based security middleware that intercepts HTTP traffic, detects malicious requests, and redirects potential attackers to a honeypot environment while legitimate traffic flows to the real backend.

## Overview

This project provides a security layer that sits between clients and your backend services. It analyzes incoming HTTP requests for common attack patterns like SQL injection, XSS, and Remote Code Execution attempts. When a malicious request is detected, the middleware silently redirects the traffic to a honeypot environment, allowing you to monitor attack vectors while keeping your real systems safe.

## Features

- **Traffic Inspection**: Analyzes HTTP requests for malicious patterns
- **Pattern Detection**: Identifies SQL injection, XSS, and RCE attempts using regex
- **Selective Routing**: Routes legitimate requests to the real backend, malicious ones to a honeypot
- **Comprehensive Logging**: Records all attack attempts with detailed information
- **Database Integration**: Stores attack information in a MariaDB/MySQL database
- **Easy Configuration**: Simple property-based configuration
- **Web Management Interface**: Python-based Flask web interface for monitoring and managing security logs

## Architecture

```
Client Request → Security Middleware → Analysis → Route to Real Backend
                                              └→ Route to Honeypot (if malicious)
```

## Technology Stack

- Java (with Jetty server)
- MariaDB/MySQL
- Node.js (for test environment)
- Flask (Python web interface)
- Regular expressions for pattern matching
- HTTP request forwarding

## Prerequisites

- Java 8+
- MariaDB/MySQL
- Node.js (for test environment)
- Python 3.6+ with Flask (for web interface)

## Directory Structure

```
.
├── MiddleWare-Interception/         # Main middleware project
│   ├── config.properties            # Configuration file
│   ├── lib/                         # Dependencies
│   ├── src/                         # Source code
│   ├── sql/                         # Database setup scripts
│   └── python_interface/            # Python web interface
│       ├── app.py                   # Flask application
│       ├── populate_db.py           # Utility to populate the database
│       └── templates/               # HTML templates
│           └── index.html           # Web interface main page
├── Test-Environment/                # Test environment
│   ├── app.js                       # Real backend for testing
│   ├── honeypot.js                  # Honeypot server for testing
│   └── logs/                        # Log files
└── ControlScripts/                  # Utility scripts
    ├── setup.sh                     # Setup script
    └── stop.sh                      # Stop script
```

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repository-url>
cd security-middleware
```

### 2. Run the setup script

```bash
./ControlScripts/setup.sh
```

This script will:
- Check for required dependencies
- Install Node.js packages for the test environment
- Set up the MariaDB database
- Configure the middleware
- Start all services (real backend, honeypot, middleware)

### 3. Manual setup (if needed)

If the automated setup fails, you can perform these steps manually:

#### Database setup

```bash
mariadb -u your_user -p < MiddleWare-Interception/sql/setup_db.sql
```

#### Configure the middleware

Edit `MiddleWare-Interception/config.properties` with your settings:

```properties
server.port=8080
backend.real.url=http://localhost:3000
backend.honeypot.url=http://localhost:3001
db.url=jdbc:mysql://localhost:3306/security_middleware
db.username=your_username
db.password=your_password
logging.enabled=true
```

change the respective properties in setup.sh

#### Build the middleware (if source is modified)

```bash
cd MiddleWare-Interception
mvn clean package
```

#### Set up the Python web interface

```bash
cd MiddleWare-Interception/python_interface
pip install flask mysql-connector-python
```

## Usage

### Java Middleware

After running the setup script, the middleware will be listening on port 8080 (by default) and will forward traffic to either:
- Real backend (port 3000)
- Honeypot (port 3001)

### Python Web Interface

To run the web interface:

```bash
cd MiddleWare-Interception/python_interface
python app.py
```

Access the web interface at:

```
http://localhost:5000
```

The web interface provides the following features:
- View security logs with filtering options
- Analyze attack patterns and distribution
- Flag/block suspicious IP addresses
- View currently blocked IPs
- Unblock previously flagged IPs
- Advanced analysis of potential threats

## Security Patterns Detection

The middleware uses regex patterns to detect malicious content:

- **SQL Injection**: Detecting SQL keywords, comment markers, etc.
- **XSS (Cross-Site Scripting)**: Identifying script tags, JavaScript events, etc.
- **RCE (Remote Code Execution)**: Looking for command execution patterns

## Stopping the Services

To stop all running services:

```bash
./ControlScripts/stop.sh
```

## Logging

Logs are stored in these locations:
- Middleware logs: `Test-Environment/logs/middleware.log`
- Real backend logs: `Test-Environment/logs/real-backend.log`
- Honeypot logs: `Test-Environment/logs/honeypot.log`

Attack information is also stored in the `security_logs` table in the database.

## Testing

```bash
curl -i -X POST http://localhost:8080/api/users \
              -H "Content-Type: application/json" \
              -d '{"username": "hacker", "email": "a@example.com; DROP TABLE users;--"}'
```

```bash
curl -i -X POST http://localhost:8080/api/users \
              -H "Content-Type: application/json" \
              -d '{"username": "john_doe", "email": "john@example.com"}'
```

```bash
curl -i -X POST http://localhost:8080/api/users \
           -H "Content-Type: application/json" \
           -d '{"username": "<script>alert(1)</script>", "email": "john@example.com"}'
```

```bash
curl -i "http://localhost:8080/api/users?id=1%27%20OR%20%271%27%3D%271"
```

```bash
curl -i -X GET http://localhost:8080/api/users
```

```bash
curl -i "http://localhost:8080/api/users?id=1' OR '1'='1"
```
