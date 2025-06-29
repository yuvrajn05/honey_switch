#!/bin/bash
cd "$(dirname "$0")/.." || exit 1

TEST_ENV="Test-Environment"
MW="MiddleWare-Interception"

echo "====================================================="
echo "   Security Middleware Test Environment Setup"
echo "====================================================="
echo

for cmd in java node mariadb; do
    command -v $cmd >/dev/null 2>&1 || { echo "$cmd is required but not installed. Aborting."; exit 1; }
done

echo "✓ Required programs found"
echo

mkdir -p "$TEST_ENV/logs"

if [ ! -d "$TEST_ENV/node_modules" ]; then
    echo "Installing Node.js dependencies..."
    cd "$TEST_ENV" || exit 1
    npm install express body-parser
    cd ..
    echo "✓ Node.js dependencies installed"
fi

echo "Building Java middleware..."
cd "$MW" || exit 1

mvn clean package
if [ $? -eq 0 ]; then
    echo "✓ Java dependencies installed and project built"
else
    echo "✗ Maven build failed"
    exit 1
fi
cd ..

echo "Setting up MariaDB database..."
read -s -p "Enter MySQL user password: " MYSQL_PASSWORD
echo

if [ -n "$MYSQL_PASSWORD" ]; then
    mariadb -u reon -p"$MYSQL_PASSWORD" < "$MW/sql/setup_db.sql"
else
    mariadb -u root < "$MW/sql/setup_db.sql"
fi

if [ $? -eq 0 ]; then
    echo "✓ Database setup complete"
else
    echo "✗ Database setup failed — run $MW/sql/setup_db.sql manually if needed"
fi

echo "Updating MySQL password in config..."
sed -i "s|password=.*|password=$MYSQL_PASSWORD|" "$MW/config.properties"
echo "✓ Config updated"
echo

# Start services
echo "Starting services..."
cd "$TEST_ENV" || exit 1

node app.js > logs/real-backend.log 2>&1 &
REAL_PID=$!
echo "✓ Real backend server (PID: $REAL_PID)"

node honeypot.js > logs/honeypot.log 2>&1 &
HONEYPOT_PID=$!
echo "✓ Honeypot server (PID: $HONEYPOT_PID)"

cd ..
java -cp "$MW/target/security-middleware-1.0.0.jar:$MW/lib/*" com.security.middleware.SecurityMiddleware "$MW/config.properties" > "$TEST_ENV/logs/middleware.log" 2>&1 &
MIDDLEWARE_PID=$!
echo "✓ Security middleware (PID: $MIDDLEWARE_PID)"

echo -e "$REAL_PID\n$HONEYPOT_PID\n$MIDDLEWARE_PID" > "$TEST_ENV/logs/pids.txt"

echo
echo "====================================================="
echo "All services started! Access the interface at:"
echo "http://localhost/index.html"
echo "To stop all services, run: ./Control-Scripts/stop.sh"
echo "====================================================="
