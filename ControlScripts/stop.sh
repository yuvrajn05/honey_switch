#!/bin/bash
cd "$(dirname "$0")/.." || exit 1

PID_FILE="Test-Environment/logs/pids.txt"

echo "====================================================="
echo "   Stopping Security Middleware Test Environment"
echo "====================================================="
echo

if [ -f "$PID_FILE" ]; then
    while read -r pid; do
        if ps -p $pid > /dev/null 2>&1; then
            kill $pid
            echo "✓ Stopped PID: $pid"
        else
            echo "⚠ PID $pid not running"
        fi
    done < "$PID_FILE"
    rm "$PID_FILE"
    echo "✓ All services stopped"
else
    echo "No running services found (no PID file)"
fi

echo
echo "====================================================="
echo "Shutdown complete"
echo "====================================================="
