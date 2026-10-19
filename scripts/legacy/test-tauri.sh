#!/bin/bash

# Kill any existing processes
pkill -f "system-monitor" || true
pkill -f "tauri dev" || true

# Wait a moment
sleep 2

echo "Starting Tauri development server..."

# Start the Tauri dev server in the background
cd /home/ubuntu/system-detection
pnpm run tauri dev > tauri-test.log 2>&1 &
TAURI_PID=$!

echo "Tauri dev server started with PID: $TAURI_PID"

# Wait for the application to compile and start
echo "Waiting for application to compile (this may take 2-3 minutes)..."
sleep 180

# Check if the process is still running
if ps -p $TAURI_PID > /dev/null; then
    echo "Tauri dev server is running"
    
    # Check for Tauri window
    echo "Checking for Tauri window..."
    xwininfo -root -children | grep -i "system monitor" | grep -v Firefox | grep -v Chrome || echo "No Tauri window found"
    
    # Check logs for debug output
    echo "Checking for debug output in logs..."
    grep -E "(get_system_info called|start_monitoring called)" tauri-test.log || echo "No debug output found"
    
    # List all windows
    echo "All windows:"
    xwininfo -root -children | grep -E '"[^"]+":' | head -20
else
    echo "Tauri dev server crashed"
    echo "Last 50 lines of log:"
    tail -50 tauri-test.log
fi