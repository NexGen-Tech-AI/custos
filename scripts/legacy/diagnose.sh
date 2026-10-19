#!/bin/bash

echo "=== System Monitor Diagnostic ==="
echo

echo "1. Checking processes:"
ps aux | grep -E "(system-monitor|vite|tauri)" | grep -v grep || echo "No processes found"
echo

echo "2. Checking port 5173:"
netstat -tln | grep 5173 || echo "Port 5173 not listening"
echo

echo "3. Testing frontend:"
curl -s http://localhost:5173 >/dev/null 2>&1 && echo "Frontend is accessible" || echo "Frontend not accessible"
echo

echo "4. Checking display:"
echo "DISPLAY=$DISPLAY"
xset q >/dev/null 2>&1 && echo "X server is accessible" || echo "X server not accessible"
echo

echo "5. Checking for error logs:"
tail -20 tauri.log 2>/dev/null | grep -i error || echo "No errors in tauri.log"
echo

echo "6. Library dependencies:"
ldd /home/ubuntu/system-detection/src-tauri/target/debug/system-monitor | grep "not found" || echo "All libraries found"