#!/bin/bash

echo "==================================="
echo "TAURI LAUNCHER - SNAP ISSUE FIXER"
echo "==================================="
echo ""

# Step 1: Check current environment
echo "1. Checking your environment..."
if [ -n "$SNAP" ] || [ -n "$SNAP_NAME" ]; then
    echo "❌ You are in a SNAP environment (probably VS Code terminal)"
    echo "   This will cause the pthread error!"
else
    echo "✓ Not in a snap environment"
fi

echo ""
echo "2. Current LD_LIBRARY_PATH:"
echo "   $LD_LIBRARY_PATH"
echo ""

# Step 2: Clean and run
echo "3. Starting Tauri with CLEAN environment..."
echo "   This will bypass ALL snap conflicts"
echo ""

# Kill existing processes
pkill -f "system-monitor" 2>/dev/null
pkill -f "tauri dev" 2>/dev/null

# The nuclear option - completely new environment
exec env -i \
    HOME="$HOME" \
    USER="$USER" \
    SHELL="/bin/bash" \
    TERM="xterm-256color" \
    PATH="/home/ubuntu/.cargo/bin:/home/ubuntu/.nvm/versions/node/v22.17.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    DISPLAY="$DISPLAY" \
    XAUTHORITY="$XAUTHORITY" \
    LANG="en_US.UTF-8" \
    bash --login -c '
        echo "=== Clean Environment Established ==="
        echo "PATH: $PATH"
        echo ""
        
        # Verify tools are available
        echo "Checking tools..."
        which cargo || { echo "ERROR: cargo not found"; exit 1; }
        which pnpm || { echo "ERROR: pnpm not found"; exit 1; }
        echo "✓ All tools found"
        echo ""
        
        # Change to project directory
        cd /home/ubuntu/system-detection || { echo "ERROR: Project directory not found"; exit 1; }
        
        # Run Tauri
        echo "Starting Tauri..."
        echo "================================="
        pnpm run tauri dev
    '