#!/bin/bash

# Kill any existing processes
pkill -f "system-monitor" || true
pkill -f "tauri dev" || true
sleep 2

# Unset all snap-related environment variables
unset $(env | grep -E '^SNAP|^LD_' | cut -d= -f1)

# Set up clean environment
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"

# Add Node.js to PATH if using nvm
if [ -f "$HOME/.nvm/nvm.sh" ]; then
    source "$HOME/.nvm/nvm.sh"
fi

# Add Rust/Cargo to PATH
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

# Set Tauri environment variables
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export WEBKIT_FORCE_SANDBOX=0

echo "Starting Tauri with clean environment..."
echo "Current LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "Current PATH: $PATH"

# Navigate to the project directory
cd /home/ubuntu/system-detection

# Start Tauri
echo "Running pnpm tauri dev..."
pnpm run tauri dev