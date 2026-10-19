#!/bin/bash

echo "=== Running Tauri in Clean Environment ==="
echo "This bypasses snap conflicts"
echo ""

# Kill any existing processes
pkill -f "tauri dev" 2>/dev/null
pkill -f "system-monitor" 2>/dev/null
sleep 1

# Create a completely clean environment
env -i \
  HOME="$HOME" \
  USER="$USER" \
  PATH="/home/ubuntu/.cargo/bin:/home/ubuntu/.nvm/versions/node/v22.17.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  DISPLAY="$DISPLAY" \
  XAUTHORITY="$XAUTHORITY" \
  WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 \
  WEBKIT_FORCE_SANDBOX=0 \
  bash -l -c '
    echo "Environment cleaned. Starting Tauri..."
    cd /home/ubuntu/system-detection
    pnpm run tauri dev
  '