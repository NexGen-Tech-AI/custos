#!/bin/bash

# Kill any existing instances
pkill -f system-monitor

# Set up clean environment
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/ubuntu/.nvm/versions/node/v22.17.1/bin:/home/ubuntu/.cargo/bin
export HOME=/home/ubuntu
export USER=ubuntu
export DISPLAY=:0
export RUST_BACKTRACE=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1

# Remove all snap-related variables
for var in $(env | grep -i snap | cut -d= -f1); do
    unset $var
done

# Set proper library paths
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu

cd /home/ubuntu/system-detection

# Run the dev server
exec pnpm run tauri dev