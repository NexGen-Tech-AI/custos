#!/bin/bash
cd /home/ubuntu/system-detection

# Kill any running instances
pkill -f system-monitor || true
pkill -f vite || true

# Clear all environment
export -n $(env | cut -d= -f1 | grep -E '^(SNAP|GDK_BACKEND|GTK_EXE|LOCPATH|GTK_PATH|GTK_IM|GIO_MODULE)')

# Set minimal environment
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/home/ubuntu
export USER=ubuntu  
export DISPLAY=:0
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu
export RUST_LOG=debug
export RUST_BACKTRACE=1

# Run the binary directly
exec /home/ubuntu/system-detection/src-tauri/target/debug/system-monitor