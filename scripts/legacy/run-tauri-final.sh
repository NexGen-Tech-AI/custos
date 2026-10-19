#!/bin/bash

# Clear snap environment
for var in $(env | grep -i snap | cut -d= -f1); do
    unset $var
done

# Set clean paths
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/ubuntu/.nvm/versions/node/v22.17.1/bin:/home/ubuntu/.cargo/bin
export HOME=/home/ubuntu
export USER=ubuntu
export DISPLAY=:0
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu
export RUST_BACKTRACE=1

cd /home/ubuntu/system-detection

# Run tauri dev
pnpm run tauri dev