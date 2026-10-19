#!/bin/bash
# Fix for snap library conflicts
export PATH="/home/vboxuser/.npm-global/bin:$PATH"
export DISPLAY=$DISPLAY
export XAUTHORITY=$XAUTHORITY
export DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS
env -i HOME=$HOME USER=$USER PATH=$PATH DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS RUST_BACKTRACE=1 /home/vboxuser/.npm-global/bin/pnpm run tauri dev