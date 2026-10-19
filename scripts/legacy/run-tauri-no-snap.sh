#!/bin/bash

# Clear all snap-related environment variables
unset $(env | grep -i snap | grep -v PATH | cut -d= -f1)

# Set clean library paths
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu
export GTK_PATH=
export GDK_BACKEND=x11

# Run tauri dev
pnpm run tauri dev