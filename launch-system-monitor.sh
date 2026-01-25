#!/bin/bash

# System Monitor Launch Script
# Fixes GPU/Wayland rendering issues on Linux

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           SYSTEM MONITOR LAUNCHER                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Navigate to the project directory
cd "$(dirname "$0")"

# Apply graphics workarounds for Linux
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export LIBGL_ALWAYS_SOFTWARE=1
export GDK_BACKEND=x11  # Force X11 backend to avoid Wayland/DRM permission issues

echo "Starting System Monitor with GPU compatibility fixes..."
echo ""

pnpm run tauri dev
