#!/bin/bash

# Tauri Standalone Launcher
# This script attempts to run the Tauri app without snap conflicts

echo "=== TAURI STANDALONE LAUNCHER ==="
echo "Attempting to run Tauri app without snap conflicts..."

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. Please run this script from the project root."
    exit 1
fi

# Check if pnpm is available
if ! command -v pnpm &> /dev/null; then
    echo "Error: pnpm is not installed. Please install pnpm first."
    echo "npm install -g pnpm"
    exit 1
fi

# Check if Rust is available
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo is not installed. Please install Rust first."
    echo "Visit: https://rustup.rs/"
    exit 1
fi

echo "✓ Dependencies check passed"
echo ""

# Try to run Tauri in development mode
echo "Starting Tauri development mode..."
echo "This will open a native application window with real system data."
echo ""

# Set environment variables to avoid snap conflicts
export LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
export PATH="/usr/local/bin:/usr/bin:$PATH"

# Run Tauri
pnpm run tauri dev

echo ""
echo "Tauri application closed."
echo "If you encountered issues, try building for production instead:"
echo "  pnpm run tauri build"