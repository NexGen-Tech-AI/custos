#!/bin/bash

# Tauri Debug Helper
# This script helps diagnose Tauri application issues

echo "=== TAURI DEBUG HELPER ==="
echo ""

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. Please run this script from the project root."
    exit 1
fi

echo "Checking system requirements..."

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "✓ Node.js: $NODE_VERSION"
else
    echo "✗ Node.js not found"
fi

# Check pnpm
if command -v pnpm &> /dev/null; then
    PNPM_VERSION=$(pnpm --version)
    echo "✓ pnpm: $PNPM_VERSION"
else
    echo "✗ pnpm not found"
fi

# Check Rust
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(cargo --version)
    echo "✓ Rust: $RUST_VERSION"
else
    echo "✗ Rust not found"
fi

# Check Tauri CLI
if command -v tauri &> /dev/null; then
    TAURI_VERSION=$(tauri --version)
    echo "✓ Tauri CLI: $TAURI_VERSION"
else
    echo "✗ Tauri CLI not found"
fi

echo ""
echo "Checking project setup..."

# Check if dependencies are installed
if [ -d "node_modules" ]; then
    echo "✓ Node dependencies installed"
else
    echo "✗ Node dependencies not installed (run: pnpm install)"
fi

# Check if Rust dependencies are built
if [ -d "src-tauri/target" ]; then
    echo "✓ Rust target directory exists"
else
    echo "✗ Rust target directory not found (will be created on first build)"
fi

echo ""
echo "Common issues and solutions:"

echo "1. If Tauri window doesn't open:"
echo "   - Check console for error messages"
echo "   - Ensure you're running 'pnpm run tauri dev' (not just 'pnpm run dev')"
echo "   - Look for a separate application window (not browser tab)"

echo ""
echo "2. If you see 'Tauri environment not detected':"
echo "   - You're running in a browser instead of Tauri"
echo "   - Use 'pnpm run tauri dev' to launch the native app"

echo ""
echo "3. If the app is stuck loading:"
echo "   - Check the developer console (F12 in Tauri window)"
echo "   - Look for initialization errors"
echo "   - Verify system permissions are granted"

echo ""
echo "4. For GPU monitoring issues:"
echo "   - Ensure NVIDIA drivers are installed"
echo "   - Check that nvml-wrapper feature is enabled"
echo "   - Verify you have an NVIDIA GPU"

echo ""
echo "To run the application:"
echo "  pnpm run tauri dev    # Development mode"
echo "  pnpm run tauri build  # Production build"

echo ""
echo "For more detailed debugging, run:"
echo "  RUST_LOG=debug pnpm run tauri dev"