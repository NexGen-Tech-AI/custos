#!/bin/bash

echo "=== Running Compiled Tauri App Directly ==="
echo ""

# Check if the app is compiled
if [ ! -f "src-tauri/target/debug/system-monitor" ]; then
    echo "App not compiled. Compiling now..."
    cd src-tauri && cargo build
    cd ..
fi

# Create a minimal environment runner
cat > /tmp/run-app.sh << 'EOF'
#!/bin/bash
# Run with minimal environment to avoid snap conflicts
env -i \
  HOME="$HOME" \
  USER="$USER" \
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu" \
  WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 \
  DISPLAY="$DISPLAY" \
  XAUTHORITY="$XAUTHORITY" \
  /home/ubuntu/system-detection/src-tauri/target/debug/system-monitor
EOF

chmod +x /tmp/run-app.sh

echo "Starting the Tauri app..."
echo "A new window should open with REAL system data!"
echo ""

# First, let's test if it can run at all
ldd src-tauri/target/debug/system-monitor | head -20
echo ""

# Run it
/tmp/run-app.sh