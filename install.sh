#!/bin/bash
# VibeCheat Package Builder & Pacman Installer

set -e

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Synchronizing source files ==="
if [ -f "src/main.rs" ]; then
    mkdir -p src/vibecheat/src
    cp src/main.rs src/vibecheat/src/main.rs
    echo "Synchronized src/main.rs to src/vibecheat/src/main.rs"
else
    echo "Warning: src/main.rs not found in the root directory."
fi

echo ""
echo "=== 2. Building package with makepkg ==="
makepkg -f

# Find the built package file
PKG_FILE=$(find . -maxdepth 1 -name "vibecheat-*.pkg.tar.zst" ! -name "*-debug-*" -print -quit)

if [ -z "$PKG_FILE" ]; then
    echo "Error: Pacman package (.pkg.tar.zst) was not created."
    exit 1
fi

echo ""
echo "=== 3. Installing package system-wide ==="
ABS_PKG_FILE="$(realpath "$PKG_FILE")"

# Check if pkexec is available, otherwise use sudo
if command -v pkexec >/dev/null 2>&1; then
    pkexec pacman -U --noconfirm "$ABS_PKG_FILE"
elif command -v sudo >/dev/null 2>&1; then
    sudo pacman -U --noconfirm "$ABS_PKG_FILE"
else
    echo "Error: Neither pkexec nor sudo is available to run pacman as root."
    exit 1
fi

echo ""
echo "=== Installation complete! ==="
echo "You can now run VibeCheat by typing 'vibecheat' in your terminal or launching it from your desktop applications."
