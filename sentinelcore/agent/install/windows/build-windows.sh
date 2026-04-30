#!/usr/bin/env bash
# Cross-compile sentinel-agent for Windows x64 from Linux/macOS.
# Requires: rustup target + either cross (Docker) or mingw-w64 toolchain.
set -euo pipefail

TARGET="x86_64-pc-windows-gnu"
OUT_DIR="install/windows"

echo "==> Adding Rust Windows target..."
rustup target add "$TARGET"

# Prefer 'cross' (uses Docker, handles all deps automatically)
if command -v cross &>/dev/null; then
    echo "==> Building with 'cross' (Docker)..."
    cross build --release --target "$TARGET"
else
    echo "==> Building with cargo + mingw-w64..."
    echo "    (install mingw-w64: apt-get install gcc-mingw-w64-x86-64)"
    cargo build --release --target "$TARGET"
fi

BINARY="target/$TARGET/release/sentinel-agent.exe"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build succeeded but binary not found at $BINARY"
    exit 1
fi

echo "==> Copying binary to $OUT_DIR/..."
cp "$BINARY" "$OUT_DIR/sentinel-agent.exe"

echo ""
echo "Binary size: $(du -sh $OUT_DIR/sentinel-agent.exe | cut -f1)"
echo ""
echo "Next steps:"
echo "  1. Build NSIS installer:  makensis $OUT_DIR/sentinel.nsi"
echo "  2. Or distribute directly: $OUT_DIR/sentinel-agent.exe"
echo "     Install service on target:  powershell -File $OUT_DIR/install-service.ps1 -ApiUrl https://your.domain -ApiKey <key>"
