#!/usr/bin/env bash
set -euo pipefail
SKILL="fenrir"
HERMES="${HERMES_HOME:-$HOME/.hermes}/skills"
TARGET="$HERMES/$SKILL"
echo "Installing Fenrir skill for Hermes Agent..."
if [ -d "$TARGET" ]; then
  echo "  Replacing existing version..."
  rm -rf "$TARGET"
fi
mkdir -p "$TARGET"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/../SKILL.md" "$TARGET/"
echo "✅ Fenrir installed at: $TARGET"
echo ""
echo "Usage: Start Hermes → /skill fenrir → scan target.com"
echo "Or just say: scan target.com"
