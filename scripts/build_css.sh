#!/bin/bash
# =====================================================================
# Build the panel's Tailwind CSS -> public/assets/app.css
# =====================================================================
# Uses the Tailwind standalone CLI (no Node/npm). The binary is cached in
# .cache/ (gitignored) and downloaded once. Run this after editing templates
# or resources/input.css, then commit the regenerated public/assets/app.css
# (the committed file is the deploy fallback if a build-time download fails).
# =====================================================================
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/.cache"
BIN="$CACHE/tailwindcss"
VERSION="v3.4.17"
URL="https://github.com/tailwindlabs/tailwindcss/releases/download/${VERSION}/tailwindcss-linux-x64"

mkdir -p "$CACHE" "$ROOT/public/assets"

if [ ! -x "$BIN" ]; then
  echo "Downloading Tailwind CLI ${VERSION}..."
  curl -fsSL -o "$BIN" "$URL"
  chmod +x "$BIN"
fi

"$BIN" \
  --config "$ROOT/tailwind.config.js" \
  --input "$ROOT/resources/input.css" \
  --output "$ROOT/public/assets/app.css" \
  --minify

echo "Built public/assets/app.css ($(wc -c < "$ROOT/public/assets/app.css") bytes)"
