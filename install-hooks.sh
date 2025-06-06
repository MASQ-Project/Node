#!/bin/bash
# install-hooks.sh

HOOK_DIR=".githooks"
TARGET_DIR=".git/hooks"

echo "Installing Git hooks..."

for hook in $HOOK_DIR/*; do
  hook_name=$(basename "$hook")
  cp "$hook" "$TARGET_DIR/$hook_name"
  chmod +x "$TARGET_DIR/$hook_name"
  echo "Installed $hook_name"
done

echo "Done."
