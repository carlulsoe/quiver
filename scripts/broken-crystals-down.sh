#!/usr/bin/env bash
set -euo pipefail

target_dir=".prototype/broken-crystals"
if [[ -f "$target_dir/compose.local.yml" ]]; then
  docker compose \
    -f "$target_dir/compose.local.yml" \
    -f scripts/broken-crystals-loopback.yml \
    down
fi
