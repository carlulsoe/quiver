#!/usr/bin/env bash
set -euo pipefail

target_dir=".prototype/broken-crystals"
target_revision="2a64b95586d4ef8dbb26803bf9ae8ec5182964f0"

if [[ ! -d "$target_dir/.git" ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/NeuraLegion/brokencrystals.git "$target_dir"
fi

git -C "$target_dir" fetch --depth 1 origin "$target_revision"
git -C "$target_dir" checkout --detach "$target_revision"
docker compose \
  -f "$target_dir/compose.local.yml" \
  -f scripts/broken-crystals-loopback.yml \
  up -d --build --wait
