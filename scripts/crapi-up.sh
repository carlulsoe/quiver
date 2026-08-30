#!/usr/bin/env bash
set -euo pipefail

crapi_dir=".prototype/crapi"
crapi_revision="73d309cc8f28bbdeed31dbb35f05dba8354de3c9"

if [[ ! -d "$crapi_dir/.git" ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/OWASP/crAPI.git "$crapi_dir"
fi

git -C "$crapi_dir" fetch --depth 1 origin "$crapi_revision"
git -C "$crapi_dir" checkout --detach "$crapi_revision"

docker compose \
  -f "$crapi_dir/deploy/docker/docker-compose.yml" \
  -f "$crapi_dir/deploy/docker/docker-compose.minimal.yml" \
  up -d --wait
