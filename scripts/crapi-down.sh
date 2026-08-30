#!/usr/bin/env bash
set -euo pipefail

crapi_dir=".prototype/crapi"
if [[ ! -d "$crapi_dir/deploy/docker" ]]; then
  exit 0
fi

docker compose \
  -f "$crapi_dir/deploy/docker/docker-compose.yml" \
  -f "$crapi_dir/deploy/docker/docker-compose.minimal.yml" \
  down
