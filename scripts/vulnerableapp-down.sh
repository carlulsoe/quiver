#!/usr/bin/env bash
set -euo pipefail

docker rm --force quiver-vulnerableapp >/dev/null 2>&1 || true
