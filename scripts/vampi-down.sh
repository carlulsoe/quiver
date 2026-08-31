#!/usr/bin/env bash
set -euo pipefail

docker rm --force quiver-vampi-secure quiver-vampi-vulnerable >/dev/null 2>&1 || true
