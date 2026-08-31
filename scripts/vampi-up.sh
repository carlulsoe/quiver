#!/usr/bin/env bash
set -euo pipefail

target_dir=".prototype/vampi"
target_revision="f16052dce83f05847133ec98f01c5193a41de7d8"

if [[ ! -d "$target_dir/.git" ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/erev0s/VAmPI.git "$target_dir"
fi

git -C "$target_dir" fetch --depth 1 origin "$target_revision"
git -C "$target_dir" checkout --detach "$target_revision"
image="quiver-vampi:$target_revision"
docker build --tag "$image" "$target_dir"
docker rm --force quiver-vampi-secure quiver-vampi-vulnerable >/dev/null 2>&1 || true
docker run --detach --name quiver-vampi-secure --env vulnerable=0 --env tokentimetolive=3600 --publish 127.0.0.1:5001:5000 "$image" >/dev/null
docker run --detach --name quiver-vampi-vulnerable --env vulnerable=1 --env tokentimetolive=3600 --publish 127.0.0.1:5002:5000 "$image" >/dev/null

for port in 5001 5002; do
  for attempt in {1..30}; do
    if curl --silent --fail "http://127.0.0.1:$port/createdb" >/dev/null; then
      break
    fi
    if [[ "$attempt" == 30 ]]; then
      docker logs "quiver-vampi-$([[ "$port" == 5001 ]] && printf secure || printf vulnerable)"
      exit 1
    fi
    sleep 1
  done
done
