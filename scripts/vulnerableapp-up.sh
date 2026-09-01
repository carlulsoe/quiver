#!/usr/bin/env bash
set -euo pipefail

target_dir=".prototype/vulnerableapp"
target_revision="f8581f6e6dbd335f698e7fb10446c503cfc1e3cc"
container_name="quiver-vulnerableapp"

if [[ ! -d "$target_dir/.git" ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/SasanLabs/VulnerableApp.git "$target_dir"
fi

git -C "$target_dir" fetch --depth 1 origin "$target_revision"
git -C "$target_dir" checkout --detach "$target_revision"
(cd "$target_dir" && ./gradlew jibDockerBuild)
docker rm --force "$container_name" >/dev/null 2>&1 || true
docker run --detach --name "$container_name" --publish 127.0.0.1:9090:9090 sasanlabs/owasp-vulnerableapp:unreleased >/dev/null

for attempt in {1..150}; do
  if curl --silent --fail http://127.0.0.1:9090/VulnerableApp/scanner/dast >/dev/null; then
    exit 0
  fi
  sleep 2
done

docker logs "$container_name"
exit 1
