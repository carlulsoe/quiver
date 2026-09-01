#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
scan_dir="$(mktemp -d)"
readonly repo_root scan_dir
trap 'rm -rf -- "$scan_dir"' EXIT

# Scan exactly the files that could be committed: tracked files plus non-ignored
# additions. This avoids vendored vulnerable-target fixtures under .prototype/.
git -C "$repo_root" ls-files --cached --others --exclude-standard -z |
  tar --directory="$repo_root" --null --files-from=- --create --file=- |
  tar --directory="$scan_dir" --extract --file=-

docker run --rm \
  --volume "$scan_dir:/repo:ro" \
  zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  dir /repo --redact --no-banner
