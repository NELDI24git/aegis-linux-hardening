#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v docker >/dev/null 2>&1; then ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then ENGINE=podman
  else echo "Docker or Podman is required for the container matrix." >&2; exit 2
  fi
fi
for distro in ubuntu debian fedora; do
  image="aegis-integration:${distro}-1.1.0"
  echo "==> Building $distro"
  "$ENGINE" build -f "$ROOT/integration/containers/${distro}.Dockerfile" -t "$image" "$ROOT"
  echo "==> Testing $distro"
  "$ENGINE" run --rm "$image"
done
