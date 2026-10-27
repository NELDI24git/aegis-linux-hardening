#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root for a system-wide install, or use: python3 -m pip install --user ." >&2
  exit 2
fi
"$PYTHON" -m pip install "$ROOT"
install -d -m 0755 /etc/aegis /var/lib/aegis/backups /var/log/aegis
if [[ ! -e /etc/aegis/policy.example.json ]]; then
  aegis policy example > /etc/aegis/policy.example.json
  chmod 0644 /etc/aegis/policy.example.json
fi
install -Dm 0644 "$ROOT/docs/aegis.1" /usr/local/share/man/man1/aegis.1
install -Dm 0644 "$ROOT/completions/aegis.bash" /usr/local/share/bash-completion/completions/aegis
install -Dm 0644 "$ROOT/completions/_aegis" /usr/local/share/zsh/site-functions/_aegis
echo "Aegis installed. Review /etc/aegis/policy.example.json and copy it to /etc/aegis/policy.json only after declaring this host's intended role."
