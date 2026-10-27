#!/usr/bin/env bash
set -euo pipefail
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root for system-wide uninstall." >&2
  exit 2
fi
python3 -m pip uninstall -y aegis-linux-hardening || true
rm -f /usr/local/share/man/man1/aegis.1 /usr/local/share/bash-completion/completions/aegis /usr/local/share/zsh/site-functions/_aegis
if [[ $PURGE -eq 1 ]]; then
  rm -rf /etc/aegis /var/lib/aegis /var/log/aegis
  echo "Aegis removed with state/config purge."
else
  echo "Aegis package removed. /etc/aegis, /var/lib/aegis and /var/log/aegis were intentionally preserved. Use --purge to remove them."
fi
