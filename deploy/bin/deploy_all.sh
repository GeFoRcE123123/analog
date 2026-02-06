#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

services=("$@")
if [[ "${#services[@]}" -eq 0 ]]; then
  services=(database backend-env backend parsers frontend ml-api osint-api)
fi

for svc in "${services[@]}"; do
  "${SCRIPT_DIR}/deploy_microservice.sh" "${svc}"
done

echo "✅ Deploy finished for: ${services[*]}"
