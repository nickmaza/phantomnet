#!/usr/bin/env bash
# Force one web-decoy profile rotation (optionally to a given profile id).
#   scripts/rotate-now.sh [profile-id]
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T phantomnet-controller python -m controller.rotator --once ${1:+--profile "$1"}
