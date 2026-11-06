#!/usr/bin/env bash
# Newest release of every enabled tool against the current baseline, then print the report path.
set -euo pipefail
cd "$(dirname "$0")/.."
orchestrator -v run "$@"
echo "latest run: results/latest"
