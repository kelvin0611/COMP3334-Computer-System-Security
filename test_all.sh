#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running automated R1-R25 test harness (client-based evidence)..."
.venv/bin/python test_all.py

