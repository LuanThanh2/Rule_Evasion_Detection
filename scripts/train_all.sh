#!/bin/bash
set -e
for cfg in config/process_creation.yaml config/registry_event.yaml config/powershell.yaml config/proxy_web.yaml; do
    echo "=== Training $cfg ==="
    python3 scripts/train.py --config "$cfg"
done
