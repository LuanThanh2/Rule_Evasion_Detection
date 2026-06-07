#!/bin/bash
# Run the complete RED pipeline for process creation events
# Usage: bash run_all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  Rule Evasion Detection - Full Pipeline"
echo "=============================================="

# Install dependencies (if needed)
# pip install -r requirements.txt

# Run complete pipeline
python scripts/run_pipeline.py --config config/process_creation.yaml

echo ""
echo "Done! Check models/process_creation/ for results."
