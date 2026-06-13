#!/usr/bin/env python3
"""
Convert das-lab/mpsd PowerShell benign dataset (.ps1 files) → benign_train.txt.

Each .ps1 file = one ScriptBlockText sample (newlines collapsed to spaces).

Usage:
    python3 mpsd_to_benign.py \
        --mpsd-dir ~/KLTN/KLTN/datasets/benign_data/mpsd/powershell_benign_dataset \
        --output-dir ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection/data/benign/powershell
"""

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def convert(mpsd_dir: str, output_dir: str):
    mpsd_path = Path(mpsd_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ps1_files = sorted(mpsd_path.glob("*.ps1"))
    if not ps1_files:
        logger.error("No .ps1 files found in %s", mpsd_path)
        return

    samples = set()
    skipped = 0

    for ps1 in ps1_files:
        try:
            content = ps1.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception as e:
            logger.debug("Skipping %s: %s", ps1.name, e)
            skipped += 1
            continue

        if not content:
            skipped += 1
            continue

        # Collapse to single line
        single_line = " ".join(content.splitlines())
        samples.add(single_line)

    out_file = out_path / "benign_train.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        for s in sorted(samples):
            f.write(s + "\n")

    logger.info("PowerShell benign samples: %d (skipped: %d) → %s", len(samples), skipped, out_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mpsd-dir", required=True, help="Path to powershell_benign_dataset/")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    args = parser.parse_args()
    convert(args.mpsd_dir, args.output_dir)


if __name__ == "__main__":
    main()
