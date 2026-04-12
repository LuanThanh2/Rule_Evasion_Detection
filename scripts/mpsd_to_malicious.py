#!/usr/bin/env python3
"""
Filter das-lab/mpsd malicious PowerShell scripts by Sigma rule patterns → malicious_extra.txt.

Only keeps .ps1 files whose content matches at least one Sigma rule's detection pattern
for ScriptBlockText (i.e., the script would have triggered the rule if executed and logged).

Each matched file → one line (newlines collapsed to spaces).

Usage:
    python3 mpsd_to_malicious.py \
        --mpsd-dir ~/data_featute/malicious_data/mpsd/malicious_pure \
        --rules-dir ~/data/sigma/rules/windows/powershell \
        --output ~/data/benign/powershell/malicious_extra.txt
"""

import argparse
import logging
import re
import yaml
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Sigma fields that map to ScriptBlockText content
SCRIPTBLOCK_FIELDS = {"scriptblocktext", "scriptblock"}


def extract_sigma_patterns(rules_dir: str) -> list:
    """Extract all string patterns from Sigma detection blocks targeting ScriptBlockText."""
    patterns = []
    rules_path = Path(rules_dir)
    for yml_file in rules_path.rglob("*.yml"):
        try:
            docs = list(yaml.safe_load_all(yml_file.read_text(encoding="utf-8", errors="ignore")))
            for doc in docs:
                if not isinstance(doc, dict) or "detection" not in doc:
                    continue
                _extract_from_detection(doc["detection"], patterns)
        except Exception as e:
            logger.debug("Skipping %s: %s", yml_file.name, e)

    # Deduplicate, keep non-empty
    patterns = list({p.lower() for p in patterns if p and len(p) > 3})
    logger.info("Extracted %d unique patterns from Sigma rules", len(patterns))
    return patterns


def _extract_from_detection(detection: dict, out: list):
    """Recursively extract string values for ScriptBlockText fields."""
    if not isinstance(detection, dict):
        return
    for key, content in detection.items():
        if key == "condition":
            continue
        if isinstance(content, dict):
            for field_spec, value in content.items():
                field_name = field_spec.split("|")[0].lower().replace("-", "").replace("_", "")
                if field_name not in SCRIPTBLOCK_FIELDS:
                    continue
                modifier = "|".join(field_spec.split("|")[1:]).lower()
                if "re" in modifier:
                    continue  # skip regex patterns
                if isinstance(value, str):
                    out.append(value)
                elif isinstance(value, list):
                    out.extend(v for v in value if isinstance(v, str))
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    _extract_from_detection(item, out)


def matches_any_pattern(content_lower: str, patterns: list) -> bool:
    """Return True if content contains at least one pattern."""
    return any(p in content_lower for p in patterns)


def convert(mpsd_dir: str, rules_dir: str, output: str):
    out_file = Path(output)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Load Sigma patterns
    patterns = extract_sigma_patterns(rules_dir)
    if not patterns:
        logger.error("No patterns extracted — check rules_dir: %s", rules_dir)
        return

    ps1_files = sorted(Path(mpsd_dir).rglob("*.ps1"))
    if not ps1_files:
        logger.error("No .ps1 files found in %s", mpsd_dir)
        return

    logger.info("Scanning %d .ps1 files against %d patterns...", len(ps1_files), len(patterns))

    matched = set()
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

        if matches_any_pattern(content.lower(), patterns):
            single_line = " ".join(content.splitlines())
            matched.add(single_line)

    with open(out_file, "w", encoding="utf-8") as f:
        for s in sorted(matched):
            f.write(s + "\n")

    logger.info(
        "Matched: %d / %d files (skipped: %d) → %s",
        len(matched), len(ps1_files), skipped, out_file
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mpsd-dir", required=True, help="Path to malicious_pure/")
    parser.add_argument("--rules-dir", required=True, help="Path to Sigma powershell rules dir")
    parser.add_argument("--output", required=True, help="Output .txt file path")
    args = parser.parse_args()
    convert(args.mpsd_dir, args.rules_dir, args.output)


if __name__ == "__main__":
    main()
