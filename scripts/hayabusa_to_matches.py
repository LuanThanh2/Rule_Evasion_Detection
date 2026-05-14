#!/usr/bin/env python3
"""
Convert Hayabusa JSONL output to AMIDES-format match events.

Usage:
    python3 hayabusa_to_matches.py \
        --input hayabusa_matches.jsonl \
        --output-dir ~/data/sigma/events_hayabusa/windows/process_creation \
        --event-type process_creation

    python3 hayabusa_to_matches.py \
        --input hayabusa_registry.jsonl \
        --output-dir ~/data/sigma/events_hayabusa/windows/registry_event \
        --event-type registry_event

    python3 hayabusa_to_matches.py \
        --input hayabusa_powershell.jsonl \
        --output-dir ~/data/sigma/events_hayabusa/windows/powershell \
        --event-type powershell
"""

import argparse
import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Default EventID filters per event type (None = accept all EventIDs)
EVENT_TYPE_IDS = {
    "process_creation": {1},
    "registry_event":   None,   # accept all — Hayabusa already filtered by rule
    "powershell":       None,   # accept all — Hayabusa already filtered by rule
}


def normalize_rule_name(title: str, max_len: int = 60) -> str:
    name = re.sub(r'[^\w]', '_', title).lower().strip('_')
    name = re.sub(r'_+', '_', name)
    return name[:max_len].rstrip('_')


def enrich_event(ev: dict, event_type: str) -> dict:
    """Add AMIDES-compatible fields based on event type."""
    details = ev.get("Details", {}) or {}
    extra = ev.get("ExtraFieldInfo", {}) or {}

    if event_type == "process_creation":
        cmdline = details.get("Cmdline", "") if isinstance(details, dict) else ""
        ev["process"] = {"command_line": cmdline}
        ev["winlog"] = {
            "event_data": {
                "CommandLine": cmdline,
                "Image": details.get("Proc", "") if isinstance(details, dict) else "",
                "ParentImage": extra.get("ParentImage", "") if isinstance(extra, dict) else "",
                "ParentCommandLine": details.get("ParentCmdline", "") if isinstance(details, dict) else "",
            }
        }

    elif event_type == "registry_event":
        # Try multiple field names Hayabusa may use
        target = ""
        for key in ("TargetObject", "Key", "RegKey", "Object"):
            target = details.get(key, "") if isinstance(details, dict) else ""
            if target:
                break
        if not target and isinstance(extra, dict):
            for key in ("TargetObject", "Key", "RegKey", "Object"):
                target = extra.get(key, "")
                if target:
                    break
        ev["winlog"] = {
            "event_data": {
                "TargetObject": target,
                "Details": details.get("Details", "") if isinstance(details, dict) else "",
                "EventType": details.get("EventType", "") if isinstance(details, dict) else "",
            }
        }

    elif event_type == "powershell":
        script = ""
        if isinstance(details, dict):
            for key in ("ScriptBlockText", "ScriptBlock", "Cmdline", "CommandLine"):
                script = details.get(key, "")
                if script:
                    break
        if not script and isinstance(extra, dict):
            for key in ("ScriptBlockText", "ScriptBlock", "Cmdline", "CommandLine"):
                script = extra.get(key, "")
                if script:
                    break
        ev["winlog"] = {
            "event_data": {
                "ScriptBlockText": script,
            }
        }

    return ev


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Hayabusa JSONL output file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--event-type", required=True,
                        choices=list(EVENT_TYPE_IDS.keys()),
                        help="Event type to process")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    valid_ids = EVENT_TYPE_IDS[args.event_type]
    output_dir = Path(os.path.expanduser(args.output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)

    counters = defaultdict(int)
    skipped = 0

    with open(os.path.expanduser(args.input), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            # Filter by EventID only when valid_ids is specified
            if valid_ids is not None and ev.get("EventID") not in valid_ids:
                skipped += 1
                continue

            rule_title = ev.get("RuleTitle", "")
            if not rule_title:
                skipped += 1
                continue

            ev = enrich_event(ev, args.event_type)

            rule_name = normalize_rule_name(rule_title)
            rule_dir = output_dir / rule_name
            rule_dir.mkdir(exist_ok=True)

            counters[rule_name] += 1
            n = counters[rule_name]
            out_file = rule_dir / f"{rule_name}_Match_{n:02d}.json"
            with open(out_file, "w", encoding="utf-8") as fout:
                json.dump(ev, fout, indent=2, default=str)
            logger.debug("Saved %s", out_file)

    logger.info("Event type: %s", args.event_type)
    logger.info("Rules matched: %d", len(counters))
    logger.info("Total events saved: %d", sum(counters.values()))
    logger.info("Skipped: %d", skipped)
    for rule, count in sorted(counters.items()):
        logger.info("  %s: %d", rule, count)


if __name__ == "__main__":
    main()
