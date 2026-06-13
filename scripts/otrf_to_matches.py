#!/usr/bin/env python3
"""
Convert OTRF Security-Datasets JSON files to AMIDES-format match events.

Handles:
- Standard Sigma HQ YAML format (detection.selection_* blocks)
- Multiple OTRF JSON event formats (Winlogbeat ECS, raw WEL, simplified)

Usage:
    python3 otrf_to_matches.py \
        --otrf-dir /mnt/e/KLTN/data/Security-Datasets/datasets/atomic/windows \
        --rules-dir /mnt/e/KLTN/Rule_Evasion_Detection/rule_evasion_detection/data/sigma/rules/windows/process_creation \
        --output-dir /mnt/e/KLTN/Rule_Evasion_Detection/rule_evasion_detection/data/sigma/events_otrf/windows/process_creation
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CommandLine extraction — handles multiple OTRF JSON formats
# ---------------------------------------------------------------------------

def extract_commandline(event: dict) -> Optional[str]:
    """Try all known field paths for CommandLine across OTRF JSON formats."""

    # Format C: CommandLine at top level (simplified Sysmon format)
    if "CommandLine" in event:
        return event["CommandLine"]

    # Format A: Winlogbeat ECS format
    try:
        return event["process"]["command_line"]
    except (KeyError, TypeError):
        pass
    try:
        return event["winlog"]["event_data"]["CommandLine"]
    except (KeyError, TypeError):
        pass

    # Format B: Nested EventData
    try:
        return event["EventData"]["CommandLine"]
    except (KeyError, TypeError):
        pass

    # Fallback: parse from Message text field
    msg = event.get("Message", "")
    if "CommandLine:" in msg:
        for line in msg.split("\n"):
            stripped = line.strip()
            if stripped.startswith("CommandLine:"):
                return stripped.split("CommandLine:", 1)[1].strip()

    return None


def is_process_creation(event: dict) -> bool:
    """Check if event is a Sysmon process creation (EventID=1)."""

    # Get EventID from various field locations
    eid = (
        event.get("EventID")
        or event.get("event_id")
    )
    try:
        eid = eid or event["winlog"]["event_id"]
    except (KeyError, TypeError):
        pass
    try:
        eid = eid or int(event["event"]["code"])
    except (KeyError, TypeError, ValueError):
        pass

    if eid != 1:
        return False

    # Check it's Sysmon (not Security or other channel with EventID=1)
    channel = (
        event.get("Channel", "")
        or event.get("SourceName", "")
    )
    try:
        channel = channel or event["winlog"]["channel"]
    except (KeyError, TypeError):
        pass

    if channel and "Sysmon" in str(channel):
        return True

    # Format C: has CommandLine + Image + ParentImage at top level = Sysmon
    if all(k in event for k in ("CommandLine", "Image", "ParentImage")):
        return True

    # Format A: Winlogbeat with process.command_line
    try:
        if event["process"]["command_line"] and event["event"]["code"] == 1:
            return True
    except (KeyError, TypeError):
        pass

    return False


# ---------------------------------------------------------------------------
# Sigma YAML parsing — handles standard Sigma HQ format
# ---------------------------------------------------------------------------

def extract_commandline_patterns(rule_data: dict) -> List[str]:
    """Extract CommandLine match patterns from standard Sigma detection block.

    Handles modifiers: CommandLine|contains, CommandLine|endswith,
    CommandLine|startswith, CommandLine|contains|all
    """
    patterns = []
    detection = rule_data.get("detection", {})
    if not detection:
        return patterns

    for key, block in detection.items():
        if key == "condition":
            continue
        _extract_from_block(block, patterns)

    return patterns


def _extract_from_block(block, patterns: list):
    """Recursively extract CommandLine values from a detection block."""
    if isinstance(block, dict):
        for field, values in block.items():
            if "CommandLine" in field or "commandline" in field.lower():
                _collect_values(values, patterns)

    elif isinstance(block, list):
        for item in block:
            if isinstance(item, dict):
                for field, values in item.items():
                    if "CommandLine" in field or "commandline" in field.lower():
                        _collect_values(values, patterns)


def _collect_values(values, patterns: list):
    if isinstance(values, list):
        for v in values:
            if isinstance(v, str):
                patterns.append(v)
    elif isinstance(values, str):
        patterns.append(values)


def load_sigma_rules(rules_dir: str) -> Dict[str, dict]:
    """Load Sigma HQ YAML rules and extract CommandLine patterns."""
    rules = {}
    skipped = 0

    for f in sorted(Path(rules_dir).glob("*.yml")):
        try:
            data = yaml.safe_load(open(f, encoding="utf-8"))
            if not isinstance(data, dict):
                skipped += 1
                continue

            patterns = extract_commandline_patterns(data)
            if not patterns:
                skipped += 1
                continue

            rules[f.stem] = {
                "title": data.get("title", f.stem),
                "patterns": patterns,
            }
            logger.debug(f"Rule {f.stem}: {len(patterns)} patterns")

        except Exception as e:
            logger.debug(f"Skip {f.name}: {e}")
            skipped += 1

    logger.info(f"Loaded {len(rules)} rules with CommandLine patterns ({skipped} skipped)")
    return rules


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def wildcard_match(pattern: str, text: str) -> bool:
    """Case-insensitive wildcard match (* = any substring)."""
    regex = ".*".join(re.escape(p) for p in pattern.lower().split("*"))
    return bool(re.search(regex, text.lower()))


def event_matches_rule(cmd: str, rule: dict) -> bool:
    """Check if command line matches any pattern in rule."""
    for pattern in rule["patterns"]:
        if wildcard_match(pattern, cmd):
            return True
    return False


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def find_json_files(otrf_dir: str) -> List[Path]:
    """Find all host JSON files (skip network captures and macOS metadata)."""
    files = []
    for path in sorted(Path(otrf_dir).rglob("*.json")):
        parts = path.parts
        if "network" in parts:
            continue
        if path.name.startswith("._"):
            continue
        files.append(path)
    logger.info(f"Found {len(files)} JSON files")
    return files


def load_events(json_path: Path) -> List[dict]:
    """Load events from NDJSON file (one JSON object per line)."""
    events = []
    try:
        with open(json_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                    elif isinstance(obj, list):
                        events.extend(e for e in obj if isinstance(e, dict))
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        logger.warning(f"Failed to load {json_path.name}: {e}")
    return events


def process_all_files(
    json_files: List[Path],
    rules: Dict[str, dict],
) -> Dict[str, List[dict]]:
    matches_by_rule = defaultdict(list)
    total_events = 0
    total_proc = 0

    for i, json_path in enumerate(json_files, 1):
        events = load_events(json_path)
        total_events += len(events)

        proc_events = [e for e in events if is_process_creation(e)]
        total_proc += len(proc_events)

        if not proc_events:
            logger.debug(f"[{i}/{len(json_files)}] {json_path.name}: no process creation events")
            continue

        logger.info(f"[{i}/{len(json_files)}] {json_path.name}: {len(proc_events)} process events")

        for event in proc_events:
            cmd = extract_commandline(event)
            if not cmd:
                continue
            for rule_name, rule in rules.items():
                if event_matches_rule(cmd, rule):
                    matches_by_rule[rule_name].append(event)
                    logger.debug(f"  MATCH: {rule_name} ← {cmd[:70]}")

    logger.info(f"Scanned: {total_events} total events, {total_proc} process creation")
    return dict(matches_by_rule)


def save_matches(matches_by_rule: Dict[str, List[dict]], output_dir: str) -> int:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    total = 0

    for rule_name, events in sorted(matches_by_rule.items()):
        rule_dir = output_path / rule_name
        rule_dir.mkdir(exist_ok=True)
        for i, event in enumerate(events, 1):
            out_file = rule_dir / f"{rule_name}_Match_{i:02d}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2, default=str)
            total += 1
        logger.info(f"  {rule_name}: {len(events)} matches")

    return total


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="OTRF → AMIDES match events converter")
    parser.add_argument("--otrf-dir", required=True)
    parser.add_argument("--rules-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    for path, name in [(args.otrf_dir, "otrf-dir"), (args.rules_dir, "rules-dir")]:
        if not Path(path).is_dir():
            logger.error(f"{name} not found: {path}")
            sys.exit(1)

    logger.info("=" * 60)
    logger.info("OTRF → AMIDES Match Events Converter")
    logger.info(f"  OTRF dir:   {args.otrf_dir}")
    logger.info(f"  Rules dir:  {args.rules_dir}")
    logger.info(f"  Output dir: {args.output_dir}")
    logger.info("=" * 60)

    rules = load_sigma_rules(args.rules_dir)
    json_files = find_json_files(args.otrf_dir)
    matches = process_all_files(json_files, rules)

    if not matches:
        logger.warning("No matches found!")
        sys.exit(0)

    total = save_matches(matches, args.output_dir)

    logger.info("=" * 60)
    logger.info(f"Rules matched: {len(matches)}")
    logger.info(f"Total events saved: {total}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
