#!/usr/bin/env python3
"""Generate evasion events from match events by applying transformation techniques.

For each Sigma rule with match events:
  1. Load match events and extract the relevant field value
  2. Apply evasion transformations (per event type)
  3. Verify the transformation bypasses the rule's detection patterns
  4. Save valid evasions as JSON files: events_dir/rule_name/rule_Evasion_technique_N.json

Supported event types and their transformations:
  - process_creation : remove_exe, double_space, quote_wrap, case_upper, case_lower,
                       env_systemroot, env_temp
  - registry_event   : hklm_expand, hklm_abbrev, hku_expand, case_lower, case_upper
  - powershell       : backtick_insert, case_mix, concat_keywords

Usage:
    python scripts/generate_evasions.py --config config/process_creation.yaml
    python scripts/generate_evasions.py --config config/registry_event.yaml
    python scripts/generate_evasions.py --config config/powershell.yaml
"""

import os
import sys
import re
import json
import copy
import fnmatch
import argparse
import logging
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import (
    load_rule_set,
    extract_commandline,
    extract_filter_values,
    _extract_sigma_detection_values,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("generate_evasions")


# ---------------------------------------------------------------------------
# Evasion transformations — per event type
# ---------------------------------------------------------------------------

def _transforms_process_creation():
    return {
        "remove_exe": _t_remove_exe,
        "double_space": _t_double_space,
        "quote_wrap_flags": _t_quote_wrap_flags,
        "case_upper": lambda t: t.upper(),
        "case_lower": lambda t: t.lower(),
        "env_systemroot": _t_env_systemroot,
        "env_temp": _t_env_temp,
        "long_flag_o": _t_long_flag_o,
    }

def _transforms_registry_event():
    return {
        "hklm_expand": _t_hklm_expand,
        "hklm_abbrev": _t_hklm_abbrev,
        "hku_expand": _t_hku_expand,
        "hku_abbrev": _t_hku_abbrev,
        "case_lower": lambda t: t.lower(),
        "case_upper": lambda t: t.upper(),
        "trailing_backslash": lambda t: t.rstrip("\\") + "\\",
    }

def _transforms_powershell():
    return {
        "backtick_insert": _t_backtick_insert,
        "case_mix": _t_case_mix,
        "concat_keywords": _t_concat_keywords,
        "double_space": _t_double_space,
        "env_comspec": _t_env_comspec,
    }

TRANSFORMS_BY_TYPE = {
    "process_creation": _transforms_process_creation,
    "registry_event": _transforms_registry_event,
    "powershell": _transforms_powershell,
}

# -- process_creation transforms --

def _t_remove_exe(text):
    """cscript.exe → cscript (OS resolves automatically)"""
    return re.sub(r'(\w+)\.exe\b', r'\1', text, flags=re.IGNORECASE)

def _t_double_space(text):
    """Insert extra space: /create → /create  (double space between tokens)"""
    return re.sub(r'(\S) (\S)', r'\1  \2', text)

def _t_quote_wrap_flags(text):
    """Wrap flags with quotes: /create → /"create" """
    return re.sub(r'/([A-Za-z]\w*)', r'/"\1"', text)

def _t_env_systemroot(text):
    """C:\\Windows → %SystemRoot%"""
    return re.sub(r'[Cc]:\\[Ww]indows', r'%SystemRoot%', text)

def _t_env_temp(text):
    """C:\\Users\\...\\Temp → %TEMP%"""
    return re.sub(
        r'[Cc]:\\[Uu]sers\\[^\\]+\\[Aa]pp[Dd]ata\\[Ll]ocal\\[Tt]emp',
        r'%TEMP%', text
    )

def _t_long_flag_o(text):
    """curl -O → curl --remote-name"""
    return re.sub(r'\b-O\b', '--remote-name', text)

# -- registry_event transforms --

def _t_hklm_expand(text):
    return re.sub(r'\bHKLM\\', r'HKEY_LOCAL_MACHINE\\', text, flags=re.IGNORECASE)

def _t_hklm_abbrev(text):
    return re.sub(r'\bHKEY_LOCAL_MACHINE\\', r'HKLM\\', text, flags=re.IGNORECASE)

def _t_hku_expand(text):
    return re.sub(r'\bHKU\\', r'HKEY_USERS\\', text, flags=re.IGNORECASE)

def _t_hku_abbrev(text):
    return re.sub(r'\bHKEY_USERS\\', r'HKU\\', text, flags=re.IGNORECASE)

# -- powershell transforms --

_PS_KEYWORDS = [
    "Invoke-Expression", "Invoke-Command", "Invoke-WebRequest",
    "DownloadString", "DownloadFile", "EncodedCommand",
    "Net.WebClient", "FromBase64String", "powershell",
]

def _t_backtick_insert(text):
    """Insert backtick after first char of known PS keywords: Invoke → I`nvoke"""
    result = text
    for kw in _PS_KEYWORDS:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        def _add_backtick(m):
            s = m.group(0)
            return s[0] + '`' + s[1:]
        result = pattern.sub(_add_backtick, result)
    return result

def _t_case_mix(text):
    """Alternate upper/lower per character: invoke → iNvOkE"""
    return ''.join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(text)
    )

def _t_concat_keywords(text):
    """Split known keywords with string concatenation: IEX → ('IE'+'X')"""
    result = text
    for kw in _PS_KEYWORDS:
        if len(kw) < 4:
            continue
        mid = len(kw) // 2
        replacement = f"('{kw[:mid]}'+" + f"'{kw[mid:]}')"
        result = re.sub(re.escape(kw), replacement, result, flags=re.IGNORECASE)
    return result

def _t_env_comspec(text):
    """cmd.exe → %ComSpec%"""
    return re.sub(r'\bcmd\.exe\b', r'%ComSpec%', text, flags=re.IGNORECASE)


# ---------------------------------------------------------------------------
# Pattern extraction — build map from Sigma YAML titles
# ---------------------------------------------------------------------------

def _normalize_rule_name(title: str, max_len: int = 60) -> str:
    """Normalize a rule title the same way hayabusa_to_matches.py does."""
    name = title.lower()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    name = name.strip('_')
    return name[:max_len]


def _extract_all_detection_values(detection: dict) -> list:
    """Extract ALL string values from a Sigma detection block (any field, any modifier)."""
    values = []
    if not isinstance(detection, dict):
        return values
    for key, content in detection.items():
        if key == "condition":
            continue
        if isinstance(content, dict):
            for field_spec, value in content.items():
                modifier = "|".join(field_spec.split("|")[1:]).lower()
                if "re" in modifier:
                    continue  # skip regex
                if isinstance(value, str):
                    values.append(value)
                elif isinstance(value, list):
                    values.extend(v for v in value if isinstance(v, str))
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    values.extend(_extract_all_detection_values(item))
                elif isinstance(item, str):
                    values.append(item)
    return values


def build_title_pattern_map(rules_dir: str) -> dict:
    """Scan all Sigma YAMLs under rules_dir, build map: normalized_title → [patterns].

    Used to find rule patterns even when events_dir subdir names don't match YAML filenames.
    """
    pattern_map = {}
    if not os.path.isdir(rules_dir):
        logger.warning("rules_dir does not exist or is not a directory: %s", rules_dir)
        return pattern_map

    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in filenames:
            if not fname.endswith(".yml"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                docs = list(yaml.safe_load_all(open(fpath, encoding="utf-8", errors="ignore")))
            except Exception:
                continue
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                title = doc.get("title", "")
                if not title:
                    continue
                key = _normalize_rule_name(title)
                patterns = []
                if "detection" in doc:
                    raw = _extract_all_detection_values(doc["detection"])
                    for p in raw:
                        p_clean = p.replace("*", "").replace("?", "").strip()
                        if len(p_clean) > 2:
                            patterns.append(p_clean.lower())
                if patterns:
                    pattern_map.setdefault(key, [])
                    pattern_map[key].extend(patterns)

    logger.info("Built pattern map: %d rules with patterns", len(pattern_map))
    return pattern_map


def lookup_patterns(rule_dir_name: str, pattern_map: dict) -> list:
    """Find patterns for a rule dir name using exact then prefix match."""
    # Exact match
    if rule_dir_name in pattern_map:
        return pattern_map[rule_dir_name]
    # Prefix match (rule dir may be truncated)
    for key, patterns in pattern_map.items():
        if key.startswith(rule_dir_name) or rule_dir_name.startswith(key):
            return patterns
    return []


def find_patterns_in_value(value: str, pattern_map: dict) -> list:
    """Find all patterns from pattern_map that appear in value (case-insensitive).

    Used as fallback when rule name doesn't match any pattern map key.
    Returns the union of all matching patterns across all rules.
    """
    v_lower = value.lower()
    found = set()
    for patterns in pattern_map.values():
        for p in patterns:
            if p in v_lower:
                found.add(p)
    return list(found)


def bypasses_rule(transformed: str, patterns: list) -> bool:
    """Return True if the transformed text no longer matches any rule pattern."""
    t_lower = transformed.lower()
    for p in patterns:
        if p in t_lower:
            return False
    return True


# ---------------------------------------------------------------------------
# Field extraction and event patching
# ---------------------------------------------------------------------------

def get_event_field_value(event: dict, search_fields: list) -> tuple:
    """Return (value, field_path) for the first non-empty field found."""
    from red.data import _extract_field_from_dict
    for field in search_fields:
        val = _extract_field_from_dict(event, field)
        if val:
            return val, field
    # Fallback for process_creation
    try:
        val = event["process"]["command_line"]
        if val:
            return val, "process.command_line"
    except (KeyError, TypeError):
        pass
    try:
        val = event["winlog"]["event_data"]["CommandLine"]
        if val:
            return val, "winlog.event_data.CommandLine"
    except (KeyError, TypeError):
        pass
    return None, None


def patch_event(event: dict, field_path: str, new_value: str) -> dict:
    """Deep-copy event and set field_path to new_value."""
    patched = copy.deepcopy(event)
    parts = field_path.split(".")
    obj = patched
    for part in parts[:-1]:
        if part not in obj:
            obj[part] = {}
        obj = obj[part]
    obj[parts[-1]] = new_value
    return patched


# ---------------------------------------------------------------------------
# Evasion generation
# ---------------------------------------------------------------------------

def generate_evasions_for_rule(rule_name, rule_data, transforms, search_fields,
                                evasions_dir, pattern_map=None, dry_run=False):
    """Generate and save evasion events for one rule into evasions_dir."""
    if not rule_data.matches:
        logger.debug("Rule %s: no match events, skipping", rule_name[:60])
        return 0

    # Try title-based lookup first; fall back to value-based pattern discovery
    rule_patterns = lookup_patterns(rule_name, pattern_map or {})

    rule_dir = os.path.join(evasions_dir, rule_name)
    saved = 0

    for match_event in rule_data.matches:
        original_value, field_path = get_event_field_value(match_event, search_fields)
        if not original_value or not field_path:
            continue

        # Per-event patterns: use rule-level if found, else discover from value
        if rule_patterns:
            patterns = rule_patterns
        else:
            patterns = find_patterns_in_value(original_value, pattern_map or {})
            if not patterns:
                logger.debug("Rule %s: no patterns found for value, skipping event", rule_name[:60])
                continue

        for technique_name, transform_fn in transforms.items():
            try:
                transformed = transform_fn(original_value)
            except Exception as e:
                logger.debug("Transform %s failed: %s", technique_name, e)
                continue

            # Skip if nothing changed
            if transformed == original_value:
                continue

            # Skip if transform is not meaningful (too similar)
            if transformed.lower() == original_value.lower():
                continue

            # Verify evasion bypasses rule
            if not bypasses_rule(transformed, patterns):
                continue

            # Build evasion event
            evasion_event = patch_event(match_event, field_path, transformed)
            evasion_event["_evasion_technique"] = technique_name
            evasion_event["_original_value"] = original_value

            if not dry_run:
                fname = f"{rule_name}_Evasion_{technique_name}_{saved}.json"
                fpath = os.path.join(rule_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(evasion_event, f, indent=2, ensure_ascii=False)

            saved += 1

    return saved


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate evasion events from match events")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--events-dir", type=str)
    parser.add_argument("--rules-dir", type=str)
    parser.add_argument("--evasions-dir", type=str,
                        help="Output dir for evasion files (default: events_dir/../evasions/<event_type>)")
    parser.add_argument("--event-type", type=str,
                        choices=list(TRANSFORMS_BY_TYPE.keys()),
                        help="Event type (auto-detected from config if omitted)")
    parser.add_argument("--search-fields", type=str, nargs="+", default=None)
    parser.add_argument("--dry-run", action="store_true",
                        help="Count evasions without writing files")
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        data_cfg = cfg.get("data", {})
        args.events_dir = args.events_dir or data_cfg.get("events_dir")
        args.rules_dir = args.rules_dir or data_cfg.get("rules_dir")
        args.evasions_dir = args.evasions_dir or data_cfg.get("evasions_dir")
        args.search_fields = args.search_fields or data_cfg.get("search_fields")
        args.event_field_map = data_cfg.get("event_field_map", {})
        if not args.event_type:
            config_name = os.path.basename(args.config).replace(".yaml", "")
            if config_name in TRANSFORMS_BY_TYPE:
                args.event_type = config_name

    if not args.events_dir or not args.rules_dir:
        parser.error("--events-dir and --rules-dir are required")
    if not args.event_type:
        parser.error("--event-type is required")
    if not args.search_fields:
        parser.error("--search-fields is required")

    # Resolve Sigma field names → JSON event paths
    from red.data import resolve_event_paths
    event_field_map = getattr(args, "event_field_map", {}) or {}
    event_paths = resolve_event_paths(args.search_fields, event_field_map)
    logger.info("Sigma fields: %s → event paths: %s", args.search_fields, event_paths)

    args.events_dir = os.path.expanduser(args.events_dir)
    args.rules_dir = os.path.expanduser(args.rules_dir)

    # Default evasions_dir: sibling of events_dir parent, named "evasions/<event_type>"
    if not args.evasions_dir:
        base = os.path.dirname(os.path.dirname(args.events_dir))  # e.g. ~/data/sigma
        args.evasions_dir = os.path.join(base, "evasions", "windows", args.event_type)
    else:
        args.evasions_dir = os.path.expanduser(args.evasions_dir)

    logger.info("Evasions output dir: %s", args.evasions_dir)

    transforms = TRANSFORMS_BY_TYPE[args.event_type]()
    logger.info("Event type: %s — %d transforms", args.event_type, len(transforms))

    logger.info("Building pattern map from Sigma rules...")
    pattern_map = build_title_pattern_map(args.rules_dir)

    logger.info("Loading rule set...")
    rule_set = load_rule_set(args.events_dir, args.rules_dir)
    logger.info("Loaded %d rules", len(rule_set))

    total_evasions = 0
    total_rules = 0

    for rule_name, rule_data in sorted(rule_set.items()):
        count = generate_evasions_for_rule(
            rule_name, rule_data, transforms,
            event_paths, args.evasions_dir,
            pattern_map=pattern_map,
            dry_run=args.dry_run,
        )
        if count > 0:
            logger.info("Rule %-60s → %d evasions", rule_name[:60], count)
            total_evasions += count
            total_rules += 1

    logger.info(
        "%s %d evasions across %d rules",
        "[DRY RUN]" if args.dry_run else "Generated",
        total_evasions, total_rules
    )


if __name__ == "__main__":
    main()
