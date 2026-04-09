"""Data loading for benign samples, Sigma rules, and match/evasion events.

Handles three data sources:
  - Benign samples: plain text files (one sample per line) or JSONL
  - Sigma rules: YAML files with detection filters parsed via luqum
  - Events: JSON files for matches and evasions organized per-rule

The central flow:
  1. load_benign_samples()         → list[str]
  2. load_rule_set()               → dict[rule_name → RuleData]
  3. extract_commandlines(events)  → list[str]
  4. extract_filter_values(rules)  → list[str]
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import yaml
import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class RuleData:
    """Holds data for a single Sigma rule."""
    name: str
    filters: list = field(default_factory=list)      # raw filter strings from YAML
    matches: list = field(default_factory=list)       # match event dicts
    evasions: list = field(default_factory=list)      # evasion event dicts


# ---------------------------------------------------------------------------
# Benign sample loading
# ---------------------------------------------------------------------------

def _extract_field_from_dict(obj: dict, field: Optional[str]) -> Optional[str]:
    """Extract a value from a nested dict using a dot-separated field path.

    If field is None, falls back to trying common CommandLine paths.
    """
    if field:
        val = obj
        for part in field.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return str(val).strip() if val else None

    # Fallback: try common paths when no field specified
    candidates = [
        lambda o: o["process"]["command_line"],
        lambda o: o["winlog"]["event_data"]["CommandLine"],
        lambda o: o["CommandLine"],
        lambda o: o["command_line"],
        lambda o: o["Details"]["Cmdline"],
    ]
    for fn in candidates:
        try:
            val = fn(obj)
            if isinstance(val, str) and val.strip():
                return val.strip()
        except (KeyError, TypeError):
            pass
    return None


def _iter_benign_file(path: str, field: Optional[str] = None):
    """Yield CommandLine strings from a file, auto-detecting format.

    Supported formats:
      - Plain text (.txt or no extension): one value per line
      - JSONL / NDJSON (.jsonl, .ndjson): one JSON object per line
      - JSON (.json): array of objects or single object
      - CSV (.csv): header row required; uses `field` to find column

    Parameters
    ----------
    path : str
        Path to benign data file.
    field : str, optional
        Dot-separated field path to extract from JSON/CSV objects.
        e.g. "process.command_line", "winlog.event_data.ScriptBlockText"
        If None, falls back to trying common CommandLine paths.
    """
    import csv
    ext = os.path.splitext(path)[1].lower()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        if ext in (".jsonl", ".ndjson"):
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    val = _extract_field_from_dict(obj, field) if isinstance(obj, dict) else None
                    if val:
                        yield val
                except json.JSONDecodeError:
                    pass

        elif ext == ".json":
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return
            items = data if isinstance(data, list) else [data]
            for obj in items:
                if isinstance(obj, dict):
                    val = _extract_field_from_dict(obj, field)
                    if val:
                        yield val

        elif ext == ".csv":
            reader = csv.DictReader(f)
            col = None
            # Determine target column from field or by guessing
            if field:
                col_key = field.split(".")[-1].lower()
            else:
                col_key = None
            for row in reader:
                if col is None:
                    for c in row:
                        c_low = c.lower()
                        if col_key and c_low == col_key:
                            col = c
                            break
                        if not col_key and c_low in ("commandline", "command_line", "cmdline",
                                                      "scriptblocktext", "targetobject", "url"):
                            col = c
                            break
                    if col is None:
                        logger.warning("No matching column for field '%s' in %s", field, path)
                        return
                val = row.get(col, "").strip()
                if val:
                    yield val

        else:  # plain text
            for line in f:
                line = line.rstrip("\n")
                if line:
                    yield line


def load_benign_samples(path: str, field: Optional[str] = None) -> List[str]:
    """Load benign samples from a file (auto-detects format).

    Parameters
    ----------
    path : str
        Path to benign data file.
    field : str, optional
        Dot-separated field path to extract (e.g. "process.command_line").
    """
    samples = list(_iter_benign_file(path, field))
    logger.info("Loaded %d benign samples from %s", len(samples), path)
    return samples


def benign_samples_iter(path: str, field: Optional[str] = None):
    """Yield benign samples one at a time (memory efficient, auto-detects format)."""
    yield from _iter_benign_file(path, field)


def count_benign_samples(path: str, field: Optional[str] = None) -> int:
    """Count benign samples without loading all into memory."""
    return sum(1 for _ in _iter_benign_file(path, field))


# ---------------------------------------------------------------------------
# Command-line extraction from event dicts
# ---------------------------------------------------------------------------

def extract_commandline(event: dict, search_fields: Optional[List[str]] = None) -> Optional[str]:
    """Extract a value from an event dict using search_fields or common fallback paths.

    Parameters
    ----------
    event : dict
        Event dictionary.
    search_fields : list of str, optional
        Dot-separated field paths to try (e.g. ["winlog.event_data.TargetObject"]).
        Falls back to common CommandLine paths if None.
    """
    if search_fields:
        for field in search_fields:
            val = _extract_field_from_dict(event, field)
            if val:
                return val
        return None

    # Default fallback for process_creation
    try:
        return event["process"]["command_line"]
    except (KeyError, TypeError):
        pass
    try:
        return event["winlog"]["event_data"]["CommandLine"]
    except (KeyError, TypeError):
        pass
    return None


def extract_commandlines(events: List[dict], search_fields: Optional[List[str]] = None) -> List[str]:
    """Extract field values from a list of event dicts using search_fields."""
    results = []
    for event in events:
        val = extract_commandline(event, search_fields)
        if val is not None:
            results.append(val)
    return results


# ---------------------------------------------------------------------------
# Sigma rule filter value extraction (using luqum)
# ---------------------------------------------------------------------------

def extract_filter_values(filter_str: str, search_fields: List[str]) -> List[str]:
    """Parse a Sigma rule filter string and extract values for given fields.

    Uses luqum to parse the Lucene-like filter expression and visits the
    AST to extract SearchField values matching the requested field names.

    Parameters
    ----------
    filter_str : str
        Lucene-like filter expression from the Sigma rule YAML.
    search_fields : list of str
        Field names to extract values for, e.g. ["process.command_line"].

    Returns
    -------
    list of str
        Extracted field values.
    """
    try:
        from luqum.parser import parser as luqum_parser
        from luqum.visitor import TreeVisitor
        from luqum.tree import NoneItem

        tree = luqum_parser.parse(filter_str)
        visitor = _FieldValueVisitor(search_fields)
        visitor.visit(tree)
        return visitor.values
    except Exception as e:
        logger.warning("Failed to parse filter '%s': %s", filter_str[:80], e)
        return []


class _FieldValueVisitor:
    """luqum TreeVisitor that extracts values for specified search fields."""

    def __init__(self, fields: List[str]):
        from luqum.visitor import TreeVisitor
        self._visitor_cls = TreeVisitor
        self._fields = fields
        self.values = []
        self._inner = _InnerVisitor(fields, self.values)

    def visit(self, tree):
        self._inner.visit(tree)


class _InnerVisitor:
    """Actual visitor implementation using luqum's TreeVisitor."""

    def __init__(self, fields, values_list):
        from luqum.visitor import TreeVisitor
        from luqum.tree import NoneItem

        self._fields = fields
        self._values = values_list
        self._NoneItem = NoneItem

        class Visitor(TreeVisitor):
            def __init__(inner_self):
                super().__init__(track_parents=False)

            def visit_search_field(inner_self, node, context):
                match = False
                for fld in fields:
                    if node.name == fld or node.name.startswith(fld + "|"):
                        match = True
                if match:
                    context = inner_self.child_context(node, NoneItem(), context)
                    context[node.name.split("|")[0]] = True
                yield from inner_self.generic_visit(node, context)

            def visit_phrase(inner_self, node, context):
                for fld in fields:
                    if context.get(fld, False):
                        val = node.value
                        if val.startswith('"') and val.endswith('"'):
                            val = val[1:-1]
                        values_list.append(val)
                yield from inner_self.generic_visit(node, context)

            def visit_not(inner_self, node, context):
                yield NoneItem()

        self._visitor = Visitor()

    def visit(self, tree):
        self._visitor.visit(tree)


# ---------------------------------------------------------------------------
# Rule set loading
# ---------------------------------------------------------------------------

MATCH_REGEX = re.compile(r"^.+_Match_\d+\.json$")
EVASION_REGEX = re.compile(r"^.+_Evasion_.+_\d+\.json$")


def load_rule_set(events_dir: str, rules_dir: str) -> Dict[str, RuleData]:
    """Load a complete rule set from events and rules directories.

    Parameters
    ----------
    events_dir : str
        Path to directory containing per-rule subdirectories with
        JSON match/evasion files and properties.yml.
    rules_dir : str
        Path to directory containing per-rule YAML files.

    Returns
    -------
    dict of str → RuleData
        Mapping from rule name to its data.
    """
    rule_set = {}

    if not os.path.isdir(events_dir):
        raise FileNotFoundError(f"Events directory not found: {events_dir}")

    for rule_dir_name in sorted(os.listdir(events_dir)):
        rule_events_path = os.path.join(events_dir, rule_dir_name)
        if not os.path.isdir(rule_events_path):
            continue

        rule_yaml_path = os.path.join(rules_dir, f"{rule_dir_name}.yml")
        try:
            rule_data = _load_single_rule(rule_dir_name, rule_events_path, rule_yaml_path)
            if rule_data is not None:
                rule_set[rule_data.name] = rule_data
        except Exception as e:
            logger.warning("Skipping rule %s: %s", rule_dir_name, e)

    logger.info(
        "Loaded %d rules from %s", len(rule_set), events_dir
    )
    return rule_set


def _load_single_rule(
    dir_name: str, events_path: str, rule_yaml_path: str
) -> Optional[RuleData]:
    """Load matches, evasions, and rule filter for a single rule."""
    rule_data = RuleData(name=dir_name)

    # Load matches and evasions from JSON files
    for fname in sorted(os.listdir(events_path)):
        if fname == "properties.yml":
            continue
        fpath = os.path.join(events_path, fname)
        if not fname.endswith(".json"):
            continue

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                event = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.debug("Skipping %s: %s", fpath, e)
            continue

        if MATCH_REGEX.match(fname):
            if isinstance(event, dict):
                rule_data.matches.append(event)
        elif EVASION_REGEX.match(fname):
            if isinstance(event, dict):
                rule_data.evasions.append(event)

    # Load rule filter from YAML
    if os.path.isfile(rule_yaml_path):
        try:
            with open(rule_yaml_path, "r", encoding="utf-8") as f:
                rules_yaml = list(yaml.safe_load_all(f))
            # Flatten if nested list
            rules_list = []
            for item in rules_yaml:
                if isinstance(item, list):
                    rules_list.extend(item)
                elif isinstance(item, dict):
                    rules_list.append(item)

            for rule in rules_list:
                if isinstance(rule, dict):
                    if "filter" in rule:
                        rule_data.filters.append(rule["filter"])
                    if "pre_detector" in rule:
                        title = rule["pre_detector"].get("title")
                        if title:
                            rule_data.name = title
        except Exception as e:
            logger.debug("Could not load rule YAML %s: %s", rule_yaml_path, e)

    return rule_data


# ---------------------------------------------------------------------------
# High-level data preparation helpers
# ---------------------------------------------------------------------------

def get_all_filter_values(
    rule_set: Dict[str, RuleData],
    search_fields: List[str],
) -> List[str]:
    """Extract all filter field values across the entire rule set.

    For each rule, parse its filter strings and extract values for the
    given search fields. Results are wrapped as single-field event dicts.
    """
    values = []
    for rule_data in rule_set.values():
        for filt in rule_data.filters:
            vals = extract_filter_values(filt, search_fields)
            values.extend(vals)
    logger.info("Extracted %d filter values for fields %s", len(values), search_fields)
    return values


def get_all_matches(rule_set: Dict[str, RuleData]) -> List[dict]:
    """Collect all match events across the entire rule set."""
    matches = []
    for rd in rule_set.values():
        matches.extend(rd.matches)
    return matches


def get_all_evasions(rule_set: Dict[str, RuleData]) -> List[dict]:
    """Collect all evasion events across the entire rule set."""
    evasions = []
    for rd in rule_set.values():
        evasions.extend(rd.evasions)
    return evasions


def create_labels(num_benign: int, num_malicious: int) -> np.ndarray:
    """Create a labels array: 0 for benign, 1 for malicious."""
    return np.array([0] * num_benign + [1] * num_malicious)
