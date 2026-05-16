#!/usr/bin/env python3
"""Convert local Sigma rules into Elastic Security detection rules.

This is a small wrapper around sigma-cli/pySigma. It defaults to the local
Windows Sigma rule tree used by this project and emits Elastic Security
Detection Engine NDJSON that can be imported in Kibana Security -> Rules.

Examples:
  python3 scripts/convert_sigma_to_elastic.py

  python3 scripts/convert_sigma_to_elastic.py \
    --index-pattern logs-winlog.* --index-pattern winlogbeat-*

  python3 scripts/convert_sigma_to_elastic.py \
    --import-to-kibana \
    --kibana-url http://10.10.20.100:5601 \
    --kibana-user elastic \
    --kibana-password "$KIBANA_PASSWORD"
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional

import requests

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience
    load_dotenv = None


LOGGER = logging.getLogger("convert_sigma_to_elastic")

DEFAULT_RULES_ROOT = "~/data/sigma/rules/windows"
DEFAULT_OUT = "~/data/sigma/elastic_rules/windows_sigma_elastic.ndjson"
EVENT_TYPES = ("process_creation", "powershell", "registry")
ELASTIC_SEVERITIES = {"low", "medium", "high", "critical"}
SEVERITY_FALLBACKS = {
    "informational": "low",
    "info": "low",
}
FIELD_PROFILES = {
    "winlog-raw": {
        "process.parent.command_line": "winlog.event_data.ParentCommandLine",
        "process.parent.executable": "winlog.event_data.ParentImage",
        "process.command_line": "winlog.event_data.CommandLine",
        "process.executable": "winlog.event_data.Image",
        "process.pe.original_file_name": "winlog.event_data.OriginalFileName",
        "process.pe.description": "winlog.event_data.Description",
        "process.pe.product": "winlog.event_data.Product",
        "process.pe.company": "winlog.event_data.Company",
        "process.pe.file_version": "winlog.event_data.FileVersion",
        "process.working_directory": "winlog.event_data.CurrentDirectory",
        "process.pid": "winlog.event_data.ProcessId",
        "process.parent.pid": "winlog.event_data.ParentProcessId",
        "user.name": "winlog.event_data.User",
    },
}


def expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


def find_sigma_bin(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit

    for candidate in (
        Path(sys.executable).parent / "sigma",
        Path(sys.prefix) / "bin" / "sigma",
    ):
        if candidate.exists():
            return str(candidate)

    sigma = shutil.which("sigma")
    if sigma:
        return sigma

    raise SystemExit(
        "sigma CLI not found. Install it first: "
        "pip install sigma-cli pySigma-backend-elasticsearch"
    )


def default_rule_paths(rules_root: Path, event_type: str) -> List[Path]:
    if event_type == "all":
        selected = EVENT_TYPES
    else:
        selected = (event_type,)
    return [rules_root / item for item in selected]


def validate_paths(paths: Iterable[Path]) -> None:
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SystemExit("Rule path not found:\n  " + "\n  ".join(missing))


def run_sigma_convert(args: argparse.Namespace, rule_paths: List[Path], sigma_bin: str) -> None:
    output = expand(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sigma_bin,
        "convert",
        "-t",
        args.target,
        "-p",
        args.pipeline,
        "-f",
        args.format,
        "-P",
        args.file_pattern,
    ]
    command.append("--fail-unsupported" if args.fail_unsupported else "--skip-unsupported")
    command += ["-o", str(output)]
    if args.verbose:
        command.append("--verbose")
    command += [str(path) for path in rule_paths]

    LOGGER.info("Converting Sigma rules:")
    for path in rule_paths:
        LOGGER.info("  - %s", path)
    LOGGER.info("Output: %s", output)
    LOGGER.info("Command: %s", " ".join(command))

    if args.dry_run:
        LOGGER.info("Dry-run only; not executing sigma convert.")
        return

    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.stdout.strip():
        LOGGER.info(result.stdout.strip())
    if result.stderr.strip():
        LOGGER.info(result.stderr.strip())
    if result.returncode != 0:
        raise SystemExit(f"sigma convert failed with exit code {result.returncode}")

    if not output.exists():
        raise SystemExit(f"sigma convert completed but output file was not created: {output}")

    if args.index_pattern:
        patch_rule_indices(output, args.index_pattern)
    if args.normalize_severity:
        normalize_rule_severity(output)
    if args.field_profile:
        patch_rule_fields(output, args.field_profile)

    count = count_ndjson_objects(output)
    LOGGER.info("Done. Converted %d Elastic rule object(s).", count)


def count_ndjson_objects(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid NDJSON at {path}:{line_no}: {exc}") from exc
            count += 1
    return count


def patch_rule_indices(path: Path, index_patterns: List[str]) -> None:
    """Replace the imported rule index patterns in siem_rule_ndjson output."""
    patched = 0
    objects = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj.get("index"), list):
                obj["index"] = index_patterns
                patched += 1
            objects.append(obj)

    with path.open("w", encoding="utf-8") as handle:
        for obj in objects:
            handle.write(json.dumps(obj, ensure_ascii=False) + "\n")

    LOGGER.info("Patched index patterns on %d rule(s): %s", patched, ", ".join(index_patterns))


def normalize_rule_severity(path: Path) -> None:
    """Normalize Sigma severities to Elastic Detection Engine enum values."""
    patched = 0
    objects = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            severity = str(obj.get("severity", "")).lower()
            if severity and severity not in ELASTIC_SEVERITIES:
                obj["severity"] = SEVERITY_FALLBACKS.get(severity, "low")
                patched += 1
            objects.append(obj)

    if patched:
        with path.open("w", encoding="utf-8") as handle:
            for obj in objects:
                handle.write(json.dumps(obj, ensure_ascii=False) + "\n")
        LOGGER.info("Normalized unsupported severities on %d rule(s)", patched)


def patch_rule_fields(path: Path, profile: str) -> None:
    """Rewrite converted ECS query fields for the lab's raw Winlog/Sysmon schema."""
    field_map = FIELD_PROFILES[profile]
    replacements = {key: 0 for key in field_map}
    patched_rules = 0
    objects = []

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            changed = False

            query = obj.get("query")
            if isinstance(query, str):
                new_query = query
                for source, target in field_map.items():
                    count = new_query.count(source)
                    if count:
                        replacements[source] += count
                        new_query = new_query.replace(source, target)
                if new_query != query:
                    obj["query"] = new_query
                    changed = True

            required_fields = obj.get("required_fields")
            if isinstance(required_fields, list):
                for item in required_fields:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    if name in field_map:
                        item["name"] = field_map[name]
                        changed = True

            if changed:
                patched_rules += 1
            objects.append(obj)

    with path.open("w", encoding="utf-8") as handle:
        for obj in objects:
            handle.write(json.dumps(obj, ensure_ascii=False) + "\n")

    LOGGER.info("Patched query fields using profile '%s' on %d rule(s)", profile, patched_rules)
    for source, count in replacements.items():
        if count:
            LOGGER.info("  %s -> %s (%d replacement(s))", source, field_map[source], count)


def import_to_kibana(args: argparse.Namespace) -> None:
    ndjson_path = expand(args.out)
    if not ndjson_path.exists():
        raise SystemExit(f"NDJSON file not found: {ndjson_path}")

    password = args.kibana_password or os.getenv("KIBANA_PASSWORD") or os.getenv("ES_PASSWORD")
    user = args.kibana_user or os.getenv("KIBANA_USER") or os.getenv("ES_USER")
    if not user or not password:
        raise SystemExit(
            "Missing Kibana credentials. Use --kibana-user/--kibana-password "
            "or set KIBANA_USER/KIBANA_PASSWORD in the environment."
        )

    kibana_url = (args.kibana_url or os.getenv("KIBANA_URL") or "http://10.10.20.100:5601").rstrip("/")
    overwrite = "true" if args.overwrite else "false"
    url = f"{kibana_url}/api/detection_engine/rules/_import?overwrite={overwrite}"

    LOGGER.info("Importing rules into Kibana: %s", kibana_url)
    if args.import_chunk_size and args.import_chunk_size > 0:
        import_ndjson_in_chunks(ndjson_path, url, user, password, args)
    else:
        payload = post_import_file(ndjson_path, url, user, password, args.import_timeout)
        log_import_payload(payload)


def post_import_file(path: Path, url: str, user: str, password: str, timeout: int) -> dict:
    with path.open("rb") as handle:
        files = {
            "file": (path.name, handle, "application/ndjson"),
        }
        response = requests.post(
            url,
            headers={"kbn-xsrf": "true"},
            files=files,
            auth=(user, password),
            timeout=timeout,
        )

    if response.status_code >= 400:
        raise SystemExit(
            f"Kibana import failed: HTTP {response.status_code}\n{response.text}"
        )

    try:
        return response.json()
    except ValueError:
        LOGGER.info("Import response: %s", response.text)
        return {}


def import_ndjson_in_chunks(
    ndjson_path: Path,
    url: str,
    user: str,
    password: str,
    args: argparse.Namespace,
) -> None:
    lines = [line for line in ndjson_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    total_chunks = (len(lines) + args.import_chunk_size - 1) // args.import_chunk_size
    totals = {"rules": 0, "success": 0, "errors": 0}

    with tempfile.TemporaryDirectory(prefix="sigma_elastic_import_") as tmpdir:
        tmpdir_path = Path(tmpdir)
        for chunk_idx, start in enumerate(range(0, len(lines), args.import_chunk_size), start=1):
            chunk_lines = lines[start:start + args.import_chunk_size]
            chunk_path = tmpdir_path / f"{ndjson_path.stem}.part{chunk_idx:04d}.ndjson"
            chunk_path.write_text("\n".join(chunk_lines) + "\n", encoding="utf-8")

            LOGGER.info(
                "Importing chunk %d/%d (%d rules)...",
                chunk_idx,
                total_chunks,
                len(chunk_lines),
            )
            payload = post_import_file(chunk_path, url, user, password, args.import_timeout)
            log_import_payload(payload)
            totals["rules"] += payload.get("rules_count") or len(chunk_lines)
            totals["success"] += payload.get("success_count") or 0
            totals["errors"] += len(payload.get("errors", []) or [])

    LOGGER.info(
        "Chunked import summary: chunks=%d rules=%d success_count=%d errors=%d",
        total_chunks,
        totals["rules"],
        totals["success"],
        totals["errors"],
    )


def log_import_payload(payload: dict) -> None:
    LOGGER.info(
        "Import result: success=%s rules=%s success_count=%s errors=%s",
        payload.get("success"),
        payload.get("rules_count"),
        payload.get("success_count"),
        len(payload.get("errors", []) or []),
    )
    errors = payload.get("errors") or []
    for err in errors[:10]:
        LOGGER.warning("Import error: %s", err)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to Elastic Security Detection Rule NDJSON"
    )
    parser.add_argument("--rules-root", default=DEFAULT_RULES_ROOT,
                        help="Root of Windows Sigma rules")
    parser.add_argument("--event-type", choices=("all",) + EVENT_TYPES, default="all",
                        help="Event type directory to convert")
    parser.add_argument("--rules-path", action="append", default=None,
                        help="Explicit rule file/dir. Can be repeated; overrides --rules-root.")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Output Elastic Detection Rule NDJSON path")

    parser.add_argument("--target", choices=("lucene", "eql", "esql"), default="lucene",
                        help="pySigma target. lucene creates Elastic Custom Query rules.")
    parser.add_argument("--pipeline", default="ecs_windows",
                        help="pySigma processing pipeline")
    parser.add_argument("--format", default="siem_rule_ndjson",
                        help="pySigma output format for Detection Engine import")
    parser.add_argument("--file-pattern", default="*.yml",
                        help="Rule filename pattern for recursive conversion")
    parser.add_argument("--fail-unsupported", action="store_true",
                        help="Fail instead of skipping unsupported Sigma rules")
    parser.add_argument("--sigma-bin", default=None,
                        help="Path to sigma CLI binary")
    parser.add_argument("--index-pattern", action="append", default=None,
                        help="Override Elastic rule index patterns. Can be repeated.")
    parser.add_argument("--normalize-severity", action=argparse.BooleanOptionalAction, default=True,
                        help="Map unsupported Elastic severities such as informational -> low")
    parser.add_argument("--field-profile", choices=tuple(FIELD_PROFILES), default=None,
                        help="Rewrite converted ECS fields for a local log schema, e.g. winlog-raw")

    parser.add_argument("--import-to-kibana", action="store_true",
                        help="Import generated NDJSON into Kibana Detection Engine")
    parser.add_argument("--kibana-url", default=None,
                        help="Kibana URL, e.g. http://10.10.20.100:5601")
    parser.add_argument("--kibana-user", default=None,
                        help="Kibana username")
    parser.add_argument("--kibana-password", default=None,
                        help="Kibana password")
    parser.add_argument("--overwrite", action=argparse.BooleanOptionalAction, default=True,
                        help="Overwrite existing rules on import")
    parser.add_argument("--import-timeout", type=int, default=300,
                        help="HTTP read timeout in seconds for each Kibana import request")
    parser.add_argument("--import-chunk-size", type=int, default=0,
                        help="Import NDJSON in chunks of N rules (recommended: 100-300)")

    parser.add_argument("--dry-run", action="store_true",
                        help="Print conversion command but do not run it")
    parser.add_argument("--skip-convert", action="store_true",
                        help="Skip sigma convert and import/validate the existing --out file")
    parser.add_argument("--verbose", action="store_true",
                        help="Pass --verbose to sigma convert")
    return parser.parse_args()


def main() -> None:
    if load_dotenv:
        load_dotenv()

    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.skip_convert:
        out_path = expand(args.out)
        if not out_path.exists():
            raise SystemExit(f"Cannot --skip-convert; output file not found: {out_path}")
        if args.normalize_severity:
            normalize_rule_severity(out_path)
        if args.field_profile:
            patch_rule_fields(out_path, args.field_profile)
        LOGGER.info("Using existing NDJSON: %s (%d rule object(s))", out_path, count_ndjson_objects(out_path))
    else:
        if args.rules_path:
            rule_paths = [expand(path) for path in args.rules_path]
        else:
            rule_paths = default_rule_paths(expand(args.rules_root), args.event_type)

        validate_paths(rule_paths)
        sigma_bin = find_sigma_bin(args.sigma_bin)
        run_sigma_convert(args, rule_paths, sigma_bin)

    if args.import_to_kibana and not args.dry_run:
        import_to_kibana(args)


if __name__ == "__main__":
    main()
