#!/usr/bin/env python3
"""Run and verify demo/apt_demo_v2.ps1 against the lab Elastic/Kibana stack."""

from __future__ import annotations

import argparse
import codecs
import io
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience
    load_dotenv = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = ROOT / "demo" / "apt_demo_v2.ps1"
DEFAULT_ECS_NDJSON = ROOT / "data" / "sigma" / "elastic_rules" / "windows_sigma_elastic_ecs.ndjson"
DEFAULT_WINLOG_RAW_NDJSON = ROOT / "data" / "sigma" / "elastic_rules" / "windows_sigma_elastic_winlog_raw.ndjson"
DEFAULT_NDJSON = DEFAULT_ECS_NDJSON if DEFAULT_ECS_NDJSON.exists() else DEFAULT_WINLOG_RAW_NDJSON

TARGET_RULES = [
    {
        "phase": 1,
        "event": "powershell 4104",
        "rule_id": "189e3b02-82b2-4b90-9662-411eb64486d4",
        "title": "Potential Invoke-Mimikatz PowerShell Script",
    },
    {
        "phase": 2,
        "event": "process EID 1",
        "rule_id": "cc36992a-4671-4f21-a91d-6c2b72a2edf5",
        "title": "Suspicious Eventlog Clearing or Configuration Change Activity",
    },
    {
        "phase": 3,
        "event": "process EID 1",
        "rule_id": "85b0b087-eddf-4a2b-b033-d771fa2b9775",
        "title": "PowerShell Download and Execution Cradles",
    },
    {
        "phase": 4,
        "event": "process EID 1",
        "rule_id": "b98d0db6-511d-45de-ad02-e82a98729620",
        "title": "Remotely Hosted HTA File Executed Via Mshta.EXE",
    },
    {
        "phase": 5,
        "event": "process EID 1",
        "rule_id": "24357373-078f-44ed-9ac4-6d334a668a11",
        "title": "Direct Autorun Keys Modification",
    },
    {
        "phase": 6,
        "event": "process EID 1",
        "rule_id": "e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a",
        "title": "File Encoded To Base64 Via Certutil.EXE",
    },
]


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def load_environment() -> None:
    if load_dotenv:
        load_dotenv(ROOT / ".env", override=True)


def short_rule_id(rule_id: str) -> str:
    return rule_id.split("-", 1)[0]


def maybe_http_fallback(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    return urlunparse(parsed._replace(scheme="http"))


def request_json(
    method: str,
    url: str,
    *,
    auth: tuple[str, str] | None,
    verify: bool,
    fallback_http: bool = False,
    **kwargs: Any,
) -> tuple[dict[str, Any], str]:
    urls = [url]
    fallback = maybe_http_fallback(url) if fallback_http else None
    if fallback:
        urls.append(fallback)

    last_error: Exception | None = None
    timeout = kwargs.pop("timeout", 30)
    for candidate in urls:
        try:
            response = requests.request(
                method,
                candidate,
                auth=auth,
                verify=verify,
                timeout=timeout,
                **kwargs,
            )
            if response.status_code >= 400:
                raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")
            if not response.text.strip():
                return {}, candidate
            return response.json(), candidate
        except Exception as exc:  # noqa: BLE001 - keep diagnostics compact for lab script
            last_error = exc

    raise RuntimeError(str(last_error) if last_error else f"request failed: {url}")


def load_target_queries(path: Path) -> dict[str, dict[str, Any]]:
    queries: dict[str, dict[str, Any]] = {}
    target_ids = {rule["rule_id"] for rule in TARGET_RULES}
    if not path.exists():
        raise FileNotFoundError(f"NDJSON not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid NDJSON at {path}:{line_no}: {exc}") from exc
            rule_id = obj.get("rule_id") or obj.get("id")
            if rule_id in target_ids and rule_id not in queries:
                queries[rule_id] = obj
    return queries


def kibana_rule_check(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    print("\n[Kibana target rules]")
    status: dict[str, dict[str, Any]] = {}
    if not args.kibana_url or not args.kibana_user or not args.kibana_password:
        print("SKIP: missing Kibana URL/user/password")
        return status

    auth = (args.kibana_user, args.kibana_password)
    headers = {"kbn-xsrf": "true"}
    for target in TARGET_RULES:
        rule_id = target["rule_id"]
        url = f"{args.kibana_url.rstrip('/')}/api/detection_engine/rules"
        try:
            payload, used_url = request_json(
                "GET",
                url,
                params={"rule_id": rule_id},
                headers=headers,
                auth=auth,
                verify=args.verify_ssl,
                fallback_http=args.kibana_http_fallback,
                timeout=args.http_timeout,
            )
            enabled = payload.get("enabled")
            indices = ",".join(payload.get("index") or [])
            language = payload.get("language")
            query = payload.get("query") or ""
            if "winlog.event_data" in query:
                field_profile = "winlog-raw"
            elif any(prefix in query for prefix in ("process.", "powershell.", "registry.")):
                field_profile = "ecs"
            else:
                field_profile = "other"
            state = "OK" if enabled else "DISABLED"
            print(
                f"{state:8} phase={target['phase']} rule={short_rule_id(rule_id)} "
                f"lang={language} fields={field_profile} index=[{indices}] via={urlparse(used_url).scheme}"
            )
            status[rule_id] = payload
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            label = "ERROR" if "Connection" in message or "Operation not permitted" in message else "MISSING"
            print(f"{label:8} phase={target['phase']} rule={short_rule_id(rule_id)} error={message}")
    return status


def effective_target_queries(
    local_queries: dict[str, dict[str, Any]],
    kibana_rules: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Prefer live Kibana Lucene queries over the local NDJSON copy."""
    queries = dict(local_queries)
    live_count = 0
    for rule_id, rule in kibana_rules.items():
        query = rule.get("query")
        language = (rule.get("language") or "lucene").lower()
        if query and language == "lucene":
            enriched = dict(rule)
            enriched["_query_source"] = "kibana"
            queries[rule_id] = enriched
            live_count += 1

    if live_count:
        print(f"\n[Raw Sigma query source]\nusing live Kibana queries for {live_count}/6 target rules")
    else:
        print("\n[Raw Sigma query source]\nusing local NDJSON queries")
    return queries


def ensure_paramiko() -> Any:
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - depends on caller env
        raise SystemExit("paramiko is required for --run-endpoint. Install with: pip install paramiko") from exc
    return paramiko


def quote_windows(value: str) -> str:
    escaped = value.replace('"', '`"')
    return f'"{escaped}"'


def run_endpoint(args: argparse.Namespace, run_id: str) -> None:
    paramiko = ensure_paramiko()
    script_path = Path(args.script)
    if not script_path.exists():
        raise FileNotFoundError(f"PowerShell demo script not found: {script_path}")

    print("\n[Endpoint run]")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        args.endpoint_host,
        username=args.endpoint_user,
        password=args.endpoint_password,
        timeout=args.ssh_timeout,
        banner_timeout=args.ssh_timeout,
        auth_timeout=args.ssh_timeout,
    )
    try:
        if args.copy_script:
            data = script_path.read_bytes()
            if not data.startswith(codecs.BOM_UTF8):
                data = codecs.BOM_UTF8 + data
            with client.open_sftp() as sftp:
                sftp.putfo(io.BytesIO(data), args.remote_path)
            print(f"copied {script_path} -> {args.endpoint_host}:{args.remote_path}")

        keep = " -KeepArtifacts" if args.keep_artifacts else ""
        phase = f" -Phase {args.phase}" if args.phase else ""
        command = (
            f"powershell -ExecutionPolicy Bypass -File {quote_windows(args.remote_path)} "
            f"-Mode {args.mode} -RunId {run_id}{phase} "
            f"-SleepSeconds {args.sleep_seconds} "
            f"-CleanupDelaySeconds {args.cleanup_delay_seconds}{keep}"
        )
        print(f"running mode={args.mode} run_id={run_id}")
        stdin, stdout, stderr = client.exec_command(command, timeout=args.command_timeout)
        del stdin
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        if out:
            print(out)
        if err:
            print(err, file=sys.stderr)
        if exit_code != 0:
            raise RuntimeError(f"endpoint command failed with exit code {exit_code}")
    finally:
        client.close()


def es_search(args: argparse.Namespace, index: str, body: dict[str, Any]) -> dict[str, Any]:
    if not args.es_host or not args.es_user or not args.es_password:
        raise RuntimeError("missing Elasticsearch host/user/password")
    url = f"{args.es_host.rstrip('/')}/{index}/_search"
    payload, _ = request_json(
        "POST",
        url,
        params={"ignore_unavailable": "true", "expand_wildcards": "open,hidden"},
        json=body,
        headers={"Content-Type": "application/json"},
        auth=(args.es_user, args.es_password),
        verify=args.verify_ssl,
        timeout=args.http_timeout,
    )
    return payload


def total_hits(payload: dict[str, Any]) -> int:
    total = payload.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total or 0)


def run_id_query(run_id: str) -> dict[str, Any]:
    return {
        "query_string": {
            "query": f"*{run_id}*",
            "analyze_wildcard": True,
            "lenient": True,
        }
    }


def range_filter(lookback: str) -> dict[str, Any]:
    return {"range": {"@timestamp": {"gte": f"now-{lookback}"}}}


def count_run_events(args: argparse.Namespace, run_id: str) -> int:
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [range_filter(args.raw_lookback)],
                "must": [run_id_query(run_id)],
            }
        },
    }
    return total_hits(es_search(args, args.raw_index, body))


def raw_rule_counts(
    args: argparse.Namespace,
    run_id: str,
    target_queries: dict[str, dict[str, Any]],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for target in TARGET_RULES:
        rule_id = target["rule_id"]
        rule = target_queries.get(rule_id)
        if not rule or not rule.get("query"):
            counts[rule_id] = -1
            continue
        body = {
            "size": args.sample_size,
            "track_total_hits": True,
            "_source": [
                "@timestamp",
                "host.name",
                "winlog.computer_name",
                "event.code",
                "process.executable",
                "process.command_line",
                "powershell.file.script_block_text",
                "winlog.event_data.Image",
                "winlog.event_data.CommandLine",
                "winlog.event_data.ScriptBlockText",
                "message",
            ],
            "query": {
                "bool": {
                    "filter": [range_filter(args.raw_lookback)],
                    "must": [
                        run_id_query(run_id),
                        {
                            "query_string": {
                                "query": rule["query"],
                                "analyze_wildcard": True,
                                "lenient": True,
                            }
                        },
                    ],
                }
            },
        }
        counts[rule_id] = total_hits(es_search(args, args.raw_index, body))
    return counts


def alert_rule_counts(args: argparse.Namespace, run_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for target in TARGET_RULES:
        rule_id = target["rule_id"]
        body = {
            "size": args.sample_size,
            "track_total_hits": True,
            "_source": [
                "@timestamp",
                "kibana.alert.rule.name",
                "kibana.alert.rule.rule_id",
                "signal.rule.name",
                "signal.rule.rule_id",
                "process.command_line",
                "winlog.event_data.CommandLine",
                "winlog.event_data.ScriptBlockText",
            ],
            "query": {
                "bool": {
                    "filter": [range_filter(args.alert_lookback)],
                    "must": [run_id_query(run_id)],
                    "should": [
                        {"term": {"kibana.alert.rule.rule_id": rule_id}},
                        {"term": {"signal.rule.rule_id": rule_id}},
                        {"term": {"rule.id": rule_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        counts[rule_id] = total_hits(es_search(args, args.alert_index, body))
    return counts


def print_counts(label: str, counts: dict[str, int]) -> None:
    print(f"\n[{label}]")
    for target in TARGET_RULES:
        rule_id = target["rule_id"]
        count = counts.get(rule_id, 0)
        count_text = "NO_LOCAL_QUERY" if count == -1 else str(count)
        print(
            f"phase={target['phase']} rule={short_rule_id(rule_id)} "
            f"count={count_text} title={target['title']}"
        )


def all_present(counts: dict[str, int]) -> bool:
    return all(counts.get(rule["rule_id"], 0) > 0 for rule in TARGET_RULES)


def all_absent(counts: dict[str, int]) -> bool:
    return all(counts.get(rule["rule_id"], 0) == 0 for rule in TARGET_RULES)


def poll_until(
    label: str,
    args: argparse.Namespace,
    fetch_counts: Any,
    expected_present: bool,
    timeout_seconds: int,
) -> dict[str, int]:
    deadline = time.time() + max(0, timeout_seconds)
    counts: dict[str, int] = {}
    while True:
        counts = fetch_counts()
        print_counts(label, counts)
        if expected_present and all_present(counts):
            return counts
        if not expected_present and time.time() >= deadline:
            return counts
        if expected_present and time.time() >= deadline:
            return counts
        time.sleep(args.poll_interval)


def wait_for_ingest(args: argparse.Namespace, run_id: str) -> int:
    print("\n[Raw ingest marker]")
    deadline = time.time() + max(0, args.wait_raw_seconds)
    count = 0
    while True:
        count = count_run_events(args, run_id)
        print(f"run_id={run_id} raw_events={count}")
        if count > 0 or time.time() >= deadline:
            return count
        time.sleep(args.poll_interval)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run and verify demo/apt_demo_v2.ps1 benign/baseline/evasion against Elastic/Kibana"
    )
    parser.add_argument("--mode", choices=("benign", "baseline", "evasion"), default="baseline")
    parser.add_argument("--run-id", default=None, help="Existing/custom 8-char RunId. Generated if omitted.")
    parser.add_argument("--phase", type=int, default=0, choices=range(0, 7), help="PowerShell phase, 0 = all")

    parser.add_argument("--check-only", action="store_true", help="Only check Kibana rules and local NDJSON")
    parser.add_argument("--run-endpoint", action="store_true", help="Copy and run the PowerShell demo on endpoint")
    parser.add_argument("--copy-script", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--skip-rule-check", action="store_true")
    parser.add_argument("--skip-raw", action="store_true")
    parser.add_argument("--skip-alerts", action="store_true")

    parser.add_argument("--script", default=str(DEFAULT_SCRIPT))
    parser.add_argument("--rules-ndjson", default=str(DEFAULT_NDJSON))

    parser.add_argument("--endpoint-host", default=os.getenv("DEMO_ENDPOINT_HOST", "192.168.10.103"))
    parser.add_argument("--endpoint-user", default=os.getenv("DEMO_ENDPOINT_USER", "endpoint"))
    parser.add_argument("--endpoint-password", default=os.getenv("DEMO_ENDPOINT_PASSWORD", "123"))
    parser.add_argument("--remote-path", default="C:/Users/endpoint/apt_demo_v2.ps1")
    parser.add_argument("--sleep-seconds", type=int, default=1)
    parser.add_argument("--cleanup-delay-seconds", type=int, default=60)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--ssh-timeout", type=int, default=15)
    parser.add_argument("--command-timeout", type=int, default=240)

    parser.add_argument("--es-host", default=os.getenv("ES_HOST", "https://192.168.10.10:9200"))
    parser.add_argument("--es-user", default=os.getenv("ES_USER", "elastic"))
    parser.add_argument("--es-password", default=os.getenv("ES_PASSWORD") or os.getenv("ES_PASS"))
    parser.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", "http://192.168.10.10:5601"))
    parser.add_argument("--kibana-user", default=os.getenv("KIBANA_USER", os.getenv("ES_USER", "elastic")))
    parser.add_argument("--kibana-password", default=os.getenv("KIBANA_PASSWORD") or os.getenv("ES_PASSWORD") or os.getenv("ES_PASS"))
    parser.add_argument("--kibana-http-fallback", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction, default=env_bool("ES_VERIFY_SSL", False))
    parser.add_argument("--http-timeout", type=int, default=30)

    parser.add_argument("--raw-index", default="logs-windows.*")
    parser.add_argument("--alert-index", default=".alerts-security.alerts-*,.siem-signals-*")
    parser.add_argument("--raw-lookback", default="45m")
    parser.add_argument("--alert-lookback", default="90m")
    parser.add_argument("--wait-raw-seconds", type=int, default=180)
    parser.add_argument("--wait-alert-seconds", type=int, default=420)
    parser.add_argument("--poll-interval", type=int, default=15)
    parser.add_argument("--sample-size", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    load_environment()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    args = parse_args()

    target_queries = load_target_queries(Path(args.rules_ndjson))
    missing_local = [rule for rule in TARGET_RULES if rule["rule_id"] not in target_queries]
    print("[Local NDJSON target queries]")
    print(f"path={args.rules_ndjson}")
    if missing_local:
        for rule in missing_local:
            print(f"MISSING phase={rule['phase']} rule={short_rule_id(rule['rule_id'])}")
    else:
        print("OK: 6/6 target rule queries found")

    kibana_rules: dict[str, dict[str, Any]] = {}
    if not args.skip_rule_check:
        kibana_rules = kibana_rule_check(args)
    target_queries = effective_target_queries(target_queries, kibana_rules)

    if args.check_only:
        return 0

    run_id = args.run_id or uuid.uuid4().hex[:8]
    print(f"\n[Run]")
    print(f"mode={args.mode} run_id={run_id}")

    if args.run_endpoint:
        run_endpoint(args, run_id)
    elif not args.run_id:
        raise SystemExit("Use --run-endpoint or provide --run-id for an existing manual run.")

    expected_present = args.mode == "baseline"

    raw_counts: dict[str, int] = {}
    if not args.skip_raw:
        marker_count = wait_for_ingest(args, run_id)
        if marker_count == 0:
            print("FAIL: no raw event containing RunId reached logs-windows.* within timeout")
        raw_counts = poll_until(
            "Raw Sigma query counts",
            args,
            lambda: raw_rule_counts(args, run_id, target_queries),
            expected_present=expected_present,
            timeout_seconds=0 if marker_count else args.wait_raw_seconds,
        )

    alert_counts: dict[str, int] = {}
    if not args.skip_alerts:
        alert_counts = poll_until(
            "Kibana Security alert counts",
            args,
            lambda: alert_rule_counts(args, run_id),
            expected_present=expected_present,
            timeout_seconds=args.wait_alert_seconds,
        )

    print("\n[Result]")
    ok = True
    if raw_counts:
        raw_ok = all_present(raw_counts) if expected_present else all_absent(raw_counts)
        print(f"raw_sigma={'PASS' if raw_ok else 'FAIL'}")
        ok = ok and raw_ok
    if alert_counts:
        alert_ok = all_present(alert_counts) if expected_present else all_absent(alert_counts)
        print(f"security_alerts={'PASS' if alert_ok else 'FAIL'}")
        ok = ok and alert_ok
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
