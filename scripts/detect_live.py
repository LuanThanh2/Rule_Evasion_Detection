#!/usr/bin/env python3
"""Live evasion detection daemon — polls Elasticsearch for new events,
runs Stage 1 + Stage 2, and indexes alerts back to Elasticsearch.

Usage:
  python scripts/detect_live.py \\
    --config config/process_creation.yaml \\
    --es-host http://elk-server:9200 \\
    --es-index "winlogbeat-*" \\
    --out-index red-alerts \\
    --threshold 0.0 \\
    --method hybrid \\
    --interval 60

State file: .detect_live_state.json (stores last-seen timestamp to avoid duplicates)

Requires: pip install requests
"""

import os
import sys
import json
import time
import argparse
import logging
import datetime
from urllib.parse import urlsplit, urlunsplit
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.normalize import Normalizer
from red.persist import load_result
from red.data import resolve_event_paths
from red.attribution import reciprocal_rank_fusion

logger = logging.getLogger("detect_live")

STATE_FILE = ".detect_live_state.json"


def mask_url_password(url: str) -> str:
    parts = urlsplit(url)
    if not parts.password:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    userinfo = parts.username or ""
    if userinfo:
        host = f"{userinfo}:****@{host}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


# ---------------------------------------------------------------------------
# Elasticsearch helpers (uses plain requests — no elasticsearch-py needed)
# ---------------------------------------------------------------------------

def es_search(es_host: str, index: str, query: dict) -> list:
    import requests
    url = f"{es_host.rstrip('/')}/{index}/_search"
    resp = requests.get(url, json=query, timeout=30)
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


def es_index(es_host: str, index: str, doc: dict) -> None:
    import requests
    url = f"{es_host.rstrip('/')}/{index}/_doc"
    resp = requests.post(url, json=doc, timeout=10)
    resp.raise_for_status()


def get_dotted(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def poll_new_events(es_host: str, index: str, event_id: int,
                    since_ts: str, size: int = 500,
                    timestamp_field: str = "@timestamp",
                    until_ts: str | None = None,
                    query_string: str | None = None) -> tuple[list, str]:
    time_range = {"gt": since_ts}
    if until_ts:
        time_range["lte"] = until_ts
    filters = [
        {"term": {"winlog.event_id": event_id}},
        {"range": {timestamp_field: time_range}},
    ]
    must = []
    if query_string:
        must.append({"query_string": {"query": query_string}})
    query = {
        "query": {
            "bool": {
                "filter": filters,
                "must": must,
            }
        },
        "sort": [{timestamp_field: "asc"}],
        "size": size,
    }
    hits = es_search(es_host, index, query)
    events = [h["_source"] for h in hits]
    last_ts = get_dotted(hits[-1]["_source"], timestamp_field) if hits else since_ts
    if not last_ts:
        last_ts = since_ts
    return events, last_ts


# ---------------------------------------------------------------------------
# Model helpers
# ---------------------------------------------------------------------------

def extract_field(event: dict, paths: list) -> str:
    for path in paths:
        obj = event
        for key in path.split("."):
            obj = obj.get(key) if isinstance(obj, dict) else None
        if obj and isinstance(obj, str):
            return obj
    return ""


def score_stage1(normalized: str, estimator, vectorizer, scaler, shift: float) -> float:
    X = vectorizer.transform([normalized])
    raw = float(estimator.decision_function(X)[0])
    if scaler is not None:
        shifted = np.array([[raw - shift]])
        return float(np.clip(scaler.transform(shifted).flatten()[0], 0.0, 1.0))
    return raw


def attribute_stage2(normalized: str, rule_models: dict, cosine_attributor,
                     method: str, top_k: int, rrf_k: int = 60) -> list:
    if method == "cosine" and cosine_attributor is not None:
        return cosine_attributor.score_samples([normalized])[0][:top_k]

    svm_scores = {}
    for rule_name, model in rule_models.items():
        try:
            X = model["vectorizer"].transform([normalized])
            svm_scores[rule_name] = float(model["estimator"].decision_function(X)[0])
        except Exception:
            pass
    svm_ranking = sorted(svm_scores.items(), key=lambda x: x[1], reverse=True)

    if method == "svm" or cosine_attributor is None:
        return svm_ranking[:top_k]

    cosine_ranking = cosine_attributor.score_samples([normalized])[0]

    return reciprocal_rank_fusion([svm_ranking, cosine_ranking], k=rrf_k)[:top_k]


# ---------------------------------------------------------------------------
# State persistence (last-seen timestamp)
# ---------------------------------------------------------------------------

def load_state(path: str, default_ts: str) -> str:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f).get("last_ts", default_ts)
    return default_ts


def save_state(path: str, last_ts: str) -> None:
    with open(path, "w") as f:
        json.dump({"last_ts": last_ts}, f)


def parse_time_arg(value: str | None) -> str | None:
    """Parse ISO timestamp or relative lookback (15m, 2h, 7d) into UTC ISO."""
    if not value:
        return None
    value = value.strip()
    if value == "now":
        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    unit_sec = {"m": 60, "h": 3600, "d": 86400}
    if len(value) >= 2 and value[-1] in unit_sec:
        seconds = unit_sec[value[-1]] * int(value[:-1])
        return (
            datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if value.endswith("Z"):
        return value
    if "T" in value:
        return value + "Z"
    raise ValueError(f"Invalid time value '{value}'. Use 15m, 2h, now, or 2026-05-15T10:00:00Z")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Live evasion detection via Elasticsearch polling")
    parser.add_argument("--config", type=str, required=True, help="YAML config file")
    parser.add_argument("--es-host", type=str, default="http://localhost:9200",
                        help="Elasticsearch base URL")
    parser.add_argument("--es-index", type=str, default="winlogbeat-*",
                        help="Source index pattern to poll")
    parser.add_argument("--out-index", type=str, default="red-alerts",
                        help="Destination index for alert documents")
    parser.add_argument("--event-id", type=int, default=1,
                        help="Windows Event ID to monitor (1=Sysmon process creation)")
    parser.add_argument("--threshold", type=float, default=0.0,
                        help="Stage 1 detection threshold. Raw DF score >= threshold → suspicious.")
    parser.add_argument("--method", type=str, default="hybrid",
                        choices=["svm", "cosine", "hybrid"],
                        help="Rule attribution method")
    parser.add_argument("--top-k", type=int, default=5,
                        help="Number of top candidate rules to include in alert")
    parser.add_argument("--interval", type=int, default=60,
                        help="Poll interval in seconds")
    parser.add_argument("--lookback", type=str, default="1h",
                        help="Initial lookback if no state file exists (e.g. 1h, 24h)")
    parser.add_argument("--since", type=str, default=None,
                        help="Backfill start time. ISO UTC or relative, e.g. 2026-05-15T10:00:00Z, 30m")
    parser.add_argument("--until", type=str, default=None,
                        help="Backfill end time. ISO UTC, relative, or now")
    parser.add_argument("--timestamp-field", type=str, default="@timestamp",
                        help=("Timestamp field for polling. @timestamp is event time from the Windows log; "
                              "event.ingested is Elastic ingest time from the ELK/ingest node clock."))
    parser.add_argument("--query-string", type=str, default=None,
                        help="Optional Elasticsearch query_string filter, useful for demo-focused backfills")
    parser.add_argument("--state-file", type=str, default=STATE_FILE,
                        help="File to persist last-seen timestamp between runs")
    parser.add_argument("--reset-state", action="store_true",
                        help="Delete state file before starting")
    parser.add_argument("--no-state", action="store_true",
                        help="Do not load or save state; useful for bounded backfill windows")
    parser.add_argument("--max-iter", type=int, default=0,
                        help="Stop after N polling iterations (0 = run forever)")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Max events to fetch per poll")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logging.getLogger("sklearnex").setLevel(logging.WARNING)

    # Load config
    import yaml
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    data_cfg = cfg.get("data", {})
    out_cfg = cfg.get("output", {})

    search_fields = data_cfg.get("search_fields", ["CommandLine"])
    event_field_map = data_cfg.get("event_field_map", {})
    event_paths = resolve_event_paths(search_fields, event_field_map)
    logger.info("Monitoring field paths: %s", event_paths)

    # Load Stage 1 model
    s1_path = os.path.expanduser(out_cfg["train_result_path"])
    logger.info("Loading Stage 1 from %s ...", s1_path)
    r1 = load_result(s1_path)
    s1_estimator = r1["estimator"]
    s1_vectorizer = r1["vectorizer"]
    s1_scaler = r1.get("scaler")
    s1_shift = float(r1.get("shift", 0.0))
    logger.info("Stage 1 ready")

    # Load Stage 2 models
    out_dir = os.path.expanduser(out_cfg.get("dir", "models"))
    attr_name = out_cfg.get("attr_result_name", "attr_ensemble")
    s2_path = os.path.join(out_dir, f"train_rslt_{attr_name}.zip")
    logger.info("Loading Stage 2 from %s ...", s2_path)
    r2 = load_result(s2_path)
    rule_models = r2["rule_models"]
    cosine_attributor = r2.get("cosine_attributor")
    logger.info("Stage 2 ready — %d rule models, cosine=%s",
                len(rule_models), "yes" if cosine_attributor else "no")

    normalizer = Normalizer()

    if args.reset_state and os.path.exists(args.state_file):
        os.remove(args.state_file)
        logger.info("Removed state file: %s", args.state_file)

    # Initial timestamp
    unit_sec = {"m": 60, "h": 3600, "d": 86400}
    lookback_sec = unit_sec.get(args.lookback[-1], 3600) * int(args.lookback[:-1])
    default_ts = (
        datetime.datetime.utcnow() - datetime.timedelta(seconds=lookback_sec)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    explicit_since = parse_time_arg(args.since)
    until_ts = parse_time_arg(args.until)
    if explicit_since:
        since_ts = explicit_since
    elif args.no_state:
        since_ts = default_ts
    else:
        since_ts = load_state(args.state_file, default_ts)

    logger.info("Starting — polling %s every %ds (%s > %s%s)",
                args.es_index, args.interval, args.timestamp_field, since_ts,
                f", <= {until_ts}" if until_ts else "")
    logger.info("Alerts → %s/%s, threshold=%.2f, method=%s",
                mask_url_password(args.es_host), args.out_index,
                args.threshold, args.method)

    # Polling loop
    iter_count = 0
    while True:
        try:
            iter_count += 1
            events, last_ts = poll_new_events(
                args.es_host, args.es_index, args.event_id, since_ts, args.batch_size,
                timestamp_field=args.timestamp_field,
                until_ts=until_ts,
                query_string=args.query_string,
            )

            if events:
                logger.info("Fetched %d new events (up to %s)", len(events), last_ts)

                n_alerts = 0
                for event in events:
                    text = extract_field(event, event_paths)
                    if not text:
                        continue

                    normalized = normalizer.normalize(text)
                    if not normalized:
                        continue

                    # Stage 1 — misuse detection
                    score = score_stage1(normalized, s1_estimator, s1_vectorizer,
                                        s1_scaler, s1_shift)
                    if score < args.threshold:
                        continue

                    # Stage 2 — rule attribution
                    top_rules = attribute_stage2(
                        normalized, rule_models, cosine_attributor,
                        args.method, args.top_k,
                    )

                    alert = {
                        "@timestamp": event.get("@timestamp"),
                        "red.detection_score": round(score, 4),
                        "red.attribution_method": args.method,
                        "red.top_rule": top_rules[0][0] if top_rules else None,
                        "red.top_rules": [
                            {"rule": r, "score": round(s, 4)} for r, s in top_rules
                        ],
                        "red.command_line": text,
                        "host.name": event.get("host", {}).get("name", "unknown"),
                        "winlog.event_id": event.get("winlog", {}).get("event_id"),
                        "winlog.computer_name": event.get("winlog", {}).get("computer_name"),
                        "process": event.get("process", {}),
                        "user": event.get("user", {}),
                    }

                    es_index(args.es_host, args.out_index, alert)
                    n_alerts += 1

                    logger.info(
                        "[ALERT] host=%s  score=%.3f  top=%s | %s",
                        alert["host.name"], score, alert["red.top_rule"], text[:100],
                    )

                since_ts = last_ts
                if not args.no_state and not explicit_since:
                    save_state(args.state_file, since_ts)

                if n_alerts:
                    logger.info("Indexed %d alerts to '%s'", n_alerts, args.out_index)

            else:
                logger.debug("No new events since %s", since_ts)

        except KeyboardInterrupt:
            logger.info("Interrupted — saving state and exiting.")
            if not args.no_state and not explicit_since:
                save_state(args.state_file, since_ts)
            break
        except Exception as exc:
            logger.error("Poll error: %s", exc, exc_info=True)

        if args.max_iter and iter_count >= args.max_iter:
            logger.info("Reached max_iter=%d — exiting.", args.max_iter)
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
