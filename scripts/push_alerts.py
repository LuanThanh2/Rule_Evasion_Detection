#!/usr/bin/env python3
"""Push alerts JSONL file into Elasticsearch using the Bulk API.

Usage:
  python scripts/push_alerts.py \\
    --alerts /tmp/alerts.jsonl \\
    --es-host http://10.10.20.100:9200 \\
    --es-user elastic --es-password tzxr74123 \\
    --es-index red-alerts

Requires: pip install requests
"""

import os
import sys
import json
import argparse
import logging

logger = logging.getLogger("push_alerts")

# Bulk requests are capped per chunk to avoid huge POST bodies
DEFAULT_CHUNK_SIZE = 500


def bulk_index(es_host: str, es_index: str, alerts: list,
               auth=None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple:
    """Bulk-index alerts into Elasticsearch. Returns (ok, failed)."""
    import requests

    url = f"{es_host.rstrip('/')}/_bulk"
    headers = {"Content-Type": "application/x-ndjson"}
    action = json.dumps({"index": {"_index": es_index}})

    ok = 0
    failed = 0

    for i in range(0, len(alerts), chunk_size):
        chunk = alerts[i:i + chunk_size]
        body_lines = []
        for alert in chunk:
            body_lines.append(action)
            body_lines.append(json.dumps(alert, ensure_ascii=False))
        body = "\n".join(body_lines) + "\n"

        resp = requests.post(url, data=body, headers=headers, auth=auth, timeout=60)
        resp.raise_for_status()
        result = resp.json()

        for item in result.get("items", []):
            status = item.get("index", {}).get("status", 0)
            if 200 <= status < 300:
                ok += 1
            else:
                failed += 1
                err = item.get("index", {}).get("error", {})
                logger.warning("Index failure: %s", err)

        logger.info("Chunk %d/%d: %d indexed", i // chunk_size + 1,
                    (len(alerts) + chunk_size - 1) // chunk_size, len(chunk))

    return ok, failed


def get_count(es_host: str, es_index: str, auth=None) -> int:
    import requests
    url = f"{es_host.rstrip('/')}/{es_index}/_count"
    resp = requests.get(url, auth=auth, timeout=10)
    resp.raise_for_status()
    return resp.json().get("count", 0)


def main():
    parser = argparse.ArgumentParser(description="Push alerts JSONL to Elasticsearch")
    parser.add_argument("--alerts", type=str, required=True,
                        help="Path to alerts JSONL file (from detect_batch.py)")
    parser.add_argument("--es-host", type=str, default="http://localhost:9200")
    parser.add_argument("--es-user", type=str, default=None)
    parser.add_argument("--es-password", type=str, default=None)
    parser.add_argument("--es-index", type=str, default="red-alerts",
                        help="Destination index name")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help="Alerts per bulk request")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    auth = (args.es_user, args.es_password) if args.es_user else None

    # Load alerts
    if not os.path.exists(args.alerts):
        parser.error(f"Alerts file not found: {args.alerts}")

    with open(args.alerts, encoding="utf-8") as f:
        alerts = [json.loads(line) for line in f if line.strip()]

    if not alerts:
        logger.warning("No alerts to push (file is empty)")
        return

    logger.info("Loaded %d alerts from %s", len(alerts), args.alerts)
    logger.info("Pushing to %s/%s ...", args.es_host, args.es_index)

    count_before = get_count(args.es_host, args.es_index, auth) if _index_exists(
        args.es_host, args.es_index, auth) else 0

    ok, failed = bulk_index(args.es_host, args.es_index, alerts, auth, args.chunk_size)

    count_after = get_count(args.es_host, args.es_index, auth)

    logger.info("Done — indexed: %d  failed: %d", ok, failed)
    logger.info("Index '%s' count: %d → %d (delta %+d)",
                args.es_index, count_before, count_after, count_after - count_before)


def _index_exists(es_host: str, es_index: str, auth) -> bool:
    import requests
    url = f"{es_host.rstrip('/')}/{es_index}"
    try:
        resp = requests.head(url, auth=auth, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


if __name__ == "__main__":
    main()
