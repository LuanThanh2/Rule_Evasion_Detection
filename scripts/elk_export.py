#!/usr/bin/env python3
"""Export Windows events from Elasticsearch to JSONL for batch detection.

Usage:
  python scripts/elk_export.py \\
    --es-host http://elk-server:9200 \\
    --es-index "winlogbeat-*" \\
    --out /tmp/events.jsonl \\
    --since 24h \\
    --event-id 1

Requires: pip install requests
"""

import os
import sys
import json
import argparse
import logging
import datetime

logger = logging.getLogger("elk_export")

UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def parse_lookback(s: str) -> int:
    try:
        return UNIT_SECONDS[s[-1]] * int(s[:-1])
    except (KeyError, ValueError):
        raise ValueError(f"Invalid lookback format '{s}'. Use e.g. 1h, 24h, 7d.")


def export_events(es_host: str, index: str, event_id: int, since_ts: str, size: int,
                  auth=None) -> list:
    import requests

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"winlog.event_id": event_id}},
                    {"range": {"@timestamp": {"gt": since_ts}}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": size
    }

    url = f"{es_host.rstrip('/')}/{index}/_search"
    resp = requests.get(url, json=query, timeout=30, auth=auth)
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return [h["_source"] for h in hits]


def main():
    parser = argparse.ArgumentParser(description="Export ELK events to JSONL")
    parser.add_argument("--es-host", type=str, default="http://localhost:9200")
    parser.add_argument("--es-index", type=str, default="winlogbeat-*")
    parser.add_argument("--es-user", type=str, default=None, help="Elasticsearch username")
    parser.add_argument("--es-password", type=str, default=None, help="Elasticsearch password")
    parser.add_argument("--event-id", type=int, default=1,
                        help="Windows Event ID (1=process creation, 4688=process creation alt)")
    parser.add_argument("--since", type=str, default="24h",
                        help="Lookback window, e.g. 1h, 24h, 7d")
    parser.add_argument("--size", type=int, default=10000,
                        help="Maximum number of events to fetch")
    parser.add_argument("--out", type=str, default="exported_events.jsonl",
                        help="Output JSONL file path")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    seconds = parse_lookback(args.since)
    since_ts = (
        datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    logger.info("Querying Event ID %d from %s (since %s, max %d)",
                args.event_id, args.es_index, since_ts, args.size)

    auth = (args.es_user, args.es_password) if args.es_user else None
    events = export_events(args.es_host, args.es_index, args.event_id, since_ts, args.size, auth=auth)
    logger.info("Fetched %d events", len(events))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    logger.info("Saved to %s", args.out)


if __name__ == "__main__":
    main()
