#!/usr/bin/env python3
"""Inject 1 test alert vào red-alerts để test daemon end-to-end.

Usage:
  python3 -m agent.inject_test_alert            # inject 1 alert mặc định
  python3 -m agent.inject_test_alert --host WIN-02  # custom host
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from agent.es_io import ES_HOST, ES_AUTH, ES_RED_INDEX, ES_VERIFY

logger = logging.getLogger("inject")


def make_test_alert(host: str = "WIN-01", user: str = "alice") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "@timestamp": now,
        "host": {"name": host},
        "user": {"name": user},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell -e SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
            "parent": {"name": "outlook.exe"},
        },
        "red": {
            "stage1_score": 0.87,
            "stage1_model": "ensemble_f1",
            "top_rules": [
                {"rule_id": "powershell_encoded_command", "cosine_score": 0.91},
                {"rule_id": "powershell_suspicious", "cosine_score": 0.78},
            ],
            "evasion_type": "near_miss",
        },
        "source_event_id": f"test-{datetime.now().strftime('%H%M%S')}",
    }


def main():
    parser = argparse.ArgumentParser(description="Inject test alert into red-alerts")
    parser.add_argument("--host", default="WIN-01")
    parser.add_argument("--user", default="alice")
    parser.add_argument("--alert-file", help="Path tới custom alert JSON")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if args.alert_file:
        with open(args.alert_file) as f:
            alert = json.load(f)
    else:
        alert = make_test_alert(args.host, args.user)

    r = requests.post(
        f"{ES_HOST}/{ES_RED_INDEX}/_doc",
        auth=ES_AUTH,
        json=alert,
        timeout=10,
        verify=ES_VERIFY,
    )
    if r.ok:
        result = r.json()
        logger.info("✓ Injected: index=%s id=%s @timestamp=%s host=%s",
                    result.get("_index"), result.get("_id"),
                    alert["@timestamp"], alert["host"]["name"])
    else:
        logger.error("✗ Inject failed: %d %s", r.status_code, r.text)
        sys.exit(1)


if __name__ == "__main__":
    main()
