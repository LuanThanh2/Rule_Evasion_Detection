"""Elasticsearch I/O — đọc red-alerts, ghi ai-investigations-*, manage state.

Pure requests-based — không cần elasticsearch-py.
"""

import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone

import requests

from agent.schemas import Investigation

logger = logging.getLogger("agent.es_io")

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_AUTH = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
ES_RED_INDEX = os.environ.get("ES_RED_INDEX", "red-alerts")
ES_AI_INDEX = os.environ.get("ES_AI_INDEX", "ai-investigations")

STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".agent_daemon_state.json",
)


# ── ES index mapping (flat structure, Kibana-friendly) ──
AI_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "investigation_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "trigger_alert": {"type": "object", "enabled": True},
            "workflow_plan": {
                "properties": {
                    "workflow_type": {"type": "keyword"},
                    "priority": {"type": "integer"},
                    "reasoning": {"type": "text"},
                    "agents_to_run": {"type": "keyword"},
                },
            },
            "triage": {
                "properties": {
                    "severity": {"type": "keyword"},
                    "is_false_positive": {"type": "boolean"},
                    "confidence": {"type": "float"},
                    "reasoning": {"type": "text"},
                    "mitre_technique": {"type": "keyword"},
                    "quick_findings": {"type": "text"},
                    "needs_deeper_investigation": {"type": "boolean"},
                },
            },
            "hunt": {
                "properties": {
                    "related_events_count": {"type": "integer"},
                    "iocs_found": {"type": "keyword"},
                    "network_indicators": {"type": "text"},
                    "suspicious_score": {"type": "float"},
                    "hunt_summary_vi": {"type": "text"},
                    "timeline_vi": {"type": "text"},
                },
            },
            "red_analyst": {
                "properties": {
                    "evasion_technique": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "evasion_reasoning_vi": {"type": "text"},
                    "discriminative_tokens": {"type": "keyword"},
                    "sigma_rule_comparison_vi": {"type": "text"},
                },
            },
            "mitre": {
                "properties": {
                    "primary_tactic": {"type": "keyword"},
                    "primary_technique": {"type": "keyword"},
                    "sub_techniques": {"type": "keyword"},
                    "severity_baseline": {"type": "keyword"},
                    "ttp_chain_vi": {"type": "text"},
                },
            },
            "response": {
                "properties": {
                    "sigma_patch_yaml": {"type": "text"},
                    "sigma_patch_explanation_vi": {"type": "text"},
                    "notification_sent": {"type": "boolean"},
                    "notification_target": {"type": "keyword"},
                    "requires_human_approval": {"type": "boolean"},
                    "summary_vi": {"type": "text"},
                    # containment_actions kept as nested object array
                },
            },
            "report": {
                "properties": {
                    "title_vi": {"type": "text"},
                    "summary_vi": {"type": "text"},
                    "full_markdown_vi": {"type": "text"},
                    "recommended_actions_vi": {"type": "text"},
                },
            },
            "agent_metadata": {
                "properties": {
                    "agent_name": {"type": "keyword"},
                    "duration_ms": {"type": "float"},
                    "steps": {"type": "integer"},
                    "tokens_prompt": {"type": "long"},
                    "tokens_completion": {"type": "long"},
                    "tokens_cached": {"type": "long"},
                    "error": {"type": "keyword"},
                },
            },
            "total_duration_ms": {"type": "float"},
            "total_tokens": {"type": "long"},
            "estimated_cost_usd": {"type": "float"},
        },
    },
}


# ── Index management ────────────────────────────────────────────────
def ensure_ai_index() -> bool:
    """Tạo ai-investigations index với mapping nếu chưa có."""
    r = requests.head(f"{ES_HOST}/{ES_AI_INDEX}", auth=ES_AUTH, timeout=5)
    if r.status_code == 200:
        logger.debug("Index %s đã tồn tại", ES_AI_INDEX)
        return True
    if r.status_code == 404:
        logger.info("Tạo index %s với mapping...", ES_AI_INDEX)
        r2 = requests.put(
            f"{ES_HOST}/{ES_AI_INDEX}",
            auth=ES_AUTH,
            json=AI_INDEX_MAPPING,
            timeout=10,
        )
        if r2.ok:
            logger.info("✓ Index %s created", ES_AI_INDEX)
            return True
        raise RuntimeError(f"Tạo index thất bại: {r2.status_code} {r2.text}")
    raise RuntimeError(f"ES check failed: {r.status_code} {r.text}")


# ── Investigation write ─────────────────────────────────────────────
def write_investigation(inv: Investigation) -> dict:
    """Index Investigation vào ai-investigations.

    Document ID = investigation_id (idempotent — chạy lại không tạo dup).
    """
    doc = inv.model_dump(mode="json", exclude_none=False)
    r = requests.put(
        f"{ES_HOST}/{ES_AI_INDEX}/_doc/{inv.investigation_id}",
        auth=ES_AUTH,
        json=doc,
        timeout=15,
    )
    if not r.ok:
        raise RuntimeError(f"Index failed ({r.status_code}): {r.text}")
    return r.json()


# ── Alert read ──────────────────────────────────────────────────────
def poll_new_alerts(
    since_timestamp: Optional[str] = None,
    limit: int = 50,
    score_threshold: float = 0.0,
) -> list[dict]:
    """Lấy alerts mới từ red-alerts.

    - since_timestamp: ISO 8601, lấy alerts có @timestamp > giá trị này
    - score_threshold: chỉ lấy alerts có red.stage1_score >= ngưỡng
    """
    must: list[dict] = []
    if since_timestamp:
        must.append({"range": {"@timestamp": {"gt": since_timestamp}}})
    if score_threshold > 0:
        must.append({"range": {"red.stage1_score": {"gte": score_threshold}}})

    query = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
    }

    r = requests.post(
        f"{ES_HOST}/{ES_RED_INDEX}/_search",
        auth=ES_AUTH,
        json=query,
        timeout=15,
    )
    if not r.ok:
        raise RuntimeError(f"Poll failed ({r.status_code}): {r.text}")

    hits = r.json().get("hits", {}).get("hits", [])
    out: list[dict] = []
    for h in hits:
        src = h["_source"]
        src["_es_id"] = h["_id"]
        out.append(src)
    return out


def get_alert_by_id(es_id: str) -> Optional[dict]:
    """Lấy 1 alert theo ES document ID."""
    r = requests.get(
        f"{ES_HOST}/{ES_RED_INDEX}/_doc/{es_id}",
        auth=ES_AUTH,
        timeout=10,
    )
    if r.status_code == 404:
        return None
    if not r.ok:
        raise RuntimeError(f"Get failed: {r.text}")
    src = r.json().get("_source", {})
    src["_es_id"] = es_id
    return src


# ── State management ────────────────────────────────────────────────
def load_state() -> dict:
    """Load daemon state — last processed timestamp + counters."""
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {
        "last_processed_timestamp": None,
        "processed_count": 0,
        "error_count": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


def save_state(state: dict) -> None:
    """Atomic write — viết temp file rồi rename."""
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def reset_state() -> None:
    """Xóa state file (sẽ process lại tất cả alerts)."""
    if os.path.isfile(STATE_FILE):
        os.remove(STATE_FILE)
        logger.info("State file removed")


# ── Health check ────────────────────────────────────────────────────
def check_es_connection() -> bool:
    """Verify ES reachable + credentials đúng."""
    try:
        r = requests.get(f"{ES_HOST}/_cluster/health", auth=ES_AUTH, timeout=5)
        if r.ok:
            health = r.json()
            logger.info("✓ ES connection OK: cluster=%s status=%s",
                        health.get("cluster_name"), health.get("status"))
            return True
        logger.error("ES health check failed: %d %s", r.status_code, r.text)
        return False
    except Exception as e:
        logger.error("ES unreachable: %s", e)
        return False
