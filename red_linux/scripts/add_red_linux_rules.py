#!/usr/bin/env python3
"""Build + import the RED-Linux demo detection rules for the auditd ELK lab.

Phong cách giống scripts/convert_sigma_to_elastic.py, nhưng dành cho Linux
auditd_manager logs (index logs-auditd_manager.auditd-*), nơi KHÔNG có field
`process.command_line`. Vì pySigma không có pipeline ecs_linux sạch và convert
thẳng sẽ sinh query trên process.command_line (fire 0 alert trên auditd), script
này dịch TRUNG THỰC phần `detection:` của các Sigma YAML gốc rồi remap field:

    Image|endswith '/x'      -> process.executable : */x
    CommandLine|contains 'y' -> process.title : *y*      (process.title = full cmdline)
    CommandLine arg '-c'     -> process.args : "-c"       (khớp đúng phần tử mảng)
    CommandLine|re '\\s-[FTd]\\s' -> process.args : ("-F" or "-T" or "-d")

Metadata (title, id, description, references, author, level, MITRE) đọc THẲNG từ
YAML để bám đúng nguồn Sigma. 2 rule không có Sigma (tar/gzip, crontab) là custom.

Ví dụ:
  python3 scripts/add_red_linux_rules.py \
    --kibana-url http://100.75.12.114:5601 \
    --kibana-user elastic --kibana-password 'Admin123@' --import-to-kibana
"""

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

import requests
import yaml

LOGGER = logging.getLogger("add_red_linux_rules")

DEFAULT_RULES_ROOT = "~/data/sigma/rules/linux"
DEFAULT_OUT = "~/data/sigma/elastic_rules/linux_auditd_red.ndjson"
DEFAULT_INDEX = ["logs-auditd_manager.auditd-*"]

SEVERITY_BY_LEVEL = {
    "informational": "low", "info": "low", "low": "low",
    "medium": "medium", "high": "high", "critical": "critical",
}
RISK_BY_SEVERITY = {"low": 21, "medium": 47, "high": 73, "critical": 99}

# MITRE ATT&CK reference (chỉ những TTP dùng ở đây)
_TACTIC = {
    "TA0007": "Discovery", "TA0002": "Execution",
    "TA0010": "Exfiltration", "TA0011": "Command and Control",
}
_TECH = {
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1567": "Exfiltration Over Web Service",
    "T1105": "Ingress Tool Transfer",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
}


def expand(path: str) -> Path:
    return Path(path).expanduser()


def _tactic(tid: str) -> dict:
    return {"id": tid, "name": _TACTIC[tid],
            "reference": f"https://attack.mitre.org/tactics/{tid}/"}


def _tech(tid: str) -> dict:
    base = tid.split(".")[0]
    ref = f"https://attack.mitre.org/techniques/{base.replace('.', '/')}/"
    entry = {"id": base, "name": _TECH[base], "reference": ref}
    if "." in tid:
        sub = tid.split(".")[1]
        entry["subtechnique"] = [{
            "id": tid, "name": _TECH[tid],
            "reference": f"https://attack.mitre.org/techniques/{base}/{sub}/",
        }]
    return entry


def threat(pairs: List[tuple]) -> List[dict]:
    """pairs = [(tactic_id, [technique_id, ...]), ...]"""
    out = []
    for tac, techs in pairs:
        out.append({
            "framework": "MITRE ATT&CK",
            "tactic": _tactic(tac),
            "technique": [_tech(t) for t in techs],
        })
    return out


# Bản dịch TRUNG THỰC `detection:` của từng Sigma rule (keyed by Sigma id),
# đã remap sang field auditd. Mỗi clause ghi rõ nó đến từ selection nào.
SIGMA_QUERIES: Dict[str, dict] = {
    # System Information Discovery — condition: selection (Image|endswith ...)
    "42df45e7-e6e9-43b5-8f26-bec5b39cc239": {
        "rule_id": "red-linux-01-sysinfo-disc",
        "query": (
            'event.category:"process" and process.executable:('
            '*/uname or */hostname or */uptime or */lspci or */dmidecode or '
            '*/lscpu or */lsmod)'
        ),
        "threat": threat([("TA0007", ["T1082"])]),
    },
    # File and Directory Discovery — condition: 1 of selection_*
    # Bỏ selection_file_with_asterisk (CommandLine|re '(.){200,}' — độ dài >=200,
    # không biểu diễn được bằng KQL); giữ 5 selection còn lại.
    "d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72": {
        "rule_id": "red-linux-02-file-dir-disc",
        "query": (
            'event.category:"process" and ('
            '(process.executable:*/ls and process.args:"-R") or '       # selection_recursive_ls
            'process.executable:(*/find or */tree or */findmnt or */mlocate))'  # find/tree/findmnt/mlocate
        ),
        "threat": threat([("TA0007", ["T1083"])]),
    },
    # Execution Of Script In Suspicious Directory — condition: all of selection_*
    "30bcce26-51c5-49f2-99c8-7b59e3af36c7": {
        "rule_id": "red-linux-03-script-in-tmp",
        "query": (
            'event.category:"process" and '
            'process.executable:(*/bash or */csh or */dash or */fish or */ksh or */sh or */zsh) '  # selection_img
            'and process.args:"-c" '                  # selection_flag  (CommandLine|contains ' -c ')
            'and process.title:*/tmp/*'               # selection_paths (CommandLine|contains '/tmp/')
        ),
        "threat": threat([("TA0002", ["T1059.004"])]),
    },
    # Suspicious Curl File Upload — condition: all of selection_* and not 1 of filter_optional_*
    "00b90cc1-17ec-402c-96ad-3a8117d7a582": {
        "rule_id": "red-linux-05-curl-upload",
        "query": (
            'event.category:"process" and process.executable:*/curl and ('
            'process.args:(--form* or --upload-file or --data* or "-F" or "-T" or "-d")'  # selection_cli (flags trong argv)
            ') and not process.title:(*localhost* or *127.0.0.1*)'                         # filter_optional_localhost
        ),
        "threat": threat([("TA0010", ["T1567"]), ("TA0011", ["T1105"])]),
    },
}

# Map id YAML -> đường dẫn tương đối dưới rules-root
SIGMA_FILES = {
    "42df45e7-e6e9-43b5-8f26-bec5b39cc239": "process_creation/proc_creation_lnx_system_info_discovery.yml",
    "d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72": "process_creation/proc_creation_lnx_file_and_directory_discovery.yml",
    "30bcce26-51c5-49f2-99c8-7b59e3af36c7": "process_creation/proc_creation_lnx_susp_shell_script_exec_from_susp_location.yml",
    "00b90cc1-17ec-402c-96ad-3a8117d7a582": "process_creation/proc_creation_lnx_susp_curl_fileupload.yml",
}

# Chỉ tạo rule có Sigma gốc. Phase 4 (tar/gzip) và 6 (crontab) không có Sigma
# upstream nên KHÔNG tạo rule.
CUSTOM_RULES: List[dict] = []


def load_sigma_meta(rules_root: Path, sigma_id: str) -> dict:
    path = rules_root / SIGMA_FILES[sigma_id]
    if not path.exists():
        raise SystemExit(f"Sigma YAML not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if str(doc.get("id")) != sigma_id:
        raise SystemExit(f"ID mismatch in {path}: {doc.get('id')} != {sigma_id}")
    return doc


def build_rule(common: dict) -> dict:
    """common -> Detection Engine rule object (Custom Query)."""
    sev = common["severity"]
    rule = {
        "rule_id": common["rule_id"],
        "name": common["name"],
        "description": common["description"],
        "type": "query",
        "language": "kuery",
        "query": common["query"],
        "index": common["index"],
        "enabled": True,
        "severity": sev,
        "risk_score": RISK_BY_SEVERITY[sev],
        "from": "now-360s",
        "interval": "5m",
        "to": "now",
        "tags": ["RED-Linux", "demo"],
        "author": common.get("author") and [common["author"]] or [],
        "references": common.get("references", []),
        "threat": common.get("threat", []),
    }
    return rule


def build_all(rules_root: Path, index: List[str]) -> List[dict]:
    rules = []
    for sigma_id, q in SIGMA_QUERIES.items():
        meta = load_sigma_meta(rules_root, sigma_id)
        sev = SEVERITY_BY_LEVEL.get(str(meta.get("level", "")).lower(), "medium")
        name = f"RED-Linux {q['rule_id'].split('-')[2]} - {meta['title']} ({sigma_id[:8]})"
        desc = meta.get("description", meta["title"])
        if isinstance(desc, str):
            desc = desc.strip()
        rules.append(build_rule({
            "rule_id": q["rule_id"], "name": name, "description": desc,
            "severity": sev, "query": q["query"], "index": index,
            "author": (meta.get("author") or "Sigma"),
            "references": meta.get("references", []),
            "threat": q.get("threat", []),
        }))
    for c in CUSTOM_RULES:
        rules.append(build_rule({**c, "index": index}))
    # Sắp theo rule_id để output ổn định
    rules.sort(key=lambda r: r["rule_id"])
    return rules


def write_ndjson(rules: List[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rules:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    LOGGER.info("Wrote %d rule(s) -> %s", len(rules), out)


def import_to_kibana(out: Path, url: str, user: str, password: str, timeout: int) -> None:
    endpoint = f"{url.rstrip('/')}/api/detection_engine/rules/_import?overwrite=true"
    with out.open("rb") as fh:
        files = {"file": (out.name, fh, "application/ndjson")}
        resp = requests.post(endpoint, headers={"kbn-xsrf": "true"},
                             files=files, auth=(user, password), timeout=timeout)
    if resp.status_code >= 400:
        raise SystemExit(f"Import failed HTTP {resp.status_code}\n{resp.text}")
    payload = resp.json()
    LOGGER.info("Import: success=%s rules=%s success_count=%s errors=%s",
                payload.get("success"), payload.get("rules_count"),
                payload.get("success_count"), len(payload.get("errors", []) or []))
    for err in (payload.get("errors") or [])[:10]:
        LOGGER.warning("Import error: %s", err)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rules-root", default=DEFAULT_RULES_ROOT)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--index-pattern", action="append", default=None,
                   help="Index pattern(s). Default: logs-auditd_manager.auditd-*")
    p.add_argument("--import-to-kibana", action="store_true")
    p.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", "http://100.75.12.114:5601"))
    p.add_argument("--kibana-user", default=None)
    p.add_argument("--kibana-password", default=None)
    p.add_argument("--import-timeout", type=int, default=120)
    return p.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    args = parse_args()
    rules_root = expand(args.rules_root)
    index = args.index_pattern or DEFAULT_INDEX
    out = expand(args.out)

    rules = build_all(rules_root, index)
    write_ndjson(rules, out)
    for r in rules:
        LOGGER.info("  %-30s | %-8s | %s", r["rule_id"], r["severity"], r["name"])

    if args.import_to_kibana:
        user = args.kibana_user or os.getenv("KIBANA_USER") or os.getenv("ES_USER")
        password = args.kibana_password or os.getenv("KIBANA_PASSWORD") or os.getenv("ES_PASSWORD")
        if not user or not password:
            raise SystemExit("Thiếu creds: --kibana-user/--kibana-password hoặc env KIBANA_USER/KIBANA_PASSWORD")
        import_to_kibana(out, args.kibana_url, user, password, args.import_timeout)


if __name__ == "__main__":
    main()
