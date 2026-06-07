#!/usr/bin/env python3
"""Windows Stage 3 Layer-3 Sigma-logic validator.

Cosine Stage 2 ranks the whole Windows Sigma catalog by token similarity. On
ground-truth fired events this is intentionally hard: many sibling rules share
LOLBin/path/PowerShell tokens, so top-1 can be much lower than top-10 recall.

Layer 3 uses cosine only as a cheap top-N candidate generator, then lets a
Sigma-logic validator confirm which candidate actually fires. In this offline
evaluation script, the validator oracle is the Hayabusa-confirmed match-event
label already stored under events_hayabusa/windows/<event_type>_<split>.

Production hook:
  replace `oracle_confirmed` with a Hayabusa/pySigma call over only top-N rules.

Usage:
  ~/venvs/rule_evasion_env/bin/python scripts/stage3_layer3_windows.py
  ~/venvs/rule_evasion_env/bin/python scripts/stage3_layer3_windows.py --event-type process_creation
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from red.data import extract_commandline, resolve_event_paths  # noqa: E402
from red.normalize import Normalizer  # noqa: E402
from red.persist import load_result  # noqa: E402
from red.rule_metadata import normalize_title  # noqa: E402


DEFAULT_CONFIGS = {
    "process_creation": ROOT / "config" / "process_creation.yaml",
    "powershell": ROOT / "config" / "powershell.yaml",
    "registry_event": ROOT / "config" / "registry_event.yaml",
}
DEFAULT_OUT_DIR = ROOT / "reports" / "windows"
KS_DEFAULT = (1, 3, 5, 10)
NS_DEFAULT = (3, 5, 10)


@dataclass
class FiredItem:
    event_type: str
    key: str
    sample: str
    gt_rules: set[str]
    event_paths: list[str]
    source_files: list[str]
    event_ids: set[str]


def pct(numer: int, denom: int) -> float:
    return 100.0 * numer / denom if denom else 0.0


def expand_path(value: str | None) -> str | None:
    return os.path.expanduser(value) if value else value


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def split_events_dir(data_cfg: dict[str, Any], split: str) -> str:
    if split == "train":
        key = "events_dir"
    elif split == "valid":
        key = "events_valid_dir"
    elif split == "test":
        key = "events_test_dir"
    else:
        raise ValueError(f"unsupported split: {split}")
    value = data_cfg.get(key)
    if not value:
        raise ValueError(f"config missing data.{key}")
    return os.path.expanduser(value)


def load_cosine_attributor(cfg: dict[str, Any]) -> tuple[Any, set[str], str]:
    out_cfg = cfg.get("output", {})
    out_dir = expand_path(out_cfg.get("dir", "models"))
    attr_path = out_cfg.get("attr_result_path")
    if not attr_path:
        attr_name = out_cfg.get("attr_result_name", "attr_ensemble")
        attr_path = os.path.join(out_dir, f"train_rslt_{attr_name}.zip")
    attr_path = os.path.expanduser(attr_path)

    result = load_result(attr_path)
    cosine = result.get("cosine_attributor")
    if cosine is None:
        raise RuntimeError(f"cosine_attributor missing in {attr_path}")
    return cosine, set(cosine.rule_filter_matrices.keys()), attr_path


def event_identity(event: dict[str, Any], sample: str) -> str:
    """Stable key for grouping multiple Hayabusa alerts on the same event."""
    parts = [
        event.get("Computer"),
        event.get("Channel"),
        event.get("EventID"),
        event.get("RecordID"),
    ]
    if all(part not in (None, "") for part in parts):
        return "|".join(str(part) for part in parts)

    details = event.get("Details", {}) if isinstance(event.get("Details"), dict) else {}
    extra = event.get("ExtraFieldInfo", {}) if isinstance(event.get("ExtraFieldInfo"), dict) else {}
    parts = [
        event.get("Timestamp"),
        event.get("Computer"),
        event.get("EventID"),
        details.get("PID"),
        details.get("PGUID"),
        extra.get("ScriptBlockId"),
        sample,
    ]
    return "|".join(str(part or "") for part in parts)


def item_identity(event: dict[str, Any], sample: str, gt_rule: str, dedupe_by: str) -> str:
    """Return grouping key for an offline fired sample.

    `sample_rule` matches the Windows fired measurement in the report: repeated
    JSON files for the same command and same Hayabusa rule collapse, while the
    same command firing two different rules remains two evaluation items.
    """
    if dedupe_by == "event":
        return event_identity(event, sample)
    if dedupe_by == "sample":
        return sample
    if dedupe_by == "sample_rule":
        return f"{sample}\nRULE={gt_rule}"
    raise ValueError(f"unsupported dedupe mode: {dedupe_by}")


def iter_match_files(events_dir: str) -> list[Path]:
    base = Path(events_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"events dir not found: {events_dir}")
    return sorted(base.glob("*/*_Match_*.json"))


def load_fired_items(
    *,
    event_type: str,
    events_dir: str,
    event_paths: list[str],
    valid_rules: set[str],
    dedupe_by: str,
    gt_source: str,
) -> list[FiredItem]:
    """Load Hayabusa-confirmed fired events and merge duplicate event alerts."""
    by_key: dict[str, FiredItem] = {}
    skipped_no_sample = 0
    skipped_no_rule = 0

    for path in iter_match_files(events_dir):
        try:
            event = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        if gt_source == "dir":
            # Match hayabusa_to_matches.py output and RED model internal keys.
            # Long titles may be truncated to 60 chars in the directory name.
            gt_rule = path.parent.name
        elif gt_source == "title":
            title = event.get("RuleTitle") or path.parent.name
            gt_rule = normalize_title(str(title))
        else:
            raise ValueError(f"unsupported gt source: {gt_source}")
        if gt_rule not in valid_rules:
            skipped_no_rule += 1
            continue

        sample = extract_commandline(event, event_paths)
        if not sample:
            skipped_no_sample += 1
            continue

        key = item_identity(event, sample, gt_rule, dedupe_by)
        event_id = str(event.get("EventID", ""))
        if key not in by_key:
            by_key[key] = FiredItem(
                event_type=event_type,
                key=key,
                sample=sample,
                gt_rules=set(),
                event_paths=event_paths,
                source_files=[],
                event_ids=set(),
            )
        by_key[key].gt_rules.add(gt_rule)
        by_key[key].source_files.append(str(path))
        if event_id:
            by_key[key].event_ids.add(event_id)

    items = [item for item in by_key.values() if item.gt_rules]
    items.sort(key=lambda item: item.key)
    print(
        f"{event_type}: loaded {len(items)} fired samples from {events_dir} "
        f"(dedupe_by={dedupe_by}, gt_source={gt_source}) "
        f"(skipped_no_rule={skipped_no_rule}, skipped_no_sample={skipped_no_sample})"
    )
    return items


def names(ranking: list[tuple[str, float]]) -> list[str]:
    return [rule for rule, _ in ranking]


def min_true_rank(gt_rules: set[str], ranked_names: list[str]) -> int | None:
    for idx, rule in enumerate(ranked_names, start=1):
        if rule in gt_rules:
            return idx
    return None


def topk_metrics(items: list[FiredItem], rankings: list[list[str]], ks: tuple[int, ...]) -> dict[int, float]:
    hits = {k: 0 for k in ks}
    for item, ranking in zip(items, rankings):
        gt = item.gt_rules
        for k in ks:
            if gt & set(ranking[:k]):
                hits[k] += 1
    return {k: pct(v, len(items)) for k, v in hits.items()}


def layer3_rerank(ranking: list[str], confirmed: set[str], n: int) -> list[str]:
    """Push Sigma-confirmed candidate(s) in cosine top-N to rank #1."""
    head = [rule for rule in ranking[:n] if rule in confirmed]
    rest = [rule for rule in ranking if rule not in head]
    return head + rest


def evaluate_event_type(
    *,
    event_type: str,
    config_path: Path,
    split: str,
    ks: tuple[int, ...],
    ns: tuple[int, ...],
    detail_top_k: int,
    dedupe_by: str,
    gt_source: str,
    out_dir: Path,
) -> dict[str, Any]:
    cfg = load_config(config_path)
    data_cfg = cfg.get("data", {})
    events_dir = split_events_dir(data_cfg, split)
    event_paths = resolve_event_paths(
        data_cfg.get("search_fields", ["CommandLine"]),
        data_cfg.get("event_field_map", {}),
    )
    cosine, valid_rules, attr_path = load_cosine_attributor(cfg)
    items = load_fired_items(
        event_type=event_type,
        events_dir=events_dir,
        event_paths=event_paths,
        valid_rules=valid_rules,
        dedupe_by=dedupe_by,
        gt_source=gt_source,
    )

    normalizer = Normalizer()
    normalized = [normalizer.normalize(item.sample) for item in items]
    ranked_scored = cosine.score_samples(normalized) if items else []
    cosine_rankings = [names(ranked) for ranked in ranked_scored]
    cosine_metrics = topk_metrics(items, cosine_rankings, ks)

    layer3_metrics: dict[int, dict[int, float]] = {}
    layer3_rankings: dict[int, list[list[str]]] = {}
    for n in ns:
        reranked = [
            layer3_rerank(ranking, item.gt_rules, n)
            for item, ranking in zip(items, cosine_rankings)
        ]
        layer3_rankings[n] = reranked
        layer3_metrics[n] = topk_metrics(items, reranked, ks)

    detail_path = out_dir / f"layer3_{event_type}_{split}_details.jsonl"
    with detail_path.open("w", encoding="utf-8") as handle:
        for item, scored, ranking in zip(items, ranked_scored, cosine_rankings):
            true_rank = min_true_rank(item.gt_rules, ranking)
            row = {
                "event_type": event_type,
                "split": split,
                "dedupe_by": dedupe_by,
                "gt_source": gt_source,
                "key": item.key,
                "event_ids": sorted(item.event_ids),
                "ground_truth_rules": sorted(item.gt_rules),
                "cosine_true_rank": true_rank,
                "cosine_top_rules": [
                    {"rank": idx + 1, "rule": rule, "score": float(score)}
                    for idx, (rule, score) in enumerate(scored[:detail_top_k])
                ],
                "layer3": {},
                "sample_preview": item.sample[:500],
                "source_files": item.source_files,
            }
            for n in ns:
                reranked = layer3_rerank(ranking, item.gt_rules, n)
                row["layer3"][str(n)] = {
                    "confirmed_in_top_n": bool(item.gt_rules & set(ranking[:n])),
                    "top_rule_after_rerank": reranked[0] if reranked else None,
                    "true_rank_after_rerank": min_true_rank(item.gt_rules, reranked),
                }
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    rescued_top2_to_top10 = max(cosine_metrics.get(10, 0.0) - cosine_metrics.get(1, 0.0), 0.0)
    return {
        "event_type": event_type,
        "config": str(config_path),
        "attr_path": attr_path,
        "events_dir": events_dir,
        "split": split,
        "dedupe_by": dedupe_by,
        "gt_source": gt_source,
        "n": len(items),
        "cosine": cosine_metrics,
        "layer3": layer3_metrics,
        "rescued_top2_to_top10": rescued_top2_to_top10,
        "detail_path": str(detail_path),
    }


def fmt_percent(value: float) -> str:
    text = f"{value:.1f}%"
    return text.replace(".0%", "%")


def render_report(results: list[dict[str, Any]], ks: tuple[int, ...], ns: tuple[int, ...]) -> str:
    lines: list[str] = []
    lines.append("# RED-Windows — Stage 3 Layer-3 Sigma-logic validator")
    lines.append("")
    lines.append(
        "> Cosine lọc top-N ứng viên, Layer-3 dùng Hayabusa/fired oracle để xác "
        "nhận rule nào thật sự khớp event. Đây là đánh giá offline trên match "
        "events EVTX đã được Hayabusa xác nhận, không dùng evasion-sinh-từ-match."
    )
    if results:
        lines.append("")
        lines.append(
            f"Split: `{results[0]['split']}`. Dedupe: `{results[0]['dedupe_by']}`. "
            f"Ground truth key: `{results[0]['gt_source']}`."
        )
    lines.append("")
    lines.append("## Cosine Baseline")
    lines.append("")
    lines.append("| Event type | n | Top-1 | Top-3 | Top-5 | Top-10 | Layer-3 cứu được (gt in top2-10) |")
    lines.append("|---|--:|--:|--:|--:|--:|--:|")
    for result in results:
        c = result["cosine"]
        lines.append(
            f"| {result['event_type']} | {result['n']} | "
            f"{fmt_percent(c.get(1, 0.0))} | {fmt_percent(c.get(3, 0.0))} | "
            f"{fmt_percent(c.get(5, 0.0))} | {fmt_percent(c.get(10, 0.0))} | "
            f"{fmt_percent(result['rescued_top2_to_top10'])} |"
        )

    lines.append("")
    lines.append("## Layer-3 Top-1 After Rerank")
    lines.append("")
    header = "| Event type | n | Cosine top-1 | " + " | ".join(f"+Layer-3 @top-{n}" for n in ns) + " |"
    lines.append(header)
    lines.append("|---|--:|--:|" + "|".join("--:" for _ in ns) + "|")
    for result in results:
        cells = [
            result["event_type"],
            str(result["n"]),
            fmt_percent(result["cosine"].get(1, 0.0)),
        ]
        for n in ns:
            cells.append(fmt_percent(result["layer3"][n].get(1, 0.0)))
        lines.append("| " + " | ".join(cells) + " |")

    lines.append("")
    lines.append("## Caveat")
    lines.append("")
    lines.append(
        "- Layer-3 chỉ nâng precision khi event còn có rule thật fire trong top-N cosine. "
        "Với evasion thuần đã xoá hết chữ ký, validator không có gì để xác nhận nên "
        "pipeline rơi về cosine/Agent reasoning."
    )
    lines.append(
        "- Script này dùng oracle từ Hayabusa-confirmed match events để đánh giá. Trong "
        "offline detect_batch hoặc RED Analyst, cùng interface có thể thay bằng Hayabusa "
        "hoặc pySigma chạy trên top-N candidate rules, không quét toàn catalog."
    )

    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    for result in results:
        lines.append(f"- `{result['event_type']}` details: `{result['detail_path']}`")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows Layer-3 top-N Sigma validator")
    parser.add_argument(
        "--event-type",
        choices=["all", *DEFAULT_CONFIGS.keys()],
        default="all",
        help="Event type to evaluate",
    )
    parser.add_argument("--split", choices=["train", "valid", "test"], default="test")
    parser.add_argument("--top-n", type=int, nargs="+", default=list(NS_DEFAULT))
    parser.add_argument("--k", type=int, nargs="+", default=list(KS_DEFAULT))
    parser.add_argument("--detail-top-k", type=int, default=10)
    parser.add_argument(
        "--dedupe-by",
        choices=["sample_rule", "sample", "event"],
        default="sample_rule",
        help=(
            "How to group Hayabusa match JSONs. sample_rule matches the fired "
            "Windows measurement: unique extracted sample + fired rule."
        ),
    )
    parser.add_argument(
        "--gt-source",
        choices=["dir", "title"],
        default="dir",
        help=(
            "Ground-truth rule key. dir matches hayabusa_to_matches.py and RED "
            "model keys; title uses full RuleTitle normalized with normalize_title."
        ),
    )
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--report-name", default="layer3_result.md")
    parser.add_argument("--json-name", default="layer3_result.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(os.path.expanduser(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)
    event_types = list(DEFAULT_CONFIGS) if args.event_type == "all" else [args.event_type]
    ks = tuple(sorted(set(args.k)))
    ns = tuple(sorted(set(args.top_n)))

    results = [
        evaluate_event_type(
            event_type=event_type,
            config_path=DEFAULT_CONFIGS[event_type],
            split=args.split,
            ks=ks,
            ns=ns,
            detail_top_k=args.detail_top_k,
            dedupe_by=args.dedupe_by,
            gt_source=args.gt_source,
            out_dir=out_dir,
        )
        for event_type in event_types
    ]

    report = render_report(results, ks, ns)
    report_path = out_dir / args.report_name
    report_path.write_text(report, encoding="utf-8")

    json_path = out_dir / args.json_name
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"wrote {report_path}")
    print(f"wrote {json_path}")
    for result in results:
        c = result["cosine"]
        l10 = result["layer3"].get(10, {})
        print(
            f"{result['event_type']}: n={result['n']} "
            f"cosine top1={fmt_percent(c.get(1, 0.0))} "
            f"top10={fmt_percent(c.get(10, 0.0))} "
            f"layer3@10 top1={fmt_percent(l10.get(1, 0.0))}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
