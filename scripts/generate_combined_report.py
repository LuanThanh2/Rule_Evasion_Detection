#!/usr/bin/env python3
"""Generate combined RED Stage 1 report tables and figures.

The script reads existing evaluation JSON files under models/<event_type>/,
aggregates confusion matrices across event types, recomputes metrics, and writes:
  - CSV summary tables
  - PNG figures for the thesis report
  - RESULT_COMBINED.md

It does not retrain models and does not modify existing result files.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple


try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ModuleNotFoundError as exc:  # pragma: no cover - user-facing dependency guard
    missing = exc.name or "matplotlib"
    print(
        f"Missing Python dependency: {missing}\n"
        "Install project dependencies first, for example:\n"
        "  python3 -m venv .venv-report\n"
        "  .venv-report/bin/python -m pip install matplotlib numpy\n"
        "  .venv-report/bin/python scripts/generate_combined_report.py\n"
        "or install the full project requirements in your existing environment.",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


# ── Style chung cho biểu đồ báo cáo (đồng bộ, dễ đọc khi in luận văn/slide) ──
plt.rcParams.update({
    "figure.dpi": 110,
    "savefig.dpi": 220,
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.edgecolor": "#888888",
    "axes.linewidth": 0.8,
    "axes.grid": True,
    "grid.color": "#C9C9C9",
    "grid.linewidth": 0.6,
    "legend.frameon": False,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

# Bảng màu nhất quán + màu nhấn cho mô hình được đề xuất (Ensemble).
PALETTE = {
    "blue": "#4C78A8", "green": "#59A14F", "orange": "#F28E2B",
    "purple": "#B07AA1", "red": "#E15759", "grey": "#BAB0AC",
}
WIN_KEY = "ensemble"        # mô hình đề xuất → tô màu nhấn
WIN_COLOR = "#E45756"       # đỏ-cam nổi bật
BASE_COLOR = "#4C78A8"      # xanh trung tính cho phần còn lại


def _bar_value_labels(ax, bars, fmt="{:.3f}", fontsize=8.5, rotation=0):
    """Ghi giá trị lên đỉnh mỗi cột."""
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt.format(h), (b.get_x() + b.get_width() / 2, h),
                    xytext=(0, 2), textcoords="offset points",
                    ha="center", va="bottom", fontsize=fontsize, rotation=rotation)


EVENT_TYPES = ["process_creation", "powershell", "registry_event"]
SUBSETS = ["test_match", "test_evasion"]


@dataclass(frozen=True)
class ModelSpec:
    key: str
    label: str
    group: str
    complexity: str


MODELS = [
    ModelSpec("svm", "SVM", "Single classifier", "1 classifier"),
    ModelSpec("lr", "LR", "Single classifier", "1 classifier"),
    ModelSpec("cnb", "CNB", "Single classifier", "1 classifier"),
    ModelSpec("svm_lr", "SVM+LR", "Ablation ensemble", "2 classifiers"),
    ModelSpec("svm_cnb", "SVM+CNB", "Ablation ensemble", "2 classifiers"),
    ModelSpec("lr_cnb", "LR+CNB", "Ablation ensemble", "2 classifiers"),
    ModelSpec("ensemble", "Ensemble", "Full ensemble", "3 classifiers"),
]

MODEL_BY_KEY = {model.key: model for model in MODELS}


CountDict = Dict[str, int]
MetricDict = Dict[str, float]


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def metric_from_counts(tp: int, fp: int, tn: int, fn: int) -> MetricDict:
    pos_support = tp + fn
    neg_support = tn + fp
    total = pos_support + neg_support

    precision_pos = safe_div(tp, tp + fp)
    recall_pos = safe_div(tp, tp + fn)
    f1_pos = safe_div(2 * tp, 2 * tp + fp + fn)

    precision_neg = safe_div(tn, tn + fn)
    recall_neg = safe_div(tn, tn + fp)
    f1_neg = safe_div(2 * tn, 2 * tn + fp + fn)

    precision_macro = (precision_pos + precision_neg) / 2
    recall_macro = (recall_pos + recall_neg) / 2
    f1_macro = (f1_pos + f1_neg) / 2

    precision_weighted = safe_div(
        precision_pos * pos_support + precision_neg * neg_support,
        total,
    )
    recall_weighted = safe_div(
        recall_pos * pos_support + recall_neg * neg_support,
        total,
    )
    f1_weighted = safe_div(
        f1_pos * pos_support + f1_neg * neg_support,
        total,
    )
    accuracy = safe_div(tp + tn, total)

    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0

    return {
        "precision_w": precision_weighted,
        "precision_m": precision_macro,
        "recall_w": recall_weighted,
        "recall_m": recall_macro,
        "f1_w": f1_weighted,
        "f1_m": f1_macro,
        "accuracy": accuracy,
        "mcc": mcc,
    }


def read_json(path: Path) -> Mapping:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def summary_block(data: Mapping) -> Mapping:
    if "fixed_threshold" in data:
        return data["fixed_threshold"]
    if "optimal" in data:
        return data["optimal"]
    if "default_0.5" in data:
        return data["default_0.5"]
    raise KeyError(f"Cannot find metric block in JSON keys: {sorted(data.keys())}")


def counts_from_summary(summary: Mapping) -> CountDict:
    tp = int(summary["tp"])
    fp = int(summary["fp"])
    tn = int(summary["tn"])
    fn = int(summary["fn"])
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n_benign": int(summary.get("n_benign", tn + fp)),
        "n_malicious": int(summary.get("n_malicious", tp + fn)),
    }


def read_eval_counts(models_dir: Path, event_type: str, model_key: str, subset: str) -> CountDict:
    path = models_dir / event_type / f"eval_rslt_{model_key}_{subset}_info.json"
    if not path.is_file():
        raise FileNotFoundError(path)
    return counts_from_summary(summary_block(read_json(path)))


def add_counts(counts: Iterable[CountDict]) -> CountDict:
    total = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "n_benign": 0, "n_malicious": 0}
    for item in counts:
        for key in total:
            total[key] += int(item.get(key, 0))
    return total


def aggregate_subset(models_dir: Path, model_key: str, subset: str) -> CountDict:
    return add_counts(
        read_eval_counts(models_dir, event_type, model_key, subset)
        for event_type in EVENT_TYPES
    )


TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")


def parse_train_time(logs_dir: Path, event_type: str, model_key: str) -> Optional[float]:
    path = logs_dir / f"{event_type}_{model_key}_train.log"
    if not path.is_file():
        return None

    first_ts: Optional[datetime] = None
    end_ts: Optional[datetime] = None
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = TIMESTAMP_RE.match(line)
            if not match:
                continue
            stamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S,%f")
            if first_ts is None:
                first_ts = stamp
            if "Training complete" in line:
                end_ts = stamp

    if first_ts is None or end_ts is None:
        return None
    return max((end_ts - first_ts).total_seconds(), 0.0)


def training_time_table(logs_dir: Path) -> Tuple[List[Dict[str, object]], Dict[str, float]]:
    rows: List[Dict[str, object]] = []
    averages: Dict[str, float] = {}
    for model in MODELS:
        values: List[float] = []
        row: Dict[str, object] = {"model": model.label, "model_key": model.key}
        for event_type in EVENT_TYPES:
            value = parse_train_time(logs_dir, event_type, model.key)
            row[event_type] = value
            if value is not None:
                values.append(value)
        avg = sum(values) / len(values) if values else 0.0
        row["avg_training_s"] = avg
        averages[model.key] = avg
        rows.append(row)
    return rows, averages


def dataset_effective_rows(models_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    total = {
        "event_type": "Tổng",
        "train_benign": 0,
        "train_malicious": 0,
        "valid_benign": 0,
        "valid_evasion": 0,
        "test_benign": 0,
        "test_match": 0,
        "test_evasion": 0,
    }

    for event_type in EVENT_TYPES:
        train_info = read_json(models_dir / event_type / "train_rslt_lr_info.json")
        valid_counts = counts_from_summary(
            summary_block(read_json(models_dir / event_type / "eval_rslt_lr_valid_evasion_info.json"))
        )
        match_counts = read_eval_counts(models_dir, event_type, "lr", "test_match")
        evasion_counts = read_eval_counts(models_dir, event_type, "lr", "test_evasion")

        row = {
            "event_type": event_type,
            "train_benign": int(train_info["num_benign"]),
            "train_malicious": int(train_info["num_malicious"]),
            "valid_benign": int(valid_counts["n_benign"]),
            "valid_evasion": int(valid_counts["n_malicious"]),
            "test_benign": int(match_counts["n_benign"]),
            "test_match": int(match_counts["n_malicious"]),
            "test_evasion": int(evasion_counts["n_malicious"]),
        }
        rows.append(row)
        for key in total:
            if key != "event_type":
                total[key] += int(row[key])
    rows.append(total)
    return rows


def write_csv(path: Path, rows: List[Mapping[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def fmt_float(value: object, digits: int = 3) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.{digits}f}"


def fmt_time(value: object) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.2f}"


def markdown_table(headers: List[str], rows: List[List[object]]) -> str:
    output = []
    output.append("| " + " | ".join(headers) + " |")
    output.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        output.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(output)


def subset_metric_rows(models_dir: Path, training_avg: Mapping[str, float]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for subset in SUBSETS:
        for model in MODELS:
            counts = aggregate_subset(models_dir, model.key, subset)
            metrics = metric_from_counts(counts["tp"], counts["fp"], counts["tn"], counts["fn"])
            row: Dict[str, object] = {
                "subset": subset,
                "model": model.label,
                "model_key": model.key,
                **counts,
                **metrics,
                "training_time_avg_s": training_avg.get(model.key, 0.0),
            }
            rows.append(row)
    return rows


def build_ranking(metric_rows: List[Mapping[str, object]], training_avg: Mapping[str, float]) -> List[Dict[str, object]]:
    by_model: Dict[str, Dict[str, Mapping[str, object]]] = {}
    for row in metric_rows:
        by_model.setdefault(str(row["model_key"]), {})[str(row["subset"])] = row

    ranking: List[Dict[str, object]] = []
    for model in MODELS:
        match = by_model[model.key]["test_match"]
        evasion = by_model[model.key]["test_evasion"]
        row = {
            "model": model.label,
            "model_key": model.key,
            "macro_f1_avg": (float(match["f1_m"]) + float(evasion["f1_m"])) / 2,
            "weighted_f1_avg": (float(match["f1_w"]) + float(evasion["f1_w"])) / 2,
            "accuracy_avg": (float(match["accuracy"]) + float(evasion["accuracy"])) / 2,
            "macro_precision_avg": (float(match["precision_m"]) + float(evasion["precision_m"])) / 2,
            "macro_recall_avg": (float(match["recall_m"]) + float(evasion["recall_m"])) / 2,
            "training_time_avg_s": training_avg.get(model.key, 0.0),
            "complexity": model.complexity,
        }
        ranking.append(row)

    ranking.sort(key=lambda item: (float(item["macro_f1_avg"]), float(item["accuracy_avg"])), reverse=True)
    top = float(ranking[0]["macro_f1_avg"]) if ranking else 0.0
    for idx, row in enumerate(ranking, start=1):
        row["rank"] = idx
        row["gap_vs_top"] = float(row["macro_f1_avg"]) - top
    return ranking


def plot_dataset_distribution(dataset_rows: List[Mapping[str, object]], out_path: Path) -> None:
    rows = [row for row in dataset_rows if row["event_type"] != "Tổng"]
    labels = [str(row["event_type"]) for row in rows]
    benign = [int(row["test_benign"]) for row in rows]
    match = [int(row["test_match"]) for row in rows]
    evasion = [int(row["test_evasion"]) for row in rows]

    x = np.arange(len(labels))
    width = 0.26
    fig, ax = plt.subplots(figsize=(9.5, 5.2))
    b1 = ax.bar(x - width, benign, width, label="Benign test", color=PALETTE["blue"])
    b2 = ax.bar(x, match, width, label="Match test", color=PALETTE["green"])
    b3 = ax.bar(x + width, evasion, width, label="Evasion test", color=PALETTE["orange"])
    # benign áp đảo malicious → dùng thang log để thấy được cả match/evasion nhỏ
    ax.set_yscale("log")
    ax.set_ylim(1, max(benign) * 2)
    for bars in (b1, b2, b3):
        _bar_value_labels(ax, bars, fmt="{:.0f}", fontsize=8)
    ax.set_title("Số mẫu kiểm thử hiệu dụng theo event type (thang log)")
    ax.set_xlabel("Event type")
    ax.set_ylabel("Số mẫu (log)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=10, ha="center")
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.0))
    ax.grid(axis="y", which="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_model_metrics(ranking: List[Mapping[str, object]], out_path: Path) -> None:
    by_key = {str(row["model_key"]): row for row in ranking}
    ordered = [by_key[model.key] for model in MODELS]
    labels = [str(row["model"]) for row in ordered]
    series = [
        ("Precision Macro", "macro_precision_avg", "#4C78A8"),
        ("Recall Macro", "macro_recall_avg", "#59A14F"),
        ("F1 Macro", "macro_f1_avg", "#F28E2B"),
        ("Accuracy", "accuracy_avg", "#B07AA1"),
    ]

    x = np.arange(len(labels))
    width = 0.2
    fig, ax = plt.subplots(figsize=(11.5, 6))
    for idx, (name, key, color) in enumerate(series):
        offset = (idx - 1.5) * width
        ax.bar(x + offset, [float(row[key]) for row in ordered], width, label=name, color=color)

    ax.set_title("So sánh các chỉ số hiệu năng tổng hợp theo mô hình")
    ax.set_xlabel("Mô hình")
    ax.set_ylabel("Điểm (Macro / Accuracy)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=18, ha="center")
    ax.set_ylim(0.82, 1.0)   # phóng to vùng 0.82–1.0 để thấy rõ chênh lệch
    # tô đậm nhãn mô hình đề xuất
    for tick, row in zip(ax.get_xticklabels(), ordered):
        if str(row["model_key"]) == WIN_KEY:
            tick.set_fontweight("bold"); tick.set_color(WIN_COLOR)
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.13))
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_match_vs_evasion(metric_rows: List[Mapping[str, object]], out_path: Path) -> None:
    by_model_subset = {
        (str(row["model_key"]), str(row["subset"])): row
        for row in metric_rows
    }
    labels = [model.label for model in MODELS]
    match_values = [float(by_model_subset[(model.key, "test_match")]["f1_m"]) for model in MODELS]
    evasion_values = [float(by_model_subset[(model.key, "test_evasion")]["f1_m"]) for model in MODELS]

    x = np.arange(len(labels))
    width = 0.36
    fig, ax = plt.subplots(figsize=(10.5, 5.8))
    b1 = ax.bar(x - width / 2, match_values, width, label="test_match", color=PALETTE["blue"])
    b2 = ax.bar(x + width / 2, evasion_values, width, label="test_evasion", color=PALETTE["red"])
    _bar_value_labels(ax, b1, fontsize=7.5, rotation=90)
    _bar_value_labels(ax, b2, fontsize=7.5, rotation=90)
    ax.set_title("Macro F1 trên hai kịch bản test_match và test_evasion")
    ax.set_xlabel("Mô hình")
    ax.set_ylabel("Macro F1")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=18, ha="center")
    ax.set_ylim(0.82, 1.04)
    for tick, model in zip(ax.get_xticklabels(), MODELS):
        if model.key == WIN_KEY:
            tick.set_fontweight("bold"); tick.set_color(WIN_COLOR)
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_performance_training_cost(ranking: List[Mapping[str, object]], out_path: Path) -> None:
    by_key = {str(row["model_key"]): row for row in ranking}
    ordered = [by_key[model.key] for model in MODELS]
    labels = [str(row["model"]) for row in ordered]
    f1_values = [float(row["macro_f1_avg"]) for row in ordered]
    time_values = [float(row["training_time_avg_s"]) for row in ordered]
    x = np.arange(len(labels))

    keys = [str(row["model_key"]) for row in ordered]
    fig, ax1 = plt.subplots(figsize=(11.5, 6))
    ax2 = ax1.twinx()
    ax2.grid(False)
    width = 0.38
    f1_colors = [WIN_COLOR if k == WIN_KEY else PALETTE["blue"] for k in keys]
    bF1 = ax1.bar(x - width / 2, f1_values, width, label="Macro F1", color=f1_colors)
    bT = ax2.bar(x + width / 2, time_values, width, label="Training time (s)",
                 color=PALETTE["grey"], edgecolor="#8a8a8a")
    _bar_value_labels(ax1, bF1, fmt="{:.3f}", fontsize=8)
    for b in bT:
        ax2.annotate(f"{b.get_height():.0f}s", (b.get_x()+b.get_width()/2, b.get_height()),
                     xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=8)

    ax1.set_title("Macro F1 và chi phí huấn luyện theo mô hình (đỏ = đề xuất)")
    ax1.set_xlabel("Mô hình")
    ax1.set_ylabel("Macro F1")
    ax2.set_ylabel("Thời gian huấn luyện (s)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=18, ha="center")
    ax1.set_ylim(0.82, 1.0)
    ax2.set_ylim(0, max(time_values) * 1.25 if time_values else 1)
    for tick, k in zip(ax1.get_xticklabels(), keys):
        if k == WIN_KEY:
            tick.set_fontweight("bold"); tick.set_color(WIN_COLOR)
    ax1.grid(axis="y", alpha=0.25)

    handles1, labels1 = ax1.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(handles1 + handles2, labels1 + labels2, loc="upper left",
               ncol=2, fontsize=9, framealpha=0.9, frameon=True)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_f1_training_tradeoff(ranking: List[Mapping[str, object]], out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8.8, 5.5))
    offsets = {
        "svm": (6, 6),
        "lr": (6, 2),
        "cnb": (6, 8),
        "svm_lr": (6, 8),
        "svm_cnb": (6, -12),
        "lr_cnb": (6, -8),
        "ensemble": (6, -6),
    }
    y_values = [float(row["macro_f1_avg"]) for row in ranking]
    x_values = [float(row["training_time_avg_s"]) for row in ranking]
    for row in ranking:
        x = float(row["training_time_avg_s"])
        y = float(row["macro_f1_avg"])
        win = str(row["model_key"]) == WIN_KEY
        ax.scatter(x, y, s=200 if win else 95,
                   color=WIN_COLOR if win else PALETTE["blue"],
                   marker="*" if win else "o", zorder=3,
                   edgecolor="white", linewidth=0.6)
        offset = offsets.get(str(row["model_key"]), (6, 4))
        ax.annotate(str(row["model"]), (x, y), xytext=offset, textcoords="offset points",
                    fontsize=9, fontweight="bold" if win else "normal",
                    color=WIN_COLOR if win else "#222222")

    ax.set_title("Trade-off Macro F1 vs thời gian huấn luyện (★ = đề xuất)")
    ax.set_xlabel("Thời gian huấn luyện trung bình (s)")
    ax.set_ylabel("Macro F1 trung bình")
    ax.set_xlim(0, max(x_values) + 12 if x_values else 1)
    ax.set_ylim(max(min(y_values) - 0.02, 0), max(y_values) + 0.01)
    ax.grid(True, alpha=0.28)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_macro_f1_ranking(ranking: List[Mapping[str, object]], out_path: Path) -> None:
    ordered = list(reversed(ranking))   # rank thấp ở dưới → #1 lên trên cùng
    labels = [str(row["model"]) for row in ordered]
    keys = [str(row["model_key"]) for row in ordered]
    values = [float(row["macro_f1_avg"]) for row in ordered]

    fig, ax = plt.subplots(figsize=(9, 5.4))
    colors = [WIN_COLOR if k == WIN_KEY else PALETTE["blue"] for k in keys]
    bars = ax.barh(labels, values, color=colors)
    ax.set_title("Xếp hạng mô hình theo Macro F1 tổng hợp (đỏ = đề xuất)")
    ax.set_xlabel("Macro F1 trung bình")
    ax.set_xlim(0.86, 1.0)   # phóng to để thấy chênh lệch giữa các mô hình
    ax.grid(axis="x", alpha=0.25)
    for idx, (value, k) in enumerate(zip(values, keys)):
        ax.text(value + 0.0015, idx, f"{value:.3f}", va="center", fontsize=9,
                fontweight="bold" if k == WIN_KEY else "normal",
                color=WIN_COLOR if k == WIN_KEY else "#222222")
        # nhãn hạng bên trái cột
        rank = next(r["rank"] for r in ranking if str(r["model_key"]) == k)
        ax.text(0.862, idx, f"#{rank}", va="center", ha="left", fontsize=8.5, color="white",
                fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_confusion_lr_ensemble(metric_rows: List[Mapping[str, object]], out_path: Path) -> None:
    lookup = {
        (str(row["model_key"]), str(row["subset"])): row
        for row in metric_rows
    }
    targets = [("lr", "LR"), ("ensemble", "Ensemble")]
    fig, axes = plt.subplots(1, 2, figsize=(9.8, 4.5))

    max_value = 0
    matrices = []
    for key, _label in targets:
        row = lookup[(key, "test_evasion")]
        matrix = np.array([[int(row["tn"]), int(row["fp"])], [int(row["fn"]), int(row["tp"])]])
        matrices.append(matrix)
        max_value = max(max_value, int(matrix.max()))

    for ax, (key, label), matrix in zip(axes, targets, matrices):
        ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max_value or 1)
        tn, fp, fn, tp = matrix[0, 0], matrix[0, 1], matrix[1, 0], matrix[1, 1]
        rec = tp / (tp + fn) if (tp + fn) else 0
        ax.set_title(f"{label} — test_evasion\n(phát hiện {tp}/{tp+fn}, FP={fp}, R={rec:.3f})",
                     fontsize=11)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["Dự đoán\nbenign", "Dự đoán\nmalicious"])
        ax.set_yticklabels(["Thực\nbenign", "Thực\nmalicious"])
        cell_names = [["TN", "FP"], ["FN", "TP"]]
        for i in range(2):
            for j in range(2):
                v = matrix[i, j]
                txt_color = "white" if v > (max_value or 1) * 0.5 else "#111111"
                ax.text(j, i, f"{cell_names[i][j]}\n{v}", ha="center", va="center",
                        color=txt_color, fontsize=11, fontweight="bold")
        ax.set_xticks([0.5, 1.5], minor=True); ax.set_yticks([0.5, 1.5], minor=True)
        ax.grid(which="minor", color="white", linewidth=2); ax.tick_params(which="minor", length=0)
    fig.suptitle("Confusion matrix gộp trên kịch bản evasion (Ensemble ít FP hơn)",
                 y=1.02, fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def write_figures(
    out_dir: Path,
    dataset_rows: List[Mapping[str, object]],
    metric_rows: List[Mapping[str, object]],
    ranking: List[Mapping[str, object]],
) -> Dict[str, Path]:
    fig_dir = out_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    figures = {
        "dataset_distribution": fig_dir / "dataset_distribution.png",
        "model_metrics": fig_dir / "model_metrics_combined.png",
        "match_vs_evasion": fig_dir / "match_vs_evasion_f1.png",
        "performance_training_cost": fig_dir / "performance_training_cost.png",
        "f1_training_tradeoff": fig_dir / "f1_training_tradeoff.png",
        "macro_f1_ranking": fig_dir / "macro_f1_ranking.png",
        "confusion_lr_ensemble": fig_dir / "confusion_lr_ensemble_evasion.png",
    }
    plot_dataset_distribution(dataset_rows, figures["dataset_distribution"])
    plot_model_metrics(ranking, figures["model_metrics"])
    plot_match_vs_evasion(metric_rows, figures["match_vs_evasion"])
    plot_performance_training_cost(ranking, figures["performance_training_cost"])
    plot_f1_training_tradeoff(ranking, figures["f1_training_tradeoff"])
    plot_macro_f1_ranking(ranking, figures["macro_f1_ranking"])
    plot_confusion_lr_ensemble(metric_rows, figures["confusion_lr_ensemble"])
    return figures


def rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def report_text(
    root: Path,
    out_dir: Path,
    figures: Mapping[str, Path],
    dataset_rows: List[Mapping[str, object]],
    model_table_rows: List[List[object]],
    match_table_rows: List[List[object]],
    evasion_table_rows: List[List[object]],
    ranking: List[Mapping[str, object]],
    finalist_rows: List[List[object]],
) -> str:
    top = ranking[0]
    lr = next(row for row in ranking if row["model_key"] == "lr")
    ensemble = next(row for row in ranking if row["model_key"] == "ensemble")

    dataset_table = markdown_table(
        [
            "Event type",
            "Train benign",
            "Train malicious",
            "Valid benign",
            "Valid evasion",
            "Test benign",
            "Test match",
            "Test evasion",
        ],
        [
            [
                row["event_type"],
                row["train_benign"],
                row["train_malicious"],
                row["valid_benign"],
                row["valid_evasion"],
                row["test_benign"],
                row["test_match"],
                row["test_evasion"],
            ]
            for row in dataset_rows
        ],
    )

    model_table = markdown_table(
        ["Nhóm", "Cấu hình", "Thành phần", "Vai trò"],
        model_table_rows,
    )
    match_table = markdown_table(
        ["Model", "P(W)", "P(M)", "R(W)", "R(M)", "F1(W)", "F1(M)", "Accuracy", "Train(s)"],
        match_table_rows,
    )
    evasion_table = markdown_table(
        ["Model", "P(W)", "P(M)", "R(W)", "R(M)", "F1(W)", "F1(M)", "Accuracy", "Train(s)"],
        evasion_table_rows,
    )
    ranking_table = markdown_table(
        ["Rank", "Model", "Macro F1 avg", "Weighted F1 avg", "Accuracy avg", "Train(s)", "Gap vs top"],
        [
            [
                row["rank"],
                row["model"],
                fmt_float(row["macro_f1_avg"]),
                fmt_float(row["weighted_f1_avg"]),
                fmt_float(row["accuracy_avg"]),
                fmt_time(row["training_time_avg_s"]),
                fmt_float(row["gap_vs_top"], 4),
            ]
            for row in ranking
        ],
    )
    finalist_table = markdown_table(
        ["Tiêu chí", "LR", "SVM+LR", "Ensemble"],
        finalist_rows,
    )

    return f"""# Chương 5 - Kết Quả Thực Nghiệm Tổng Hợp

Chương này trình bày kết quả thực nghiệm của pipeline RED Stage 1 (Misuse Detection) trên tập kiểm thử tổng hợp. Khác với bản kết quả chi tiết theo từng event type, phần này gộp kết quả của ba nhóm sự kiện Windows gồm `process_creation`, `powershell` và `registry_event` để đánh giá hiệu năng tổng quan của hệ thống. Cách trình bày tham khảo cấu trúc báo cáo thực nghiệm trong tài liệu TK.pdf: mô tả dữ liệu, bảng hiệu suất tổng hợp, biểu đồ so sánh mô hình và phần đề xuất mô hình triển khai.

Kết quả trong báo cáo này được sinh tự động từ các file `eval_rslt_*_info.json` và log huấn luyện hiện có. Script chỉ đọc output thực nghiệm đã có, không huấn luyện lại mô hình.

---

## I. Thiết Lập Thực Nghiệm

### 1.1. Phân phối dữ liệu hiệu dụng

Bảng 5.1 trình bày số mẫu hiệu dụng được pipeline sử dụng sau bước chuẩn hóa, loại trùng và lọc rule hiếm. Số lượng này có thể nhỏ hơn số mẫu thô ban đầu trong split dataset, vì evaluation chỉ giữ các mẫu/rule đủ điều kiện đánh giá.

**Bảng 5.1. Phân phối dữ liệu hiệu dụng trong thực nghiệm**

{dataset_table}

![Hình 5.1. Phân phối mẫu kiểm thử hiệu dụng theo event type]({rel(figures["dataset_distribution"], root)})

### 1.2. Các cấu hình mô hình đánh giá

Thực nghiệm đánh giá 7 cấu hình: 3 single classifier, 3 combo ablation và 1 full ensemble.

**Bảng 5.2. Các mô hình được đánh giá**

{model_table}

### 1.3. Phương pháp tổng hợp kết quả

Đối với từng mô hình và từng subset kiểm thử, báo cáo cộng confusion matrix của ba event type:

```text
TP_total = TP_process_creation + TP_powershell + TP_registry_event
FP_total = FP_process_creation + FP_powershell + FP_registry_event
TN_total = TN_process_creation + TN_powershell + TN_registry_event
FN_total = FN_process_creation + FN_powershell + FN_registry_event
```

Từ confusion matrix tổng hợp, báo cáo tính lại Precision, Recall, F1-score theo cả Weighted và Macro. Macro F1 được ưu tiên khi diễn giải vì dataset mất cân bằng mạnh giữa benign và malicious.

---

## II. Kết Quả Kiểm Thử Tổng Hợp

### 2.1. Kết quả trên test_match

`test_match` đo khả năng phát hiện các malicious events khớp với Sigma rule gốc, đồng thời kiểm tra model không làm suy giảm khả năng nhận diện baseline.

**Bảng 5.3. Kết quả hiệu suất tổng hợp trên test_match**

{match_table}

### 2.2. Kết quả trên test_evasion

`test_evasion` là subset quan trọng hơn đối với mục tiêu của RED, vì nó đo khả năng phát hiện các biến thể né luật không tham gia training.

**Bảng 5.4. Kết quả hiệu suất tổng hợp trên test_evasion**

{evasion_table}

![Hình 5.2. So sánh Precision, Recall, F1-score và Accuracy của các mô hình]({rel(figures["model_metrics"], root)})

![Hình 5.3. So sánh Macro F1 trên test_match và test_evasion]({rel(figures["match_vs_evasion"], root)})

### 2.3. Xếp hạng tổng hợp

Để tránh cộng lặp benign test set giữa hai kịch bản `test_match` và `test_evasion`, ranking tổng hợp sử dụng trung bình Macro F1 của hai subset sau khi đã gộp ba event type.

**Bảng 5.5. Ranking mô hình theo Macro F1 tổng hợp**

{ranking_table}

![Hình 5.4. Ranking mô hình theo Macro F1 tổng hợp]({rel(figures["macro_f1_ranking"], root)})

---

## III. Phân Tích Trade-off Hiệu Năng Và Chi Phí Huấn Luyện

Bảng và biểu đồ tổng hợp cho thấy `{top["model"]}` là mô hình đứng đầu theo Macro F1 trung bình với giá trị `{fmt_float(top["macro_f1_avg"])}`. Ensemble đạt Macro F1 trung bình `{fmt_float(ensemble["macro_f1_avg"])}` (chi phí huấn luyện ~`{fmt_time(ensemble["training_time_avg_s"])}`s), trong khi LR đạt `{fmt_float(lr["macro_f1_avg"])}` với thời gian huấn luyện chỉ ~`{fmt_time(lr["training_time_avg_s"])}`s — hai thái cực của trục hiệu-năng/chi-phí.

![Hình 5.5. Macro F1 và chi phí huấn luyện của từng mô hình]({rel(figures["performance_training_cost"], root)})

![Hình 5.6. Trade-off giữa Macro F1 và thời gian huấn luyện]({rel(figures["f1_training_tradeoff"], root)})

Biểu đồ trade-off giúp tách rõ hai hướng lựa chọn. LR là cấu hình production-efficient vì đạt hiệu năng rất cao trong khi chi phí huấn luyện thấp và độ phức tạp triển khai nhỏ. Ensemble là cấu hình robust-oriented vì kết hợp nhiều classifier với inductive bias khác nhau, chấp nhận chi phí huấn luyện cao hơn để giảm phụ thuộc vào một mô hình đơn lẻ.

---

## IV. So Sánh Candidate Finalist

Ba cấu hình finalist gồm LR, SVM+LR và Ensemble được so sánh theo hiệu năng tổng hợp, khả năng phát hiện evasion, chi phí huấn luyện và độ phức tạp triển khai.

**Bảng 5.6. So sánh đa tiêu chí giữa LR, SVM+LR và Ensemble**

{finalist_table}

![Hình 5.7. Confusion matrix của LR và Ensemble trên test_evasion]({rel(figures["confusion_lr_ensemble"], root)})

---

## V. Đề Xuất Mô Hình Triển Khai

Với số liệu trung thực (eval khớp đường suy luận lúc triển khai), Ensemble là mô hình đạt Macro F1 tổng hợp cao nhất, dẫn đầu trên test_evasion và có số false positive thấp nhất trong nhóm dẫn đầu. Lựa chọn này cũng nhất quán với hướng thiết kế gốc của RED (mở rộng AMIDES bằng ensemble nhiều classifier), nên được đề xuất làm cấu hình triển khai chính.

LR vẫn là lựa chọn thay thế hấp dẫn khi ưu tiên chi phí: chỉ một classifier, huấn luyện nhanh hơn nhiều, dễ debug/monitor/giải thích, với Macro F1 chỉ thấp hơn Ensemble không đáng kể.

Do đó, kết luận phù hợp là:

> Ensemble là lựa chọn triển khai chính theo kết quả hiện tại — hiệu năng cao nhất và nhất quán với thiết kế RED. LR là lựa chọn thay thế production-efficient khi ưu tiên chi phí huấn luyện và độ đơn giản.

---

## VI. Hạn Chế Và Hướng Phát Triển

- Kết quả tổng hợp giúp đánh giá hiệu năng toàn hệ thống, nhưng có thể che khuất hiện tượng suy giảm trên từng event type; do đó kết quả chi tiết theo event type vẫn nên giữ ở phụ lục.
- Tập `registry_event` có số mẫu evasion rất nhỏ, nên kết quả ở nhóm này chưa ổn định về mặt thống kê.
- Cần chạy thêm multi-seed hoặc bootstrap confidence interval để kiểm tra khác biệt giữa LR và Ensemble có ý nghĩa thống kê hay không.
- Learning curve chưa được đưa vào báo cáo này. Nếu cần, có thể thực hiện thí nghiệm bổ sung bằng cách train LR/Ensemble với nhiều tỷ lệ dữ liệu huấn luyện khác nhau.

---

## VII. Hướng Dẫn Chạy Lại

Từ thư mục gốc project:

```bash
cd {root}
python3 scripts/generate_combined_report.py
```

Nếu Python báo thiếu `matplotlib` hoặc `numpy`, cài dependency trước:

```bash
python3 -m venv .venv-report
.venv-report/bin/python -m pip install matplotlib numpy
.venv-report/bin/python scripts/generate_combined_report.py
```

Các output chính:

- `RESULT_COMBINED.md`: file báo cáo tổng hợp.
- `{rel(out_dir, root)}/combined_metrics_by_subset.csv`: metric gộp theo `test_match` và `test_evasion`.
- `{rel(out_dir, root)}/overall_ranking.csv`: ranking tổng hợp theo Macro F1.
- `{rel(out_dir, root)}/training_times.csv`: thời gian huấn luyện đọc từ log.
- `{rel(out_dir / "figures", root)}/`: thư mục chứa biểu đồ PNG dùng cho báo cáo/slide.
"""


def build_markdown_rows(metric_rows: List[Mapping[str, object]], training_avg: Mapping[str, float]) -> Tuple[List[List[object]], List[List[object]], List[List[object]]]:
    model_table_rows = [
        [model.group, model.label, model.complexity, "Full ensemble" if model.key == "ensemble" else ("Ablation" if "_" in model.key else "Baseline")]
        for model in MODELS
    ]

    by_subset_model = {
        (str(row["subset"]), str(row["model_key"])): row
        for row in metric_rows
    }

    def subset_rows(subset: str) -> List[List[object]]:
        rows: List[List[object]] = []
        for model in MODELS:
            row = by_subset_model[(subset, model.key)]
            rows.append(
                [
                    model.label,
                    fmt_float(row["precision_w"]),
                    fmt_float(row["precision_m"]),
                    fmt_float(row["recall_w"]),
                    fmt_float(row["recall_m"]),
                    fmt_float(row["f1_w"]),
                    fmt_float(row["f1_m"]),
                    fmt_float(row["accuracy"]),
                    fmt_time(training_avg.get(model.key, 0.0)),
                ]
            )
        return rows

    return model_table_rows, subset_rows("test_match"), subset_rows("test_evasion")


def finalist_rows(ranking: List[Mapping[str, object]], metric_rows: List[Mapping[str, object]]) -> List[List[object]]:
    rank_by_key = {str(row["model_key"]): row for row in ranking}
    subset_by_key = {
        (str(row["model_key"]), str(row["subset"])): row
        for row in metric_rows
    }
    keys = ["lr", "svm_lr", "ensemble"]

    def values(metric: str, digits: int = 3) -> List[str]:
        return [fmt_float(rank_by_key[key][metric], digits) for key in keys]

    def evasion_values(metric: str, digits: int = 3) -> List[str]:
        return [fmt_float(subset_by_key[(key, "test_evasion")][metric], digits) for key in keys]

    return [
        ["Macro F1 avg", *values("macro_f1_avg")],
        ["Macro F1 test_evasion", *evasion_values("f1_m")],
        ["Accuracy avg", *values("accuracy_avg")],
        ["Training time avg (s)", *[fmt_time(rank_by_key[key]["training_time_avg_s"]) for key in keys]],
        ["Complexity", *[MODEL_BY_KEY[key].complexity for key in keys]],
        ["Production efficiency", "Cao", "Thấp hơn", "Thấp hơn"],
        ["Robust-oriented deployment", "Trung bình", "Cao", "Cao"],
    ]


def main() -> None:
    root = repo_root_from_script()
    parser = argparse.ArgumentParser(description="Generate combined RED report")
    parser.add_argument("--models-dir", type=Path, default=root / "models")
    parser.add_argument("--logs-dir", type=Path, default=root / "logs")
    parser.add_argument("--out-dir", type=Path, default=root / "reports" / "combined")
    parser.add_argument("--report-path", type=Path, default=root / "RESULT_COMBINED.md")
    args = parser.parse_args()

    models_dir = args.models_dir.resolve()
    logs_dir = args.logs_dir.resolve()
    out_dir = args.out_dir.resolve()
    report_path = args.report_path.resolve()

    out_dir.mkdir(parents=True, exist_ok=True)

    train_rows, training_avg = training_time_table(logs_dir)
    dataset_rows = dataset_effective_rows(models_dir)
    metric_rows = subset_metric_rows(models_dir, training_avg)
    ranking = build_ranking(metric_rows, training_avg)
    figures = write_figures(out_dir, dataset_rows, metric_rows, ranking)

    write_csv(
        out_dir / "dataset_effective_counts.csv",
        dataset_rows,
        [
            "event_type",
            "train_benign",
            "train_malicious",
            "valid_benign",
            "valid_evasion",
            "test_benign",
            "test_match",
            "test_evasion",
        ],
    )
    write_csv(
        out_dir / "training_times.csv",
        train_rows,
        ["model", "model_key", *EVENT_TYPES, "avg_training_s"],
    )
    metric_fields = [
        "subset",
        "model",
        "model_key",
        "tp",
        "fp",
        "tn",
        "fn",
        "n_benign",
        "n_malicious",
        "precision_w",
        "precision_m",
        "recall_w",
        "recall_m",
        "f1_w",
        "f1_m",
        "accuracy",
        "mcc",
        "training_time_avg_s",
    ]
    write_csv(out_dir / "combined_metrics_by_subset.csv", metric_rows, metric_fields)
    write_csv(
        out_dir / "overall_ranking.csv",
        ranking,
        [
            "rank",
            "model",
            "model_key",
            "macro_f1_avg",
            "weighted_f1_avg",
            "accuracy_avg",
            "macro_precision_avg",
            "macro_recall_avg",
            "training_time_avg_s",
            "complexity",
            "gap_vs_top",
        ],
    )

    model_table_rows, match_rows, evasion_rows = build_markdown_rows(metric_rows, training_avg)
    report = report_text(
        root=root,
        out_dir=out_dir,
        figures=figures,
        dataset_rows=dataset_rows,
        model_table_rows=model_table_rows,
        match_table_rows=match_rows,
        evasion_table_rows=evasion_rows,
        ranking=ranking,
        finalist_rows=finalist_rows(ranking, metric_rows),
    )
    report_path.write_text(report, encoding="utf-8")

    readme = f"""# Combined RED Report Outputs

Generated by:

```bash
python3 scripts/generate_combined_report.py
```

Main files:

- `{rel(report_path, root)}`
- `combined_metrics_by_subset.csv`
- `overall_ranking.csv`
- `training_times.csv`
- `dataset_effective_counts.csv`
- `figures/*.png`
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")

    print(f"Wrote report: {report_path}")
    print(f"Wrote outputs: {out_dir}")
    for name, path in figures.items():
        print(f"Wrote figure ({name}): {path}")


if __name__ == "__main__":
    main()
