"""Rule attribution: per-rule SVM classifiers for evasion-to-rule mapping.

Trains one binary SVC per Sigma rule (benign vs. rule_X filter/matches),
then for each evasion event, scores it against all rule models and ranks
by decision_function value to find the most likely evaded rule.

Evaluation metrics: top-k hit rate (k=1, 5, 10, ..., N).
"""

import logging
import numpy as np
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class RuleAttributionEvaluation:
    """Evaluate rule attribution by checking where the true evaded rule
    ranks in the sorted attribution list.

    Attributes
    ----------
    top_n_hits : np.ndarray
        Count of evasions where true rule is at exactly rank k (0-indexed).
    top_n_hit_rates : np.ndarray
        Fraction of hits at each rank.
    """

    def __init__(self, num_rules: int):
        self.num_rules = num_rules
        self.top_n_hits = np.zeros(num_rules)
        self.top_n_hit_rates = np.zeros(num_rules)
        self.num_total = 0
        self.num_misses = 0
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0

    def evaluate_single(self, true_rule: str, ranked_attributions: List[Tuple[str, float]]):
        """Evaluate a single evasion sample.

        Parameters
        ----------
        true_rule : str or None
            Name of the truly evaded rule (None if unknown / benign).
        ranked_attributions : list of (rule_name, score) or None
            Rules sorted by decision_function score descending.
            None if no rule models matched.
        """
        self.num_total += 1

        if true_rule is not None and ranked_attributions is not None:
            self.tp += 1
            self._record_rank(true_rule, ranked_attributions)
        elif true_rule is not None and ranked_attributions is None:
            self.fn += 1
        elif true_rule is None and ranked_attributions is not None:
            self.fp += 1
        else:
            self.tn += 1

    def calculate_hit_rates(self):
        """Convert hit counts to rates (call after all samples processed)."""
        total_hits = self.top_n_hits.sum()
        if total_hits > 0:
            self.top_n_hit_rates = self.top_n_hits / total_hits

    def summary(self) -> dict:
        """Return evaluation summary."""
        cumulative = np.cumsum(self.top_n_hit_rates)
        return {
            "num_rules": self.num_rules,
            "num_total_samples": self.num_total,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "num_misses": self.num_misses,
            "top_1_hit_rate": float(self.top_n_hit_rates[0]) if len(self.top_n_hit_rates) > 0 else 0,
            "top_1_cumulative": float(cumulative[0]) if len(cumulative) > 0 else 0,
            "top_5_cumulative": float(cumulative[min(4, len(cumulative) - 1)]) if len(cumulative) > 0 else 0,
            "top_10_cumulative": float(cumulative[min(9, len(cumulative) - 1)]) if len(cumulative) > 0 else 0,
        }

    def _record_rank(self, true_rule, ranked_attributions):
        sorted_names = [name for name, _ in ranked_attributions]
        for idx in range(min(self.num_rules, len(sorted_names))):
            if true_rule == sorted_names[idx]:
                self.top_n_hits[idx] += 1
                return
        self.num_misses += 1


def score_evasion(
    sample_vector,
    rule_models: Dict[str, dict],
) -> List[Tuple[str, float]]:
    """Score a single evasion sample against all rule models.

    Parameters
    ----------
    sample_vector : array-like
        Feature vector of the evasion sample (already transformed).
    rule_models : dict
        Mapping rule_name → {"estimator": SVC, "vectorizer": ..., "scaler": ...}.
        For pre-transformed input, only "estimator" is needed.

    Returns
    -------
    list of (rule_name, score)
        Sorted by score descending.
    """
    scores = {}
    for rule_name, model in rule_models.items():
        estimator = model["estimator"]
        df_val = estimator.decision_function(sample_vector)
        # df_val may be an array if sample_vector has >1 sample
        if hasattr(df_val, "__len__"):
            scores[rule_name] = float(df_val[0])
        else:
            scores[rule_name] = float(df_val)

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked


def process_evasions_batch(
    normalized_samples: List[str],
    evasion_to_rule: Dict[str, str],
    rule_models: Dict[str, dict],
) -> Tuple[RuleAttributionEvaluation, list]:
    """Score all evasion samples and evaluate rule attribution.

    Parameters
    ----------
    normalized_samples : list of str
        Normalized evasion command lines (sorted to match evasion_to_rule keys).
    evasion_to_rule : dict
        Mapping evasion_cmdline → true_rule_name.
    rule_models : dict
        Mapping rule_name → {"estimator": SVC, "vectorizer": vectorizer}.

    Returns
    -------
    evaluation : RuleAttributionEvaluation
        Evaluation results.
    all_results : list of (true_rule, ranked_attributions)
        Per-sample results.
    """
    eval_result = RuleAttributionEvaluation(num_rules=len(rule_models))
    all_results = []

    # Score each sample against all rule models
    # For efficiency: transform all samples per rule-model at once
    sample_results = [{} for _ in normalized_samples]

    for rule_name, model in rule_models.items():
        vectorizer = model["vectorizer"]
        estimator = model["estimator"]

        transformed = vectorizer.transform(normalized_samples)
        df_values = estimator.decision_function(transformed)

        for i in range(len(normalized_samples)):
            sample_results[i][rule_name] = float(df_values[i])

    # Rank and evaluate
    sorted_samples = sorted(evasion_to_rule.keys())
    for i, sample in enumerate(sorted_samples):
        true_rule = evasion_to_rule[sample]
        ranked = sorted(sample_results[i].items(), key=lambda x: x[1], reverse=True)
        eval_result.evaluate_single(true_rule, ranked)
        all_results.append((true_rule, ranked))

    eval_result.calculate_hit_rates()
    logger.info("Attribution evaluation: %s", eval_result.summary())

    return eval_result, all_results
