"""Score a results file: precision, recall, false positive rate, and AUROC."""

from __future__ import annotations

import json
from pathlib import Path

THRESHOLDS = [0.2, 0.5, 0.8, 0.9, 0.95, 0.99]
REVIEW_PATH = Path("labels/phishing_review.jsonl")


def load_review(path: Path = REVIEW_PATH) -> dict[str, dict]:
    """Load the manual review of the phishing feed labels, keyed by site."""
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return {row["site"]: row for row in map(json.loads, handle)}


def apply_review(results: list[dict], review: dict[str, dict]) -> list[dict]:
    """Keep a phishing result only if the review confirmed live phishing on its site.

    Feed labels are noisy: some sites are dead, some hide from scanners, and some
    were never phishing. Duplicates (www and non-www of one site) are removed too.
    Benign results do not change.
    """
    kept = []
    for result in results:
        if result["label"] == "phishing":
            verdict = review.get(result["site"])
            if not verdict or verdict["verdict"] != "phishing" or verdict["duplicate_of"]:
                continue
        kept.append(result)
    return kept


def _latest_answers(results: list[dict]) -> list[dict]:
    """Keep the last answered line for each page id."""
    by_id = {}
    for result in results:
        if result.get("probability") is not None:
            by_id[result["id"]] = result
    return list(by_id.values())


def auroc(positives: list[float], negatives: list[float]) -> float | None:
    """Probability that a random phishing page gets a higher score than a random benign page."""
    if not positives or not negatives:
        return None
    ranked = sorted([(p, 1) for p in positives] + [(n, 0) for n in negatives])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        average_rank = (i + 1 + j) / 2  # Ties share the average rank.
        rank_sum += average_rank * sum(is_pos for _, is_pos in ranked[i:j])
        i = j
    n_pos, n_neg = len(positives), len(negatives)
    return (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def at_threshold(positives: list[float], negatives: list[float], threshold: float) -> dict:
    tp = sum(p >= threshold for p in positives)
    fp = sum(n >= threshold for n in negatives)
    fn = len(positives) - tp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / len(positives) if positives else None
    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": len(negatives) - fp,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fp / len(negatives) if negatives else None,
    }


def score(results: list[dict]) -> dict:
    answers = _latest_answers(results)
    positives = [r["probability"] for r in answers if r["label"] == "phishing"]
    negatives = [r["probability"] for r in answers if r["label"] == "benign"]
    return {
        "phishing_pages": len(positives),
        "benign_pages": len(negatives),
        "refused": len({r["id"] for r in results if r.get("refused")}),
        "errors": sum(1 for r in results if r.get("error")),
        "input_tokens": sum(r.get("input_tokens", 0) for r in results),
        "cost_usd": round(sum(r.get("cost_usd", 0.0) for r in results), 4),
        "auroc": auroc(positives, negatives),
        "thresholds": [at_threshold(positives, negatives, t) for t in THRESHOLDS],
    }


def _pct(value: float | None) -> str:
    return "   n/a" if value is None else f"{value * 100:5.1f}%"


def format_report(title: str, summary: dict) -> str:
    area = summary["auroc"]
    lines = [
        title,
        f"  pages: {summary['phishing_pages']} phishing, {summary['benign_pages']} benign"
        f" | refused: {summary['refused']} | errors: {summary['errors']}",
        f"  input tokens: {summary['input_tokens']:,} | cost: ${summary['cost_usd']:.4f}",
        f"  AUROC: {'n/a' if area is None else f'{area:.3f}'}",
        "  threshold  precision  recall  false-positive rate   TP   FP   FN   TN",
    ]
    for row in summary["thresholds"]:
        lines.append(
            f"  {row['threshold']:>9.2f}  {_pct(row['precision']):>9}  {_pct(row['recall']):>6}"
            f"  {_pct(row['false_positive_rate']):>19}"
            f"  {row['tp']:>3}  {row['fp']:>3}  {row['fn']:>3}  {row['tn']:>3}"
        )
    return "\n".join(lines)
