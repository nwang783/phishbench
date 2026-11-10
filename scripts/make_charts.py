"""Make the README charts from the results and the reviewed labels.

Run:  uv run --group charts python scripts/make_charts.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from phishbench.run import load_results
from phishbench.score import apply_review, at_threshold, load_review

MODEL = "openai-decisions"
OUT = Path("docs/charts")
THRESHOLD = 0.5

SURFACE, INK, INK_2, MUTED = "#fcfcfb", "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
BLUE, ORANGE = "#2a78d6", "#eb6834"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Inter", "Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "font.size": 11,
    "text.color": INK,
    "axes.labelcolor": INK_2,
    "xtick.color": INK_2,
    "ytick.color": MUTED,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
})


def _axes(width: float = 8.0, height: float = 4.4):
    fig, ax = plt.subplots(figsize=(width, height))
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    return fig, ax


def _title(fig, title: str) -> None:
    fig.text(0.02, 0.96, title, fontsize=14, fontweight="bold", va="top")


def _save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, dpi=200)
    plt.close(fig)
    print("wrote", OUT / name)


def _scores(view: str, target: str, review: dict) -> tuple[list[dict], list[float]]:
    latest = {}
    for result in load_results(Path("results") / MODEL / view / f"{target}.jsonl"):
        if result.get("probability") is not None:
            latest[result["id"]] = result
    kept = apply_review(list(latest.values()), review)
    return (
        [r for r in kept if r["label"] == "phishing"],
        [r["probability"] for r in kept if r["label"] == "benign"],
    )


def _recall(phishing: list[dict], threshold: float = THRESHOLD) -> float:
    return 100 * sum(r["probability"] >= threshold for r in phishing) / len(phishing)


def chart_recall(review: dict) -> None:
    groups = [("url", "Model sees the\nreported phishing page"), ("homepage", "Model sees only\nthe homepage")]
    views = [("html", "Plain HTML", BLUE), ("rendered", "Headless browser", ORANGE)]
    fig, ax = _axes()
    width = 0.34
    for v, (view, label, color) in enumerate(views):
        for g, (target, _) in enumerate(groups):
            phishing, _ = _scores(view, target, review)
            value = _recall(phishing)
            x = g + (v - 0.5) * (width + 0.02)
            ax.bar(x, value, width, color=color, label=label if g == 0 else None)
            ax.text(x, value + 1.5, f"{value:.0f}%", ha="center", fontsize=12, fontweight="bold")
    ax.set_xticks(range(len(groups)), [name for _, name in groups], fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_ylabel("Phishing sites caught")
    ax.legend(frameon=False, loc="upper right", bbox_to_anchor=(1.0, 1.02), ncols=2)
    _title(fig, "How much phishing does the model catch?")
    fig.subplots_adjust(top=0.86, left=0.09, right=0.98, bottom=0.14)
    _save(fig, "recall.png")


def chart_tradeoff(review: dict) -> None:
    phishing, benign = _scores("rendered", "url", review)
    scores = [r["probability"] for r in phishing]
    thresholds = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.15, 0.1, 0.07, 0.05, 0.03]
    rows = [at_threshold(scores, benign, t) for t in thresholds]
    recall = [100 * r["recall"] for r in rows]
    false_rate = [100 * r["false_positive_rate"] for r in rows]
    xs = range(len(thresholds))

    fig, ax = _axes()
    ax.plot(xs, recall, color=BLUE, linewidth=2, marker="o", markersize=5)
    ax.plot(xs, false_rate, color=ORANGE, linewidth=2, marker="o", markersize=5)
    ax.text(7.6, 86, "Phishing caught (recall)", color=INK, fontsize=11, fontweight="bold")
    ax.text(5.6, 13, "Good sites flagged (false positives)", color=INK, fontsize=11,
            fontweight="bold")
    pick = thresholds.index(0.3)
    ax.axvline(pick, color=AXIS, linewidth=1, linestyle=(0, (3, 3)))
    ax.text(pick + 0.15, 50, f"threshold 0.3\n{recall[pick]:.0f}% caught\n{false_rate[pick]:.1f}% flagged",
            fontsize=10.5, color=INK_2, va="center")
    ax.set_xticks(list(xs), [str(t) for t in thresholds])
    ax.set_xlabel("Threshold (lower = flag more pages)")
    ax.set_ylabel("Share of sites")
    ax.set_ylim(0, 105)
    ax.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    _title(fig, "A lower threshold catches more, until false positives take over")
    fig.subplots_adjust(top=0.86, left=0.09, right=0.98, bottom=0.15)
    _save(fig, "tradeoff.png")


def chart_homepage(review: dict) -> None:
    phishing, _ = _scores("rendered", "homepage", review)
    is_root = {site for site, row in review.items() if row["url"].rstrip("/").count("/") == 2}
    on_home = [r for r in phishing if r["site"] in is_root]
    deep = [r for r in phishing if r["site"] not in is_root]
    bars = [
        (f"Phishing is on the homepage\n({len(on_home)} sites)", _recall(on_home)),
        (f"Phishing is on a deeper page\n({len(deep)} sites)", _recall(deep)),
    ]
    fig, ax = _axes(height=3.9)
    for i, (_, value) in enumerate(bars):
        ax.bar(i, value, 0.45, color=BLUE)
        ax.text(i, value + 1.5, f"{value:.0f}%", ha="center", fontsize=12, fontweight="bold")
    ax.set_xticks(range(len(bars)), [name for name, _ in bars], fontsize=11)
    ax.set_xlim(-0.6, 1.6)
    ax.set_ylim(0, 108)
    ax.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_ylabel("Phishing sites caught")
    _title(fig, "The homepage is enough only when the phishing is on it")
    fig.subplots_adjust(top=0.86, left=0.09, right=0.98, bottom=0.17)
    _save(fig, "homepage.png")


def chart_labels(review: dict) -> None:
    names = {
        "phishing": "Live phishing",
        "dead": "Dead or taken down",
        "not_phishing": "Not phishing (old blogs, real sites)",
        "cloaked": "Hidden behind a bot check or decoy",
        "clone": "Brand copy made as a code project",
        "unclear": "Unclear",
    }
    counts = Counter(row["verdict"] for row in review.values())
    order = sorted(names, key=lambda key: counts[key])
    fig, ax = _axes(height=3.9)
    ax.spines["bottom"].set_visible(False)
    for i, key in enumerate(order):
        ax.barh(i, counts[key], 0.62, color=BLUE)
        ax.text(counts[key] + 1, i, str(counts[key]), va="center", fontsize=12, fontweight="bold")
    ax.set_yticks(range(len(order)), [names[key] for key in order], fontsize=11, color=INK)
    ax.set_xticks([])
    ax.set_xlabel("Number of sites")
    ax.set_xlim(0, max(counts.values()) * 1.12)
    _title(fig, "Only 6 in 10 feed entries were live phishing")
    fig.subplots_adjust(top=0.86, left=0.42, right=0.97, bottom=0.1)
    _save(fig, "labels.png")


def main() -> None:
    review = load_review()
    if not review:
        raise SystemExit("No labels/phishing_review.jsonl. The charts need the reviewed labels.")
    chart_recall(review)
    chart_tradeoff(review)
    chart_homepage(review)
    chart_labels(review)
    counts = Counter(row["verdict"] for row in review.values())
    Path("docs/label_review_summary.json").write_text(json.dumps(dict(counts), indent=2) + "\n")


if __name__ == "__main__":
    main()
