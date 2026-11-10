"""Run one decision model on the dataset, with a hard cost limit.

Results go to a .jsonl file, one line for each page. A second run continues
where the first run stopped: pages that have an answer are not sent again.
"""

from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .models import DecisionModel, ModelError
from .reduce import reduce_page

# Worst case used for the cost limit: one token for each character, plus the question.
_QUESTION_TOKENS = 300


def worst_case_tokens(summary: str) -> int:
    return len(summary) + _QUESTION_TOKENS


class Budget:
    """Thread-safe cost limit. A call must reserve its worst-case cost first."""

    def __init__(self, limit_usd: float, already_spent_usd: float = 0.0):
        self.limit = limit_usd
        self.spent = already_spent_usd
        self._reserved = 0.0
        self._lock = threading.Lock()

    def reserve(self, usd: float) -> bool:
        with self._lock:
            if self.spent + self._reserved + usd > self.limit:
                return False
            self._reserved += usd
            return True

    def settle(self, reserved_usd: float, actual_usd: float) -> None:
        with self._lock:
            self._reserved -= reserved_usd
            self.spent += actual_usd


def load_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _is_answered(result: dict) -> bool:
    return result.get("probability") is not None or result.get("refused", False)


def estimate(model: DecisionModel, rows: list[dict]) -> dict:
    """Estimate the cost without a model call."""
    chars = sum(len(reduce_page(r["url"], r["html"], r["status"])) for r in rows)
    return {
        "pages": len(rows),
        "expected_usd": round(model.cost_usd(chars // 3 + _QUESTION_TOKENS * len(rows)), 4),
        "worst_case_usd": round(model.cost_usd(chars + _QUESTION_TOKENS * len(rows)), 4),
    }


def run(
    model: DecisionModel,
    rows: list[dict],
    out_path: Path,
    budget_usd: float,
    workers: int = 8,
) -> dict:
    previous = load_results(out_path)
    done_ids = {r["id"] for r in previous if _is_answered(r)}
    budget = Budget(budget_usd, sum(r.get("cost_usd", 0.0) for r in previous))
    todo = [row for row in rows if row["id"] not in done_ids]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_lock = threading.Lock()
    stop = threading.Event()
    counts = {"answered": 0, "refused": 0, "errors": 0, "skipped_for_budget": 0}
    fatal: list[str] = []

    def work(row: dict) -> None:
        if stop.is_set():
            return
        summary = reduce_page(row["url"], row["html"], row["status"])
        reserved = model.cost_usd(worst_case_tokens(summary))
        if not budget.reserve(reserved):
            with write_lock:
                counts["skipped_for_budget"] += 1
            return
        result = {"id": row["id"], "label": row["label"], "site": row["site"], "url": row["url"]}
        cost = 0.0
        try:
            verdict = model.judge(summary)
            cost = model.cost_usd(verdict.input_tokens)
            result |= {
                "probability": verdict.probability,
                "refused": verdict.refused,
                "input_tokens": verdict.input_tokens,
                "cost_usd": cost,
            }
            key = "refused" if verdict.refused else "answered"
        except ModelError as exc:
            result |= {"probability": None, "refused": False, "error": str(exc)[:300]}
            key = "errors"
            if exc.fatal:
                fatal.append(str(exc))
                stop.set()
        finally:
            budget.settle(reserved, cost)
        with write_lock:
            counts[key] += 1
            handle.write(json.dumps(result) + "\n")
            handle.flush()
            total = counts["answered"] + counts["refused"] + counts["errors"]
            if total % 25 == 0:
                print(f"  {total}/{len(todo)} pages, ${budget.spent:.4f} spent", file=sys.stderr)

    with out_path.open("a", encoding="utf-8") as handle:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, todo))

    return {
        **counts,
        "already_done": len(done_ids),
        "spent_usd": round(budget.spent, 4),
        "budget_usd": budget_usd,
        "fatal_error": fatal[0] if fatal else None,
        "path": str(out_path),
    }
