"""Command line: phishbench collect | render | run | score."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from .collect import collect, load_snapshots
from .models import REGISTRY, ModelError, get_model
from .render import render
from .run import estimate, load_results, run
from .score import apply_review, format_report, load_review, score

DATA_DIR = Path("data")
TARGETS = ["homepage", "url"]
# A view is how the page was read: plain HTTP ("html") or a headless browser ("rendered").
VIEWS = {
    "html": DATA_DIR / "snapshots.jsonl.gz",
    "rendered": DATA_DIR / "snapshots.rendered.jsonl.gz",
}


def _results_path(model: str, view: str, target: str) -> Path:
    return Path("results") / model / view / f"{target}.jsonl"


def _cmd_collect(args: argparse.Namespace) -> int:
    out = VIEWS["html"]
    if out.exists() and not args.force:
        print(f"{out} exists. Use --force to replace it.", file=sys.stderr)
        return 1
    print(json.dumps(collect(out, n=args.n, seed=args.seed), indent=2))
    return 0


def _cmd_render(args: argparse.Namespace) -> int:
    if not VIEWS["html"].exists():
        print("No dataset. Run `phishbench collect` first.", file=sys.stderr)
        return 1
    print(json.dumps(render(VIEWS["html"], VIEWS["rendered"], DATA_DIR / "render_io"), indent=2))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    data = VIEWS[args.view]
    if not data.exists():
        step = "collect" if args.view == "html" else "render"
        print(f"{data} does not exist. Run `phishbench {step}` first.", file=sys.stderr)
        return 1
    rows = load_snapshots(data, args.target)
    if args.limit:
        rows = rows[: args.limit]
    try:
        model = get_model(args.model)
    except ModelError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    try:
        guess = estimate(model, rows)
        print(f"Estimate: {json.dumps(guess)}", file=sys.stderr)
        if args.dry_run:
            return 0
        out_path = _results_path(args.model, args.view, args.target)
        report = run(model, rows, out_path, budget_usd=args.budget, workers=args.workers)
    finally:
        model.close()
    print(json.dumps(report, indent=2))
    if report["fatal_error"]:
        return 1
    title = f"{args.model} / {args.view} / {args.target}"
    print(format_report(title, score(load_results(out_path))))
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    found = False
    review = load_review()
    for model in sorted(REGISTRY):
        for view in VIEWS:
            for target in TARGETS:
                path = _results_path(model, view, target)
                if not path.exists():
                    continue
                found = True
                results = load_results(path)
                summary = {"feed_labels": score(results)}
                title = f"{model} / {view} / {target}"
                if review and not args.raw:
                    summary["reviewed_labels"] = score(apply_review(results, review))
                    print(format_report(f"{title} / reviewed labels", summary["reviewed_labels"]))
                else:
                    print(format_report(f"{title} / feed labels", summary["feed_labels"]))
                print()
                path.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if not found:
        print("No results. Run `phishbench run` first.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="phishbench", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("collect", help="Fetch live phishing and benign pages.")
    p.add_argument("--n", type=int, default=200, help="Sites for each label (default 200).")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--force", action="store_true", help="Replace the dataset file.")
    p.set_defaults(func=_cmd_collect)

    p = commands.add_parser("render", help="Open each page in a headless browser (Docker).")
    p.set_defaults(func=_cmd_render)

    p = commands.add_parser("run", help="Run one model on the dataset.")
    p.add_argument("--model", default="openai-decisions", choices=sorted(REGISTRY))
    p.add_argument("--view", default="html", choices=sorted(VIEWS))
    p.add_argument("--target", default="homepage", choices=TARGETS)
    p.add_argument("--budget", type=float, default=0.20,
                   help="Cost limit in USD for this model, view, and target (default 0.20).")
    p.add_argument("--limit", type=int, default=0, help="Use only the first N pages.")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--dry-run", action="store_true", help="Print the cost estimate and stop.")
    p.set_defaults(func=_cmd_run)

    p = commands.add_parser("score", help="Score all results and write summary files.")
    p.add_argument("--raw", action="store_true",
                   help="Print scores with the feed labels, not the reviewed labels.")
    p.set_defaults(func=_cmd_score)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
