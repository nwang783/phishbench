"""Build the dataset: fetch live phishing pages and live benign pages.

Phishing URLs come from the OpenPhish community feed. Benign sites come from
the Tranco list. The collector does plain HTTP requests only. It does not run
JavaScript and it stores the HTML as text.

Each phishing site gives two rows:
- target "url": the page that the feed reported.
- target "homepage": the root page of the same host. This is what a scanner
  of newly registered domains sees.
Each benign site gives one row that is valid for the two targets.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import random
import sys
import warnings
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

OPENPHISH_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
]
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_MAX_RANK = 100_000
MAX_HTML_BYTES = 200_000
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
_BATCH = 32


def _client() -> httpx.Client:
    # Phishing sites frequently have bad certificates. We only read text.
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    return httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(10.0),
        verify=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"},
    )


def fetch_page(client: httpx.Client, url: str) -> dict:
    """Fetch one page. Return status, final URL, and HTML (or an error)."""
    try:
        with client.stream("GET", url) as response:
            content_type = response.headers.get("content-type", "")
            chunks, size = [], 0
            if "html" in content_type or "text" in content_type or not content_type:
                for chunk in response.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_HTML_BYTES:
                        break
            raw = b"".join(chunks)[:MAX_HTML_BYTES]
            return {
                "status": response.status_code,
                "final_url": str(response.url),
                "html": raw.decode(response.encoding or "utf-8", errors="replace"),
                "error": None,
            }
    except (httpx.HTTPError, OSError, ValueError, LookupError) as exc:
        return {"status": None, "final_url": None, "html": "", "error": type(exc).__name__}


def _row(label: str, targets: list[str], site: str, url: str, page: dict) -> dict:
    key = f"{label}|{','.join(targets)}|{url}"
    return {
        "id": hashlib.sha1(key.encode()).hexdigest()[:12],
        "label": label,
        "targets": targets,
        "site": site,
        "url": url,
        "final_url": page["final_url"],
        "status": page["status"],
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "html": page["html"],
    }


def _root(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/"


def _phishing_urls(client: httpx.Client) -> list[str]:
    for feed in OPENPHISH_FEEDS:
        try:
            response = client.get(feed)
            response.raise_for_status()
        except httpx.HTTPError:
            continue
        urls = [line.strip() for line in response.text.splitlines() if line.startswith("http")]
        if urls:
            return urls
    raise RuntimeError("Could not read the OpenPhish feed.")


def _benign_domains(client: httpx.Client) -> list[str]:
    response = client.get(TRANCO_URL, timeout=60.0)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        with archive.open(archive.namelist()[0]) as handle:
            reader = csv.reader(io.TextIOWrapper(handle, encoding="utf-8"))
            return [row[1] for row in reader if len(row) == 2 and int(row[0]) <= TRANCO_MAX_RANK]


def _one_per_host(urls: list[str]) -> list[str]:
    seen, result = set(), []
    for url in urls:
        host = (urlsplit(url).hostname or "").removeprefix("www.")
        if host and host not in seen:
            seen.add(host)
            result.append(url)
    return result


def _collect_phishing(client: httpx.Client, urls: list[str], n: int, pool) -> list[dict]:
    def visit(url: str) -> list[dict]:
        page = fetch_page(client, url)
        if page["status"] != 200 or not page["html"].strip():
            return []  # The reported page is gone. We cannot use this site.
        host = urlsplit(url).hostname or ""
        home = fetch_page(client, _root(url))
        rows = [_row("phishing", ["url"], host, url, page)]
        if home["status"] is not None:
            rows.append(_row("phishing", ["homepage"], host, _root(url), home))
        return rows

    rows, sites = [], 0
    for start in range(0, len(urls), _BATCH):
        for found in pool.map(visit, urls[start : start + _BATCH]):
            if found and sites < n:
                rows.extend(found)
                sites += 1
        print(f"  phishing: {sites}/{n} live sites", file=sys.stderr)
        if sites >= n:
            break
    return rows


def _collect_benign(client: httpx.Client, domains: list[str], n: int, pool) -> list[dict]:
    def visit(domain: str) -> list[dict]:
        url = f"https://{domain}/"
        page = fetch_page(client, url)
        if page["status"] != 200 or not page["html"].strip():
            return []
        return [_row("benign", ["homepage", "url"], domain, url, page)]

    rows = []
    for start in range(0, len(domains), _BATCH):
        for found in pool.map(visit, domains[start : start + _BATCH]):
            if found and len(rows) < n:
                rows.extend(found)
        print(f"  benign: {len(rows)}/{n} live sites", file=sys.stderr)
        if len(rows) >= n:
            break
    return rows


def collect(out_path: Path, n: int = 200, seed: int = 0, workers: int = 16) -> dict:
    """Fetch up to `n` phishing sites and `n` benign sites. Write a .jsonl.gz file."""
    rng = random.Random(seed)
    with _client() as client, ThreadPoolExecutor(max_workers=workers) as pool:
        phishing_urls = _one_per_host(_phishing_urls(client))
        rng.shuffle(phishing_urls)
        phishing = _collect_phishing(client, phishing_urls, n, pool)

        domains = _benign_domains(client)
        rng.shuffle(domains)
        benign = _collect_benign(client, domains[: n * 4], n, pool)

    rows = phishing + benign
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return {
        "phishing_url_rows": sum(r["label"] == "phishing" and r["targets"] == ["url"] for r in rows),
        "phishing_homepage_rows": sum(r["targets"] == ["homepage"] for r in rows),
        "benign_rows": len(benign),
        "path": str(out_path),
    }


def load_snapshots(path: Path, target: str) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    return [row for row in rows if target in row["targets"]]
