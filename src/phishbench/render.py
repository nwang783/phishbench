"""Make the "rendered" view: open each page in a headless browser in Docker.

The browser runs live phishing scripts, so it runs only in a container. The
container runs as a non-root user with no extra privileges, and it gets one
host folder: data/render_io.
"""

from __future__ import annotations

import gzip
import json
import subprocess
from pathlib import Path

IMAGE = "phishbench-browser"
BROWSER_DIR = Path(__file__).resolve().parents[2] / "browser"


def render(snapshots: Path, out_path: Path, io_dir: Path) -> dict:
    """Render each page of `snapshots`. Write the same rows with rendered HTML."""
    with gzip.open(snapshots, "rt", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]

    io_dir.mkdir(parents=True, exist_ok=True)
    (io_dir / "rendered.jsonl").unlink(missing_ok=True)
    with (io_dir / "urls.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps({"id": row["id"], "url": row["url"]}) + "\n")

    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(BROWSER_DIR)], check=True)
    subprocess.run(
        [
            "docker", "run", "--rm",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", "4g",
            "--shm-size", "1g",
            "--user", "render",
            "-v", f"{io_dir.resolve()}:/io",
            IMAGE,
        ],
        check=True,
    )

    rendered = {}
    with (io_dir / "rendered.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            rendered[item["id"]] = item

    kept = 0
    with gzip.open(out_path, "wt", encoding="utf-8") as handle:
        for row in rows:
            item = rendered.get(row["id"])
            if not item or item["status"] is None:
                continue  # The site did not answer the browser. Leave it out.
            row = row | {"status": item["status"], "final_url": item["final_url"], "html": item["html"]}
            handle.write(json.dumps(row) + "\n")
            kept += 1
    return {"pages": len(rows), "rendered": kept, "failed": len(rows) - kept, "path": str(out_path)}
