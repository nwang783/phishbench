"""Runs in the Docker sandbox. Opens each URL in headless Chromium.

Input:  /io/urls.jsonl      one {"id", "url"} for each line
Output: /io/rendered.jsonl  one {"id", "status", "final_url", "html", "error"} for each line
        /io/shots/<id>.png  a screenshot of each page that loaded
"""

import asyncio
import json
from pathlib import Path

from playwright.async_api import Error, async_playwright

IO = Path("/io")
CONCURRENCY = 6
MAX_HTML_CHARS = 400_000
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


async def render(browser, item: dict) -> dict:
    result = {"id": item["id"], "status": None, "final_url": None, "html": "", "error": None}
    # A new context for each page: no cookies or storage go from one site to the next.
    context = await browser.new_context(
        accept_downloads=False,
        ignore_https_errors=True,
        user_agent=USER_AGENT,
        viewport={"width": 1280, "height": 800},
    )
    try:
        page = await context.new_page()
        response = await page.goto(item["url"], wait_until="domcontentloaded", timeout=20_000)
        try:
            await page.wait_for_load_state("networkidle", timeout=6_000)
        except Error:
            pass  # Some pages never go idle. Use what is there.
        result["status"] = response.status if response else None
        result["final_url"] = page.url
        result["html"] = (await page.content())[:MAX_HTML_CHARS]
        await page.screenshot(path=str(IO / "shots" / f"{item['id']}.png"), timeout=10_000)
    except Exception as exc:  # noqa: BLE001 - one bad page must not stop the batch
        result["error"] = type(exc).__name__
    finally:
        try:
            await asyncio.wait_for(context.close(), timeout=10)
        except Exception:  # noqa: BLE001
            pass
    return result


async def main() -> None:
    items = [json.loads(line) for line in (IO / "urls.jsonl").read_text().splitlines() if line]
    (IO / "shots").mkdir(exist_ok=True)
    semaphore = asyncio.Semaphore(CONCURRENCY)
    done = 0
    async with async_playwright() as pw:
        # The container is the sandbox. Chromium's own sandbox needs privileges
        # that the container does not give.
        browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        with (IO / "rendered.jsonl").open("w") as out:

            async def one(item: dict) -> None:
                nonlocal done
                async with semaphore:
                    try:
                        result = await asyncio.wait_for(render(browser, item), timeout=60)
                    except Exception as exc:  # noqa: BLE001
                        result = {"id": item["id"], "status": None, "final_url": None,
                                  "html": "", "error": type(exc).__name__}
                out.write(json.dumps(result) + "\n")
                out.flush()
                done += 1
                if done % 25 == 0:
                    print(f"  rendered {done}/{len(items)}", flush=True)

            await asyncio.gather(*(one(item) for item in items))
        await browser.close()


asyncio.run(main())
