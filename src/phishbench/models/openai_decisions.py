"""Adapter for the OpenAI Decisions API (POST /v1/decisions, model gpt-6-luna).

Docs: https://developers.openai.com/api/docs/guides/decisions
"""

from __future__ import annotations

import os
import time

import httpx

from .base import QUESTION, DecisionModel, ModelError, Verdict

_URL = "https://api.openai.com/v1/decisions"
_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 5


class OpenAIDecisions(DecisionModel):
    name = "openai-decisions"
    # Uncached input price from the OpenAI guide. Output tokens are free.
    usd_per_million_input_tokens = 0.10

    def __init__(self, api_key: str | None = None, client: httpx.Client | None = None):
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise ModelError("OPENAI_API_KEY is not set. Put it in the .env file.", fatal=True)
        self._client = client or httpx.Client(timeout=httpx.Timeout(60.0))
        self._headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def judge(self, page_summary: str) -> Verdict:
        body = {
            "model": "gpt-6-luna",
            "input": page_summary,
            "questions": [{"type": "predicate", "name": "phishing", "instructions": QUESTION}],
        }
        data = self._post(body)
        try:
            answer = data["answers"][0]
            tokens = int(data.get("usage", {}).get("input_tokens", 0))
            if answer.get("type") == "refusal":
                return Verdict(probability=None, input_tokens=tokens, refused=True)
            return Verdict(probability=float(answer["probability"]), input_tokens=tokens)
        except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
            raise ModelError(f"Unexpected response shape: {str(data)[:300]}") from exc

    def _post(self, body: dict) -> dict:
        last = "no attempt"
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = self._client.post(_URL, headers=self._headers, json=body)
            except httpx.HTTPError as exc:
                last = type(exc).__name__
            else:
                if response.status_code == 200:
                    return response.json()
                last = f"HTTP {response.status_code}: {response.text[:300]}"
                if response.status_code not in _RETRY_STATUS:
                    # 400, 401, 403, 404: the request or the key is wrong.
                    raise ModelError(last, fatal=response.status_code in {401, 403, 404})
                retry_after = response.headers.get("retry-after", "")
                if retry_after.replace(".", "", 1).isdigit():
                    time.sleep(min(float(retry_after), 30.0))
                    continue
            time.sleep(min(2.0**attempt, 30.0))
        raise ModelError(f"No answer after {_MAX_ATTEMPTS} attempts. Last: {last}")

    def close(self) -> None:
        self._client.close()
