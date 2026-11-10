"""A free, offline model. Use it to test the pipeline without an API key."""

from __future__ import annotations

from .base import DecisionModel, Verdict


class MockModel(DecisionModel):
    name = "mock"
    usd_per_million_input_tokens = 0.0

    def judge(self, page_summary: str) -> Verdict:
        has_password = "PASSWORD FIELDS: 0" not in page_summary
        return Verdict(probability=0.9 if has_password else 0.1, input_tokens=len(page_summary) // 4)
