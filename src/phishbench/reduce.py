"""Change one HTML page into a short text summary for a decision model.

Each model gets the same summary, so the benchmark compares models and not
page parsers. The summary keeps the signals that show phishing: the host, the
title, the forms, the hosts that the page links to, and the visible text.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser as HTMLParser

DEFAULT_MAX_CHARS = 6000
_MAX_FORMS = 5
_MAX_INPUTS = 12
_MAX_HOSTS = 8
_WHITESPACE = re.compile(r"\s+")
_HIDDEN_TAGS = ["script", "style", "noscript", "template", "svg"]


def _clean(text: str | None, limit: int = 200) -> str:
    return _WHITESPACE.sub(" ", text or "").strip()[:limit]


def _host_of(base_url: str, ref: str | None) -> str | None:
    if not ref:
        return None
    try:
        return urlsplit(urljoin(base_url, ref.strip())).hostname
    except ValueError:
        return None


def _top_hosts(hosts: list[str], own_host: str) -> str:
    counts = Counter(h for h in hosts if h and h != own_host)
    if not counts:
        return "(none)"
    return ", ".join(f"{host} ({n})" for host, n in counts.most_common(_MAX_HOSTS))


def _form_lines(tree: HTMLParser, url: str) -> list[str]:
    lines = []
    for form in tree.css("form")[:_MAX_FORMS]:
        method = (form.attributes.get("method") or "get").upper()
        action = form.attributes.get("action")
        target = _host_of(url, action) if action else "(same page)"
        inputs = []
        for field in form.css("input, select, textarea")[:_MAX_INPUTS]:
            kind = field.attributes.get("type") or field.tag
            if kind == "hidden":
                continue
            label = (
                field.attributes.get("name")
                or field.attributes.get("placeholder")
                or field.attributes.get("id")
                or "?"
            )
            inputs.append(f"{_clean(label, 40)}({kind})")
        lines.append(f"- {method} -> {target} | inputs: {', '.join(inputs) or '(none)'}")
    return lines


def reduce_page(
    url: str,
    html: str | None,
    status: int | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Return the text summary of one page, at most `max_chars` long."""
    host = urlsplit(url).hostname or ""
    tree = HTMLParser(html or "")

    title_node = tree.css_first("title")
    description_node = tree.css_first('meta[name="description"]')
    description = description_node.attributes.get("content") if description_node else None

    link_hosts = [_host_of(url, a.attributes.get("href")) for a in tree.css("a[href]")]
    resource_hosts = [
        _host_of(url, node.attributes.get("src") or node.attributes.get("href"))
        for node in tree.css("script[src], img[src], iframe[src], link[href]")
    ]
    password_fields = len(tree.css('input[type="password"]'))
    forms = _form_lines(tree, url)

    tree.strip_tags(_HIDDEN_TAGS)
    body = tree.body
    visible = _clean(body.text(separator=" ") if body else "", limit=max_chars)

    head = [
        f"URL: {url}",
        f"HOST: {host}",
        f"HTTP STATUS: {status if status is not None else 'unknown'}",
        f"TITLE: {_clean(title_node.text() if title_node else '') or '(none)'}",
        f"META DESCRIPTION: {_clean(description, 300) or '(none)'}",
        f"PASSWORD FIELDS: {password_fields}",
        "FORMS:" if forms else "FORMS: (none)",
        *forms,
        f"LINK HOSTS: {_top_hosts(link_hosts, host)}",
        f"RESOURCE HOSTS: {_top_hosts(resource_hosts, host)}",
        "VISIBLE TEXT:",
    ]
    summary = "\n".join(head) + "\n" + (visible or "(empty page)")
    return summary[:max_chars]
