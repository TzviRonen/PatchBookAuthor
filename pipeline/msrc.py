"""MSRC CVRF v2.0 API client."""
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

import requests

from pipeline.config import MSRC_BASE_URL, DATA_DIR

log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"Accept": "application/json"})


def _get(path: str, **kwargs) -> dict:
    url = f"{MSRC_BASE_URL}{path}"
    resp = _SESSION.get(url, timeout=30, **kwargs)
    resp.raise_for_status()
    return resp.json()


def list_updates(since: datetime | None = None) -> list[dict]:
    """Return all update metadata entries, optionally filtered to those after *since*."""
    data = _get("/Updates")
    updates = data.get("value", [])
    if since:
        updates = [
            u for u in updates
            if _parse_date(u.get("CurrentReleaseDate", "")) > since
        ]
    updates.sort(key=lambda u: u.get("CurrentReleaseDate", ""))
    return updates


def _parse_date(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.rstrip("Z"))
    except Exception:
        return datetime.min


def fetch_cvrf(update_id: str) -> dict:
    """Fetch the full CVRF document for a given update ID (e.g. '2024-Jan').

    Caches to DATA_DIR/fixtures/cvrf/{update_id}.json — MSRC monthly documents
    are immutable once published so the cache never expires.
    """
    cache_path = DATA_DIR / "fixtures" / "cvrf" / f"{update_id}.json"
    if cache_path.exists():
        log.debug("Loading CVRF for %s from cache", update_id)
        return json.loads(cache_path.read_text(encoding="utf-8"))

    log.info("Fetching CVRF for update %s", update_id)
    data = _get(f"/cvrf/{update_id}")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data), encoding="utf-8")
    return data


def iter_cves(cvrf: dict) -> Iterator[dict]:
    """Yield normalised CVE records from a CVRF document."""
    for vuln in cvrf.get("Vulnerability", []):
        cve_id = vuln.get("CVE", "")
        if not cve_id:
            continue

        title = ""
        title_node = vuln.get("Title", {})
        if isinstance(title_node, dict):
            title = title_node.get("Value", "")

        description = _extract_description(vuln)
        kb_numbers = _extract_kb_numbers(vuln)
        cvss = _extract_cvss(vuln)

        yield {
            "id": cve_id,
            "title": title,
            "description": description,
            "kb_numbers": kb_numbers,
            "cvss": cvss,
        }


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s{2,}")


def _strip_html(html: str) -> str:
    text = _HTML_TAG_RE.sub(" ", html)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _extract_description(vuln: dict) -> str:
    """Extract the most useful description text from CVRF Notes.

    Priority:
    1. Type 2 Note with non-empty Value (official Description field)
    2. Combine all Type 4 (FAQ) note values — these often contain rich detail
       about exploitation conditions even when the Description is empty.
    """
    notes = vuln.get("Notes", [])

    # Try official description first
    for note in notes:
        if note.get("Type") in (2, "Description") or note.get("Title") == "Description":
            val = note.get("Value", "")
            if val and val.strip():
                return _strip_html(val)

    # Fall back to FAQ content (Type 4) — strip HTML, join paragraphs
    faq_parts = []
    for note in notes:
        if note.get("Type") == 4 and note.get("Value"):
            faq_parts.append(_strip_html(note["Value"]))

    if faq_parts:
        return " ".join(faq_parts)

    return ""


def _extract_kb_numbers(vuln: dict) -> list[str]:
    kbs = set()
    for rem in vuln.get("Remediations", []):
        desc = rem.get("Description", {})
        if isinstance(desc, dict):
            desc = desc.get("Value", "")
        if isinstance(desc, str):
            # Match "KB5039217" or bare "5039217" (MSRC sometimes omits the "KB" prefix)
            for m in re.findall(r"KB\d{6,8}", desc, re.IGNORECASE):
                kbs.add(m.upper())
            for m in re.findall(r"(?<!\d)(\d{7})(?!\d)", desc):
                kbs.add(f"KB{m}")
        url = rem.get("URL", "")
        for m in re.findall(r"KB\d{6,8}", url, re.IGNORECASE):
            kbs.add(m.upper())
        # help/5039217 style URLs
        for m in re.findall(r"/help/(\d{7})(?!\d)", url):
            kbs.add(f"KB{m}")
        subtype = rem.get("SubType", "")
        if re.fullmatch(r"\d{7}", subtype):
            kbs.add(f"KB{subtype}")
    return sorted(kbs)


def _extract_cvss(vuln: dict) -> float | None:
    for score_set in vuln.get("CVSSScoreSets", []):
        base = score_set.get("BaseScore")
        if base is not None:
            try:
                return float(base)
            except (TypeError, ValueError):
                pass
    return None
