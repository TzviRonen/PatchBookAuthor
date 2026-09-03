"""MSRC CVRF v2.0 API client."""
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

import requests

from pipeline.config import MSRC_BASE_URL, MSRC_SUG_BASE_URL, DATA_DIR

log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"Accept": "application/json"})


def _get(path: str, **kwargs) -> dict:
    url = f"{MSRC_BASE_URL}{path}"
    resp = _SESSION.get(url, timeout=30, **kwargs)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Security Update Guide (SUG) API — authoritative per-CVE ground truth
# ---------------------------------------------------------------------------
# The CVRF document lists KBs for *all* affected products lumped together, which is
# too coarse to pick the right build lineage. The SUG API exposes, per CVE:
#   - cweList (e.g. CWE-416 Use After Free, CWE-122 Heap-based Buffer Overflow)
#   - vectorString / baseScore / impact / severity
#   - one affectedProduct row per Windows release, each with its fixedBuildNumber + KB
# We treat this as the single source of truth for which lineage/build to diff and for
# validating that a candidate patch matches the CVE's real bug class and attack vector.


def _sug_get(path: str, **params) -> dict:
    url = f"{MSRC_SUG_BASE_URL}{path}"
    resp = _SESSION.get(url, timeout=30, params=params or None)
    resp.raise_for_status()
    return resp.json()


def fetch_vuln_details(cve_id: str) -> dict:
    """Return normalised ground truth for *cve_id* from the SUG API.

    Keys: cwe_list, impact, severity, base_score, vector_string, exploited,
    publicly_disclosed. Empty dict if the CVE is not found.
    """
    try:
        d = _sug_get(f"/vulnerability/{cve_id}")
    except requests.HTTPError as e:
        log.warning("SUG vulnerability fetch failed for %s: %s", cve_id, e)
        return {}
    return {
        "cwe_list": d.get("cweList", []) or [],
        "impact": d.get("impact", ""),
        "severity": d.get("severity", ""),
        "base_score": d.get("baseScore"),
        "vector_string": d.get("vectorString", ""),
        "exploited": d.get("exploited"),
        "publicly_disclosed": d.get("publiclyDisclosed"),
        "title": d.get("cveTitle", ""),
        "description": d.get("unformattedDescription") or d.get("description", ""),
        "release_number": d.get("releaseNumber", ""),  # e.g. "2026-Aug" — the CVRF update id
        # Patch Tuesday release date (the date the fix shipped), e.g. "2026-06-09".
        "release_date": (d.get("releaseDate", "") or "")[:10],
    }


def find_update_id(cve_id: str) -> str:
    """Return the CVRF update id (e.g. '2026-Aug') a CVE belongs to, from the SUG API.

    The CVRF /Updates feed lags (it may not list the latest month yet), so resolving
    the month from the per-CVE SUG record is far more reliable than scanning the feed.
    Returns "" if unknown.
    """
    return fetch_vuln_details(cve_id).get("release_number", "")


def fetch_affected_products(cve_id: str) -> list[dict]:
    """Return per-product affected rows for *cve_id* from the SUG API.

    Each row: {product, fixed_build (e.g. '10.0.22631.7219'), kb (e.g. 'KB5093998')}.
    The fixed_build's 3rd component is the build lineage; the 4th is the fixed revision.
    """
    flt = f"cveNumber eq '{cve_id}'"
    try:
        d = _sug_get("/affectedProduct", **{"$filter": flt})
    except requests.HTTPError as e:
        log.warning("SUG affectedProduct fetch failed for %s: %s", cve_id, e)
        return {}.get("value", [])
    rows: list[dict] = []
    for v in d.get("value", []):
        product = v.get("product") or v.get("productName") or ""
        for kb in (v.get("kbArticles") or []):
            fixed = kb.get("fixedBuildNumber") or ""
            name = kb.get("articleName") or ""
            if fixed:
                rows.append({
                    "product": product,
                    "fixed_build": fixed,
                    "kb": f"KB{name}" if name and not str(name).upper().startswith("KB") else name,
                })
    return rows


def fetch_ground_truth(cve_id: str) -> dict:
    """Combine fetch_vuln_details + fetch_affected_products into one ground-truth record."""
    gt = fetch_vuln_details(cve_id)
    gt["affected_products"] = fetch_affected_products(cve_id)
    return gt


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


_CVRF_CACHE_MAX_AGE_DAYS = 45  # re-fetch if cached copy is newer than this


def fetch_cvrf(update_id: str, force: bool = False) -> dict:
    """Fetch the full CVRF document for a given update ID (e.g. '2024-Jan').

    Caches to DATA_DIR/fixtures/cvrf/{update_id}.json.
    MSRC documents are immutable once Patch Tuesday has passed, but may gain
    new CVEs in the days before it.  Files cached less than
    _CVRF_CACHE_MAX_AGE_DAYS ago are re-fetched to pick up any additions.
    """
    import time
    cache_path = DATA_DIR / "fixtures" / "cvrf" / f"{update_id}.json"
    if not force and cache_path.exists():
        age_days = (time.time() - cache_path.stat().st_mtime) / 86_400
        if age_days >= _CVRF_CACHE_MAX_AGE_DAYS:
            log.debug("Loading CVRF for %s from cache (age=%.0fd)", update_id, age_days)
            return json.loads(cache_path.read_text(encoding="utf-8"))
        log.info("CVRF cache for %s is %.0f days old — re-fetching", update_id, age_days)

    log.info("Fetching CVRF for update %s", update_id)
    data = _get(f"/cvrf/{update_id}")
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data), encoding="utf-8")
    except Exception as e:
        log.warning("Could not cache CVRF for %s: %s", update_id, e)
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
