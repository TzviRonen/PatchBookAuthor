"""Download pre- and post-patch Windows kernel binaries using Winbindex.

Actual Winbindex JSON structure (verified against live API):
  {
    "<sha256>": {
      "fileInfo": {
        "timestamp": <PE TimeDateStamp int>,
        "virtualSize": <PE SizeOfImage int>,
        "version": "10.0.19041.4522 (WinBuild...)",
        ...
      },
      "windowsVersions": {
        "<release_str>": {   # e.g. "22H2", "21H2", "1507"
          "<KB_number>": {   # e.g. "KB5039211"
            "updateInfo": {
              "releaseVersion": "19044.4529",  # OS build for this update
              "releaseDate": "2024-06-11",
              "heading": "...",
              ...
            }
          }
        }
      }
    }
  }

Download URL: https://msdl.microsoft.com/download/symbols/{fn}/{ts:08X}{vs:X}/{fn}
"""
import gzip
import io
import json
import logging
import re
from pathlib import Path
from typing import NamedTuple

import requests

from pipeline.config import WINBINDEX_BASE_URL, SYMBOL_SERVER_URL, TARGET_WINDOWS_BUILD, DATA_DIR

log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "kernel-cve-pipeline/1.0"})

# In-process cache: filename → list of BinaryVersion sorted by file_version_num
_INDEX_CACHE: dict[str, list["BinaryVersion"]] = {}


class BinaryVersion(NamedTuple):
    sha256: str
    timestamp: int
    virtual_size: int
    file_version: str             # e.g. "10.0.19041.4522"
    version_tuple: tuple          # (10, 0, 19041, 4522) — sort key
    build_component: int          # 3rd component (19041) — used to filter by Windows release
    revision_component: int       # 4th component (4522) — monotonic within a build branch
    kb_numbers: list[str]         # all KBs in any windowsVersions branch
    release_date: str             # from first updateInfo found


def _parse_version_tuple(version_str: str) -> tuple:
    """Return (major, minor, build, revision) from a PE file version string."""
    parts = re.findall(r"\d+", version_str)
    padded = (parts + ["0", "0", "0", "0"])[:4]
    return tuple(int(x) for x in padded)


def _fetch_index(filename: str) -> list[BinaryVersion]:
    if filename in _INDEX_CACHE:
        return _INDEX_CACHE[filename]

    # Disk cache — winbindex historical entries are immutable so no TTL needed
    disk_cache = DATA_DIR / "fixtures" / "winbindex" / f"{filename}.json"
    if disk_cache.exists():
        log.debug("Loading Winbindex index for %s from disk cache", filename)
        raw = json.loads(disk_cache.read_text(encoding="utf-8"))
    else:
        url = f"{WINBINDEX_BASE_URL}/{filename}.json.gz"
        log.info("Fetching Winbindex index for %s", filename)
        resp = _SESSION.get(url, timeout=120)
        if resp.status_code == 404:
            raise FileNotFoundError(f"No Winbindex entry for {filename}")
        resp.raise_for_status()
        with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
            raw = json.loads(gz.read())
        disk_cache.parent.mkdir(parents=True, exist_ok=True)
        disk_cache.write_text(json.dumps(raw), encoding="utf-8")

    versions: list[BinaryVersion] = []
    for sha256, entry in raw.items():
        fi = entry.get("fileInfo", {})
        timestamp = fi.get("timestamp", 0)
        virtual_size = fi.get("virtualSize", 0)
        file_version = fi.get("version", "")

        if not timestamp or not virtual_size:
            log.debug("Skipping %s — missing timestamp or virtualSize", sha256[:16])
            continue

        # Collect all KB numbers from all windowsVersions branches
        all_kbs: list[str] = []
        first_date = ""
        for ver_key, builds in entry.get("windowsVersions", {}).items():
            for kb_key, kb_data in builds.items():
                if kb_key.upper().startswith("KB") and re.match(r"KB\d{6,8}$", kb_key, re.I):
                    all_kbs.append(kb_key.upper())
                    if not first_date:
                        first_date = (kb_data.get("updateInfo") or {}).get("releaseDate", "")

        vtuple = _parse_version_tuple(file_version)
        versions.append(BinaryVersion(
            sha256=sha256,
            timestamp=timestamp,
            virtual_size=virtual_size,
            file_version=file_version,
            version_tuple=vtuple,
            build_component=vtuple[2],
            revision_component=vtuple[3],
            kb_numbers=all_kbs,
            release_date=first_date,
        ))

    # Sort by full version tuple so ordering is correct across all Windows releases
    versions.sort(key=lambda v: v.version_tuple)
    _INDEX_CACHE[filename] = versions
    log.info("Loaded %d binary versions for %s", len(versions), filename)
    return versions


def _download_url(filename: str, timestamp: int, virtual_size: int) -> str:
    ts_hex = f"{timestamp:08X}"
    vs_hex = f"{virtual_size:X}"
    return f"{SYMBOL_SERVER_URL}/{filename}/{ts_hex}{vs_hex}/{filename}"


def _download_binary(filename: str, version: BinaryVersion, dest_dir: Path) -> Path:
    safe_ver = str(version.revision_component)
    dest = dest_dir / f"{filename}.{safe_ver}"
    if dest.exists() and dest.stat().st_size > 0:
        log.debug("Binary already cached: %s", dest)
        return dest

    url = _download_url(filename, version.timestamp, version.virtual_size)
    log.info("Downloading %s v%s from %s", filename, safe_ver, url)

    resp = _SESSION.get(url, timeout=180, stream=True)
    if resp.status_code == 404:
        raise FileNotFoundError(f"Binary not on symbol server: {url}")
    resp.raise_for_status()

    tmp = dest.with_suffix(".tmp")
    try:
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(65536):
                f.write(chunk)
        tmp.rename(dest)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise

    log.info("Downloaded %s (%d KB)", dest.name, dest.stat().st_size // 1024)
    return dest


def get_binary_pair(
    filename: str,
    kb_numbers: list[str],
    dest_dir: Path,
) -> tuple[Path, Path]:
    """Return (pre_patch_path, post_patch_path) for the given KB update.

    Searches all Winbindex entries for the binary that was shipped in the KB
    update, then finds the immediately preceding file version as pre-patch.
    """
    versions = _fetch_index(filename)
    if not versions:
        raise ValueError(f"No versions found for {filename}")

    target_kbs = {kb.upper() for kb in kb_numbers}
    log.info("Looking for KB(s): %s  [target build: %s]", sorted(target_kbs), TARGET_WINDOWS_BUILD)

    # Filter to entries for the configured Windows build (e.g., 19041 for Win10 22H2)
    build_versions = [v for v in versions if v.build_component == TARGET_WINDOWS_BUILD]
    if not build_versions:
        log.warning("No versions found for build %s; using all versions", TARGET_WINDOWS_BUILD)
        build_versions = versions

    # Among the target build, find the one shipped in our KB
    matches = [v for v in build_versions if target_kbs & set(v.kb_numbers)]
    log.info("Found %d version(s) matching target KBs for build %s:", len(matches), TARGET_WINDOWS_BUILD)
    for v in matches:
        matched_kbs = [k for k in v.kb_numbers if k in target_kbs]
        log.info("  file_version=%s  kb=%s  ts=0x%X  vs=0x%X",
                 v.file_version, matched_kbs, v.timestamp, v.virtual_size)

    post_patch: BinaryVersion | None = None
    for v in reversed(build_versions):  # highest revision in the target build
        if target_kbs & set(v.kb_numbers):
            post_patch = v
            break

    if post_patch is None:
        # Winbindex data may lag; fall back to latest in the target build
        log.warning(
            "KB(s) %s not found in Winbindex for build %s; using latest as post-patch fallback",
            sorted(target_kbs), TARGET_WINDOWS_BUILD,
        )
        post_patch = build_versions[-1] if build_versions else versions[-1]

    post_idx = build_versions.index(post_patch)
    if post_idx == 0:
        raise ValueError(
            f"No pre-patch version available for {filename} "
            f"(version {post_patch.file_version} is the earliest in build {TARGET_WINDOWS_BUILD})"
        )

    pre_patch = build_versions[post_idx - 1]
    log.info(
        "Selected pair: pre=%s  post=%s",
        pre_patch.file_version, post_patch.file_version,
    )

    dest_dir.mkdir(parents=True, exist_ok=True)
    pre_path = _download_binary(filename, pre_patch, dest_dir)
    post_path = _download_binary(filename, post_patch, dest_dir)
    return pre_path, post_path
