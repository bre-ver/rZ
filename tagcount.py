"""
Count assets per 'site=<digits>' tag in a single org using the Export API,
and output results as CSV (site,count).

Behavior:
- Uses an org-scoped Export Token (ET...) so results are limited to that org.
- Paginates automatically with start_key until all assets are processed.
- Requests only the 'tags' field.
- Matches strictly 'site=NNNN' (digits only, case-insensitive).
- Each site gets +1 per asset that includes it (per-asset de-dupe per site).
- Outputs a CSV with two columns: site,count
"""

import os
import sys
import re
import csv
from collections import Counter
from typing import Any, Dict, Iterable, Optional, Set
import requests

BASE_URL = os.getenv("RUNZERO_BASE_URL", "https://console.runzero.com/api/v1.0")
EXPORT_TOKEN = os.getenv("RUNZERO_EXPORT_TOKEN")  # ET... token scoped to the target org

SITE_TAG_RE = re.compile(r"(?i)^site=(\d+)$")

def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(msg.strip() + "\n")
    sys.exit(code)

def http_get_assets_page(start_key: Optional[str]) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {EXPORT_TOKEN}", "Accept": "application/json"}
    params = {"fields": "tags"}
    if start_key:
        params["start_key"] = start_key

    resp = requests.get(f"{BASE_URL}/export/org/assets.json",
                        headers=headers, params=params, timeout=60)
    resp.raise_for_status()

    try:
        payload = resp.json()
    except Exception as e:
        die(f"ERROR: Failed to parse JSON: {e}")

    if isinstance(payload, list):
        assets = payload
        next_key = resp.headers.get("X-Next-Key") or None
    else:
        assets = payload.get("assets") or payload.get("data") or []
        next_key = payload.get("next_key")

    if not isinstance(assets, list):
        die("ERROR: Unexpected assets payload shape; expected a list of assets.")

    return {"assets": assets, "next_key": next_key}

def _iter_tags(tags_field: Any) -> Iterable[str]:
    if isinstance(tags_field, str):
        for tag in tags_field.split():
            yield tag.strip()

    elif isinstance(tags_field, (list, tuple)):
        for item in tags_field:
            if isinstance(item, str):
                for tag in item.split():
                    yield tag.strip()

    elif isinstance(tags_field, dict):
        for k, v in tags_field.items():
            if isinstance(k, str):
                for tag in k.split():
                    yield tag.strip()
            if isinstance(v, str):
                for tag in v.split():
                    yield tag.strip()
        if "site" in tags_field and isinstance(tags_field["site"], str) and tags_field["site"].strip().isdigit():
            yield f"site={tags_field['site'].strip()}"

def extract_all_site_tags(asset: Dict[str, Any]) -> Set[int]:
    sites: Set[int] = set()
    for tag in _iter_tags(asset.get("tags")):
        m = SITE_TAG_RE.match(tag)
        if m:
            sites.add(int(m.group(1)))
    return sites

def main() -> None:
    if not EXPORT_TOKEN:
        die("Set RUNZERO_EXPORT_TOKEN to your org's ET... export token.")

    site_counts: Counter[int] = Counter()
    no_site_count = 0
    start_key: Optional[str] = None

    while True:
        page = http_get_assets_page(start_key)
        assets = page["assets"]
        next_key = page["next_key"]

        if not assets:
            break

        for asset in assets:
            sites = extract_all_site_tags(asset)
            if sites:
                for s in sites:
                    site_counts[s] += 1
            else:
                no_site_count += 1

        if not next_key:
            break
        start_key = next_key

    # Write results to CSV (stdout)
    writer = csv.writer(sys.stdout)
    writer.writerow(["site", "count"])
    for site_num in sorted(site_counts.keys()):
        writer.writerow([f"site={site_num}", site_counts[site_num]])

    writer.writerow(["unlisted", no_site_count])

if __name__ == "__main__":
    main()
