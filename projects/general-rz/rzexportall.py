#!/usr/bin/env python3
"""
Export all runZero orgs: assets + software + vulnerabilities.

Outputs (per org):
  - assets.jsonl
  - software.jsonl
  - vulnerabilities.jsonl
  - assets_with_software_vulns.jsonl   (if --mode includes merged)

Auth: OAuth client_credentials to /api/v1.0/account/api/token
Base URL default: https://console.runzero.com
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def sanitize_filename(name: str) -> str:
    # safe-ish folder names on mac/linux/windows
    name = name.strip() or "org"
    name = re.sub(r"[^\w\-. ]+", "_", name)
    name = re.sub(r"\s+", "_", name)
    return name[:120]


def request_with_retries(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    stream: bool = False,
    timeout: int = 60,
    max_attempts: int = 8,
) -> requests.Response:
    backoff = 1.0
    last_exc: Optional[Exception] = None

    for _attempt in range(1, max_attempts + 1):
        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                stream=stream,
                timeout=timeout,
            )

            # Retry on rate-limit + transient server issues
            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        sleep_s = float(retry_after)
                    except ValueError:
                        sleep_s = backoff
                else:
                    sleep_s = backoff

                resp.close()
                time.sleep(min(sleep_s, 60.0))
                backoff = min(backoff * 2.0, 60.0)
                continue

            return resp

        except (requests.Timeout, requests.ConnectionError) as exc:
            last_exc = exc
            time.sleep(min(backoff, 60.0))
            backoff = min(backoff * 2.0, 60.0)

    if last_exc:
        die(f"request failed after retries: {method} {url} ({last_exc})")
    die(f"request failed after retries: {method} {url}")


def get_token(session: requests.Session, api_base: str, client_id: str, client_secret: str) -> str:
    url = f"{api_base}/account/api/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }

    resp = request_with_retries(
        session,
        "POST",
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urlencode(data),
        stream=False,
        timeout=30,
    )
    if resp.status_code != 200:
        die(f"token request failed: {resp.status_code} {resp.text[:500]}")
    body = resp.json()
    token = body.get("access_token")
    if not token:
        die(f"token response missing access_token: {body}")
    return token


def list_orgs(session: requests.Session, api_base: str, token: str) -> List[Dict[str, Any]]:
    url = f"{api_base}/account/orgs"
    resp = request_with_retries(
        session,
        "GET",
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        stream=False,
        timeout=60,
    )
    if resp.status_code != 200:
        die(f"list orgs failed: {resp.status_code} {resp.text[:500]}")
    body = resp.json()

    # Be tolerant of possible response shapes
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("orgs", "organizations", "data", "items"):
            value = body.get(key)
            if isinstance(value, list):
                return value
    die(f"unexpected org list shape: {type(body)} {str(body)[:300]}")


def stream_jsonl_to_file_and_db(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    out_path: Optional[Path],
    *,
    db: Optional[sqlite3.Connection] = None,
    table: Optional[str] = None,
    asset_id_field: Optional[str] = None,
    commit_every: int = 2000,
    refresh_headers: Optional[Callable[[], Dict[str, str]]] = None,
) -> Tuple[int, int]:
    """
    Streams a JSONL endpoint.

    If out_path is provided, writes JSONL to that path.

    Optionally inserts each object into sqlite table with schema:
      - assets(asset_id TEXT PRIMARY KEY, json TEXT)
      - software(asset_id TEXT, json TEXT)
      - vulns(asset_id TEXT, json TEXT)

    Returns: (lines_seen, rows_inserted)
    """
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)

    auth_retry_used = False
    while True:
        resp = request_with_retries(session, "GET", url, headers=headers, stream=True, timeout=300)

        if resp.status_code == 401 and refresh_headers and not auth_retry_used:
            resp.close()
            headers = refresh_headers()
            auth_retry_used = True
            continue

        if resp.status_code != 200:
            die(f"export failed: {resp.status_code} {url} {resp.text[:500]}")

        break

    rows_inserted = 0
    lines_seen = 0

    cur = db.cursor() if db else None
    batch: List[Tuple[str, str]] = []

    out_file = out_path.open("w", encoding="utf-8") if out_path else None
    try:
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue

            if out_file:
                out_file.write(raw_line + "\n")
            lines_seen += 1

            if db and table and asset_id_field:
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                asset_id = obj.get(asset_id_field)
                if not asset_id or not isinstance(asset_id, str):
                    # best-effort fallback: sometimes exports include `id` as the asset uuid
                    if asset_id_field != "id":
                        fallback_id = obj.get("id")
                        asset_id = fallback_id if isinstance(fallback_id, str) else None

                if not asset_id:
                    continue

                batch.append((asset_id, raw_line))
                if len(batch) >= commit_every:
                    _flush_batch(cur, table, batch)
                    rows_inserted += len(batch)
                    batch.clear()
    finally:
        if out_file:
            out_file.close()

    if db and cur and batch:
        _flush_batch(cur, table, batch)
        rows_inserted += len(batch)
        batch.clear()

    resp.close()
    return lines_seen, rows_inserted


def _flush_batch(cur: sqlite3.Cursor, table: str, batch: List[Tuple[str, str]]) -> None:
    if table == "assets":
        cur.executemany("INSERT OR REPLACE INTO assets(asset_id, json) VALUES (?, ?)", batch)
    elif table == "software":
        cur.executemany("INSERT INTO software(asset_id, json) VALUES (?, ?)", batch)
    elif table == "vulns":
        cur.executemany("INSERT INTO vulns(asset_id, json) VALUES (?, ?)", batch)
    else:
        die(f"unknown table: {table}")
    cur.connection.commit()


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")

    conn.execute("CREATE TABLE IF NOT EXISTS assets (asset_id TEXT PRIMARY KEY, json TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS software (asset_id TEXT NOT NULL, json TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS vulns (asset_id TEXT NOT NULL, json TEXT NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_software_asset_id ON software(asset_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_asset_id ON vulns(asset_id)")
    conn.commit()
    return conn


def build_merged_assets(db: sqlite3.Connection, out_path: Path) -> int:
    """
    Writes JSONL where each line is the asset object +:
      - software: [ ... ]
      - vulnerabilities: [ ... ]
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cur = db.cursor()

    # Stream assets deterministically
    cur.execute("SELECT asset_id, json FROM assets")
    written = 0

    with out_path.open("w", encoding="utf-8") as out_file:
        for asset_id, asset_json in cur:
            try:
                asset_obj = json.loads(asset_json)
            except json.JSONDecodeError:
                continue

            # Fetch related software/vulns
            sw_rows = db.execute("SELECT json FROM software WHERE asset_id = ?", (asset_id,)).fetchall()
            v_rows = db.execute("SELECT json FROM vulns WHERE asset_id = ?", (asset_id,)).fetchall()

            software = []
            for (software_json,) in sw_rows:
                try:
                    software.append(json.loads(software_json))
                except json.JSONDecodeError:
                    continue

            vulns = []
            for (vuln_json,) in v_rows:
                try:
                    vulns.append(json.loads(vuln_json))
                except json.JSONDecodeError:
                    continue

            asset_obj["software"] = software
            asset_obj["vulnerabilities"] = vulns

            out_file.write(json.dumps(asset_obj, separators=(",", ":"), ensure_ascii=False) + "\n")
            written += 1

    return written


def org_id_from_obj(org: Dict[str, Any]) -> Optional[str]:
    # common keys
    for key in ("id", "org_id", "organization_id", "uuid"):
        value = org.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def org_name_from_obj(org: Dict[str, Any]) -> str:
    for key in ("name", "org_name", "organization_name", "label"):
        value = org.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    oid = org_id_from_obj(org)
    return oid or "org"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base-url",
        default=os.getenv("RUNZERO_BASE_URL", "https://console.runzero.com"),
        help="runZero console base URL (default: https://console.runzero.com)",
    )
    ap.add_argument("--out", default="runzero_export", help="output directory")
    ap.add_argument(
        "--mode",
        choices=("raw", "merged", "both"),
        default="both",
        help="raw = only raw JSONL files, merged = only merged assets JSONL, both = do both",
    )
    ap.add_argument(
        "--org-limit", type=int, default=0, help="debug: limit number of orgs processed (0 = no limit)"
    )
    args = ap.parse_args()

    account_token = os.getenv("RUNZERO_ACCOUNT_TOKEN")
    client_id = os.getenv("RUNZERO_CLIENT_ID")
    client_secret = os.getenv("RUNZERO_CLIENT_SECRET")
    if not account_token and (not client_id or not client_secret):
        die("set RUNZERO_ACCOUNT_TOKEN or RUNZERO_CLIENT_ID and RUNZERO_CLIENT_SECRET env vars")

    api_base = args.base_url.rstrip("/") + "/api/v1.0"
    out_root = Path(args.out)

    with requests.Session() as session:
        list_token = account_token or get_token(session, api_base, client_id, client_secret)
        orgs = list_orgs(session, api_base, list_token)
        if args.org_limit and args.org_limit > 0:
            orgs = orgs[: args.org_limit]

        for idx, org in enumerate(orgs, start=1):
            oid = org_id_from_obj(org)
            if not oid:
                print(f"Skipping org with no id: {org}", file=sys.stderr)
                continue

            oname = org_name_from_obj(org)
            org_dir = out_root / f"{idx:03d}_{sanitize_filename(oname)}_{oid[:8]}"
            print(f"[{idx}/{len(orgs)}] Org: {oname} ({oid}) -> {org_dir}")

            db = None
            if args.mode in ("merged", "both"):
                db = init_db(org_dir / "join.sqlite")

            org_token = account_token or get_token(session, api_base, client_id, client_secret)
            headers = {"Authorization": f"Bearer {org_token}", "Accept": "application/json"}

            def refresh_headers() -> Dict[str, str]:
                new_token = account_token or get_token(session, api_base, client_id, client_secret)
                return {"Authorization": f"Bearer {new_token}", "Accept": "application/json"}

            save_raw = args.mode in ("raw", "both")

            # Assets
            assets_url = f"{api_base}/export/org/assets.jsonl?_oid={oid}"
            assets_path = org_dir / "assets.jsonl" if save_raw else None
            assets_lines, _ = stream_jsonl_to_file_and_db(
                session,
                assets_url,
                headers,
                assets_path,
                db=db,
                table="assets" if db else None,
                asset_id_field="id",
                refresh_headers=refresh_headers,
            )
            if assets_path:
                print(f"  assets: {assets_lines} lines")
            else:
                print(f"  assets: {assets_lines} lines (not written; merged mode)")

            # Software (key = software_asset_id)
            sw_url = f"{api_base}/export/org/software.jsonl?_oid={oid}"
            sw_path = org_dir / "software.jsonl" if save_raw else None
            sw_lines, _ = stream_jsonl_to_file_and_db(
                session,
                sw_url,
                headers,
                sw_path,
                db=db,
                table="software" if db else None,
                asset_id_field="software_asset_id",
                refresh_headers=refresh_headers,
            )
            if sw_path:
                print(f"  software: {sw_lines} lines")
            else:
                print(f"  software: {sw_lines} lines (not written; merged mode)")

            # Vulnerabilities (key = vulnerability_asset_id)
            v_url = f"{api_base}/export/org/vulnerabilities.jsonl?_oid={oid}"
            v_path = org_dir / "vulnerabilities.jsonl" if save_raw else None
            v_lines, _ = stream_jsonl_to_file_and_db(
                session,
                v_url,
                headers,
                v_path,
                db=db,
                table="vulns" if db else None,
                asset_id_field="vulnerability_asset_id",
                refresh_headers=refresh_headers,
            )
            if v_path:
                print(f"  vulns: {v_lines} lines")
            else:
                print(f"  vulns: {v_lines} lines (not written; merged mode)")

            if db:
                merged_path = org_dir / "assets_with_software_vulns.jsonl"
                merged_count = build_merged_assets(db, merged_path)
                print(f"  merged assets: {merged_count} lines -> {merged_path}")
                db.close()

    print("Done.")


if __name__ == "__main__":
    main()
