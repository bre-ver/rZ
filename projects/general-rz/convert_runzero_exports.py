#!/usr/bin/env python3
"""
Quick README
============
Purpose:
  Convert existing runZero JSONL exports into CSV and Parquet copies.

Dependency:
  python3 -m pip install pyarrow

Folder Path Setting:
  Set the export root with --root (default: runzero_export).
  The default root is resolved relative to your current working directory
  when you run the script.
  The root should contain org folders like:
    runzero_export/001_Brett_VerMulm_acc5bfcb/
    runzero_export/002_Child_test_b671e370/

Usage:
  python convert_runzero_exports.py
  python convert_runzero_exports.py --root /full/path/to/runzero_export
  python convert_runzero_exports.py --root runzero_export --chunk-size 5000
  python convert_runzero_exports.py --root runzero_export --include-raw-json
  python convert_runzero_exports.py --root runzero_export --include-nested-details

Output:
  For each org folder, files are written to:
    <org_folder>/converted/
  Example:
    runzero_export/001_Brett_VerMulm_acc5bfcb/converted/assets.csv
    runzero_export/001_Brett_VerMulm_acc5bfcb/converted/assets.parquet
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Callable, Dict, Iterable, List

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError as exc:
    raise SystemExit(
        "ERROR: missing dependency 'pyarrow'. Install with: python3 -m pip install pyarrow"
    ) from exc


DEFAULT_ROOT = "runzero_export"
DEFAULT_CHUNK_SIZE = 5000
DATASETS = (
    "assets.jsonl",
    "software.jsonl",
    "vulnerabilities.jsonl",
    "findings.jsonl",
    "assets_with_software_vulns.jsonl",
)


def iter_jsonl(path: Path) -> Iterable[Dict[str, object]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _to_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _s(value: object) -> str:
    return _to_cell(value)


def _json_compact(obj: Dict[str, object]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _build_assets_row(obj: Dict[str, object]) -> Dict[str, str]:
    return {
        "asset_id": _s(obj.get("id")),
        "organization_id": _s(obj.get("organization_id")),
        "org_name": _s(obj.get("org_name")),
        "site_id": _s(obj.get("site_id")),
        "site_name": _s(obj.get("site_name")),
        "alive": _s(obj.get("alive")),
        "risk": _s(obj.get("risk")),
        "risk_rank": _s(obj.get("risk_rank")),
        "criticality": _s(obj.get("criticality")),
        "criticality_rank": _s(obj.get("criticality_rank")),
        "detected_by": _s(obj.get("detected_by")),
        "first_seen": _s(obj.get("first_seen")),
        "last_seen": _s(obj.get("last_seen")),
        "os": _s(obj.get("os")),
        "os_vendor": _s(obj.get("os_vendor")),
        "os_product": _s(obj.get("os_product")),
        "os_version": _s(obj.get("os_version")),
        "hw": _s(obj.get("hw")),
        "hw_vendor": _s(obj.get("hw_vendor")),
        "hw_product": _s(obj.get("hw_product")),
        "hw_version": _s(obj.get("hw_version")),
        "service_count": _s(obj.get("service_count")),
        "software_count": _s(obj.get("software_count")),
        "vulnerability_count": _s(obj.get("vulnerability_count")),
        "addresses": _s(obj.get("addresses")),
        "macs": _s(obj.get("macs")),
        "names": _s(obj.get("names")),
        "domains": _s(obj.get("domains")),
        "tags": _s(obj.get("tags")),
        "source_ids": _s(obj.get("source_ids")),
        "surface_types": _s(obj.get("surface_types")),
        "raw_json": _json_compact(obj),
    }


def _build_software_row(obj: Dict[str, object]) -> Dict[str, str]:
    return {
        "software_id": _s(obj.get("software_id")),
        "software_asset_id": _s(obj.get("software_asset_id")),
        "organization_id": _s(obj.get("software_organization_id") or obj.get("organization_id")),
        "org_name": _s(obj.get("org_name")),
        "site_id": _s(obj.get("site_id")),
        "site_name": _s(obj.get("site_name")),
        "software_product": _s(obj.get("software_product")),
        "software_vendor": _s(obj.get("software_vendor")),
        "software_version": _s(obj.get("software_version")),
        "software_edition": _s(obj.get("software_edition")),
        "software_part": _s(obj.get("software_part")),
        "software_cpe23": _s(obj.get("software_cpe23")),
        "software_language": _s(obj.get("software_language")),
        "software_service_address": _s(obj.get("software_service_address")),
        "software_service_port": _s(obj.get("software_service_port")),
        "software_service_transport": _s(obj.get("software_service_transport")),
        "software_installed_at": _s(obj.get("software_installed_at")),
        "software_updated_at": _s(obj.get("software_updated_at")),
        "risk_rank": _s(obj.get("risk_rank")),
        "addresses": _s(obj.get("addresses")),
        "macs": _s(obj.get("macs")),
        "names": _s(obj.get("names")),
        "raw_json": _json_compact(obj),
    }


def _build_vuln_row(obj: Dict[str, object]) -> Dict[str, str]:
    return {
        "vulnerability_id": _s(obj.get("vulnerability_id")),
        "vulnerability_asset_id": _s(obj.get("vulnerability_asset_id")),
        "organization_id": _s(obj.get("vulnerability_organization_id") or obj.get("organization_id")),
        "org_name": _s(obj.get("org_name")),
        "site_id": _s(obj.get("site_id")),
        "site_name": _s(obj.get("site_name")),
        "vulnerability_name": _s(obj.get("vulnerability_name")),
        "vulnerability_cve": _s(obj.get("vulnerability_cve")),
        "vulnerability_risk": _s(obj.get("vulnerability_risk")),
        "vulnerability_risk_rank": _s(obj.get("vulnerability_risk_rank")),
        "vulnerability_risk_score": _s(obj.get("vulnerability_risk_score")),
        "vulnerability_severity": _s(obj.get("vulnerability_severity")),
        "vulnerability_severity_rank": _s(obj.get("vulnerability_severity_rank")),
        "vulnerability_severity_score": _s(obj.get("vulnerability_severity_score")),
        "vulnerability_service_address": _s(obj.get("vulnerability_service_address")),
        "vulnerability_service_port": _s(obj.get("vulnerability_service_port")),
        "vulnerability_service_transport": _s(obj.get("vulnerability_service_transport")),
        "vulnerability_first_detected_at": _s(obj.get("vulnerability_first_detected_at")),
        "vulnerability_last_detected_at": _s(obj.get("vulnerability_last_detected_at")),
        "vulnerability_published_at": _s(obj.get("vulnerability_published_at")),
        "vulnerability_exploitable": _s(obj.get("vulnerability_exploitable")),
        "vulnerability_suppressed": _s(obj.get("vulnerability_suppressed")),
        "addresses": _s(obj.get("addresses")),
        "macs": _s(obj.get("macs")),
        "names": _s(obj.get("names")),
        "raw_json": _json_compact(obj),
    }


def _build_finding_row(obj: Dict[str, object]) -> Dict[str, str]:
    return {
        "finding_code": _s(obj.get("finding_code")),
        "name": _s(obj.get("name")),
        "category": _s(obj.get("category")),
        "risk_rank": _s(obj.get("risk_rank")),
        "risk_rank_value": _s(obj.get("risk_rank_value")),
        "instance_count": _s(obj.get("instance_count")),
        "created_at": _s(obj.get("created_at")),
        "updated_at": _s(obj.get("updated_at")),
        "last_detected_at": _s(obj.get("last_detected_at")),
        "organization_id": _s(obj.get("organization_id")),
        "org_name": _s(obj.get("org_name")),
        "description": _s(obj.get("description")),
        "solution": _s(obj.get("solution")),
        "links": _s(obj.get("links")),
        "raw_json": _json_compact(obj),
    }


def _build_merged_row(obj: Dict[str, object]) -> Dict[str, str]:
    return {
        "asset_id": _s(obj.get("id")),
        "organization_id": _s(obj.get("organization_id")),
        "org_name": _s(obj.get("org_name")),
        "site_id": _s(obj.get("site_id")),
        "site_name": _s(obj.get("site_name")),
        "alive": _s(obj.get("alive")),
        "risk": _s(obj.get("risk")),
        "risk_rank": _s(obj.get("risk_rank")),
        "criticality": _s(obj.get("criticality")),
        "criticality_rank": _s(obj.get("criticality_rank")),
        "last_seen": _s(obj.get("last_seen")),
        "addresses": _s(obj.get("addresses")),
        "macs": _s(obj.get("macs")),
        "names": _s(obj.get("names")),
        "service_count": _s(obj.get("service_count")),
        "software_count": _s(len(obj.get("software", [])) if isinstance(obj.get("software"), list) else 0),
        "vulnerability_count": _s(
            len(obj.get("vulnerabilities", [])) if isinstance(obj.get("vulnerabilities"), list) else 0
        ),
        "software": _s(obj.get("software")),
        "vulnerabilities": _s(obj.get("vulnerabilities")),
        "raw_json": _json_compact(obj),
    }


DATASET_SPECS: Dict[str, Dict[str, object]] = {
    "assets.jsonl": {
        "columns": list(_build_assets_row({}).keys()),
        "builder": _build_assets_row,
    },
    "software.jsonl": {
        "columns": list(_build_software_row({}).keys()),
        "builder": _build_software_row,
    },
    "vulnerabilities.jsonl": {
        "columns": list(_build_vuln_row({}).keys()),
        "builder": _build_vuln_row,
    },
    "findings.jsonl": {
        "columns": list(_build_finding_row({}).keys()),
        "builder": _build_finding_row,
    },
    "assets_with_software_vulns.jsonl": {
        "columns": list(_build_merged_row({}).keys()),
        "builder": _build_merged_row,
    },
}


def write_csv_rows(row_iter: Iterable[Dict[str, str]], csv_path: Path, columns: List[str]) -> int:
    row_count = 0
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in row_iter:
            writer.writerow({k: row.get(k, "") for k in columns})
            row_count += 1
    return row_count


def write_parquet_rows(
    row_iter: Iterable[Dict[str, str]], parquet_path: Path, columns: List[str], chunk_size: int
) -> int:
    writer = None
    row_count = 0
    chunk: List[Dict[str, str]] = []

    try:
        for row in row_iter:
            chunk.append({k: row.get(k, "") for k in columns})

            if len(chunk) >= chunk_size:
                table = pa.Table.from_pylist(chunk)
                if writer is None:
                    writer = pq.ParquetWriter(parquet_path, table.schema)
                writer.write_table(table)
                row_count += len(chunk)
                chunk.clear()

        if chunk:
            table = pa.Table.from_pylist(chunk)
            if writer is None:
                writer = pq.ParquetWriter(parquet_path, table.schema)
            writer.write_table(table)
            row_count += len(chunk)
            chunk.clear()

        if writer is None:
            empty = pa.Table.from_pylist([], schema=pa.schema([pa.field(c, pa.string()) for c in columns]))
            pq.write_table(empty, parquet_path)
    finally:
        if writer is not None:
            writer.close()

    return row_count


def _shape_row(
    row: Dict[str, str],
    include_raw_json: bool,
    include_nested_details: bool,
    dataset_file: str,
) -> Dict[str, str]:
    out = dict(row)
    if not include_raw_json:
        out.pop("raw_json", None)
    if dataset_file == "assets_with_software_vulns.jsonl" and not include_nested_details:
        out.pop("software", None)
        out.pop("vulnerabilities", None)
    return out


def convert_dataset(
    org_dir: Path,
    dataset_file: str,
    chunk_size: int,
    include_raw_json: bool,
    include_nested_details: bool,
) -> None:
    jsonl_path = org_dir / dataset_file
    if not jsonl_path.exists():
        return

    print(f"  converting {dataset_file}...")
    spec = DATASET_SPECS.get(dataset_file)
    if not spec:
        print(f"    skipping unsupported dataset: {dataset_file}")
        return
    spec_columns: List[str] = spec["columns"]  # type: ignore[assignment]
    builder: Callable[[Dict[str, object]], Dict[str, str]] = spec["builder"]  # type: ignore[assignment]
    columns = [c for c in spec_columns if include_raw_json or c != "raw_json"]
    if dataset_file == "assets_with_software_vulns.jsonl" and not include_nested_details:
        columns = [c for c in columns if c not in ("software", "vulnerabilities")]

    out_dir = org_dir / "converted"
    out_dir.mkdir(parents=True, exist_ok=True)

    base = dataset_file[:-6] if dataset_file.endswith(".jsonl") else dataset_file
    csv_path = out_dir / f"{base}.csv"
    parquet_path = out_dir / f"{base}.parquet"

    csv_rows = write_csv_rows(
        (
            _shape_row(builder(obj), include_raw_json, include_nested_details, dataset_file)
            for obj in iter_jsonl(jsonl_path)
        ),
        csv_path,
        columns,
    )
    parquet_rows = write_parquet_rows(
        (
            _shape_row(builder(obj), include_raw_json, include_nested_details, dataset_file)
            for obj in iter_jsonl(jsonl_path)
        ),
        parquet_path,
        columns,
        chunk_size,
    )
    print(f"    rows: csv={csv_rows}, parquet={parquet_rows}")


def convert_root(root: Path, chunk_size: int, include_raw_json: bool, include_nested_details: bool) -> None:
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"ERROR: root not found or not a directory: {root}")

    org_dirs = sorted([p for p in root.iterdir() if p.is_dir()])
    if not org_dirs:
        raise SystemExit(f"ERROR: no org folders found under {root}")

    print(f"Found {len(org_dirs)} org folder(s) under {root}")
    for org_dir in org_dirs:
        print(f"Org: {org_dir.name}")
        for dataset in DATASETS:
            convert_dataset(org_dir, dataset, chunk_size, include_raw_json, include_nested_details)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT, help="Root folder containing org export folders")
    ap.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Rows per Parquet write batch")
    ap.add_argument(
        "--include-raw-json",
        action="store_true",
        help="Include raw_json column with full source object payloads",
    )
    ap.add_argument(
        "--include-nested-details",
        action="store_true",
        help="For merged assets, include full software/vulnerabilities arrays as columns",
    )
    args = ap.parse_args()

    if args.chunk_size <= 0:
        raise SystemExit("ERROR: --chunk-size must be > 0")

    convert_root(Path(args.root), args.chunk_size, args.include_raw_json, args.include_nested_details)


if __name__ == "__main__":
    main()
