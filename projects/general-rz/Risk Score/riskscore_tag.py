#!/usr/bin/env python3
"""
runZero Risk Score Tagger
- Pulls org assets + software + vulnerabilities via Export JSONL APIs
- Computes a per-asset numeric score (0-100) using heuristic risk signals
- Maps numeric score to a risk band and writes only: riskband=<band>
- Writes a CSV breakdown including numeric score components and rationale

High-level flow:
1) Export assets, software, and vulnerabilities for each target org.
2) Derive exposure, vulnerability, impact, pivot, and software risk signals.
3) Compute a numeric score, then map to a 6-level risk band.
4) Patch asset tags in runZero and emit CSV evidence for review.

Alpha status:
- This model is currently ALPHA and intentionally heuristic.
- Thresholds, multipliers, and pattern matches should be tuned over time.

Auth:
- Preferred: RUNZERO_CLIENT_ID + RUNZERO_CLIENT_SECRET -> POST /account/api/token (client_credentials)
- Alternate: RUNZERO_BEARER_TOKEN (already-issued access token)
- Org-scoped token: RUNZERO_ORG_API_KEY (org-scoped bearer)

"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import requests


DEFAULT_BASE_URL = os.environ.get("RUNZERO_BASE_URL", "https://console.runzero.com/api/v1.0")

BAND_KEY_DEFAULT = "riskband"
LEGACY_SCORE_TAG_KEYS = {"riskscore"}

# -----------------------------
# Helpers: HTTP + auth
# -----------------------------

def http_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "runzero-riskscore-tagger/1.0"})
    return s


def get_access_token(sess: requests.Session, base_url: str) -> str:
    org_api_key = os.environ.get("RUNZERO_ORG_API_KEY")
    if org_api_key:
        return org_api_key.strip()

    bearer = os.environ.get("RUNZERO_BEARER_TOKEN")
    if bearer:
        return bearer.strip()

    client_id = os.environ.get("RUNZERO_CLIENT_ID")
    client_secret = os.environ.get("RUNZERO_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit("Missing auth. Set RUNZERO_ORG_API_KEY or RUNZERO_BEARER_TOKEN or RUNZERO_CLIENT_ID + RUNZERO_CLIENT_SECRET.")

    url = f"{base_url}/account/api/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = sess.post(url, data=data, timeout=60)
    if not resp.ok:
        raise SystemExit(f"Token request failed: {resp.status_code} {resp.text}")
    tok = resp.json().get("access_token")
    if not tok:
        raise SystemExit(f"Token response missing access_token: {resp.text}")
    return tok


def api_get_json(sess: requests.Session, url: str, headers: dict, params: dict | None = None) -> dict | list:
    resp = sess.get(url, headers=headers, params=params, timeout=120)
    if not resp.ok:
        raise RuntimeError(f"GET {url} failed: {resp.status_code} {resp.text}")
    return resp.json()


def stream_jsonl(sess: requests.Session, url: str, headers: dict, params: dict | None = None) -> Iterable[dict]:
    # stream export jsonl
    with sess.get(url, headers=headers, params=params, stream=True, timeout=300) as r:
        if not r.ok:
            raise RuntimeError(f"GET {url} failed: {r.status_code} {r.text}")
        for line in r.iter_lines(decode_unicode=True):
            if not line:
                continue
            yield json.loads(line)


def backoff_sleep(attempt: int) -> None:
    # simple exponential backoff with cap
    time.sleep(min(30.0, (2 ** attempt) * 0.5))


# -----------------------------
# Tail squashing + risk bands
# -----------------------------

TAIL_START = 90.0     # linear up to 90
TAIL_RANGE = 10.0     # only 10 points above 90
TAIL_TAU   = 60.0     # bigger = harder to reach 100

def squash_to_100(raw: float) -> float:
    """
    Maps raw (unbounded) -> [0,100], with a diminishing tail above 90.
    100 remains achievable but requires a very high raw score.
    """
    if raw <= TAIL_START:
        return raw
    return TAIL_START + TAIL_RANGE * (1.0 - math.exp(-(raw - TAIL_START) / TAIL_TAU))


def round_to_5(x: float) -> int:
    # Optional stability; comment out if you want per-point precision.
    return int(5 * round(x / 5.0))


def risk_band(score: int) -> str:
    # 6 levels
    if score >= 95:
        return "emergency"
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "moderate"
    if score >= 30:
        return "low"
    return "minimal"


# -----------------------------
# Scoring model (runZero-native)
# -----------------------------

PANEL_DETECT_RE = re.compile(r"panel\s*[-:/]?\s*detect", re.IGNORECASE)

DEFAULT_CREDS_RE = re.compile(
    r"(default (password|credential|credentials)|default community|snmp default community|public community|"
    r"unauthenticated|authentication bypass|auth bypass|no authentication)",
    re.IGNORECASE,
)

PUBLICLY_EXPOSED_RE = re.compile(r"publicly\s+exposed", re.IGNORECASE)
POTENTIAL_EXTERNAL_RE = re.compile(r"potential\s+external\s+access", re.IGNORECASE)

REMOTE_ADMIN_PROTOCOLS = {"ssh", "rdp", "winrm", "wsman", "vnc", "telnet"}
WEB_PROTOCOLS = {"http", "https", "tls"}
PIVOT_PROTOCOLS = {"smb", "smb2", "smb3", "rdp", "ssh", "winrm", "wsman", "ldap", "ldaps", "kerberos", "nfs"}

# Some common OT/control protocols runZero may surface under service_protocols
OT_PROTOCOL_HINTS = {"cip", "ethernet/ip", "modbus", "bacnet", "dnp3", "s7", "profinet"}
INSECURE_PROTOCOLS = {"telnet", "ftp", "tftp", "snmp"}  # you may want snmp1/snmp2 specifically
RISKY_TCP_PORTS = {21, 22, 23, 445, 3389, 5900, 5985, 5986, 3306, 5432, 6379, 9200}

REMOTE_ADMIN_SOFTWARE_RE = re.compile(
    r"(teamviewer|anydesk|vnc|rdp|ssh|openvpn|wireguard|forticlient|connectwise|screenconnect|bomgar|beyondtrust)",
    re.IGNORECASE,
)
SERVER_STACK_SOFTWARE_RE = re.compile(
    r"(nginx|apache|iis|tomcat|jetty|mysql|mariadb|postgres|mssql|oracle|redis|elasticsearch|docker|kubernetes)",
    re.IGNORECASE,
)

SAFE_TAG_KEY_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")
SAFE_TAG_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/+@-]+$")

BREAKDOWN_CSV_FIELDS = [
    "org_id",
    "asset_id",
    "asset_name",
    "asset_type",
    "alive",
    "criticality_rank",
    "eol_os",
    "addresses",
    "service_protocols",
    "service_count",
    "service_count_tcp",
    "software_unique_products",
    "vuln_unique_count",
    "vuln_critical_count",
    "vuln_high_count",
    "vuln_exploitable_count",
    "external_confirmed",
    "external_potential",
    "default_creds",
    "nuclei_real",
    "top3_evr",
    "component_exposure",
    "component_vuln",
    "component_impact",
    "component_pivot",
    "component_software",
    "base_score",
    "total_multiplier",
    "raw_score",
    "final_score",
    "risk_score",
    "risk_band",
    "tag_update_status",
    "rationale",
]


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def normalize_tags(tags_raw: object) -> Dict[str, str]:
    if isinstance(tags_raw, dict):
        out: Dict[str, str] = {}
        for k, v in tags_raw.items():
            key = str(k).strip()
            if not key:
                continue
            out[key] = "" if v is None else str(v).strip()
        return out

    if isinstance(tags_raw, list):
        out: Dict[str, str] = {}
        for item in tags_raw:
            token = str(item).strip()
            if not token:
                continue
            if "=" in token:
                k, v = token.split("=", 1)
                k = k.strip()
                if k:
                    out[k] = v.strip()
            else:
                out[token] = ""
        return out

    return {}


def as_float(value: object) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            return float(v)
        except ValueError:
            return None
    return None


def as_int(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            return int(float(v))
        except ValueError:
            return None
    return None


def pipe_join(values: object) -> str:
    if not isinstance(values, list):
        return ""
    return "|".join(str(v) for v in values if v not in (None, ""))


def primary_asset_name(asset: dict) -> str:
    names = asset.get("names") or []
    if isinstance(names, list) and names:
        return str(names[0])
    addrs = asset.get("addresses") or []
    if isinstance(addrs, list) and addrs:
        return str(addrs[0])
    return ""


def vulnerability_rank(v: dict) -> int:
    rank = as_int(v.get("vulnerability_severity_rank"))
    if rank is not None and 0 <= rank <= 4:
        return rank

    score = severity_weight(v)
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return 0


def vulnerability_dedupe_key(v: dict) -> str:
    for key in ("vulnerability_vuln_id", "vulnerability_cve", "vulnerability_name"):
        raw = (v.get(key) or "")
        value = str(raw).strip().lower()
        if value:
            return f"{key}:{value}"

    addr = str(v.get("vulnerability_service_address") or "").strip().lower()
    port = str(v.get("vulnerability_service_port") or "").strip().lower()
    return f"fallback:{addr}:{port}"


def severity_weight(v: dict) -> float:
    # Prefer score-like fields first; fallback to rank mapping.
    for key in (
        "vulnerability_cvss3_base_score",
        "vulnerability_severity_score",
        "vulnerability_risk_score",
        "vulnerability_cvss2_base_score",
    ):
        score = as_float(v.get(key))
        if score is not None and score > 0:
            return min(10.0, score)

    rank = as_int(v.get("vulnerability_severity_rank"))
    if rank == 4:   # critical
        return 9.5
    if rank == 3:   # high
        return 8.0
    if rank == 2:   # medium
        return 5.5
    if rank == 1:   # low
        return 2.5
    return 0.0


def vulnerability_exploitable(v: dict) -> bool:
    if v.get("vulnerability_exploitable") is True:
        return True
    attrs = v.get("vulnerability_attributes") or {}
    level = str(attrs.get("exploitabilityLevel") or attrs.get("exploitability_level") or "").strip().lower()
    if not level:
        return False
    if "noexploit" in level or level in {"none", "unknown"}:
        return False
    return "exploit" in level


def recency_factor(v: dict, now_ts: int) -> float:
    # Note: You may later move this into a confidence score instead.
    ts = as_int(v.get("vulnerability_last_detected_at"))
    if ts is None or ts <= 0:
        ts = as_int(v.get("vulnerability_updated_at"))
    if ts is None or ts <= 0:
        return 1.0

    age_days = max(0.0, (now_ts - ts) / 86400.0)
    if age_days <= 30:
        return 1.0
    if age_days <= 90:
        return 0.9
    if age_days <= 180:
        return 0.75
    return 0.6


def exploit_evidence(v: dict) -> float:
    attrs = v.get("vulnerability_attributes") or {}
    vscan_type = attrs.get("vscan.type")
    name = v.get("vulnerability_name") or ""

    is_nuclei = (vscan_type == "vuln")
    if is_nuclei and PANEL_DETECT_RE.search(name):
        return 0.0  # explicitly ignored
    if is_nuclei:
        return 0.95
    if vulnerability_exploitable(v):
        return 0.80

    rank = vulnerability_rank(v)
    if rank >= 3:
        return 0.45
    if rank == 2:
        return 0.35
    return 0.25


def is_default_creds(v: dict) -> bool:
    name = v.get("vulnerability_name") or ""
    if DEFAULT_CREDS_RE.search(name):
        if PANEL_DETECT_RE.search(name):
            return False
        return True
    return False


def is_real_nuclei(v: dict) -> bool:
    attrs = v.get("vulnerability_attributes") or {}
    vscan_type = attrs.get("vscan.type")
    if vscan_type != "vuln":
        return False
    name = v.get("vulnerability_name") or ""
    if PANEL_DETECT_RE.search(name):
        return False
    return True


def reachability_factor(asset_flags: "AssetFlags") -> float:
    if asset_flags.external_confirmed:
        return 1.0
    if asset_flags.external_potential:
        return 0.8
    return 0.6


def vuln_core_evr(v: dict, now_ts: int) -> float:
    if v.get("vulnerability_suppressed") is True:
        return 0.0

    attrs = v.get("vulnerability_attributes") or {}
    name = v.get("vulnerability_name") or ""
    if attrs.get("vscan.type") == "vuln" and PANEL_DETECT_RE.search(name):
        return 0.0

    cat = (v.get("vulnerability_category") or "").strip().lower()
    if cat == "internet exposure":
        return 0.0

    sev = severity_weight(v)
    if sev <= 0:
        return 0.0

    e = exploit_evidence(v)
    rec = recency_factor(v, now_ts)
    if e <= 0:
        return 0.0

    return float(sev) * e * rec


@dataclass
class VulnStats:
    unique_vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    exploitable_count: int = 0
    default_creds_count: int = 0
    nuclei_count: int = 0


def vuln_pressure_score(stats: VulnStats) -> float:
    pressure = 0.0
    pressure += min(6.0, float(stats.critical_count) * 1.8)
    pressure += min(4.0, float(stats.high_count) * 0.8)
    if stats.exploitable_count >= 2:
        pressure += 1.0
    elif stats.exploitable_count == 1:
        pressure += 0.5
    if stats.default_creds_count > 0:
        pressure += 1.5
    return min(10.0, pressure)


def vuln_score_from_top3(top3: List[float], stats: VulnStats) -> float:
    if not top3:
        return vuln_pressure_score(stats)
    norms = [min(1.0, max(0.0, x / 10.0)) for x in top3[:3]]
    prod = 1.0
    for n in norms:
        prod *= (1.0 - n)
    agg = 1.0 - prod
    return min(40.0, (35.0 * agg) + vuln_pressure_score(stats))


def exposure_score(asset: dict, flags: "AssetFlags") -> float:
    score = 0.0
    if flags.external_confirmed:
        score += 15.0
    elif flags.external_potential:
        score += 8.0

    protos = set((asset.get("service_protocols") or []))
    protos_norm = {p.lower() for p in protos if isinstance(p, str)}

    ra = sum(3 for p in protos_norm if p in REMOTE_ADMIN_PROTOCOLS)
    score += float(min(6, ra))

    web = 2 if (protos_norm & WEB_PROTOCOLS) else 0
    score += float(min(4, web))

    bucket = 0
    if {"smb", "smb2", "smb3"} & protos_norm:
        bucket += 2
    if {"ldap", "ldaps"} & protos_norm:
        bucket += 2
    score += float(min(4, bucket))

    ot = 0
    for p in protos_norm:
        if p in OT_PROTOCOL_HINTS:
            ot += 2
    score += float(min(4, ot))

    insecure = sum(1 for p in protos_norm if p in INSECURE_PROTOCOLS)
    score += float(min(3, insecure))

    tcp_count = as_int(asset.get("service_count_tcp")) or 0
    if tcp_count >= 20:
        score += 3.0
    elif tcp_count >= 10:
        score += 2.0
    elif tcp_count >= 5:
        score += 1.0

    tcp_ports = set()
    for p in (asset.get("service_ports_tcp") or []):
        port = as_int(p)
        if port is not None and port > 0:
            tcp_ports.add(port)
    score += float(min(3, len(tcp_ports & RISKY_TCP_PORTS)))

    return min(25.0, score)


def impact_score(asset: dict) -> float:
    a_type = (asset.get("type") or "").strip().lower()
    names = " ".join(asset.get("names") or []).lower()
    tags = normalize_tags(asset.get("tags"))
    tag_keys = {str(k).lower() for k in tags.keys()}
    tag_vals = {str(v).lower() for v in tags.values() if v is not None}

    service_products = " ".join(asset.get("service_products") or []).lower()
    os_product = (asset.get("os_product") or "").lower()
    criticality_rank = as_int(asset.get("criticality_rank")) or 0
    criticality_score = 0.0
    if criticality_rank >= 4:
        criticality_score = 15.0
    elif criticality_rank == 3:
        criticality_score = 13.0
    elif criticality_rank == 2:
        criticality_score = 10.0
    elif criticality_rank == 1:
        criticality_score = 7.0

    if "firewall" in a_type or "vpn" in a_type or "router" in a_type:
        return max(15.0, criticality_score)
    if "network appliance" in a_type and ("fire" in names or "vpn" in names or "gateway" in names):
        return max(15.0, criticality_score)
    if "edge" in tag_keys or "dmz" in tag_keys:
        return max(15.0, criticality_score)

    if "proxmox" in service_products or "proxmox" in names or "pve" in names:
        return max(15.0, criticality_score)
    if "esxi" in names or "vmware" in service_products:
        return max(15.0, criticality_score)

    tag_blob = " ".join(tag_keys | tag_vals)
    if any(k in tag_blob for k in ("ot", "ics", "scada", "plc", "hmi")):
        return max(12.0, criticality_score)

    if "server" in a_type:
        return max(10.0, criticality_score)
    if "switch" in a_type or "wap" in a_type:
        return max(8.0, criticality_score)
    if "desktop" in a_type or "laptop" in a_type:
        return max(6.0, criticality_score)
    if "phone" in a_type or "mobile" in a_type:
        return max(5.0, criticality_score)
    if "tv" in a_type or "iot" in a_type:
        return max(2.0, criticality_score)
    if "windows server" in os_product or "debian" in os_product or "ubuntu" in os_product:
        return max(10.0, criticality_score)
    return max(6.0, criticality_score)


def pivot_score(asset: dict) -> float:
    score = 0.0
    protos = {p.lower() for p in (asset.get("service_protocols") or []) if isinstance(p, str)}
    for p in protos:
        if p in PIVOT_PROTOCOLS:
            score += 3.0
    score = min(score, 12.0)

    subnets = asset.get("subnets") or {}
    if isinstance(subnets, dict) and len(subnets.keys()) >= 2:
        score += 5.0
    addresses = asset.get("addresses") or []
    if isinstance(addresses, list) and len(addresses) >= 2:
        score += 2.0
    if protos & OT_PROTOCOL_HINTS:
        score += 2.0
    return min(15.0, score)


def production_multiplier(asset: dict) -> float:
    tags = normalize_tags(asset.get("tags"))
    for k, v in tags.items():
        if str(k).lower() == "production":
            return 1.15
        if str(k).lower() in {"group", "env", "environment"} and str(v).lower() == "production":
            return 1.15

    subnets = asset.get("subnets") or {}
    if isinstance(subnets, dict):
        for _, meta in subnets.items():
            if not isinstance(meta, dict):
                continue
            stags = meta.get("tags") or {}
            if any(str(t).lower() == "production" for t in stags.keys()):
                return 1.15
            for tk, tv in stags.items():
                if str(tk).lower() in {"group", "env", "environment"} and str(tv).lower() == "production":
                    return 1.15
    return 1.0


@dataclass
class SoftwareSignals:
    unique_products: int = 0
    has_remote_admin_tool: bool = False
    has_server_stack: bool = False


def software_score(signals: SoftwareSignals) -> float:
    score = 0.0
    if signals.unique_products >= 100:
        score += 3.0
    elif signals.unique_products >= 50:
        score += 2.0
    elif signals.unique_products >= 20:
        score += 1.0

    if signals.has_remote_admin_tool:
        score += 2.0
    if signals.has_server_stack:
        score += 2.0

    return min(5.0, score)


@dataclass
class AssetFlags:
    external_confirmed: bool = False
    external_potential: bool = False
    has_nuclei_real: bool = False
    has_default_creds: bool = False


def total_multiplier(asset: dict, flags: AssetFlags) -> float:
    m = 1.0
    if flags.external_confirmed:
        m *= 1.20
    elif flags.external_potential:
        m *= 1.10

    if flags.has_nuclei_real:
        m *= 1.35
    if flags.has_default_creds:
        m *= 1.70

    if (flags.external_confirmed or flags.external_potential) and (flags.has_nuclei_real or flags.has_default_creds):
        m *= 1.15

    m *= production_multiplier(asset)

    crit_rank = as_int(asset.get("criticality_rank")) or 0
    if crit_rank >= 4:
        m *= 1.25
    elif crit_rank == 3:
        m *= 1.15
    elif crit_rank == 2:
        m *= 1.08

    if asset.get("eol_os"):
        m *= 1.25

    if asset.get("alive") is False:
        m *= 0.85

    return min(2.75, m)


def compute_score(
    asset: dict,
    flags: AssetFlags,
    top3_evr: List[float],
    soft: SoftwareSignals,
    vstats: VulnStats,
) -> Tuple[int, str, dict]:
    exp = exposure_score(asset, flags)
    vul = vuln_score_from_top3(top3_evr, vstats)
    imp = impact_score(asset)
    piv = pivot_score(asset)
    sw = software_score(soft)

    base = min(100.0, exp + vul + imp + piv + sw)
    mult = total_multiplier(asset, flags)

    raw = base * mult
    final = min(100.0, squash_to_100(raw))

    # Optional stability: round to nearest 5.
    score_int = round_to_5(final)
    score_int = max(0, min(100, score_int))

    band = risk_band(score_int)

    explain = {
        "exposure": round(exp, 2),
        "vuln": round(vul, 2),
        "impact": round(imp, 2),
        "pivot": round(piv, 2),
        "software": round(sw, 2),
        "base": round(base, 2),
        "mult": round(mult, 3),
        "raw": round(raw, 2),
        "final": round(final, 2),
        "external_confirmed": flags.external_confirmed,
        "external_potential": flags.external_potential,
        "nuclei_real": flags.has_nuclei_real,
        "default_creds": flags.has_default_creds,
        "software_unique_products": soft.unique_products,
        "software_remote_admin": soft.has_remote_admin_tool,
        "software_server_stack": soft.has_server_stack,
        "vuln_unique_count": vstats.unique_vuln_count,
        "vuln_critical_count": vstats.critical_count,
        "vuln_high_count": vstats.high_count,
        "vuln_exploitable_count": vstats.exploitable_count,
        "vuln_default_creds_count": vstats.default_creds_count,
        "vuln_nuclei_count": vstats.nuclei_count,
        "top3_evr": [round(x, 3) for x in top3_evr[:3]],
    }

    return score_int, band, explain


def build_rationale(asset: dict, flags: AssetFlags, explain: dict) -> str:
    reasons: List[str] = []

    if flags.external_confirmed:
        reasons.append("Internet exposure confirmed")
    elif flags.external_potential:
        reasons.append("Potential external exposure")

    crit = as_int(asset.get("criticality_rank")) or 0
    if crit >= 3:
        reasons.append(f"High criticality rank ({crit})")

    if explain.get("vuln_critical_count", 0) > 0:
        reasons.append(f"{explain['vuln_critical_count']} critical vulnerabilities")
    if explain.get("vuln_high_count", 0) > 0:
        reasons.append(f"{explain['vuln_high_count']} high vulnerabilities")
    if explain.get("vuln_exploitable_count", 0) > 0:
        reasons.append("Known/likely exploitable findings present")

    if flags.has_default_creds:
        reasons.append("Default credentials finding detected")
    if flags.has_nuclei_real:
        reasons.append("Nuclei-validated vulnerability evidence")
    if explain.get("software_server_stack"):
        reasons.append("Server stack software detected")
    if asset.get("eol_os"):
        reasons.append("End-of-life OS signal")

    if not reasons:
        reasons.append("No major exploit or exposure amplifiers detected")
    return "; ".join(reasons[:6])


def write_breakdown_csv(path: str, rows: List[dict]) -> None:
    out_dir = os.path.dirname(path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=BREAKDOWN_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# -----------------------------
# Tag formatting + update
# -----------------------------

def tags_dict_to_list(tags: dict) -> List[str]:
    out: List[str] = []
    for k, v in (tags or {}).items():
        key = str(k).strip()
        if not key:
            continue
        val = "" if v is None else str(v).strip()
        if val == "":
            out.append(key)
        else:
            out.append(f"{key}={val}")
    return out


def encode_tag_value(value: str) -> str:
    if SAFE_TAG_VALUE_RE.fullmatch(value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def set_tag_in_list(tag_list: List[str], key: str, value: str) -> List[str]:
    key_l = key.lower()
    cleaned = []
    for t in tag_list:
        if t.lower() == key_l:
            continue
        if t.lower().startswith(key_l + "="):
            continue
        cleaned.append(t)
    cleaned.append(f"{key}={value}")
    return cleaned


def _tag_key(token: str) -> str:
    t = str(token).strip()
    if "=" in t:
        return t.split("=", 1)[0].strip().lower()
    return t.lower()


def has_any_tag_key(tag_list: List[str], keys: set[str]) -> bool:
    keys_l = {k.lower() for k in keys}
    for token in tag_list:
        if _tag_key(token) in keys_l:
            return True
    return False


def remove_tag_keys(tag_list: List[str], keys: set[str]) -> List[str]:
    keys_l = {k.lower() for k in keys}
    return [token for token in tag_list if _tag_key(token) not in keys_l]


def tags_list_to_string(tag_list: List[str]) -> str:
    return " ".join(sorted(tag_list))


def format_tag_token(key: str, value: str) -> str:
    key = key.strip()
    if not key:
        return ""
    if not SAFE_TAG_KEY_RE.fullmatch(key):
        key = re.sub(r"\s+", "_", key)
        key = re.sub(r"[^A-Za-z0-9_.:/+-]", "", key)
    if not key:
        return ""
    if value == "":
        return key
    return f"{key}={encode_tag_value(value)}"


def patch_asset_tags(
    sess: requests.Session,
    base_url: str,
    headers: dict,
    org_id: Optional[str],
    asset_id: str,
    tags_string: str,
    dry_run: bool,
) -> bool:
    if dry_run:
        return True

    url = f"{base_url}/org/assets/{asset_id}/tags"
    params = {"_oid": org_id} if org_id else None
    payload = {"tags": tags_string}

    for attempt in range(6):
        resp = sess.patch(url, headers=headers, params=params, json=payload, timeout=60)
        if resp.status_code in (429, 500, 502, 503, 504):
            backoff_sleep(attempt)
            continue
        if not resp.ok:
            print(f"PATCH tags failed org={org_id} asset={asset_id}: {resp.status_code} {resp.text}", file=sys.stderr)
            return False
        return True

    print(f"PATCH tags failed after retries org={org_id} asset={asset_id}", file=sys.stderr)
    return False


# -----------------------------
# Main pipeline: org loop
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Compute runZero risk score and write riskband=<band> tags.")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help="runZero API base URL (default: console.runzero.com)")
    ap.add_argument("--band-key", default=BAND_KEY_DEFAULT, help="Band tag key (default: riskband)")
    ap.add_argument("--org", action="append", default=[], help="Limit to specific org_id (repeatable). Default: all orgs.")
    ap.add_argument("--dry-run", action="store_true", help="Compute scores but do not update runZero tags.")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of assets per org (debug). 0 = no limit.")
    ap.add_argument("--include-inactive", action="store_true", help="Include assets where alive=false (default: active only).")
    ap.add_argument("--refresh-band", action="store_true", help="Always rewrite riskband tag even if value is unchanged.")
    ap.add_argument("--csv-out", default="riskscore_breakdown.csv", help="Write per-asset scoring breakdown CSV to this path.")
    args = ap.parse_args()

    sess = http_session()
    token = get_access_token(sess, args.base_url)
    headers = {"Authorization": f"Bearer {token}"}

    org_api_key_set = bool(os.environ.get("RUNZERO_ORG_API_KEY"))
    target_orgs: List[Optional[str]]
    if org_api_key_set:
        target_orgs = [None]
        if args.org:
            print("RUNZERO_ORG_API_KEY is set; ignoring --org filters because token scope is already org-specific.")
    else:
        orgs = api_get_json(sess, f"{args.base_url}/account/orgs", headers=headers)
        if not isinstance(orgs, list):
            raise SystemExit(f"Unexpected /account/orgs response: {type(orgs)}")

        target_orgs = []
        wanted = set(o.strip() for o in (args.org or []) if o.strip())
        for o in orgs:
            oid = o.get("id") or o.get("org_id") or o.get("organization_id")
            if not oid:
                continue
            if wanted and oid not in wanted:
                continue
            target_orgs.append(oid)

        if not target_orgs:
            raise SystemExit("No organizations found (or none matched --org).")

    print(f"Organizations to process: {len(target_orgs)}")
    all_csv_rows: List[dict] = []

    for org_id in target_orgs:
        org_label = org_id if org_id else "ORG(from token scope)"
        print(f"\n=== ORG {org_label} ===")

        assets_url = f"{args.base_url}/export/org/assets.jsonl"
        software_url = f"{args.base_url}/export/org/software.jsonl"
        vulns_url = f"{args.base_url}/export/org/vulnerabilities.jsonl"
        params = {"_oid": org_id} if org_id else None

        # 1) Load assets
        assets: Dict[str, dict] = {}
        count_assets = 0
        for a in stream_jsonl(sess, assets_url, headers=headers, params=params):
            aid = a.get("id")
            if not aid:
                continue
            if not args.include_inactive and a.get("alive") is False:
                continue
            assets[aid] = a
            count_assets += 1
            if args.limit and count_assets >= args.limit:
                break

        print(f"Assets loaded: {count_assets}")

        # Initialize per-asset working state
        flags: Dict[str, AssetFlags] = {aid: AssetFlags() for aid in assets.keys()}
        top3: Dict[str, List[float]] = {aid: [] for aid in assets.keys()}
        vuln_stats: Dict[str, VulnStats] = {aid: VulnStats() for aid in assets.keys()}
        vuln_best: Dict[str, Dict[str, dict]] = {aid: {} for aid in assets.keys()}
        sw_products: Dict[str, set[str]] = {aid: set() for aid in assets.keys()}
        sw_signals: Dict[str, SoftwareSignals] = {aid: SoftwareSignals() for aid in assets.keys()}

        # 2) Stream software rows and compute software-derived signals
        count_software = 0
        for s in stream_jsonl(sess, software_url, headers=headers, params=params):
            aid = s.get("software_asset_id") or s.get("asset_id") or s.get("id")
            if aid not in assets:
                continue
            count_software += 1

            product = str(s.get("software_product") or "").strip()
            vendor = str(s.get("software_vendor") or "").strip()
            text = " ".join(x for x in [product, vendor] if x).lower()

            if product:
                sw_products[aid].add(product.lower())
            if text and REMOTE_ADMIN_SOFTWARE_RE.search(text):
                sw_signals[aid].has_remote_admin_tool = True
            if text and SERVER_STACK_SOFTWARE_RE.search(text):
                sw_signals[aid].has_server_stack = True

        for aid in assets.keys():
            sw_signals[aid].unique_products = len(sw_products[aid])

        print(f"Software rows processed (matched to assets): {count_software}")

        # 3) Stream vulnerabilities and compute flags + best EVR per vuln key
        count_vulns = 0
        now_ts = int(time.time())
        for v in stream_jsonl(sess, vulns_url, headers=headers, params=params):
            aid = v.get("vulnerability_asset_id") or v.get("id")
            if aid not in assets:
                continue
            if v.get("vulnerability_suppressed") is True:
                continue

            count_vulns += 1
            f = flags[aid]

            cat = (v.get("vulnerability_category") or "").strip().lower()
            name = v.get("vulnerability_name") or ""

            # Internet Exposure (authoritative)
            if cat == "internet exposure":
                if PUBLICLY_EXPOSED_RE.search(name):
                    f.external_confirmed = True
                elif POTENTIAL_EXTERNAL_RE.search(name):
                    f.external_potential = True
                continue

            has_default_creds = is_default_creds(v)
            if has_default_creds:
                f.has_default_creds = True

            has_real_nuclei = is_real_nuclei(v)
            if has_real_nuclei:
                f.has_nuclei_real = True

            attrs = v.get("vulnerability_attributes") or {}
            if attrs.get("vscan.type") == "vuln" and PANEL_DETECT_RE.search(name):
                continue

            sev = severity_weight(v)
            if sev <= 0:
                continue

            core_evr = vuln_core_evr(v, now_ts)
            if core_evr <= 0:
                continue

            vkey = vulnerability_dedupe_key(v)
            rank = vulnerability_rank(v)
            is_exploitable = vulnerability_exploitable(v)

            prev = vuln_best[aid].get(vkey)
            if prev is None or core_evr > prev["core_evr"]:
                vuln_best[aid][vkey] = {
                    "core_evr": core_evr,
                    "rank": rank,
                    "sev": sev,
                    "exploitable": is_exploitable,
                    "default_creds": has_default_creds,
                    "nuclei": has_real_nuclei,
                }

        print(f"Vuln rows processed (matched to assets): {count_vulns}")

        # 4) If no Internet Exposure finding, infer potential external from any public IP observed.
        for aid, a in assets.items():
            f = flags[aid]
            if f.external_confirmed or f.external_potential:
                continue
            ip_candidates = []
            if isinstance(a.get("addresses"), list):
                ip_candidates.extend(a.get("addresses") or [])
            if isinstance(a.get("addresses_extra"), list):
                ip_candidates.extend(a.get("addresses_extra") or [])
            for ip in ip_candidates:
                if isinstance(ip, str) and is_public_ip(ip):
                    f.external_potential = True
                    break

        # finalize top3 + stats using final reachability state
        for aid in assets.keys():
            entries = list(vuln_best[aid].values())
            reach = reachability_factor(flags[aid])
            for e in entries:
                e["evr"] = float(e.get("core_evr", 0.0)) * reach

            entries.sort(key=lambda x: x["evr"], reverse=True)
            top3[aid] = [float(e["evr"]) for e in entries[:3] if float(e["evr"]) > 0]

            stats = VulnStats(unique_vuln_count=len(entries))
            for e in entries:
                rank = int(e.get("rank", 0))
                sev = float(e.get("sev", 0.0))
                if rank >= 4 or sev >= 9.0:
                    stats.critical_count += 1
                elif rank >= 3 or sev >= 7.0:
                    stats.high_count += 1
                if e.get("exploitable"):
                    stats.exploitable_count += 1
                if e.get("default_creds"):
                    stats.default_creds_count += 1
                if e.get("nuclei"):
                    stats.nuclei_count += 1
            vuln_stats[aid] = stats

        # 5) Score + update tags
        updated = 0
        skipped = 0
        failed = 0

        for aid, a in assets.items():
            score, band, explain = compute_score(a, flags[aid], top3[aid], sw_signals[aid], vuln_stats[aid])
            rationale = build_rationale(a, flags[aid], explain)

            existing_tags_dict = normalize_tags(a.get("tags"))
            tag_list = tags_dict_to_list(existing_tags_dict)

            current_band_val = None
            for k, v in existing_tags_dict.items():
                if str(k).lower() == args.band_key.lower():
                    current_band_val = "" if v is None else str(v)

            legacy_present = has_any_tag_key(tag_list, LEGACY_SCORE_TAG_KEYS)
            band_present = has_any_tag_key(tag_list, {args.band_key})
            update_status = ""
            if (
                not args.refresh_band
                and current_band_val is not None
                and current_band_val.lower() == band.lower()
                and not legacy_present
                and band_present
            ):
                skipped += 1
                update_status = "skipped_same_value"
            else:
                # Remove old band/score tags then write a fresh band tag.
                tag_list = remove_tag_keys(tag_list, LEGACY_SCORE_TAG_KEYS | {args.band_key})
                tag_list = set_tag_in_list(tag_list, args.band_key, band)

                tag_str = tags_list_to_string(
                    [tok for tok in (format_tag_token(*t.split("=", 1)) if "=" in t else format_tag_token(t, "") for t in tag_list) if tok]
                )

                ok = patch_asset_tags(
                    sess=sess,
                    base_url=args.base_url,
                    headers=headers,
                    org_id=org_id,
                    asset_id=aid,
                    tags_string=tag_str,
                    dry_run=args.dry_run,
                )
                if ok:
                    updated += 1
                    if args.dry_run:
                        update_status = "dry_run"
                    elif current_band_val is not None and current_band_val.lower() == band.lower():
                        update_status = "refreshed_same_value"
                    else:
                        update_status = "updated"
                else:
                    failed += 1
                    update_status = "failed"

            row_org_id = str(org_id or a.get("organization_id") or "")
            all_csv_rows.append(
                {
                    "org_id": row_org_id,
                    "asset_id": aid,
                    "asset_name": primary_asset_name(a),
                    "asset_type": str(a.get("type") or ""),
                    "alive": bool(a.get("alive")),
                    "criticality_rank": as_int(a.get("criticality_rank")) or 0,
                    "eol_os": bool(a.get("eol_os")),
                    "addresses": pipe_join(a.get("addresses")),
                    "service_protocols": pipe_join(a.get("service_protocols")),
                    "service_count": as_int(a.get("service_count")) or 0,
                    "service_count_tcp": as_int(a.get("service_count_tcp")) or 0,
                    "software_unique_products": explain.get("software_unique_products", 0),
                    "vuln_unique_count": explain.get("vuln_unique_count", 0),
                    "vuln_critical_count": explain.get("vuln_critical_count", 0),
                    "vuln_high_count": explain.get("vuln_high_count", 0),
                    "vuln_exploitable_count": explain.get("vuln_exploitable_count", 0),
                    "external_confirmed": explain.get("external_confirmed", False),
                    "external_potential": explain.get("external_potential", False),
                    "default_creds": explain.get("default_creds", False),
                    "nuclei_real": explain.get("nuclei_real", False),
                    "top3_evr": pipe_join(explain.get("top3_evr", [])),
                    "component_exposure": explain.get("exposure", 0.0),
                    "component_vuln": explain.get("vuln", 0.0),
                    "component_impact": explain.get("impact", 0.0),
                    "component_pivot": explain.get("pivot", 0.0),
                    "component_software": explain.get("software", 0.0),
                    "base_score": explain.get("base", 0.0),
                    "total_multiplier": explain.get("mult", 1.0),
                    "raw_score": explain.get("raw", 0.0),
                    "final_score": explain.get("final", 0.0),
                    "risk_score": score,
                    "risk_band": band,
                    "tag_update_status": update_status,
                    "rationale": rationale,
                }
            )

        print(f"Tag updates: updated={updated} skipped={skipped} failed={failed} (dry_run={args.dry_run})")

    write_breakdown_csv(args.csv_out, all_csv_rows)
    print(f"CSV breakdown written: {args.csv_out} rows={len(all_csv_rows)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
