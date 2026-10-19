"""
detector.py — Core DNS-spoof-detection engine.

Compares answers from a suspect resolver against multiple trusted public
resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9), a local trusted-records file, and
a hash-based baseline to produce a risk score and human-readable verdict.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
from typing import Any

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

# ── paths ────────────────────────────────────────────────────────────────
_HERE = pathlib.Path(__file__).resolve().parent
TRUSTED_PATH = _HERE / "trusted.json"
BASELINE_PATH = _HERE / "baseline.json"

# ── public resolvers used for cross-validation ───────────────────────────
PUBLIC_RESOLVERS: list[dict[str, Any]] = [
    {"name": "Google",      "host": "8.8.8.8",   "port": 53},
    {"name": "Cloudflare",  "host": "1.1.1.1",   "port": 53},
    {"name": "Quad9",       "host": "9.9.9.9",   "port": 53},
]

TIMEOUT = 3  # seconds – per-query timeout


# ═══════════════════════════════════════════════════════════════════════════
# Helper: query a single resolver for A records
# ═══════════════════════════════════════════════════════════════════════════
def _query_resolver(
    domain: str,
    host: str,
    port: int,
) -> dict[str, Any]:
    """
    Send an A-record query to *host:port* and return a dict with:
        ips   – sorted list of IPv4 strings
        ttl   – minimum TTL across the answer RRs (or None)
        error – error string if the query failed, else None
    """
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.port = port
        resolver.lifetime = TIMEOUT
        resolver.timeout = TIMEOUT

        answer = resolver.resolve(domain, "A")
        ips = sorted(rdata.address for rdata in answer)
        ttl = min(rrset.ttl for rrset in answer.response.answer) if answer.response.answer else None
        return {"ips": ips, "ttl": ttl, "error": None}

    except dns.resolver.NXDOMAIN:
        return {"ips": [], "ttl": None, "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"ips": [], "ttl": None, "error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        return {"ips": [], "ttl": None, "error": "NoNameservers"}
    except dns.exception.Timeout:
        return {"ips": [], "ttl": None, "error": "Timeout"}
    except Exception as exc:  # noqa: BLE001 – catch-all for robustness
        return {"ips": [], "ttl": None, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════
# Helper: DNSSEC quick-check (informational)
# ═══════════════════════════════════════════════════════════════════════════
def _check_dnssec(domain: str, host: str, port: int) -> dict[str, Any]:
    """
    Send a DNSSEC-aware query (DO flag) and report:
        ad_flag  – True if the Authenticated Data flag is set
        has_rrsig – True if the answer section contains RRSIG records
        error    – error string if the query failed, else None
    """
    try:
        qname = dns.name.from_text(domain)
        request = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
        request.flags |= dns.flags.AD  # request AD bit validation

        response = dns.query.udp(request, host, port=port, timeout=TIMEOUT)
        ad_flag = bool(response.flags & dns.flags.AD)
        has_rrsig = any(
            rrset.rdtype == dns.rdatatype.RRSIG
            for rrset in response.answer
        )
        return {"ad_flag": ad_flag, "has_rrsig": has_rrsig, "error": None}

    except Exception as exc:  # noqa: BLE001
        return {"ad_flag": False, "has_rrsig": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════
# Helper: /16 prefix comparison (CDN-friendly)
# ═══════════════════════════════════════════════════════════════════════════
def _prefix16(ip_str: str) -> str:
    """Return the /16 network prefix of an IPv4 address as a string."""
    addr = ipaddress.IPv4Address(ip_str)
    net = ipaddress.IPv4Network(f"{addr}/16", strict=False)
    return str(net.network_address)


def _prefixes_overlap(ips_a: list[str], ips_b: list[str]) -> bool:
    """True if there is at least one common /16 prefix between two IP lists."""
    return bool(set(map(_prefix16, ips_a)) & set(map(_prefix16, ips_b)))


# ═══════════════════════════════════════════════════════════════════════════
# Helper: IP-address classification
# ═══════════════════════════════════════════════════════════════════════════
def _is_private_or_reserved(ip_str: str) -> bool:
    """True if the address is private, loopback, link-local, or reserved.

    Covers IPv4 (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 0.0.0.0,
    multicast 224+) and IPv6 (::1, fc00::/7, fe80::/10).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        addr.is_private or addr.is_loopback or addr.is_reserved
        or addr.is_link_local or addr.is_multicast
    )


# ═══════════════════════════════════════════════════════════════════════════
# JSON persistence helpers
# ═══════════════════════════════════════════════════════════════════════════
def _load_json(path: pathlib.Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def _save_json(path: pathlib.Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _ip_hash(ips: list[str]) -> str:
    """SHA-256 hex-digest of the sorted, comma-joined IP list."""
    return hashlib.sha256(",".join(sorted(ips)).encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# Main analysis function
# ═══════════════════════════════════════════════════════════════════════════
def analyze(
    domain: str,
    suspect_host: str = "127.0.0.1",
    suspect_port: int = 5353,
) -> dict[str, Any]:
    """
    Query *domain* via the suspect resolver and cross-check against public
    resolvers, trusted records, hash baseline, and anomaly rules.

    Returns a dict with keys:
        domain, suspect_ips, ttl, score (0-100), verdict,
        reasons (list[str]), checks (dict[str, str]),
        resolver_table (list[dict])  – per-resolver detail for the dashboard.
    """

    score = 0
    reasons: list[str] = []
    checks: dict[str, str] = {}

    # ── 0. Query the suspect resolver ────────────────────────────────────
    suspect_result = _query_resolver(domain, suspect_host, suspect_port)

    if suspect_result["error"]:
        return {
            "domain": domain,
            "suspect_ips": [],
            "ttl": None,
            "score": 0,
            "verdict": "UNREACHABLE",
            "reasons": [
                f"Suspect resolver {suspect_host}:{suspect_port} is unreachable: "
                f"{suspect_result['error']}"
            ],
            "checks": {},
            "resolver_table": [],
        }

    suspect_ips: list[str] = suspect_result["ips"]
    suspect_ttl: int | None = suspect_result["ttl"]

    # ── 1. Query public resolvers ────────────────────────────────────────
    public_results: dict[str, dict] = {}
    all_public_ips: set[str] = set()

    for pub in PUBLIC_RESOLVERS:
        res = _query_resolver(domain, pub["host"], pub["port"])
        public_results[pub["name"]] = res
        if not res["error"]:
            all_public_ips.update(res["ips"])

    # ── Build the resolver comparison table (used by the dashboard) ──────
    resolver_table: list[dict] = [
        {
            "resolver": f"Suspect ({suspect_host}:{suspect_port})",
            "ips": ", ".join(suspect_ips) if suspect_ips else "—",
            "ttl": suspect_ttl,
            "match": "baseline",
        }
    ]
    for pub in PUBLIC_RESOLVERS:
        res = public_results[pub["name"]]
        match_status: str
        if res["error"]:
            match_status = f"error: {res['error']}"
        elif set(suspect_ips) & set(res["ips"]):
            match_status = "✅ exact"
        elif suspect_ips and res["ips"] and _prefixes_overlap(suspect_ips, res["ips"]):
            match_status = "⚠️ prefix"
        elif not suspect_ips:
            match_status = "—"
        else:
            match_status = "❌ mismatch"
        resolver_table.append({
            "resolver": f"{pub['name']} ({pub['host']})",
            "ips": ", ".join(res["ips"]) if res["ips"] else (res["error"] or "—"),
            "ttl": res["ttl"],
            "match": match_status,
        })

    # ═══ CHECK 1: Cross-resolver validation (+50) ════════════════════════
    if all_public_ips:
        exact_overlap = set(suspect_ips) & all_public_ips
        prefix_overlap = _prefixes_overlap(suspect_ips, list(all_public_ips)) if suspect_ips else False

        if not exact_overlap and not prefix_overlap and suspect_ips:
            score += 50
            reasons.append(
                "Cross-resolver mismatch: suspect IPs share no overlap "
                "(exact or /16 prefix) with Google, Cloudflare, or Quad9."
            )
            checks["cross_resolver"] = "FAIL"
        else:
            checks["cross_resolver"] = "PASS"
    else:
        # All public resolvers failed — degrade gracefully
        checks["cross_resolver"] = "SKIP"
        reasons.append(
            "Cross-resolver check skipped: all public resolvers were unreachable."
        )

    # ═══ CHECK 2: Trusted records (+30) ══════════════════════════════════
    trusted = _load_json(TRUSTED_PATH)
    if domain in trusted:
        trusted_ips = set(trusted[domain])
        if suspect_ips and not (set(suspect_ips) & trusted_ips):
            score += 30
            reasons.append(
                f"Trusted-record mismatch: suspect IPs {suspect_ips} are not "
                f"in the trusted list {sorted(trusted_ips)}."
            )
            checks["trusted_records"] = "FAIL"
        else:
            checks["trusted_records"] = "PASS"
    else:
        checks["trusted_records"] = "SKIP"

    # ═══ CHECK 3: Hash baseline (+15) ════════════════════════════════════
    baseline = _load_json(BASELINE_PATH)
    current_hash = _ip_hash(suspect_ips) if suspect_ips else ""

    if domain in baseline:
        if current_hash != baseline[domain]:
            score += 15
            reasons.append(
                "Baseline hash changed: the answer-set hash differs from a "
                "previously recorded safe baseline."
            )
            checks["hash_baseline"] = "FAIL"
        else:
            checks["hash_baseline"] = "PASS"
    else:
        checks["hash_baseline"] = "NEW"

    # ═══ CHECK 4a: Private/reserved IPs for a public domain (+25) ═══════
    private_hits = [ip for ip in suspect_ips if _is_private_or_reserved(ip)]
    if private_hits:
        score += 25
        reasons.append(
            f"Private/reserved IPs returned for a public domain: {private_hits}."
        )
        checks["private_ip"] = "FAIL"
    else:
        checks["private_ip"] = "PASS"

    # ═══ CHECK 4b: Low TTL (+10) ════════════════════════════════════════
    if suspect_ttl is not None and suspect_ttl < 30:
        score += 10
        reasons.append(
            f"Suspiciously low TTL ({suspect_ttl}s < 30s threshold)."
        )
        checks["low_ttl"] = "FAIL"
    else:
        checks["low_ttl"] = "PASS"

    # ═══ CHECK 4c: Answer-count anomaly (+5) ════════════════════════════
    public_counts = [
        len(r["ips"]) for r in public_results.values() if not r["error"] and r["ips"]
    ]
    if public_counts and suspect_ips:
        avg_count = sum(public_counts) / len(public_counts)
        if abs(len(suspect_ips) - avg_count) > max(avg_count * 0.6, 2):
            score += 5
            reasons.append(
                f"Answer-count anomaly: suspect returned {len(suspect_ips)} records "
                f"vs. public average of {avg_count:.1f}."
            )
            checks["answer_count"] = "FAIL"
        else:
            checks["answer_count"] = "PASS"
    else:
        checks["answer_count"] = "SKIP"

    # ═══ CHECK 5: DNSSEC (informational, +10) ═══════════════════════════
    dnssec_pub = _check_dnssec(domain, "8.8.8.8", 53)
    dnssec_suspect = _check_dnssec(domain, suspect_host, suspect_port)

    if dnssec_pub["error"]:
        checks["dnssec"] = "SKIP"
    elif dnssec_pub["ad_flag"] or dnssec_pub["has_rrsig"]:
        # Domain appears DNSSEC-signed; suspect should also validate
        if not dnssec_suspect["ad_flag"] and not dnssec_suspect["has_rrsig"]:
            score += 10
            reasons.append(
                "DNSSEC validation gap: public resolver sees DNSSEC signatures, "
                "but the suspect resolver does not."
            )
            checks["dnssec"] = "FAIL"
        else:
            checks["dnssec"] = "PASS"
    else:
        # Domain is not signed — nothing to flag
        checks["dnssec"] = "N/A"

    # ═══ Verdict ════════════════════════════════════════════════════════
    score = min(score, 100)

    if score < 30:
        verdict = "SAFE"
    elif score < 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SPOOFED"

    # Store a baseline only when the verdict is SAFE and no entry exists yet
    if verdict == "SAFE" and domain not in baseline and current_hash:
        baseline[domain] = current_hash
        _save_json(BASELINE_PATH, baseline)

    if not reasons:
        reasons.append("All checks passed — no anomalies detected.")

    return {
        "domain": domain,
        "suspect_ips": suspect_ips,
        "ttl": suspect_ttl,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "checks": checks,
        "resolver_table": resolver_table,
    }
