"""
cli.py — Colourful command-line interface for dns-spoof-detector.

Usage:
    python cli.py <domain> [--host 127.0.0.1] [--port 5353] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from detector import analyze

# Force UTF-8 on Windows to avoid cp1252 encoding errors
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# ── ANSI colour helpers ──────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_DIM    = "\033[2m"

VERDICT_COLOURS = {
    "SAFE":        _GREEN,
    "SUSPICIOUS":  _YELLOW,
    "SPOOFED":     _RED,
    "UNREACHABLE": _DIM,
}


def _coloured_verdict(verdict: str) -> str:
    colour = VERDICT_COLOURS.get(verdict, _RESET)
    return f"{colour}{_BOLD}  ##  {verdict}  ##  {_RESET}"


def _bar(score: int, width: int = 30) -> str:
    """Render a simple ASCII progress bar for the risk score."""
    filled = round(score / 100 * width)
    if score < 30:
        colour = _GREEN
    elif score < 60:
        colour = _YELLOW
    else:
        colour = _RED
    return f"{colour}{'#' * filled}{'-' * (width - filled)}{_RESET} {score}/100"


def pretty_print(result: dict) -> None:
    """Print a human-friendly coloured report to stdout."""
    print()
    print(f"{_CYAN}{_BOLD}+------------------------------------------------------+{_RESET}")
    print(f"{_CYAN}{_BOLD}|         DNS Spoof Detector -- Scan Result            |{_RESET}")
    print(f"{_CYAN}{_BOLD}+------------------------------------------------------+{_RESET}")
    print()

    # Verdict banner
    print(_coloured_verdict(result["verdict"]))
    print()

    # Domain & IPs
    print(f"  {_BOLD}Domain:{_RESET}      {result['domain']}")
    ips_str = ", ".join(result["suspect_ips"]) if result["suspect_ips"] else "-"
    print(f"  {_BOLD}Suspect IPs:{_RESET} {ips_str}")
    ttl_str = str(result["ttl"]) + "s" if result["ttl"] is not None else "-"
    print(f"  {_BOLD}TTL:{_RESET}         {ttl_str}")
    print(f"  {_BOLD}Risk Score:{_RESET}  {_bar(result['score'])}")
    print()

    # Reasons
    print(f"  {_BOLD}Reasons:{_RESET}")
    for reason in result["reasons"]:
        print(f"    * {reason}")
    print()

    # Per-check table
    print(f"  {_BOLD}Check Results:{_RESET}")
    for name, status in result.get("checks", {}).items():
        if status == "PASS":
            icon = f"{_GREEN}[PASS]{_RESET}"
        elif status == "FAIL":
            icon = f"{_RED}[FAIL]{_RESET}"
        elif status == "SKIP":
            icon = f"{_DIM}[SKIP]{_RESET}"
        elif status == "NEW":
            icon = f"{_CYAN}[NEW]{_RESET}"
        else:
            icon = f"{_DIM}{status}{_RESET}"
        print(f"    {name:<20s} {icon}")
    print()

    # Resolver comparison table
    table = result.get("resolver_table", [])
    if table:
        print(f"  {_BOLD}Resolver Comparison:{_RESET}")
        print(f"    {'Resolver':<35s} {'IPs':<45s} {'TTL':>5s}  {'Match'}")
        print(f"    {'-' * 35} {'-' * 45} {'-' * 5}  {'-' * 12}")
        for row in table:
            ttl_val = str(row["ttl"]) if row["ttl"] is not None else "-"
            print(f"    {row['resolver']:<35s} {row['ips']:<45s} {ttl_val:>5s}  {row['match']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS Spoof Detector — check a domain against a suspect resolver.",
    )
    parser.add_argument("domain", help="Domain name to analyse (e.g. google.com)")
    parser.add_argument("--host", default="8.8.8.8",
                        help="Suspect resolver IP (default: 8.8.8.8)")
    parser.add_argument("--port", type=int, default=53,
                        help="Suspect resolver port (default: 53)")
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="Output raw JSON instead of pretty text")

    args = parser.parse_args()

    result = analyze(args.domain, suspect_host=args.host, suspect_port=args.port)

    if args.output_json:
        print(json.dumps(result, indent=2))
    else:
        pretty_print(result)


if __name__ == "__main__":
    main()
