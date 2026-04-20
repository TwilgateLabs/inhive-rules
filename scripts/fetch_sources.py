"""
Fetch domain blocklists from first-party threat feeds.

Sources are organised by category (ads / malware / phishing / cryptominers).
Each source is best-effort: if it fails, other sources in the same category
still contribute domains. We never hard-fail the workflow on a single source.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import urllib.request
from typing import Callable, Iterable

TIMEOUT = 60
UA = "inhive-rules-bot/1.0 (+https://github.com/TwilgateLabs/inhive-rules)"

# RFC 1035 domain validation (lowercase). Strips trailing dots.
VALID_DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def clean(line: str) -> str:
    return line.strip().lower().rstrip(".")


# ---------- Sources ----------

def fetch_oisd_big() -> Iterable[str]:
    """OISD Big — ads + trackers aggregator, ~420k domains.
    Wildcard format: `*.example.com` per line. Strip the `*.` prefix."""
    text = fetch("https://big.oisd.nl/domainswild")
    for line in text.splitlines():
        d = clean(line)
        if not d or d.startswith("#"):
            continue
        if d.startswith("*."):
            d = d[2:]
        if VALID_DOMAIN.match(d):
            yield d


def fetch_easylist() -> Iterable[str]:
    """EasyList ABP format — extract bare domain-block rules `||domain^`."""
    text = fetch("https://easylist.to/easylist/easylist.txt")
    pattern = re.compile(r"^\|\|([a-z0-9.\-]+)\^")
    for line in text.splitlines():
        m = pattern.match(line.strip().lower())
        if m and VALID_DOMAIN.match(m.group(1)):
            yield m.group(1)


def fetch_urlhaus() -> Iterable[str]:
    """abuse.ch URLhaus — active malware C2/payload hosts.
    Hosts file uses either 0.0.0.0 or 127.0.0.1 as sink address."""
    text = fetch("https://urlhaus.abuse.ch/downloads/hostfile/")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            d = clean(parts[1])
            if VALID_DOMAIN.match(d):
                yield d


def fetch_threatfox() -> Iterable[str]:
    """abuse.ch ThreatFox — recent IOCs (domains, URLs, IPs, hashes).
    Free, no auth. We filter to ioc_type == "domain"."""
    import json
    text = fetch("https://threatfox.abuse.ch/export/json/recent/")
    payload = json.loads(text)
    # Format: {"id": [{"ioc_type": "domain", "ioc_value": "x.com", ...}], ...}
    for entries in payload.values():
        for entry in entries:
            if entry.get("ioc_type") == "domain":
                d = clean(entry.get("ioc_value", ""))
                if VALID_DOMAIN.match(d):
                    yield d


def fetch_phishing_army() -> Iterable[str]:
    """phishing.army — aggregates PhishTank + OpenPhish + others (no API key)."""
    text = fetch(
        "https://phishing.army/download/phishing_army_blocklist_extended.txt"
    )
    for line in text.splitlines():
        d = clean(line)
        if not d or d.startswith("#"):
            continue
        if VALID_DOMAIN.match(d):
            yield d


def fetch_nocoin() -> Iterable[str]:
    """hoshsadiq/adblock-nocoin-list — cryptocurrency miners."""
    text = fetch(
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
    )
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            d = clean(parts[1])
            if VALID_DOMAIN.match(d) and d not in {"localhost", "localhost.localdomain"}:
                yield d


CATEGORIES: dict[str, list[Callable[[], Iterable[str]]]] = {
    "ads": [fetch_oisd_big, fetch_easylist],
    "malware": [fetch_urlhaus, fetch_threatfox],
    "phishing": [fetch_phishing_army],
    "cryptominers": [fetch_nocoin],
}


def main() -> int:
    out_dir = pathlib.Path("sources")
    out_dir.mkdir(exist_ok=True)
    total_warnings = 0
    summary: list[str] = []

    for category, fetchers in CATEGORIES.items():
        seen: set[str] = set()
        for fetcher in fetchers:
            name = fetcher.__name__
            try:
                count_before = len(seen)
                for d in fetcher():
                    seen.add(d)
                added = len(seen) - count_before
                print(f"  [{category}] {name}: +{added} domains")
            except Exception as exc:
                total_warnings += 1
                print(f"  [{category}] {name}: WARN {exc!r}", file=sys.stderr)

        path = out_dir / f"{category}.txt"
        path.write_text("\n".join(sorted(seen)) + "\n", encoding="utf-8")
        summary.append(f"{category}: {len(seen)} domains")
        print(f"{category}: {len(seen)} unique domains -> {path}")

    print("\nSummary:")
    for line in summary:
        print(f"  {line}")

    if total_warnings:
        print(f"\n{total_warnings} source(s) failed — see WARN lines above.",
              file=sys.stderr)

    # Fail only if ALL sources in a category died (no domains at all)
    hard_fail = any(
        (out_dir / f"{cat}.txt").read_text(encoding="utf-8").strip() == ""
        for cat in CATEGORIES
    )
    if hard_fail:
        print("ERROR: one or more categories have zero domains", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
