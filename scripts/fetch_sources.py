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


# ABP domain-block matcher — STRICT fullmatch: only bare `||domain^` rules.
# A prefix match (re.match without `$`) silently accepts `||domain^$options`
# and drops the options — which turns a site-scoped rule like
# `||cloudfront.net^$domain=piratesite.io` into a GLOBAL block of all of
# CloudFront. That shipped and broke video players app-wide (jwplayer.com,
# b-cdn.net, cdn77.org were all globally blocked). Anything with `$options`,
# a path, or `@@` exception syntax is rejected wholesale.
_ABP_BARE_DOMAIN = re.compile(r"^\|\|([a-z0-9.\-]+)\^$")


def _parse_abp_bare(text: str) -> Iterable[str]:
    for line in text.splitlines():
        m = _ABP_BARE_DOMAIN.match(line.strip().lower())
        if m and VALID_DOMAIN.match(m.group(1)):
            yield m.group(1)


def fetch_adguard_dns() -> Iterable[str]:
    """AdGuard DNS Filter — the DNS-native tracker/analytics list that backs
    the AdGuard DNS service (~150k rules, almost all bare `||domain^`). This is
    designed for DNS-level blocking, unlike the browser-oriented EasyList."""
    text = fetch(
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    )
    yield from _parse_abp_bare(text)


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


# ads = two DNS-native, false-positive-curated sources only.
# EasyList and Peter Lowe were REMOVED 2026-07-04: EasyList is a browser
# filter (its site-scoped `$domain=` rules became global CDN blocks through our
# parser), and Peter Lowe blocks load-bearing hosts OISD deliberately keeps
# (googletagmanager.com → broken forms/checkouts). OISD Big already folds in a
# curated EasyList subset, so the removed sources added only false-positive
# noise. See NEVER_BLOCK canary below.
CATEGORIES: dict[str, list[Callable[[], Iterable[str]]]] = {
    "ads": [fetch_oisd_big, fetch_adguard_dns],
    "malware": [fetch_urlhaus, fetch_threatfox],
    "phishing": [fetch_phishing_army],
    "cryptominers": [fetch_nocoin],
}

# Domain apexes that must NEVER appear as an exact entry in any blocklist —
# shared CDNs, players and infra whose whole-domain removal breaks large swaths
# of the web. .srs compiles each entry as domain_suffix, so listing the apex
# here (exact match) catches the "block everything under this CDN" case; a
# deep subdomain block like tracker.cloudfront.net stays allowed (it doesn't
# take down the CDN). If any upstream list starts shipping one of these apexes
# (drift), the build hard-fails instead of silently poisoning the released .srs.
NEVER_BLOCK = {
    "cloudfront.net", "b-cdn.net", "cdn77.org", "akamaized.net", "akamai.net",
    "fastly.net", "jsdelivr.net", "cloudflare.com", "googleusercontent.com",
    "googlevideo.com", "ytimg.com", "googleapis.com", "gstatic.com",
    "jwplayer.com", "jwpcdn.com", "imasdk.googleapis.com", "vimeocdn.com",
    "googletagmanager.com", "cloudflareinsights.com",
}


def _canary_violations(domains: set[str]) -> list[str]:
    """NEVER_BLOCK apexes present as an EXACT entry (= domain_suffix over the
    whole domain). Safe deep-subdomain blocks are intentionally not flagged."""
    return sorted(NEVER_BLOCK & domains)


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

        violations = _canary_violations(seen)
        if violations:
            # Hard-fail: a load-bearing CDN/player apex ended up in a blocklist.
            # Better to ship yesterday's good .srs than a set that breaks video
            # players. (See fetch_sources.py NEVER_BLOCK.)
            print(
                f"ERROR: [{category}] NEVER_BLOCK canary tripped — refusing to "
                f"ship. Offending apexes: {', '.join(violations)}",
                file=sys.stderr,
            )
            return 2

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
