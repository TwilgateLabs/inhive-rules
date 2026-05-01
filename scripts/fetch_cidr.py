#!/usr/bin/env python3
"""
CIDR ruleset generator for InHive bypass rules.

Sources:
  - ASN-based providers: RIPE stat API announced-prefixes
  - Country-based: RIPE/APNIC/ARIN/LACNIC delegation stats files

Output: rule-set/bypass/<slug>.json  (sing-box rule-set source format)

Usage:
  python3 scripts/fetch_cidr.py [--output-dir rule-set/bypass]
"""

import json
import ipaddress
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Provider / country definitions
# ---------------------------------------------------------------------------

# Format: slug -> { asns: [...], label: "..." }
# Multiple ASNs per provider are merged into one rule-set.
ASN_PROVIDERS = {
    "ru-rostelecom": {
        "label": "Ростелеком",
        "asns": ["AS12389", "AS42682", "AS25086", "AS8491"],
    },
    "ru-mts": {
        "label": "МТС",
        "asns": ["AS8359", "AS15378"],
    },
    "ru-beeline": {
        "label": "Билайн",
        "asns": ["AS3216", "AS8402", "AS31200"],
    },
    "ru-megafon": {
        "label": "Мегафон",
        "asns": ["AS31133", "AS20485", "AS25159"],
    },
    "ru-tele2": {
        "label": "Tele2",
        "asns": ["AS48092", "AS197399"],
    },
    "ru-banks": {
        "label": "RU банки (Сбербанк + Тинькофф + ВТБ)",
        "asns": [
            "AS57264",  # Sberbank
            "AS31492",  # Sberbank
            "AS34337",  # Sberbank
            "AS51429",  # T-Bank (Тинькофф)
            "AS47630",  # VTB
            "AS200528", # VTB
        ],
    },
    "ru-gosuslugi": {
        "label": "Госуслуги",
        "asns": ["AS31257", "AS12389"],  # Минцифры + Ростелеком gov
    },
    "cn-telecom": {
        "label": "China Telecom",
        "asns": ["AS4134", "AS4812", "AS7497"],
    },
    "cn-unicom": {
        "label": "China Unicom",
        "asns": ["AS4837", "AS17816", "AS17621"],
    },
    "cn-mobile": {
        "label": "China Mobile",
        "asns": ["AS9808", "AS56041", "AS58453"],
    },
    "ir-tci": {
        "label": "Iran TCI (Irancell + Shatel)",
        "asns": ["AS12880", "AS44244", "AS48159", "AS197207"],
    },
    "tr-turktelekom": {
        "label": "Türk Telekom",
        "asns": ["AS9121", "AS34984"],
    },
    "eg-te": {
        "label": "Telecom Egypt",
        "asns": ["AS8452", "AS24835"],
    },
}

# Country slugs to 2-letter ISO codes for delegation stats
COUNTRY_PROVIDERS = {
    "cn": "CN",
    "ir": "IR",
    "tr": "TR",
    "eg": "EG",
    "ru": "RU",
    "by": "BY",
    "kz": "KZ",
}

# ---------------------------------------------------------------------------
# RIPE stat API
# ---------------------------------------------------------------------------

RIPE_STAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&sourceapp=inhive-rules"


def _get_url(url: str, retries: int = 3) -> Optional[bytes]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "inhive-rules/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.URLError as e:
            print(f"  WARN fetch {url}: {e}", file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    return None


def fetch_asn_cidrs(asn: str) -> list[str]:
    """Return IPv4 CIDR list for a single ASN via RIPE stat API."""
    url = RIPE_STAT_URL.format(asn=asn)
    data = _get_url(url)
    if not data:
        return []
    try:
        j = json.loads(data)
        prefixes = j.get("data", {}).get("prefixes", [])
        result = []
        for p in prefixes:
            prefix = p.get("prefix", "")
            # Only IPv4 for now (IPv6 CIDR rules supported too but bloat)
            if ":" not in prefix:
                result.append(prefix)
        print(f"  {asn}: {len(result)} IPv4 prefixes")
        return result
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  WARN parse {asn}: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Delegation stats (RIPE + APNIC + ARIN) for country-based CIDR
# ---------------------------------------------------------------------------

DELEGATION_URLS = [
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
]


def _parse_delegation_file(data: bytes, country: str) -> list[str]:
    """
    Parse RIR delegation stats file and extract IPv4 CIDR for given country code.
    Line format: rir|CC|ipv4|start_ip|count|date|status
    """
    cidrs = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        if line.startswith("#") or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        cc = parts[1].upper()
        rtype = parts[2].lower()
        if cc != country or rtype != "ipv4":
            continue
        start_ip = parts[3]
        count_str = parts[4]
        try:
            count = int(count_str)
            network = ipaddress.IPv4Network(f"{start_ip}/{32 - (count - 1).bit_length()}", strict=False)
            cidrs.append(str(network))
        except (ValueError, TypeError):
            pass
    return cidrs


def fetch_country_cidrs(country_code: str) -> list[str]:
    """Return merged IPv4 CIDRs for a country from all 5 RIR delegation files."""
    all_cidrs: set[str] = set()
    for url in DELEGATION_URLS:
        data = _get_url(url)
        if not data:
            print(f"  WARN: failed to fetch {url}", file=sys.stderr)
            continue
        cidrs = _parse_delegation_file(data, country_code.upper())
        all_cidrs.update(cidrs)
        print(f"  {url.split('/')[-1]}: {len(cidrs)} prefixes for {country_code}")
    return sorted(all_cidrs)


# ---------------------------------------------------------------------------
# Aggregate CIDR: merge overlapping/adjacent prefixes to shrink .srs size
# ---------------------------------------------------------------------------

def _collapse_cidrs(cidrs: list[str]) -> list[str]:
    networks = []
    for c in cidrs:
        try:
            networks.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            pass
    collapsed = list(ipaddress.collapse_addresses(networks))
    return [str(n) for n in collapsed]


# ---------------------------------------------------------------------------
# sing-box rule-set source JSON format
# ---------------------------------------------------------------------------

def _make_ruleset_json(cidrs: list[str]) -> dict:
    return {
        "version": 3,
        "rules": [
            {"ip_cidr": cidrs},
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="rule-set/bypass")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) ASN-based providers
    for slug, cfg in ASN_PROVIDERS.items():
        print(f"\n[{slug}] {cfg['label']}")
        all_cidrs: list[str] = []
        for asn in cfg["asns"]:
            all_cidrs.extend(fetch_asn_cidrs(asn))

        if not all_cidrs:
            print(f"  WARN: no CIDRs collected for {slug}, skipping", file=sys.stderr)
            continue

        collapsed = _collapse_cidrs(all_cidrs)
        print(f"  collapsed: {len(all_cidrs)} → {len(collapsed)} prefixes")
        out_path = out_dir / f"{slug}.json"
        out_path.write_text(json.dumps(_make_ruleset_json(collapsed), ensure_ascii=False))
        print(f"  → {out_path}")

    # 2) Country-based (delegation stats)
    for slug, cc in COUNTRY_PROVIDERS.items():
        print(f"\n[{slug}] {cc} (delegation stats)")
        cidrs = fetch_country_cidrs(cc)
        if not cidrs:
            print(f"  WARN: no CIDRs for {slug}", file=sys.stderr)
            continue
        collapsed = _collapse_cidrs(cidrs)
        print(f"  collapsed: {len(cidrs)} → {len(collapsed)} prefixes")
        out_path = out_dir / f"{slug}.json"
        out_path.write_text(json.dumps(_make_ruleset_json(collapsed), ensure_ascii=False))
        print(f"  → {out_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()
