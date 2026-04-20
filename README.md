# inhive-rules

Domain blocklists compiled into `sing-box` `.srs` format for the
[InHive](https://github.com/twilgate/inhive-app) VPN client.

[![Build rule-sets](https://github.com/TwilgateLabs/inhive-rules/actions/workflows/build.yml/badge.svg)](https://github.com/TwilgateLabs/inhive-rules/actions/workflows/build.yml)

## Categories

| File | Description | Upstream sources |
| --- | --- | --- |
| `rule-set/geosite-ads.srs` | Ads + trackers | OISD Big, EasyList |
| `rule-set/geosite-malware.srs` | Malware C2 / payload hosts | abuse.ch URLhaus, ThreatFox |
| `rule-set/geosite-phishing.srs` | Phishing landing pages | phishing.army (PhishTank + OpenPhish) |
| `rule-set/geosite-cryptominers.srs` | In-browser / drive-by miners | hoshsadiq/adblock-nocoin-list |

Rebuilt every 6 hours by GitHub Actions. Sources are aggregated, deduplicated,
validated against RFC 1035, and compiled via `sing-box rule-set compile`.

## Usage in sing-box

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geosite-ads",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/TwilgateLabs/inhive-rules/main/rule-set/geosite-ads.srs",
        "update_interval": "24h0m0s",
        "download_detour": "direct"
      }
    ]
  }
}
```

`sing-box` caches `.srs` files with ETag/Last-Modified, so `update_interval`
only fetches when upstream changed.

## Source attributions

Each upstream project is used under its own license. We do not modify
upstream data — only re-encode it into the sing-box binary rule-set format.

- [OISD](https://oisd.nl/) — © Erwin Bierens
- [EasyList](https://easylist.to/) — CC BY-SA 3.0
- [abuse.ch URLhaus & ThreatFox](https://abuse.ch/) — CC0
- [phishing.army](https://phishing.army/) — CC BY 4.0
- [adblock-nocoin-list](https://github.com/hoshsadiq/adblock-nocoin-list) — MIT

## License

The build scripts and workflow definitions in this repository are licensed
under **GPL-3.0-or-later**. The compiled `.srs` artifacts inherit the licenses
of their upstream sources — see attributions above.
