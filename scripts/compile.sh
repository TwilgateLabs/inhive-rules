#!/usr/bin/env bash
# Compile plain-text domain lists into sing-box .srs rule-sets.
# Requires sing-box CLI in PATH.
set -euo pipefail

SRS_DIR="rule-set"
SRC_DIR="sources"
TMP_DIR="$(mktemp -d)"

mkdir -p "$SRS_DIR"

python3 - "$SRC_DIR" "$TMP_DIR" <<'PY'
import json, pathlib, sys

src_dir = pathlib.Path(sys.argv[1])
tmp_dir = pathlib.Path(sys.argv[2])

for txt in src_dir.glob("*.txt"):
    domains = [ln.strip() for ln in txt.read_text().splitlines() if ln.strip()]
    rule_set = {
        "version": 3,
        "rules": [{"domain_suffix": domains}],
    }
    out = tmp_dir / f"{txt.stem}.json"
    out.write_text(json.dumps(rule_set), encoding="utf-8")
    print(f"{txt.stem}: {len(domains)} domains -> {out}")
PY

for json_file in "$TMP_DIR"/*.json; do
    name="$(basename "$json_file" .json)"
    out="$SRS_DIR/geosite-${name}.srs"
    sing-box rule-set compile --output "$out" "$json_file"
    printf "compiled %s (%s bytes)\n" "$out" "$(wc -c < "$out")"
done

rm -rf "$TMP_DIR"
