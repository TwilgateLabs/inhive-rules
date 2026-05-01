#!/usr/bin/env bash
# Compiles rule-set/bypass/*.json → *.srs using sing-box CLI.
# Called by GitHub Actions after fetch_cidr.py.
set -euo pipefail

BYPASS_DIR="rule-set/bypass"
SING_BOX="${SING_BOX_BIN:-sing-box}"

echo "=== Compiling CIDR bypass rule-sets ==="

compiled=0
failed=0

for json_file in "$BYPASS_DIR"/*.json; do
    [ -f "$json_file" ] || continue
    slug=$(basename "$json_file" .json)
    srs_file="$BYPASS_DIR/$slug.srs"

    "$SING_BOX" rule-set compile --output "$srs_file" "$json_file"

    if [ -f "$srs_file" ]; then
        size=$(wc -c < "$srs_file")
        echo "  ✓ $slug.srs  (${size} bytes)"
        compiled=$((compiled + 1))
    else
        echo "  ✗ $slug.srs  FAILED" >&2
        failed=$((failed + 1))
    fi
done

echo ""
echo "Compiled: $compiled   Failed: $failed"

if [ "$compiled" -eq 0 ]; then
    echo "ERROR: no .srs files produced" >&2
    exit 1
fi

if [ "$failed" -gt 0 ]; then
    echo "ERROR: $failed compilation(s) failed" >&2
    exit 1
fi
