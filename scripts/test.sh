#!/bin/sh
set -eu

export BEND_NO_TELEMETRY=1
BEND=${BEND:-bend}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for file in "$ROOT"/src/*.bend "$ROOT"/src/merkle/*.bend; do
  "$BEND" "$file" --check-only >/dev/null
done

python3 "$ROOT/tests/merkle_golden.py" >"$TMP/reference.out"
diff -u "$ROOT/tests/merkle.expected" "$TMP/reference.out"

"$BEND" "$ROOT/tests/merkle.bend" >"$TMP/merkle.out"
diff -u "$ROOT/tests/merkle.expected" "$TMP/merkle.out"
echo "Bend Merkle tests passed"
