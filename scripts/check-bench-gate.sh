#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <bench-name> <min-ops-per-sec>" >&2
  exit 2
fi

bench="$1"
min_ops="$2"
criterion_dir="${CRITERION_DIR:-target/criterion}"
estimate_file="${criterion_dir}/${bench}/new/estimates.json"

if [[ ! -f "${estimate_file}" ]]; then
  estimate_file="$(find "${criterion_dir}/${bench}" -path '*/new/estimates.json' -type f 2>/dev/null | sort | head -n 1 || true)"
fi

if [[ -z "${estimate_file}" || ! -f "${estimate_file}" ]]; then
  echo "criterion estimates not found for ${bench} under ${criterion_dir}" >&2
  exit 2
fi

python3 - "$estimate_file" "$bench" "$min_ops" <<'PY'
import json
import sys

path, bench, min_ops_raw = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    estimates = json.load(f)

mean_ns = float(estimates["mean"]["point_estimate"])
min_ops = float(min_ops_raw)
if mean_ns <= 0:
    print(f"{bench}: invalid mean point estimate {mean_ns}", file=sys.stderr)
    sys.exit(2)

ops = 1_000_000_000.0 / mean_ns
print(f"{bench}: {ops:.2f} ops/sec (threshold {min_ops:.2f})")
if ops < min_ops:
    sys.exit(1)
PY
