#!/usr/bin/env bash
set -euo pipefail

json_path="${1:-.github/branch-protection.json}"
required=(
  "rust / sso-integration"
  "rust / signin-bench"
  "rust / fuzz-smoke"
)

python3 - "$json_path" "${required[@]}" <<'PY'
import json
import sys

path = sys.argv[1]
required = sys.argv[2:]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

contexts = set()
for rule in payload.get("rules", []):
    if rule.get("type") == "required_status_checks":
        for check in rule.get("parameters", {}).get("required_status_checks", []):
            context = check.get("context")
            if context:
                contexts.add(context)

missing = [context for context in required if context not in contexts]
if missing:
    print(f"missing required status checks: {missing}", file=sys.stderr)
    sys.exit(1)
print("branch protection checks ok")
PY
