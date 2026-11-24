#!/usr/bin/env bash
# Apply one testbed stack to a freshly reset Moto server on localhost:5000.
# Usage: testbed/apply.sh insecure|secure [log_dir]
set -euo pipefail

stack="${1:?usage: apply.sh insecure|secure [log_dir]}"
here="$(cd "$(dirname "$0")" && pwd)"
logs="${2:-$here/../artifacts}"
tf="${TERRAFORM:-terraform}"
mkdir -p "$logs"

case "$stack" in
  insecure|secure) ;;
  *) echo "unknown stack: $stack" >&2; exit 2 ;;
esac

# Both stacks share one emulator, so wipe it first to keep the scans separate.
curl -fsS -X POST http://localhost:5000/moto-api/reset > /dev/null
cd "$here/$stack"
rm -f terraform.tfstate terraform.tfstate.backup
"$tf" init -input=false -no-color > "$logs/tf-$stack-init.log" 2>&1
"$tf" version -no-color > "$logs/tf-$stack-apply.log" 2>&1
"$tf" apply -input=false -auto-approve -no-color >> "$logs/tf-$stack-apply.log" 2>&1
grep "Apply complete" "$logs/tf-$stack-apply.log"
