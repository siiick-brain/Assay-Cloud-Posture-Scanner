#!/bin/sh
# Builds the scanner and target images, scans the target, hardens it, scans again.
# Usage: scripts/openscap/run.sh [before|harden|after|all]
# Results land in artifacts/openscap/ which git ignores.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out="$repo/artifacts/openscap"
target=assay-oscap-target
step="${1:-all}"
mkdir -p "$out"

# Git Bash rewrites "/target" style arguments into Windows paths, so turn that
# off and hand docker native paths for the host side instead.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
export MSYS_NO_PATHCONV=1

build() {
    docker build -q -t assay-openscap:local "$(native "$repo/docker/openscap")" >/dev/null
    docker build -q -t assay-oscap-target:local "$(native "$repo/docker/target")" >/dev/null
}

# The scanner reads a copy of the target root so it never needs privileges
# or access to the target's process namespace.
scan() {
    label="$1"
    vol="assay-oscap-root-$label"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
    docker volume create "$vol" >/dev/null
    docker export "$target" | docker run -i --rm -v "$vol:/target" --entrypoint tar assay-openscap:local -x -C /target
    docker rm -f "assay-oscap-scan-$label" >/dev/null 2>&1 || true
    docker run --name "assay-oscap-scan-$label" -v "$vol:/target:ro" assay-openscap:local /target "$label"
    docker cp "assay-oscap-scan-$label:/results/." "$(native "$out")"
    docker rm "assay-oscap-scan-$label" >/dev/null
    docker volume rm "$vol" >/dev/null
}

start_target() {
    docker rm -f "$target" >/dev/null 2>&1 || true
    docker run -d --name "$target" assay-oscap-target:local >/dev/null
}

harden() {
    docker cp "$(native "$here/harden.sh")" "$target:/tmp/harden.sh"
    rc=0
    docker exec "$target" sh /tmp/harden.sh > "$out/harden-log.txt" 2>&1 || rc=$?
    cat "$out/harden-log.txt"
    return "$rc"
}

case "$step" in
    before) build; start_target; scan before ;;
    harden) harden ;;
    after) scan after ;;
    all) build; start_target; scan before; harden; scan after ;;
    *) echo "unknown step: $step" >&2; exit 64 ;;
esac
