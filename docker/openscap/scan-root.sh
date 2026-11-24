#!/bin/sh
# Evaluates an XCCDF profile against a mounted root filesystem.
# Usage: scan-root <rootfs> <label> [profile]
# Sets the same variables oscap-chroot sets, so probes read files under the
# mounted root instead of the scanner container.
set -eu
root="${1:?rootfs path}"
label="${2:?label such as before or after}"
profile="${3:-xccdf_org.ssgproject.content_profile_cis_level1_server}"
ds=/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml

export OSCAP_PROBE_ROOT="$root"
export OSCAP_EVALUATION_TARGET="chroot://$root"
export OSCAP_PROBE_OS_NAME=Linux
export OSCAP_PROBE_ARCHITECTURE="$(uname -m)"

# oscap exits 2 when any rule fails, which is the normal result here.
rc=0
oscap xccdf eval --profile "$profile" \
    --results "/results/${label}-results.xml" \
    --report "/results/${label}-report.html" \
    "$ds" > "/results/${label}-stdout.txt" 2> "/results/${label}-stderr.txt" || rc=$?
echo "oscap exit code: $rc"
[ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]
