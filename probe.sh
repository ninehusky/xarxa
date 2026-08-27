#!/usr/bin/env bash
# probe.sh <def-pattern> <tag> [--timings] -- check ONE function at the firmware config.
set -uo pipefail
DEF="$1"; TAG="${2:-probe}"; shift 2 || true
mkdir -p _np
L="_np/p-$TAG.log"
FEATURES=medium-ethernet,socket-udp,socket-tcp,socket-dhcpv4,proto-ipv4,proto-ipv6
S=$(date +%s)
FLUX_SYSROOT="${FLUX_SYSROOT:-/Users/andrew/research/flux-compose0825/sysroot-release}" \
RUSTFLAGS="-C debug-assertions=off" FLUX_CACHE=false \
  cargo flux check -p xarxa --no-default-features --features "$FEATURES" \
    --only-check "def:$DEF" "$@" > "$L" 2>&1
RC=$?; E=$(( $(date +%s) - S ))
echo "=== $DEF  [tag=$TAG] rc=$RC  ${E}s  panicked=$(grep -c panicked "$L")"
# scope check: --only-check silently matching nothing exits 0 and certifies nothing
grep -iE '[0-9]+ (processed|checked)' "$L" | tail -2
if ! grep -qE 'due to [0-9]+ previous error|Finished|could not compile' "$L"; then
  echo "!! RUN DID NOT FINISH -- no number may be quoted"; exit 2
fi
grep -o '^error\[E0999\]: .*' "$L" | sed 's/error\[E0999\]: //' | sort | uniq -c
echo "E0999: $(grep -c 'E0999' "$L")   due-to: $(sed -n 's/.*due to \([0-9]*\) previous error.*/\1/p' "$L" | tail -1)"
