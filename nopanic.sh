#!/usr/bin/env bash
# nopanic.sh -- the no_panic gate. One run, standing checks, family tally.
#
# Usage: ./nopanic.sh [tag]
# Writes _np/<tag>.log and prints the tally. Exits 1 if a standing check fails,
# in which case NO NUMBER FROM THIS RUN MAY BE QUOTED.
set -uo pipefail
TAG="${1:-run}"
OUT="_np"; mkdir -p "$OUT"
L="$OUT/$TAG.log"

FEATURES=medium-ethernet,socket-udp,socket-tcp,socket-dhcpv4,proto-ipv4,proto-ipv6
FLUX_CACHE=false cargo flux check -p xarxa --no-default-features --features "$FEATURES" > "$L" 2>&1

fail=0
chk() { # name expected actual
  if [ "$2" != "$3" ]; then echo "STANDING CHECK FAILED: $1 (want $2, got $3)"; fail=1; fi
}
E=$(grep -o 'E0999' "$L" | wc -l | tr -d ' ')
N=$(sed -n 's/.*due to \([0-9]*\) previous error.*/\1/p' "$L" | tail -1)
[ -z "$N" ] && N=0
chk "panicked (ICE)"      0 "$(grep -c panicked "$L")"
chk "syntax error"        0 "$(grep -c 'syntax error' "$L")"
chk "is missing"          0 "$(grep -c 'is missing' "$L")"
chk "run finished"        "$E" "$N"

echo "=== $TAG: $E errors ==="
grep -o 'call to [^ ]* may panic' "$L" | sed 's/call to //;s/ may panic//;s/\[[a-f0-9]*\]//g' > "$OUT/$TAG.callees"
t() { printf "  %-28s %4s\n" "$1" "$(grep -cE "$2" "$OUT/$TAG.callees")"; }
t "derive: discriminant"  'discriminant_value'
t "derive: eq/ne/cmp"     'cmp::|PartialEq|PartialOrd|partial_cmp'
t "derive: hash"          'hash::'
t "derive: clone"         'Clone::clone'
t "fmt"                   'fmt::'
t "REAL panic family"     'panicking::|::unwrap$|::expect$|intrinsics::unreachable'
t "heapless"              '^heapless'
t "xarxa_driver"          '^xarxa_driver'
t "iter/closure/Into/?"   'iter::|FnOnce::|::Fn::|FnMut::|from_residual|Into::into'
printf "  %-28s %4s\n" "non-may-panic" "$(( E - $(grep -c . "$OUT/$TAG.callees") ))"

[ "$fail" = 0 ] || { echo "!! numbers from $TAG are NOT quotable"; exit 1; }
