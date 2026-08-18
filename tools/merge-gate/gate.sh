#!/usr/bin/env bash
# Mechanical pre-merge checks. Deliberately small: it checks that evidence
# EXISTS, never that the evidence is correct. Judgment stays with the reviewer.
#
#   usage: tools/merge-gate/gate.sh <flux-log> [base-ref]
#
# Exit 1 on any failure. See CHEATING-TAXONOMY.md for what a reviewer still owes.
set -uo pipefail

LOG="${1:?usage: gate.sh <flux-log> [base-ref]}"
BASE="${2:-main}"
fail=0
note() { printf '%-6s %s\n' "$1" "$2"; }

# 1. An ICE aborts rustc and silently drops most diagnostics. Any hit voids
#    every count taken from this run -- no exceptions, check it first.
if grep -qE "thread 'rustc'.*panicked|error: internal compiler error" "$LOG"; then
    note FAIL "ICE in $LOG -- every count from this run is void"
    grep -nE "thread 'rustc'.*panicked|internal compiler error" "$LOG" | head -3
    fail=1
else
    note ok "no ICE in $LOG"
fi

# 2. A run that aborted on a spec error checked nothing, but still exits quiet.
if grep -qE 'error: (syntax error|invalid refinement|cannot resolve)' "$LOG"; then
    note FAIL "spec/syntax error -- the run aborted before checking bodies"
    fail=1
else
    note ok "no spec-error abort"
fi

# 3. Negative control must be RECORDED. We do not verify it was well chosen;
#    we refuse a PR that never ran one. Flipping a conjunct absurd must error.
if ls tools/merge-gate/controls/*.txt >/dev/null 2>&1 && \
   grep -rqE '^error' tools/merge-gate/controls/ 2>/dev/null; then
    note ok "negative control recorded ($(ls tools/merge-gate/controls/*.txt | wc -l | tr -d ' ') file(s))"
else
    note FAIL "no negative control in tools/merge-gate/controls/ showing a real error"
    fail=1
fi

# 4. Every NEW trusted needs a reason tag. Genuine Flux limitations are fine --
#    they just have to say which kind, so the count stays meaningful.
#    Tags: ICE=<inbox-ref> | unexpressible=<flux error> | extern-spec-missing=<what was tried>
added=$(git diff "$BASE"...HEAD -- '*.rs' | grep -E '^\+.*flux_rs::trusted' || true)
if [ -n "$added" ]; then
    untagged=$(printf '%s\n' "$added" | grep -vcE 'ICE=|unexpressible=|extern-spec-missing=')
    total=$(printf '%s\n' "$added" | wc -l | tr -d ' ')
    if [ "$untagged" -gt 0 ]; then
        note FAIL "$untagged/$total new trusted have no reason tag"
        printf '%s\n' "$added" | grep -vE 'ICE=|unexpressible=|extern-spec-missing=' | head -5
        fail=1
    else
        note ok "$total new trusted, all tagged"
    fi
else
    note ok "no new trusted"
fi

# Reported, never gated: removing a check can ADD panic sites (it had been
# feeding the optimiser a fact), and per-site binary A/B is below the noise
# floor. Aggregate only, documented increases pass.
note info "binary panic-site delta is reported separately, not gated here"

exit $fail
