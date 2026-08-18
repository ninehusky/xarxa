#!/usr/bin/env python3
"""Check whether a claimed Flux proof is actually complete.

    ./check_proof.py <flux.log> <xarxa-checkout> <src/path/file.rs>

Two failure modes have already slipped through a plausible-looking agent report,
and both are mechanical to catch. Neither is about whether Flux said "error" --
it is about WHERE, and about what silence means.

1. ERRORS IN THE SAME FUNCTION.
   A panic site can only be called proven if Flux reports nothing anywhere in the
   function containing it. In ring_buffer.rs three of the five panic-site
   functions also held `assignment might be unsafe` errors, i.e. the reads were
   "proven" while the writes in the same body were not, so the struct invariant
   had no proof of maintenance. Reported as 20/20 anyway.

2. PRECONDITIONS WITH UNCHECKED CALLERS.
   xarxa is `default_trusted = true`, so a caller that is not opted in with
   `#[flux_rs::trusted(no, ...)]` CANNOT produce an error. "No errors at the call
   sites" and "the call sites were never examined" are byte-identical output.
   Adding a `requires` to a function whose callers are all trusted discharges
   nothing; it just moves the obligation somewhere nobody is looking.

Exit code is 1 if either check fails, so this can gate a report.
"""

import os
import re
import subprocess
import sys


def functions(path):
    """[(name, start_line, end_line)] for a Rust file, by brace depth."""
    out, src = [], open(path, errors="replace").read().splitlines()
    cur, depth, start = None, 0, 0
    for i, line in enumerate(src, 1):
        m = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*fn\s+(\w+)", line)
        if m and cur is None:
            cur, start, depth = m.group(1), i, 0
        if cur:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "{" in "".join(src[start - 1:i]):
                out.append((cur, start, i)); cur = None
    return out


def errors_by_line(log, relpath):
    """{line: message} for errors whose PRIMARY span is in relpath."""
    out, msg = {}, None
    for l in open(log, errors="replace"):
        if l.startswith("error["):
            msg = re.sub(r"^error\[[^\]]*\]: ", "", l).strip()
        m = re.match(rf"\s*--> {re.escape(relpath)}:(\d+):", l)
        if m and msg:
            out[int(m.group(1))] = msg; msg = None
    return out


def main():
    log, checkout, relpath = sys.argv[1], sys.argv[2], sys.argv[3]
    path = os.path.join(checkout, relpath)

    if subprocess.run(["grep", "-qc", "panicked", log],
                      stdout=subprocess.DEVNULL).returncode == 0:
        sys.exit("REFUSING: the log contains 'panicked' — an ICE drops most "
                 "diagnostics, so no count from it can be trusted.")

    errs = errors_by_line(log, relpath)
    fns = functions(path)
    bad = []
    for name, lo, hi in fns:
        inside = {ln: m for ln, m in errs.items() if lo <= ln <= hi}
        if inside:
            bad.append((name, lo, hi, inside))

    print(f"== {relpath}: {len(errs)} Flux errors, {len(fns)} functions")
    if bad:
        print(f"\nFAIL check 1 — {len(bad)} function(s) still have errors; no panic "
              f"site inside them is proven:")
        for name, lo, hi, inside in bad:
            print(f"  {name} (lines {lo}-{hi})")
            for ln, m in sorted(inside.items()):
                print(f"      {ln}: {m[:88]}")
    else:
        print("OK check 1 — no function in this file has a Flux error.")

    # Check 2: every function this file gives a `requires` must have checked CALLERS.
    # The caller test is per-function, not per-file: socket/tcp.rs has 7 trusted(no)
    # among 312 functions, so "the file contains trusted(no)" passes while the actual
    # calling function is still unchecked.
    src = open(path, errors="replace").read().splitlines()
    # A precondition is either `requires ...` or a refined argument type such as
    # `{usize[@count] | count <= r.cap - r.length}`. Missing the second form is
    # what made an earlier version of this check pass a file it should have failed.
    PRECOND = re.compile(r"requires\s|\{\s*\w+\[[^\]]*\]\s*\|")
    gated = [name for name, lo, hi in fns
             if PRECOND.search("\n".join(src[max(0, lo - 10):lo]))]
    # Callers are matched by BARE METHOD NAME -- there is no type resolution here.
    # In xarxa's wire module 32 different types define `emit`, so an unfiltered
    # search reported 92 callers for arp::Repr::emit of which 5 were real. Filter
    # candidates to files that actually name this module or one of its types;
    # that cut 96 rows to the handful that matter. It is still a heuristic: a
    # file that mentions the module for an unrelated reason can slip through, so
    # rows are reported as candidates, not as facts.
    # str.capitalize() used to build the camel form, which mangles snake_case
    # (ring_buffer -> Ring_buffer). Nothing matched, so the filter rejected every
    # candidate file and check 2 reported a FALSE OK on ring_buffer -- where
    # socket/tcp.rs::process is a genuine unchecked caller. A false negative is
    # worse than the false positives this filter was added to remove, so the
    # rewrite below errs permissive: it also accepts the module's own type names
    # and the bare camel module name (`RingBuffer`), which is how a module named
    # after its single type is referred to.
    mod_tok = os.path.splitext(os.path.basename(relpath))[0]
    cam = "".join(p[:1].upper() + p[1:] for p in mod_tok.split("_"))
    type_toks = re.findall(r"^\s*(?:pub\s+)?(?:struct|enum)\s+(\w+)", "\n".join(src), re.M)
    # xarxa re-exports wire types under a module-prefixed alias
    # (`arp::Repr as ArpRepr`), so the prefixed spelling is the usual one at a
    # call site. Bare `Packet`/`Repr`/... are shared by ~32 wire types and would
    # match everything, so they are only accepted for a module whose type is
    # named after it.
    # Matching is CASE-INSENSITIVE. A module name does not tell you how its type
    # is capitalised: `ndiscoption` gives the camel form `Ndiscoption`, but the
    # type is spelled `NdiscOption`, so an exact-case filter rejected `wire/ndisc.rs`
    # -- the one file that calls into it. Found by an agent, not by this script.
    toks = {f"{mod_tok}::", cam} | {f"{cam}{t}" for t in type_toks}
    toks |= {t for t in type_toks if t.lower() == cam.lower()}
    toks = {t.lower() for t in toks}
    def plausible(f):
        body = open(f, errors="replace").read().lower()
        return any(t in body for t in toks)

    unchecked = []
    for name in gated:
        hits = subprocess.run(["grep", "-rn", f"\\.{name}(", os.path.join(checkout, "src")],
                              capture_output=True, text=True).stdout.splitlines()
        for hit in hits:
            f, ln = hit.split(":")[0], int(hit.split(":")[1])
            if os.path.abspath(f) == os.path.abspath(path) or not plausible(f):
                continue
            csrc = open(f, errors="replace").read().splitlines()
            caller = next((n for n, lo, hi in functions(f) if lo <= ln <= hi), None)
            if caller is None:
                continue
            clo = next(lo for n, lo, hi in functions(f) if n == caller and lo <= ln <= hi)
            if "trusted(no" not in "\n".join(csrc[max(0, clo - 10):clo]):
                unchecked.append((name, f"{os.path.relpath(f, checkout)}::{caller}"))
    if unchecked:
        print(f"\nFAIL check 2 — CANDIDATE callers not opted into checking (matched by "
              f"method name and module mention; no type resolution, so verify each):")
        for name, f in sorted(set(unchecked)):
            print(f"  {name}() called from {f}  [no trusted(no) in that file]")
    elif gated:
        print(f"OK check 2 — {len(gated)} gated fn(s), all external callers are checked.")
    else:
        print("OK check 2 — this file adds no preconditions.")

    sys.exit(1 if (bad or unchecked) else 0)


if __name__ == "__main__":
    main()
