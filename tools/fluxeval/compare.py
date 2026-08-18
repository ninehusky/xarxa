#!/usr/bin/env python3
"""Turn two measure.py JSON files into one markdown table.

    ./compare.py results/baseline.json results/modified.json

The first argument is the BASELINE (upstream) and the second is the MODIFIED
(ninehusky) build.  Deltas are modified minus baseline, so a shrink is
negative.
"""

import json
import re
import sys

# Allocated sections worth showing individually.  The .debug_* sections are
# large and are an artifact of `[profile.release] debug = 2`, which both repos
# set; they are in the JSON and in the .sections.txt dumps if you want them.
SECTIONS = [".text", ".rodata", ".data", ".bss"]

# LLVM appends ` (.llvm.<hash>)` to internal symbols, and the hash changes
# between the two builds for what is otherwise the same function.  Strip it
# before diffing the two name sets, or every such function looks both added
# and removed.  The counts use the raw symbols.
LLVM_SUFFIX_RE = re.compile(r" \(\.llvm\.\d+\)$")


def row(label, baseline, modified):
    """One markdown table row: the two values, their difference, and a percent.

    `baseline` and `modified` are plain integers (bytes, or counts).  The
    percentage is relative to baseline, and is omitted when baseline is 0.
    """
    delta = modified - baseline
    pct = f"{100.0 * delta / baseline:+.1f}%" if baseline else "n/a"
    return f"| {label} | {baseline} | {modified} | {delta:+} | {pct} |"


def main():
    baseline = json.load(open(sys.argv[1]))
    modified = json.load(open(sys.argv[2]))

    print("| metric | baseline | modified | delta | delta % |")
    print("| --- | --- | --- | --- | --- |")
    for s in SECTIONS:
        print(row(s, baseline["sections"].get(s, 0), modified["sections"].get(s, 0)))
    # What actually gets programmed onto the device, and what it needs in RAM.
    print(row("flash total", baseline["total_flash"], modified["total_flash"]))
    print(row("RAM (.data+.bss+.uninit)", baseline["total_ram"], modified["total_ram"]))
    print(row("panic call sites", baseline["panic_call_sites"], modified["panic_call_sites"]))
    print(row("panicking functions",
              baseline["panicking_function_count"], modified["panicking_function_count"]))

    # Per-crate call-site counts.  This is the table that answers "did anything
    # gain panics?" -- unlike the function lists below, it cannot be moved
    # around by inlining.
    crates = sorted(set(baseline["panic_sites_by_crate"]) | set(modified["panic_sites_by_crate"]),
                    key=lambda c: -baseline["panic_sites_by_crate"].get(c, 0))
    print("\n### Panic call sites by crate\n")
    print("| crate | baseline | modified | delta |")
    print("| --- | --- | --- | --- |")
    for c in crates:
        a, b = (baseline["panic_sites_by_crate"].get(c, 0),
                modified["panic_sites_by_crate"].get(c, 0))
        if a or b:
            print(f"| {c} | {a} | {b} | {b - a:+} |")

    for tag, data in (("baseline", baseline), ("modified", modified)):
        if data["unmatched_panic_refs"]:
            print(f"\n**{tag}: {len(data['unmatched_panic_refs'])} unmatched panic "
                  f"references** — instructions that mention a panic symbol but were "
                  f"not counted as call sites, so the count above is an undercount. "
                  f"See `unmatched_panic_refs` in the JSON.")

    # Symbol-level movement.  Read this as re-attribution, not as panics being
    # added or removed: inlining decides which symbol contains a given branch,
    # so the same panic can move between functions between builds.  The per-crate
    # site counts above are what says whether panics actually appeared.
    names = lambda m: {LLVM_SUFFIX_RE.sub("", f) for f in m["panicking_functions"]}
    only_a = sorted(names(baseline) - names(modified))
    only_b = sorted(names(modified) - names(baseline))
    print("\n### Which symbols hold the panics\n")
    print("Inlining moves branches between symbols, so a function appearing on one "
          "side only usually means the same panic was attributed elsewhere in the "
          "other build, not that a panic was added or removed.\n")
    print(f"Holds panics in baseline only ({len(only_a)}):")
    for f in only_a:
        print(f"  - {f}")
    print(f"\nHolds panics in modified only ({len(only_b)}):")
    for f in only_b:
        print(f"  - {f}")
    print("\nFull lists: `results/*.panicking-functions.txt`; "
          "every call site with its address: `results/*.panic-call-sites.txt`")


if __name__ == "__main__":
    main()
