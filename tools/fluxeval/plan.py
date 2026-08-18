#!/usr/bin/env python3
"""Turn `results/TRIAGE.md` into an attack list: what to work on, in what order.

    ./plan.py            # writes results/PLAN.md

Joins three things that live in three places and are useless apart:

  results/TRIAGE.md              what Flux says when a panic-holding function is
                                 opted into checking -- the KIND of work
  results/modified.blame.tsv     panic sites actually linked into the firmware --
                                 the metric
  results/per-file-wins.*.tsv    `.text` bytes a file's sites are worth, from the
                                 per-file ablation sweep -- the PAYOFF

The byte column is the weakest of the three and is labelled as such everywhere it
appears; see the caveats printed into the output.
"""

import collections
import csv
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
R = lambda *p: os.path.join(HERE, "results", *p)
PREFIX = "third_party/xarxa/"

# The first Flux error on a function decides its category. Order matters: the
# first pattern that matches wins.
RULES = [
    ("CHURN", r"refinement type error"
              r"|assertion might fail"
              r"|arithmetic operation may (underflow|overflow)"),
    ("PANIC", r"panicking::panic\b|panicking::panic_fmt"),
    ("FLUXBUG", r"internal flux error"),
    ("SPEC", r"MightPanic\(NoMIRAvailable\)"),
    ("CORE", r"MightPanic\((Transitive|NotInCallGraph|UnresolvedCall)"),
]
WHAT = {
    "CHURN": "state a length/range precondition and discharge it",
    "PANIC": "explicit panic!/unreachable!/assert! -- needs a cross-API precondition",
    "SPEC":  "foreign crate with no MIR -- needs an extern spec",
    "CORE":  "core iterator/Option/Result chain Flux cannot see through",
    "FLUXBUG": "Flux emits `internal flux error` -- compiler bug, quarantine",
    "ICE":   "rustc aborted -- quarantine or compiler fix",
    "CLEAN": "no obligation (UPPER BOUND -- see caveats)",
}
ORDER = ["CHURN", "PANIC", "CORE", "SPEC", "FLUXBUG", "ICE", "CLEAN"]
# Easiest to hardest. A function is categorised by the hardest error it holds.
HARDNESS = ["CHURN", "SPEC", "CORE", "PANIC", "FLUXBUG", "ICE", "CLEAN"]


def classify_one(msg):
    for name, pat in RULES:
        if re.search(pat, msg):
            return name
    return "CORE"


def classify(outcome, msg):
    """The HARDEST category among all of a function's errors.

    Not the first error. Flux's diagnostic order is not reproducible -- two runs
    of identical code disagreed on 29 rows, because a function holding both an
    out-of-bounds error and a `NoMIRAvailable` error reported them in either
    order. Taking the hardest is deterministic and conservative: a function is
    not done until all its errors are discharged, so its bottleneck is what the
    work actually costs. Sites therefore land in CHURN only if EVERY error on the
    function is churn.
    """
    if outcome in ("ICE", "CLEAN"):
        return outcome
    cats = [classify_one(m) for m in msg.split(" ;; ")]
    return max(cats, key=lambda c: HARDNESS.index(c))


def triage_rows():
    """[(file, fn, line, sites, category, msg)] from results/TRIAGE.md."""
    out = []
    for l in open(R("TRIAGE.md")):
        if not l.startswith("| `src/"):
            continue
        p = [x.strip().strip("`") for x in l.strip().strip("|").split("|")]
        if len(p) < 6:
            continue
        rel, fn, line, sites, outcome, msg = p[0], p[1], p[2], p[3], p[4], p[5]
        out.append((rel, fn, int(line), int(sites), classify(outcome, msg), msg))
    return out


def blame_sites():
    """{relpath: n} panic sites in the linked firmware. This is the metric."""
    c = collections.Counter()
    for path, line, sym, addr in csv.reader(open(R("modified.blame.tsv")), delimiter="\t"):
        if path.startswith(PREFIX):
            c[path[len(PREFIX):]] += 1
    return c


def bytes_by_file():
    """{relpath: (delta_text, status)} from the ablation sweep."""
    out = {}
    with open(R("per-file-wins.as-shipped.tsv")) as f:
        for row in csv.DictReader(f, delimiter="\t"):
            try:
                out[row["file"]] = (int(row["delta_text"]), row["status"])
            except (ValueError, KeyError):
                out[row["file"]] = (None, row.get("status", ""))
    return out


def main():
    rows, sites, wins = triage_rows(), blame_sites(), bytes_by_file()

    # Per-category totals. Bytes are apportioned across a file's categories by
    # site share -- first-order only, and only for files whose sweep delta was a
    # saving (a positive delta is inlining noise, not a cost).
    cat_sites, cat_bytes = collections.Counter(), collections.Counter()
    per_file = collections.defaultdict(collections.Counter)
    for rel, fn, line, n, cat, msg in rows:
        cat_sites[cat] += n
        per_file[rel][cat] += n
    for rel, cats in per_file.items():
        d, _ = wins.get(rel, (None, ""))
        tot = sum(cats.values())
        if not d or d >= 0 or not tot:
            continue
        for cat, n in cats.items():
            cat_bytes[cat] += round(-d * n / tot)

    with open(R("PLAN.md"), "w") as f:
        w = f.write
        w("# Attack list\n\n")
        w(f"{len(rows)} functions hold {sum(n for *_, n, _, _ in [(0,0,0,r[3],0,0) for r in rows])} "
          f"of the {sum(sites.values())} xarxa panic sites in the firmware; the rest sit "
          "outside a function this parser recognises (macro bodies, derives, closures).\n\n")

        w("## By kind of work\n\n| sites | est. bytes | category | what it is |\n")
        w("| ---: | ---: | --- | --- |\n")
        for cat in ORDER:
            if cat_sites[cat]:
                w(f"| {cat_sites[cat]} | {cat_bytes[cat] or '--'} | **{cat}** | {WHAT[cat]} |\n")

        w("\n## By file\n\nSorted by CHURN sites, which is the tractable work.\n\n")
        w("| file | sites | churn | panic | core | spec | bug/ICE | Δ.text | status |\n")
        w("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
        for rel in sorted(per_file, key=lambda r: (-per_file[r]["CHURN"], r)):
            c = per_file[rel]
            d, st = wins.get(rel, (None, "no sweep"))
            w(f"| `{rel}` | {sites.get(rel, 0)} | {c['CHURN']} | {c['PANIC']} | {c['CORE']} | "
              f"{c['SPEC']} | {c['FLUXBUG'] + c['ICE']} | {d if d is not None else '--'} | {st} |\n")

        w("\n## Rows: every CHURN function, biggest first\n\n")
        w("| file | fn | line | sites | first error |\n| --- | --- | ---: | ---: | --- |\n")
        for rel, fn, line, n, cat, msg in sorted(
                [r for r in rows if r[4] == "CHURN"], key=lambda r: (-r[3], r[0], r[2])):
            w(f"| `{rel}` | `{fn}` | {line} | {n} | {msg} |\n")

        w("\n## Caveats\n\n")
        neg = sum(d for d, _ in wins.values() if d and d < 0)
        w(f"- **The byte columns DO NOT ADD UP, by construction.** Each file's Δ.text was "
          f"measured by making that one file panic-free against the same reference build, so "
          f"the deltas overlap and double-count shared panic machinery. They sum to "
          f"{neg} B, which is {abs(neg) / 137620:.0%} of `.text` -- not a number anything is "
          "going to deliver. Use the byte columns to RANK files against each other and "
          "ignore their totals.\n")
        w("- **Δ.text is the weakest number here.** It comes from the per-file ablation "
          "sweep, which predates the xarxa merge that moved the benchmark from -504 to "
          "-1504 B, and a single-file rebuild shifts inlining by up to ~268 B on its own. "
          "Use it to rank, not to promise.\n")
        w("- **Bytes per category are apportioned by site share within a file**, so they "
          "assume every site in a file is worth the same. They are not measured per site.\n")
        w("- **CLEAN is an upper bound.** A function with no error may simply have had no "
          "obligation generated for it.\n")
        w("- **Categories are the FIRST error on a function.** A function counted CHURN can "
          "still hold a PANIC obligation behind it.\n")
        w("- Sites here are attributed to functions by line range; sites in macro bodies "
          "and derives are counted in the file total but appear in no row.\n")

    print(f"wrote {R('PLAN.md')}")
    for cat in ORDER:
        if cat_sites[cat]:
            print(f"  {cat_sites[cat]:4} sites  {cat_bytes[cat] or '--':>6} B  {cat}")


if __name__ == "__main__":
    main()
