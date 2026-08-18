#!/usr/bin/env python3
"""Generate results/STATUS.md -- the tracking document for the panic-removal work.

    ./status.py

One page that answers three questions and nothing else:

  where are we           sites removed from the firmware, against the measured ceiling
  what is left           every panic site, grouped by file, tagged with the KIND of
                         work Flux says it needs
  what is worth doing    measured bytes, with the caveats attached rather than
                         filed somewhere else

Inputs, all of them produced by another tool rather than typed in here:

  results/ablation.json        measured .text/.rodata/flash budgets (sweep/ceiling)
  results/modified.blame.tsv   every panic site in the linked binary  (blame.py)
  results/TRIAGE-sites.tsv     per-site Flux obligations              (triage.py)

The `removed` count is deliberately not inferred. A site counts as removed when a
fresh ./run.py says it is gone from the binary -- not when a proof lands.
"""

import collections
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plan as P                                            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
R = lambda *p: os.path.join(HERE, "results", *p)
PREFIX = "third_party/xarxa/"
XARXA = os.environ.get("XARXA", "/Users/andrew/research/xarxa-specs")

# core panic entry point -> something that fits in a table cell. Same map as
# inventory.py; kept in sync by hand, which is fine for 12 entries.
SHORT = {
    "core::slice::index::slice_index_fail": "slice-index",
    "core::panicking::panic_bounds_check": "bounds-check",
    "core::panicking::panic": "panic!/unreachable!",
    "core::panicking::panic_fmt": "panic!(fmt)",
    "core::option::expect_failed": "expect",
    "core::option::unwrap_failed": "unwrap",
    "core::result::unwrap_failed": "unwrap",
    "core::slice::copy_from_slice_impl::len_mismatch_fail": "copy_from_slice",
    "core::cell::panic_already_borrowed": "RefCell",
    "core::cell::panic_already_mutably_borrowed": "RefCell",
    "core::panicking::panic_const::panic_const_rem_by_zero": "rem-by-zero",
    "_defmt_panic": "defmt",
}

OWNER = {
    "src/wire/icmpv6.rs": "andrew", "src/wire/ipv6.rs": "andrew",
    "src/wire/ndisc.rs": "andrew",
    "src/wire/ipv4.rs": "agent", "src/wire/udp.rs": "agent",
    "src/wire/ndiscoption.rs": "agent", "src/wire/sixlowpan/nhc.rs": "agent",
    "src/wire/arp.rs": "blocked: const fn new_unchecked",
}


def short(sym):
    return SHORT.get(sym, sym.split("::")[-1] if "::" in sym else sym)


def blame():
    """{relpath: {line: [kinds]}} for xarxa sites in the measured firmware."""
    out = collections.defaultdict(lambda: collections.defaultdict(list))
    for path, line, sym, addr in csv.reader(open(R("modified.blame.tsv")), delimiter="\t"):
        if path.startswith(PREFIX):
            out[path[len(PREFIX):]][int(line)].append(short(sym))
    return out


def categories():
    """{(relpath, line): (category, fn)} from the Flux triage."""
    out = {}
    with open(R("TRIAGE-sites.tsv")) as f:
        for row in csv.DictReader(f, delimiter="\t"):
            msgs = row["messages"]
            if not msgs:
                cat = "CLEAN"
            elif msgs.startswith("rustc aborted"):
                cat = "ICE"
            else:
                cat = P.classify("OBLIGATION", msgs)
            out[(row["file"], int(row["site_line"]))] = (cat, row["fn"])
    return out


def src_line(rel, line):
    path = os.path.join(XARXA, rel)
    if line <= 0 or not os.path.exists(path):
        return ""
    lines = open(path, errors="replace").read().splitlines()
    return lines[line - 1].strip() if line <= len(lines) else ""


def pct(a, b):
    return f"{100.0 * a / b:+.2f}%"


def main():
    A = json.load(open(R("ablation.json")))
    ref, ceil, batch = A["reference"], A["ceiling_all_xarxa"], A["churn_batch_8_files"]
    sites, cats = blame(), categories()

    per_file_cat = collections.defaultdict(collections.Counter)
    for rel, lines in sites.items():
        for ln, kinds in lines.items():
            cat = cats.get((rel, ln), ("UNATTRIBUTED", ""))[0]
            per_file_cat[rel][cat] += len(kinds)

    total = collections.Counter()
    for c in per_file_cat.values():
        total.update(c)

    w = open(R("STATUS.md"), "w").write
    w("# Panic removal: status\n\n")
    w(f"Measured {A['measured']} against the linked nRF52840 `usb_ethernet` firmware. "
      "Regenerate with `./status.py`.\n\n")

    # ---------------------------------------------------------------- budget
    w("## The budget\n\n")
    w("What removing panics is worth, measured by rebuilding the real firmware with "
      "the checks ablated to `get_unchecked`.\n\n")
    w("| | flash | `.text` | `.rodata` | panic sites | xarxa sites |\n")
    w("| --- | ---: | ---: | ---: | ---: | ---: |\n")
    w(f"| today | {ref['flash']} | {ref['text']} | {ref['rodata']} | {ref['sites']} "
      f"| {ref['xarxa_sites']} |\n")
    w(f"| **ceiling** (every xarxa panic gone) | **{ceil['flash']}** | {ceil['text']} "
      f"| {ceil['rodata']} | {ceil['sites']} | {ceil['xarxa_sites']} |\n")
    d = {k: ceil[k] - ref[k] for k in ("flash", "text", "rodata", "sites", "xarxa_sites")}
    w(f"| delta | **{d['flash']}** ({pct(d['flash'], ref['flash'])}) "
      f"| {d['text']} ({pct(d['text'], ref['text'])}) "
      f"| {d['rodata']} ({pct(d['rodata'], ref['rodata'])}) "
      f"| {d['sites']} | {d['xarxa_sites']} |\n\n")
    w(f"**`.rodata` nearly halves** -- {abs(ceil['rodata'] - ref['rodata'])} B, "
      f"{100 * abs(ceil['rodata'] - ref['rodata']) // abs(d['flash'])}% of the whole win. "
      "That is panic message strings and `core::panic::Location` structs, and they are "
      "SHARED: they are freed when the last user dies, not gradually. Expect a partial "
      "effort to look sublinear and the final files to pay disproportionately.\n\n")
    w(f"53 xarxa sites survive even full ablation, so {abs(d['xarxa_sites'])} of "
      f"{ref['xarxa_sites']} is the real target.\n\n")

    # -------------------------------------------------------------- progress
    w("## Progress\n\n")
    w("| | sites | flash |\n| --- | ---: | ---: |\n")
    w(f"| removed so far | **0** | **0** |\n")
    w(f"| the 8-file CHURN batch, if completed | {ref['sites'] - batch['sites']} "
      f"| {batch['flash'] - ref['flash']} |\n")
    w(f"| ceiling | {abs(d['sites'])} | {d['flash']} |\n\n")
    w("Nothing has been removed yet: every branch so far is proof-only. A site leaves "
      "the binary when a discharged obligation LICENSES replacing the checked operation "
      "with `get_unchecked` -- and only after `check_proof.py` passes for that file. "
      "A trusted shim is not a fix; it assumes the obligation.\n\n")

    # ------------------------------------------------------------- by file
    w("## By file\n\n")
    w("`churn` is the tractable work: state a length or range precondition and discharge "
      "it. Sorted by it. `Δ alone` is that file's CHURN lines ablated on their own -- see "
      "the caveats, most of those are inside the noise floor individually.\n\n")
    w("| file | sites | churn | panic | core | bug/ICE | other | Δ alone | owner |\n")
    w("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
    pf = A["per_file_churn_only"]
    for rel in sorted(per_file_cat, key=lambda r: (-per_file_cat[r]["CHURN"], r)):
        c = per_file_cat[rel]
        n = sum(c.values())
        other = n - c["CHURN"] - c["PANIC"] - c["CORE"] - c["FLUXBUG"] - c["ICE"]
        dt = pf.get(rel, [None])[0]
        w(f"| [`{rel}`](#{rel.replace('/', '').replace('.', '').replace('_', '')}) | {n} "
          f"| {c['CHURN']} | {c['PANIC']} | {c['CORE']} | {c['FLUXBUG'] + c['ICE']} "
          f"| {other} | {dt if dt is not None else '--'} | {OWNER.get(rel, '')} |\n")
    w(f"| **total** | **{sum(total.values())}** | **{total['CHURN']}** "
      f"| **{total['PANIC']}** | **{total['CORE']}** "
      f"| **{total['FLUXBUG'] + total['ICE']}** "
      f"| **{sum(total.values()) - total['CHURN'] - total['PANIC'] - total['CORE'] - total['FLUXBUG'] - total['ICE']}** "
      f"| | |\n\n")

    w("`other` is mostly UNATTRIBUTED: a site the blame data puts in this file but that "
      "falls outside any function the triage parser recognised -- macro bodies, derives, "
      "closures. Those sites are real and counted in the metric; they just have no Flux "
      "obligation attached yet.\n\n")

    # --------------------------------------------------------- the site list
    w("## Every panic site, by file\n\n")
    w("One row per source line. `sites` exceeds lines because generics and inlining "
      "duplicate a line into several machine call sites -- lines track effort, sites "
      "track the metric. A `?` line means DWARF blamed the file but no statement.\n\n")
    for rel in sorted(per_file_cat, key=lambda r: (-per_file_cat[r]["CHURN"], r)):
        anchor = rel.replace("/", "").replace(".", "").replace("_", "")
        c = per_file_cat[rel]
        w(f"<a id=\"{anchor}\"></a>\n### `{rel}`\n\n")
        w(f"{sum(c.values())} sites across {len(sites[rel])} lines. "
          f"churn {c['CHURN']}, panic {c['PANIC']}, core {c['CORE']}. "
          f"Owner: {OWNER.get(rel, '--')}.\n\n")
        w("| line | sites | kind | work | fn | source |\n")
        w("| ---: | ---: | --- | --- | --- | --- |\n")
        for ln in sorted(sites[rel]):
            kinds = sites[rel][ln]
            cat, fn = cats.get((rel, ln), ("UNATTRIBUTED", ""))
            shown = ln if ln > 0 else "?"
            code = src_line(rel, ln).replace("|", "\\|")[:90]
            w(f"| {shown} | {len(kinds)} | {', '.join(sorted(set(kinds)))} | {cat} "
              f"| `{fn}` | `{code}` |\n")
        w("\n")

    # ------------------------------------------------------------- caveats
    w("## Caveats\n\n")
    nf = A["noise_floor"]
    w(f"- **Ablation is a ceiling, not a forecast.** `get_unchecked` removes a check "
      "whether or not anything proved it safe. These binaries are measured, never "
      "flashed.\n")
    w(f"- **Per-file deltas do not sum.** The eight files' CHURN lines total -1904 B "
      f"alone but {batch['flash'] - ref['flash']} B of flash together -- superadditive, "
      "because shared panic machinery only dies with its last user. Rank with the "
      "per-file column; never total it.\n")
    w(f"- **Noise floor.** An identical rebuild reproduced `.text` exactly "
      f"({nf['identical_rebuild_delta']} B), so there is no link noise -- but a real "
      f"source change shifts inlining, and the largest INCREASE seen was "
      f"+{nf['largest_increase_seen']} B. Treat a single-file delta under ~300 B as "
      "unresolved.\n")
    w("- **Categories come from the HARDEST Flux error on a function**, not the first. "
      "Flux's diagnostic order is not reproducible: two runs of identical code disagreed "
      "on 29 rows. A line counts as churn only if every error on its function is churn.\n")
    w("- **`src/wire/mod.rs` and `src/storage/assembler.rs` are excluded from the "
      "ceiling** -- the ablator cannot rewrite them (`[u8; N]` has no `__ai` impl; "
      "`assembler.rs` hits borrowck). 5 sites.\n")
    w("- **Two files under-ablated** against their targets: `ndiscoption` removed 4 of "
      "7 targeted, `nhc` 5 of 7, mostly `const fn` bodies the rewriter skips. Their "
      "small deltas are understated.\n")

    print(f"wrote {R('STATUS.md')}")
    print(f"  {sum(total.values())} sites: " +
          ", ".join(f"{k} {v}" for k, v in total.most_common()))


if __name__ == "__main__":
    main()
