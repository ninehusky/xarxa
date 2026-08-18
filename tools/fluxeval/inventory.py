#!/usr/bin/env python3
"""List every panic site in the measured binary, grouped by source file and line.

    ./blame.py results/modified.json work/modified > results/modified.blame.tsv
    ./inventory.py results/modified.blame.tsv work/modified/third_party/xarxa \
        > results/PANIC-INVENTORY.md

One row per source line that can panic, with how many machine call sites it
compiles to and the line itself.  Sites outnumber lines because generics and
inlining duplicate a single source line into several call sites -- the line
count is the one that tracks verification effort.

Defaults to xarxa's files; pass --prefix to look at a different crate.
"""

import collections
import csv
import os
import sys

# Shorten core's panic entry points to something that fits in a table cell.
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


def short(sym):
    if sym in SHORT:
        return SHORT[sym]
    return "assert!" if "assert_failed" in sym else sym.split("::")[-1]


def main():
    blame_tsv, checkout = sys.argv[1], sys.argv[2]
    prefix = "third_party/xarxa/"
    if "--prefix" in sys.argv:
        prefix = sys.argv[sys.argv.index("--prefix") + 1]

    # file -> line -> [panic kinds]
    files = collections.defaultdict(lambda: collections.defaultdict(list))
    for path, line, sym, _addr in csv.reader(open(blame_tsv), delimiter="\t"):
        if path.startswith(prefix):
            files[path[len(prefix):]][int(line)].append(short(sym))

    order = sorted(files, key=lambda f: (-sum(len(v) for v in files[f].values()), f))
    print("# Panic sites by source file\n")
    print("Every source line in the measured `usb_ethernet` binary that can panic. "
          "`sites` counts machine call sites; one source line becomes several when "
          "generics or inlining duplicate it, so `lines` is what tracks effort.\n")
    print("A `?` line means DWARF attributed the site to the file but to no "
          "statement — generic or heavily inlined code. The site is real; find it "
          "by its address in `results/modified.blame.tsv`.\n")
    print("| file | sites | lines |")
    print("| --- | --- | --- |")
    for f in order:
        print(f"| [{f}](#{f.replace('/', '').replace('.', '')}) "
              f"| {sum(len(v) for v in files[f].values())} | {len(files[f])} |")

    for f in order:
        lines = files[f]
        n = sum(len(v) for v in lines.values())
        print(f"\n## {f}\n\n{n} sites across {len(lines)} lines.\n")
        print("| line | sites | kind | source |")
        print("| --- | --- | --- | --- |")
        src = open(os.path.join(checkout, f), errors="replace").read().splitlines()
        for ln in sorted(lines):
            kinds = collections.Counter(lines[ln])
            if ln == 0:
                # llvm-symbolizer reports line 0 when the innermost non-std frame
                # has no line entry -- generic or heavily inlined code that DWARF
                # attributes to the file but not to a statement.  The site is
                # real; only its line is unknown.
                label, text = "?", "*no DWARF line; blamed to this file only*"
            else:
                label = str(ln)
                text = "`" + (src[ln - 1].strip() if ln <= len(src) else "?"
                              ).replace("|", "\\|") + "`"
            print(f"| {label} | {len(lines[ln])} | {', '.join(sorted(kinds))} | {text} |")


if __name__ == "__main__":
    main()
