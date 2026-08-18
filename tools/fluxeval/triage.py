#!/usr/bin/env python3
"""Breadth triage: opt every panic-holding function into Flux checking at once,
run, and let Flux partition them.

    ./triage.py <xarxa-checkout> [--files src/wire/arp.rs ...]

xarxa sets `default_trusted = true`, so ~86% of the panic sites in the firmware
have never had an obligation generated for them at all. Rather than proving
files one at a time, this stamps `#[flux_rs::trusted(no)]` on every function
that holds a panic site and asks Flux what happens. Three outcomes per function:

  CLEAN      no error -- the site discharges with no annotation whatsoever
  OBLIGATION errors, with a message -- real work, and the message says what kind
  ICE        rustc aborted -- quarantine candidate

The point is to shrink "375 unknown" down to a short list of genuinely hard
cases, cheaply.

IMPORTANT: an ICE swallows the rest of the crate's diagnostics (measured, not
assumed), so a single ICE anywhere makes every other result in the same run
meaningless. When that happens this falls back to per-file runs to isolate it,
and refuses to report counts from any log containing 'panicked'.

The checkout is restored with `git checkout -- .` on the way out, including on
Ctrl-C. Nothing is committed and nothing is pushed.
"""

import collections
import csv
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BLAME = os.path.join(HERE, "results", "modified.blame.tsv")
PREFIX = "third_party/xarxa/"
# Exactly the xarxa features the measured firmware builds with. Resolved, not
# guessed, with:
#
#   cd work/modified/examples/nrf52840
#   cargo tree -i -e features -p xarxa --target thumbv7em-none-eabi \
#     | grep 'xarxa feature' | sed 's/.*"\(.*\)".*/\1/' | sort -u
#
# which gives async, auto-icmp-echo-reply, defmt, medium-ethernet,
# medium-ieee802154, proto-dhcpv4, proto-ipv4, proto-ipv6, proto-sixlowpan,
# socket, socket-dhcpv4, socket-tcp, socket-udp. Four of those are implied
# (`socket` by socket-tcp, `proto-dhcpv4` by socket-dhcpv4, `proto-sixlowpan`
# by medium-ieee802154) and need not be listed -- but `async` is implied by
# NOTHING here and was missing, so every `#[cfg(feature = "async")]` item in
# `socket/*` was invisible to the triage run while being linked into the
# firmware. An unchecked function reports no error and lands in CLEAN.
TOOLCHAIN_FEATURES = ("defmt,socket-tcp,proto-ipv4,medium-ethernet,socket-dhcpv4,"
                      "socket-udp,medium-ieee802154,proto-ipv6,auto-icmp-echo-reply,"
                      "async")
ATTR = '#[flux_rs::trusted(no, reason = "breadth triage: does this discharge?")]'


def functions(path):
    """[(name, start_line, end_line)] by brace depth. Same parser as check_proof.py."""
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


def sites_by_file(checkout):
    """{relpath: {line: n_sites}} for xarxa sites, from the measured firmware."""
    out = collections.defaultdict(collections.Counter)
    for path, line, sym, addr in csv.reader(open(BLAME), delimiter="\t"):
        if path.startswith(PREFIX) and int(line) > 0:
            rel = path[len(PREFIX):]
            if os.path.exists(os.path.join(checkout, rel)):
                out[rel][int(line)] += 1
    return out


def targets(checkout, files=None):
    """{relpath: [(idx, fn, start, end, n_sites)]} -- functions holding panic sites.

    `idx` is the function's ORDINAL POSITION in `functions(path)`, and it, not the
    name, is the identity used from here on. xarxa's wire modules define the same
    accessor name in several impl blocks (`nhc.rs` has 8 duplicates), so keying by
    bare name collapses distinct functions onto one row and then re-expands them
    over every same-named function in the file -- attributing one function's panic
    sites to its namesakes. Ordinals survive stamping because inserting an
    attribute line never adds or removes a `fn`.
    """
    out = {}
    for rel, lines in sites_by_file(checkout).items():
        if files and rel not in files:
            continue
        fns, chosen = functions(os.path.join(checkout, rel)), []
        for idx, (name, lo, hi) in enumerate(fns):
            n = sum(c for ln, c in lines.items() if lo <= ln <= hi)
            if n:
                chosen.append((idx, name, lo, hi, n))
        if chosen:
            out[rel] = chosen
    return out


def stamp(checkout, plan):
    """Insert the opt-in attribute above each target fn.

    Returns (count, post) where `post` maps relpath -> [(fn, lo, hi, sites)] with
    ranges RE-PARSED FROM THE STAMPED FILE. This matters: each insertion shifts
    every line below it, so ranges taken before stamping do not line up with the
    line numbers Flux reports. Attributing errors with pre-stamp ranges silently
    misfiles them and inflates the CLEAN bucket.

    The re-parsed ranges are matched back to targets BY ORDINAL, not by name --
    see `targets`. Stamping only inserts attribute lines, so the function list of
    a file has the same length and order before and after; if it does not, the
    parse disagrees with itself and the file is dropped rather than misreported.
    """
    n = 0
    for rel, fns in plan.items():
        p = os.path.join(checkout, rel)
        src = open(p, errors="replace").read().splitlines(True)
        for _, name, lo, hi, _ in sorted(fns, key=lambda f: -f[2]):  # back to front
            head = "".join(src[max(0, lo - 10):lo - 1])
            if "trusted(" in head:      # already opted in, or deliberately trusted
                continue
            indent = re.match(r"\s*", src[lo - 1]).group(0)
            src.insert(lo - 1, f"{indent}{ATTR}\n")
            n += 1
        open(p, "w").writelines(src)
    post, dropped = {}, []
    for rel, fns in plan.items():
        newfns = functions(os.path.join(checkout, rel))
        pre_len = max(idx for idx, *_ in fns) + 1
        if len(newfns) < pre_len:
            dropped.append(rel)
            continue
        post[rel] = [(newfns[idx][0], newfns[idx][1], newfns[idx][2], cnt)
                     for idx, name, _, _, cnt in fns
                     if newfns[idx][0] == name]
        if len(post[rel]) != len(fns):
            dropped.append(rel)
            del post[rel]
    if dropped:
        print(f"== WARNING: function list changed under stamping in {len(dropped)} "
              f"file(s); dropping them rather than misattributing: {dropped}", flush=True)
    return n, post


def run_flux(checkout, log):
    with open(log, "w") as f:
        subprocess.run(["cargo", "flux", "check", "-p", "xarxa", "--no-default-features",
                        "--features", TOOLCHAIN_FEATURES],
                       cwd=checkout, stdout=f, stderr=f)
    body = open(log, errors="replace").read()
    return ("panicked" in body), body


def errors_by_file_line(body):
    """{(relpath, line): [messages]} using PRIMARY spans only."""
    out, msg = collections.defaultdict(list), None
    for l in body.splitlines():
        if l.startswith("error["):
            msg = re.sub(r"^error\[[^\]]*\]: ", "", l).strip()
        m = re.match(r"\s*--> (src/[^:]+):(\d+):", l)
        if m and msg:
            out[(m.group(1), int(m.group(2)))].append(msg); msg = None
    return out


def restore(checkout):
    subprocess.run(["git", "checkout", "--", "."], cwd=checkout, check=False)


def main():
    checkout = os.path.abspath(sys.argv[1])
    files = None
    if "--files" in sys.argv:
        files = sys.argv[sys.argv.index("--files") + 1:]
    scratch = os.environ.get("SCRATCH", "/tmp")

    plan = targets(checkout, files)
    total_fns = sum(len(v) for v in plan.values())
    total_sites = sum(n for v in plan.values() for *_, n in v)
    print(f"== {total_fns} functions hold {total_sites} panic sites across "
          f"{len(plan)} files", flush=True)

    try:
        restore(checkout)
        n, post = stamp(checkout, plan)
        print(f"== stamped {n} functions with trusted(no); running flux", flush=True)
        iced, body = run_flux(checkout, os.path.join(scratch, "triage-all.log"))

        if iced:
            print("== ICE in the combined run -- diagnostics are unusable. "
                  "Falling back to per-file runs to isolate it.", flush=True)
            results, iced_files = {}, []
            for rel in sorted(plan):
                restore(checkout)
                _, post_one = stamp(checkout, {rel: plan[rel]})
                if rel not in post_one:
                    post.pop(rel, None)
                    continue
                post[rel] = post_one[rel]
                tag = rel.replace("/", "_")
                ic, b = run_flux(checkout, os.path.join(scratch, f"triage-{tag}.log"))
                if ic:
                    iced_files.append(rel); print(f"   {rel}: ICE", flush=True)
                else:
                    results[rel] = errors_by_file_line(b)
                    print(f"   {rel}: ok, {sum(len(v) for v in results[rel].values())} errors",
                          flush=True)
        else:
            iced_files = []
            results = {rel: errors_by_file_line(body) for rel in plan}
    finally:
        restore(checkout)

    # Classify each target function. Rows carry the (post-stamp) start line because
    # the name alone does not identify a function in these files.
    rows, kinds = [], collections.Counter()
    for rel, fns in sorted(post.items()):
        if rel in iced_files:
            for name, lo, hi, n in fns:
                rows.append((rel, name, lo, n, "ICE", "rustc aborted; quarantine candidate"))
                kinds["ICE"] += n
            continue
        errs = results.get(rel, {})
        for name, lo, hi, n in fns:
            mine = [m for (f, ln), ms in errs.items() if f == rel and lo <= ln <= hi
                    for m in ms]
            if not mine:
                rows.append((rel, name, lo, n, "CLEAN", "")); kinds["CLEAN"] += n
            else:
                # EVERY distinct message, sorted. Not `mine[0]`: the order Flux
                # emits diagnostics in is not reproducible -- two runs of the same
                # code with the same features disagreed on 29 of these rows,
                # because a function holding both an out-of-bounds error and a
                # `write_u24` error reported them in either order. Anything
                # downstream that categorises a function must see the whole set,
                # and sorting makes the row itself byte-stable.
                rows.append((rel, name, lo, n, "OBLIGATION",
                             " ;; ".join(sorted({m[:70] for m in mine}))))
                kinds["OBLIGATION"] += n

    # Machine-readable companion: one row per PANIC SITE, with the site's line in
    # the UNSTAMPED file. TRIAGE.md's line column is post-stamp and cannot be used
    # against a clean checkout, which is what the ablation sweep needs.
    sitesf = os.path.join(HERE, "results", "TRIAGE-sites.tsv")
    site_lines = sites_by_file(checkout)
    with open(sitesf, "w") as f:
        f.write("file\tfn\tsite_line\tmessages\n")
        for rel, fns in sorted(plan.items()):
            # post[rel] is built by comprehension over plan[rel] in order, so
            # position i in one is position i in the other.
            postfns = post.get(rel, [])
            for i, (idx, name, lo, hi, n) in enumerate(fns):
                msgs = ""
                if rel in iced_files:
                    msgs = "rustc aborted; quarantine candidate"
                elif i < len(postfns):
                    _, plo, phi, _ = postfns[i]
                    errs = results.get(rel, {})
                    mine = sorted({m[:70] for (ff, ln), ms in errs.items()
                                   if ff == rel and plo <= ln <= phi for m in ms})
                    msgs = " ;; ".join(mine)
                for ln, cnt in sorted(site_lines.get(rel, {}).items()):
                    if lo <= ln <= hi:
                        for _ in range(cnt):
                            f.write(f"{rel}\t{name}\t{ln}\t{msgs}\n")
    print(f"== wrote {sitesf}")

    out = os.path.join(HERE, "results", "TRIAGE.md")
    with open(out, "w") as f:
        f.write("# Breadth triage: what happens if every panic-holding function is checked\n\n")
        f.write(f"{total_fns} functions, {total_sites} panic sites, {len(plan)} files.\n\n")
        f.write("| sites | outcome |\n| ---: | --- |\n")
        for k, v in kinds.most_common():
            f.write(f"| {v} | {k} |\n")
        f.write("\n| file | fn | line | sites | outcome | first error |\n")
        f.write("| --- | --- | ---: | ---: | --- | --- |\n")
        for rel, name, lo, n, kind, msg in sorted(rows, key=lambda r: (r[4], -r[3])):
            f.write(f"| `{rel}` | `{name}` | {lo} | {n} | {kind} | {msg} |\n")
    print(f"\n== wrote {out}")
    for k, v in kinds.most_common():
        print(f"   {v:4} sites  {k}")


if __name__ == "__main__":
    main()
