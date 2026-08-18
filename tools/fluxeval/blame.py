#!/usr/bin/env python3
"""Attribute every panic call site in a linked ELF to a source file and line.

    ./blame.py <elf> [--check results/modified.json] > results/modified.blame.tsv

Four tab-separated columns, one row per panic call site, sorted by address:

    source path (relative to the build tree)  line  panic symbol  address

Where the line comes from
-------------------------
NOT from DWARF.  Every panic entry point in core is `#[track_caller]` and takes
a `&'static core::panic::Location` as its last argument -- slice_index_fail,
panic_bounds_check, unwrap_failed, expect_failed, panic.  On thumbv7 that
pointer is materialised by a movw/movt pair (or a literal-pool ldr) in the few
instructions before the `bl`, and Location is {ptr, len, line, col}, all 32-bit,
with the pointer into a string in .rodata.  So the exact file:line:col the panic
would print at runtime is *data in the binary*, and reading it needs no debug
info at all.

This matters because DWARF gives line 0 for panic branches the optimiser
tail-merged, which on this firmware is 72 xarxa sites -- 35 of them in
sixlowpan/iphc.rs, the largest file in the crate.  The Location survives the
merge because it is an argument, not a line-table entry.

DWARF is still the fallback for the sites that carry no Location: defmt's panic
macro does not pass one, and a handful of unwrap_failed calls rematerialise the
pointer further back than the instruction window here scans.  Those rows are
resolved with llvm-symbolizer, taking the innermost inlined frame that is not in
/rustc/ -- i.e. the user code, not the core internals it inlined.

Consistency
-----------
The site list is `measure.panics()` itself, imported rather than reimplemented,
so this file and measure.py cannot drift on what counts as a panic call site.
`--check` additionally compares the site addresses against a measure.py JSON and
warns loudly if they differ, which means the JSON and the ELF are from different
builds and every number derived from the pair is suspect.  That is not
hypothetical: results/modified.json and results/modified.blame.tsv disagreed on
295 of 650 addresses before this script existed.
"""

import json
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import measure                                                      # noqa: E402

# Registers the Location can arrive in.  Preference order is high-to-low because
# it is always the LAST argument: slice_index_fail(start, end, len, loc) puts it
# in r3, panic_bounds_check(index, len, loc) in r2.
ARG_ORDER = {"r0": 0, "r1": 1, "r2": 2, "r3": 3}
MOVW_RE = re.compile(r"^movw\s+(\w+), #(0x[0-9a-f]+)")
MOVT_RE = re.compile(r"^movt\s+(\w+), #(0x[0-9a-f]+)")
LDR_PC_RE = re.compile(r"^ldr(?:\.\w)?\s+(\w+), \[pc")
# How many instructions before the `bl` to scan.  16 covers every site measured
# here; the cost of raising it is false positives, since a stale movw/movt into a
# register that is not the Location argument can still decode as one.
WINDOW = 16


class Elf:
    """Just enough ELF to read a virtual address out of the file."""

    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.secs = []
        out = measure.llvm("llvm-readelf", "-S", "--wide", path)
        for line in out.splitlines():
            if not line.lstrip().startswith("[") or "]" not in line:
                continue
            f = line[line.index("]") + 1:].split()
            if len(f) < 5:
                continue
            try:
                name, addr, off, size = f[0], int(f[2], 16), int(f[3], 16), int(f[4], 16)
            except ValueError:
                continue
            # .bss occupies addresses but no file bytes; reading it would return
            # whatever happens to follow in the file.
            if name != ".bss" and addr:
                self.secs.append((addr, off, size))

    def read(self, va, n):
        for addr, off, size in self.secs:
            if addr <= va < addr + size:
                return self.data[off + va - addr: off + va - addr + n]
        return None

    def location(self, va):
        """Decode a &core::panic::Location at `va`, or None if it is not one.

        The checks are deliberately strict: this is looking at whatever value a
        register happened to hold, so anything that is not obviously a Location
        must be rejected rather than reported as a source line.
        """
        b = self.read(va, 16)
        if not b or len(b) < 16:
            return None
        ptr, ln, line, col = struct.unpack("<IIII", b)
        if not (4 <= ln <= 400 and 1 <= line <= 200000 and 1 <= col <= 1000):
            return None
        s = self.read(ptr, ln)
        if not s or len(s) < ln:
            return None
        try:
            path = s.decode("utf8")
        except UnicodeDecodeError:
            return None
        return (path, line) if path.endswith(".rs") and "\n" not in path else None


def locations(elf_path, elf):
    """{site address: (path, line)} for every site whose Location is readable."""
    out, window = {}, []
    for raw in measure.llvm("llvm-objdump", "-d", "--demangle", elf_path).splitlines():
        if measure.FUNC_RE.match(raw.strip()):
            window = []                      # registers do not carry across functions
            continue
        if ":" not in raw:
            continue
        line = measure.COMMENT_RE.split(raw, 1)[0]
        addr, _, rest = line.partition(":")
        text = " ".join(t for t in rest.split()
                        if not measure.ENCODING_RE.match(t))
        if not text:
            continue
        target = measure.TARGET_RE.search(line)
        if (target and measure.PANIC_RE.search(target.group(1))
                and measure.BRANCH_RE.match(text.split()[0])):
            loc = resolve(window, elf, raw)
            if loc:
                out[addr.strip()] = loc
            window = []
            continue
        window.append((text, raw))
        del window[:-WINDOW]
    return out


def resolve(window, elf, site_line):
    """The Location built by the instructions in `window`, if any."""
    regs = {}
    for text, raw in window:
        m = MOVW_RE.match(text)
        if m:
            regs[m.group(1)] = int(m.group(2), 16)
            continue
        m = MOVT_RE.match(text)
        if m:
            regs[m.group(1)] = ((regs.get(m.group(1), 0) & 0xFFFF)
                                | (int(m.group(2), 16) << 16))
            continue
        m = LDR_PC_RE.match(text)
        if m:
            # llvm-objdump's trailing comment gives the literal's address, not
            # its value, so read the pool word out of the file.
            pool = re.search(r"0x([0-9a-f]+)", raw.rsplit("@", 1)[-1])
            if pool:
                w = elf.read(int(pool.group(1), 16), 4)
                if w:
                    regs[m.group(1)] = struct.unpack("<I", w)[0]
    hits = [(r, elf.location(v)) for r, v in regs.items() if elf.location(v)]
    hits.sort(key=lambda h: ARG_ORDER.get(h[0], -1))
    return hits[-1][1] if hits else None


def dwarf(elf_path, addrs):
    """{address: (path, line)} from DWARF, for the sites with no Location.

    Takes the innermost inlined frame that is not in /rustc/: a bounds check in
    core::slice inlined into embassy code should be blamed on the embassy line,
    which is the frame a human would want to look at.
    """
    if not addrs:
        return {}
    out = subprocess.run(
        [os.path.join(os.environ.get("LLVM_BIN", ""), "llvm-symbolizer"),
         "--obj=" + elf_path, "--inlining=true", "--demangle"],
        # measure.py's addresses are bare hex; llvm-symbolizer reads an
        # unprefixed number as DECIMAL and silently resolves the wrong address.
        input="\n".join("0x" + a for a in addrs),
        capture_output=True, text=True).stdout
    res = {}
    for addr, block in zip(addrs, [b for b in out.split("\n\n") if b.strip()]):
        frames = []
        lines = block.strip().splitlines()
        for i in range(1, len(lines), 2):        # symbol, location, symbol, ...
            path, _, rest = lines[i].rpartition(":")
            path, _, ln = path.rpartition(":")
            # llvm-symbolizer prints `??:0:0` for a frame it cannot resolve.
            if path and path != "??":
                frames.append((path, int(ln) if ln.isdigit() else 0))
        pick = (next((f for f in frames if not f[0].startswith("/rustc/")), None)
                or (frames[0] if frames else ("", 0)))
        res[addr] = pick
    return res


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    elf_path = sys.argv[1]
    check = (sys.argv[sys.argv.index("--check") + 1]
             if "--check" in sys.argv else None)

    calls, _ = measure.panics(elf_path)
    elf = Elf(elf_path)
    locs = locations(elf_path, elf)

    missing = [a for a, _, _ in calls if a not in locs]
    locs.update(dwarf(elf_path, missing))

    # Paths in Location strings are absolute, as rustc saw them.  Strip the
    # build tree so rows read `third_party/xarxa/src/wire/udp.rs`, the form every
    # consumer of this file already expects.  Registry and /rustc/ paths are
    # outside the tree and stay absolute.
    # The ELF lives at <root>/examples/<board>/target/..., so the build tree is
    # what precedes /examples/ in its own path.  Both the path as given and its
    # realpath are tried, because rustc recorded whichever it was invoked with
    # and on macOS /tmp and /private/tmp are the same directory.
    roots = {p.rsplit("/examples/", 1)[0] + "/"
             for p in (os.path.abspath(elf_path), os.path.realpath(elf_path))
             if "/examples/" in p}
    # cargo builds the example crate with its own directory as the working
    # directory, so rustc recorded that crate's files by a RELATIVE path while
    # every path dependency got an absolute one.  Put the relative ones back
    # where they belong, so a row reads examples/nrf52840/src/bin/... as before.
    example = os.path.abspath(elf_path).rsplit("/target/", 1)[0]
    example = "examples/" + example.rsplit("/examples/", 1)[-1] + "/"

    rows = []
    for addr, _caller, sym in calls:
        path, line = locs.get(addr, ("", 0))
        for root in roots:
            if path.startswith(root):
                path = path[len(root):]
                break
        else:
            if path and not path.startswith("/"):
                path = example + path
        rows.append((path, line, sym, "0x" + addr))
    rows.sort(key=lambda r: int(r[3], 16))
    for path, line, sym, addr in rows:
        print(f"{path}\t{line}\t{sym}\t{addr}")

    resolved = len(calls) - len(missing)
    print(f"{elf_path}: {len(calls)} sites, {resolved} located from "
          f"core::panic::Location, {len(missing)} from DWARF", file=sys.stderr)
    noline = sum(1 for r in rows if r[1] == 0)
    if noline:
        print(f"  {noline} sites still have no line", file=sys.stderr)

    if check:
        d = json.load(open(check))
        mine = sorted(a for a, _, _ in calls)
        theirs = sorted(a for a, _, _ in d["sites"])
        if mine != theirs:
            n = len(set(mine) ^ set(theirs))
            print(f"  WARNING: {check} lists {len(theirs)} sites and this ELF has "
                  f"{len(mine)}, differing at {n} addresses. They are different "
                  f"builds; do not compare numbers derived from the two.",
                  file=sys.stderr)


if __name__ == "__main__":
    main()
