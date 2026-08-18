#!/usr/bin/env python3
"""Measure one linked ELF: section sizes, panic call sites, panicking functions.

    ./measure.py <elf> <out-prefix>

Writes <out-prefix>.json plus three plain-text dumps you can read to check the
classification by hand.  Nothing here is committed; ./run.py regenerates it.

The two commands it shells out to are the only source of truth:

    $LLVM_BIN/llvm-size -A <elf>
    $LLVM_BIN/llvm-objdump -d --demangle <elf>

Definitions
-----------
panic symbol
    A function symbol whose demangled name matches PANIC_RE below: the panic
    entry points in core, the #[panic_handler], and defmt/panic-probe's.  The
    list is spelled out rather than matched on the substring "panic", because
    (a) several entry points do not contain the word -- core::option::
    unwrap_failed, core::slice::index::slice_index_fail -- and (b) ordinary
    library code does, e.g. xarxa's HardwareAddress::ethernet_or_panic, which
    is a normal function that happens to panic, not part of the machinery.
    To check the list is still complete for a given ELF, run:

        llvm-nm --demangle <elf> | grep -iE 'panic|unwind|_fail'

panic call site
    One branch instruction in the disassembly whose target is a panic symbol,
    where the function containing the branch is NOT itself a panic symbol.
    The exclusion matters: core::panicking::panic calls panic_fmt calls
    rust_begin_unwind, and counting those would measure the size of the panic
    machinery rather than the number of places ordinary code can enter it.

    BRANCH_RE accepts tail calls and conditional branches as well as `bl`.
    Measured on this firmware, every panic entry is in fact a plain `bl` -- see
    `unmatched_panic_refs` below, which is how you would find out if that ever
    stopped being true.

panicking function
    A function containing at least one panic call site.  Counted once no
    matter how many panic call sites it has.  A wrapper like ethernet_or_panic
    shows up here, via the branch to core::panicking::panic inside it.

    This is call-graph depth 1: the function holding the branch, not everything
    that can reach a panic transitively.  A panic behind a function pointer
    shows up as its callee being a panicking function, not as a call site in
    the indirect caller.

unmatched_panic_refs
    Coverage self-check.  Any instruction that mentions a panic symbol but was
    NOT counted as a call site -- an indirect call, a linker veneer, a
    PC-relative load taking a panic function's address.  Expected to be empty;
    if it is not, the call-site count is missing those and the JSON says so
    rather than silently undercounting.
"""

import json
import os
import re
import subprocess
import sys

PANIC_RE = re.compile(
    r"^(?:__rustc::)?rust_begin_unwind$"                        # the #[panic_handler]
    r"|^core::panicking::"                                      # panic, panic_fmt,
                                                                # panic_bounds_check,
                                                                # panic_const::*, assert_failed
    r"|^core::cell::panic_already_"                             # RefCell
    r"|^core::(?:option|result)::(?:unwrap_failed|expect_failed)$"
    r"|^core::slice::index::slice_index_fail$"
    r"|^core::slice::copy_from_slice_impl::len_mismatch_fail$"
    r"|^(?:_|__)defmt_(?:default_)?panic$"
    r"|^panic_probe::"
)

# Sections that occupy flash.  .data is in both lists: it is stored in flash and
# copied into RAM at startup.  .bss and .uninit are RAM only; .debug_*, .defmt,
# .comment and .ARM.attributes are not loaded at all.
FLASH_SECTIONS = (".vector_table", ".text", ".rodata", ".gnu.sgstubs", ".data")
RAM_SECTIONS = (".data", ".bss", ".uninit")

# `<addr> <name>:` -- start of a function in llvm-objdump output.
FUNC_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")
# The instruction mnemonic is the first token that is not part of the hex
# encoding; thumb encodings print as 4- or 8-digit groups.
ENCODING_RE = re.compile(r"^[0-9a-f]{4}(?:[0-9a-f]{4})?$")
# b / bl / blx / conditional branches, optionally .n or .w suffixed.  `bx` and
# `blx <reg>` are deliberately absent: they have no symbolic target to match.
BRANCH_RE = re.compile(
    r"^b(l|lx|eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?(\.[nw])?$"
)
# The branch target symbol, printed last on the instruction: `bl 0x1234 <name>`.
# `.+` rather than `[^>]+` because demangled names contain angle brackets
# themselves (`<T as Trait>::f`); the trailing `@ imm = #0x123` comment that
# llvm-objdump appends is stripped off first, by COMMENT_RE.
TARGET_RE = re.compile(r"<(.+)>\s*$")
COMMENT_RE = re.compile(r"\s+@\s")
# Any `<symbol>` anywhere on the line, including inside llvm-objdump's trailing
# comment -- that is where a PC-relative load shows what it is loading.
ANY_SYMBOL_RE = re.compile(r"<([^<>]+)>")


def llvm(tool, *args):
    exe = os.path.join(os.environ.get("LLVM_BIN", ""), tool)
    return subprocess.run([exe, *args], capture_output=True, text=True, check=True).stdout


def crate_of(sym):
    """Crate that owns a demangled symbol: the first segment of its path.

        <xarxa::wire::ipv4::Packet<&[u8]>>::src_addr        -> xarxa
        core::slice::index::slice_index_fail                -> core
        <&core::net::ip_addr::Ipv4Addr as ..Display>::fmt   -> core
        <core::iter::..Map<..xarxa::iface::route::Route..>>::fold -> core

    Note the last one: a core iterator adapter instantiated with xarxa types is
    core's code, so it is counted as core.  Grouping is by whose source the
    branch is in, which is why this only ever groups the list -- it never
    affects a count, and blame.py resolves real source files from DWARF.
    """
    name = sym.lstrip("<&*( ")
    head = name.split("::", 1)[0].strip()
    return head if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", head) else "(no path)"


def sections(elf):
    """llvm-size -A output -> ({section name: size in bytes}, total from Total:)."""
    out, total = {}, 0
    for line in llvm("llvm-size", "-A", elf).splitlines():
        f = line.split()
        if len(f) >= 2 and f[0].startswith(".") and f[1].isdigit():
            out[f[0]] = int(f[1])
        elif len(f) == 2 and f[0] == "Total" and f[1].isdigit():
            total = int(f[1])
    return out, total


def panics(elf):
    """Walk the disassembly once.

    Returns (calls, unmatched) where calls is a list of
    (address, calling function, panic symbol) and unmatched is the coverage
    self-check described in the module docstring.
    """
    calls, unmatched = [], []
    func = None
    for raw in llvm("llvm-objdump", "-d", "--demangle", elf).splitlines():
        m = FUNC_RE.match(raw.strip())
        if m:
            func = m.group(1)
            continue
        if func is None or ":" not in raw:
            continue
        if PANIC_RE.search(func):  # panic machinery calling itself; not an entry
            continue
        line = COMMENT_RE.split(raw, 1)[0]
        addr, rest = line.split(":", 1)
        tokens = [t for t in rest.split() if not ENCODING_RE.match(t)]
        if not tokens:
            continue
        target = TARGET_RE.search(line)
        if target and PANIC_RE.search(target.group(1)) and BRANCH_RE.match(tokens[0]):
            calls.append((addr.strip(), func, target.group(1)))
            continue
        # Not counted.  If the instruction mentions a panic symbol anyway --
        # in its operands or in llvm-objdump's trailing comment -- record it.
        for sym in ANY_SYMBOL_RE.findall(raw):
            if PANIC_RE.search(sym):
                unmatched.append({"addr": f"0x{addr.strip()}", "function": func,
                                  "mnemonic": tokens[0], "references": sym})
                break
    return calls, unmatched


def main():
    elf, prefix = sys.argv[1], sys.argv[2]
    calls, unmatched = panics(elf)
    secs, total_elf = sections(elf)

    callers = sorted({c for _, c, _ in calls})
    targets, fns_by_crate, sites_by_crate = {}, {}, {}
    for _, c, t in calls:
        targets[t] = targets.get(t, 0) + 1
        k = crate_of(c)
        sites_by_crate[k] = sites_by_crate.get(k, 0) + 1
    for c in callers:
        k = crate_of(c)
        fns_by_crate[k] = fns_by_crate.get(k, 0) + 1

    data = {
        "elf": elf,
        "sections": secs,
        # total_flash is what gets programmed onto the device.  total_elf is the
        # whole file including DWARF, which `debug = 2` makes ~45x larger -- it
        # is here so the number in `llvm-size -A`'s Total row is explained.
        "total_flash": sum(secs.get(s, 0) for s in FLASH_SECTIONS),
        "total_ram": sum(secs.get(s, 0) for s in RAM_SECTIONS),
        "total_elf": total_elf,
        "panic_call_sites": len(calls),
        "panicking_function_count": len(callers),
        # Grouped by the crate whose code holds the branch.  The site counts are
        # the ones to compare across builds: they show whether any crate gained
        # panics, which the function lists cannot, because inlining moves a
        # branch between symbols without changing how many panics exist.
        "panic_sites_by_crate": dict(sorted(sites_by_crate.items(), key=lambda kv: -kv[1])),
        "panicking_functions_by_crate": dict(sorted(fns_by_crate.items(), key=lambda kv: -kv[1])),
        "panicking_functions": callers,
        "panic_targets": dict(sorted(targets.items(), key=lambda kv: -kv[1])),
        "unmatched_panic_refs": unmatched,
        # [address, calling function, panic symbol] per site.
        "sites": [[a, c, t] for a, c, t in calls],
    }
    with open(prefix + ".json", "w") as f:
        json.dump(data, f, indent=2)

    with open(prefix + ".sections.txt", "w") as f:
        f.write(llvm("llvm-size", "-A", elf))
    with open(prefix + ".panicking-functions.txt", "w") as f:
        f.write("\n".join(callers) + "\n")
    # One row per call site.  The direction is caller -> callee: the function
    # holding the branch, then the panic symbol it branches to.
    with open(prefix + ".panic-call-sites.txt", "w") as f:
        f.write("address\tcalling_function\tpanic_symbol\n")
        f.write("\n".join(f"0x{a}\t{c}\t{t}" for a, c, t in sorted(calls)) + "\n")

    warn = f"  WARNING {len(unmatched)} unmatched panic refs" if unmatched else ""
    print(f"{elf}: {len(calls)} panic call sites in {len(callers)} functions{warn}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
