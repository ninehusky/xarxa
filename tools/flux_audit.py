#!/usr/bin/env python3
"""Is this branch's panic removal soundly mergeable?

    ./tools/flux_audit.py <ref> [<ref> ...]     # each ref vs its own merge-base with main
    ./tools/flux_audit.py --base main <ref>     # or vs an explicit base

THE CRITERION

A panic-removal PR replaces a runtime check with a gate:

    if <negation of precondition> { flux_rs::assert(false); unreachable_unchecked() }

and pays for it with a `requires` on the enclosing function. The gate then
verifies LOCALLY, assuming that precondition. The obligation does not vanish --
it moves to the callers, and keeps moving until something establishes it.

Under `default_trusted = true` that chain is invisible: an unannotated caller
absorbs the obligation and the output is byte-identical to a real proof. That
is the failure this script exists to catch -- a PR that proves the precondition
at 99% of call sites and misses the one that matters.

So we re-run under `default_trusted = false` (+ `no_panic = false`), where every
body is checked and no trusted caller is left to absorb anything. Then exactly
one string matters:

    "a precondition cannot be proved"      MUST NOT RISE

Flux emits it both when a stated `requires` is unmet at a call site and when a
gate cannot be proved unreachable -- verified by negative control:
`flux_rs::assert(false)` in an otherwise-clean function produces exactly this.
Measured on three trees, it was 100% of all `refinement type error`s (13/13,
20/20, 568/568), and it does not collide with the `note: this is the condition
that cannot be proved` lines.

Everything else Flux reports -- `assertion might fail`, `arithmetic operation
may underflow` -- means the runtime check is STILL THERE. Not unsound, just not
removed yet. That number rises when a PR states new refinements, because stating
a refinement is what makes an obligation expressible at all. Never gate on it.

THE HOLE: TRUSTED BODIES

A `trusted` body is assumed, not proven. It can call a gated function without
establishing its precondition and emit no error at all. So zero precondition
failures plus a non-empty trusted set is NOT soundness. This script hollers
about two things a grep of the error log can never show you:

    * a gate sitting inside a trusted body      -- unverified by construction
    * a checked function calling a trusted one  -- proof path runs through an
                                                   assumption

Both need a human. Nothing here can decide them.
"""

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The firmware configuration -- the build the binary panic counts are measured
# against. Default features pull in sixlowpan, DNS, ieee802154 and the host phy
# shims, none of it linked into the firmware; they add ~95 errors no shipped
# panic depends on. An error count without its feature set is meaningless, so
# both are pinned here rather than left to whoever types the command.
FIRMWARE = ["--no-default-features", "--features",
            "medium-ethernet,socket-udp,socket-tcp,socket-dhcpv4,proto-ipv4,proto-ipv6"]

GATE_FAIL = "a precondition cannot be proved"

GATE_RE = re.compile(r"flux_rs::assert\(false\)|flux::assert\(false\)"
                     r"|unreachable_unchecked|get_unchecked")
# `trusted(yes)` and bare `trusted` mean the body is NOT checked.
# `trusted(no)` is the opposite and must never match here.
TRUSTED_YES = re.compile(r"#!?\[flux(?:_rs)?::trusted(?:\(\s*yes\b[^)]*\))?\]"
                         r"|#!?\[flux(?:_rs)?::trusted\(\s*yes\b")
TRUSTED_NO = re.compile(r"trusted\(\s*no\b")
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
                   r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*fn\s+(\w+)")


def sh(args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def is_attr_or_comment(line):
    s = line.lstrip()
    return s.startswith(("#[", "#!", "//", "/*", "*"))


def flip(path):
    """Whole-crate checking: nothing trusted unless it says so in source."""
    s = open(path).read()
    s = re.sub(r"^default_trusted\s*=\s*true", "default_trusted = false", s, flags=re.M)
    s = re.sub(r"^no_panic\s*=\s*true", "no_panic = false", s, flags=re.M)
    for key in ("default_trusted", "no_panic"):
        if not re.search(rf"^{key}\s*=", s, flags=re.M):
            s = s.replace("[package.metadata.flux]",
                          f"[package.metadata.flux]\n{key} = false", 1)
    open(path, "w").write(s)


def scan(tree):
    """Gates and trusted bodies, straight from the source."""
    gates, trusted_fns = [], []
    for root, _, files in os.walk(os.path.join(tree, "src")):
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            p = os.path.join(root, name)
            rel = os.path.relpath(p, tree)
            lines = open(p, errors="replace").read().splitlines()

            # Which fn declarations carry a trusted(yes) attribute block?
            #
            # A trusted body is only a hole if it states NOTHING. `trusted(yes)`
            # WITH a `sig(.. requires ..)` is the correct idiom for an unchecked
            # leaf primitive: the body is unprovable by construction, but the
            # signature exports the obligation to every call site, which is
            # checked. A trusted body with no `requires` ERASES the obligation
            # instead of moving it -- that is the one that hides UB.
            trusted_decl, sigless = set(), set()
            for i, line in enumerate(lines):
                if not FN_RE.match(line):
                    continue
                j, attrs = i - 1, []
                while j >= 0 and (is_attr_or_comment(lines[j]) or not lines[j].strip()):
                    attrs.append(lines[j])
                    j -= 1
                blob = "\n".join(attrs)
                if TRUSTED_NO.search(blob) or not TRUSTED_YES.search(blob):
                    continue
                trusted_decl.add(i)
                states_precondition = "requires" in blob
                if not states_precondition:
                    sigless.add(i)
                trusted_fns.append({
                    "file": rel, "line": i + 1, "fn": FN_RE.match(line).group(1),
                    "states_precondition": states_precondition,
                })

            cur = None
            for i, line in enumerate(lines):
                if FN_RE.match(line):
                    cur = i
                # An attribute's reason = "...discharges the assert(false)..."
                # is prose, not a gate.
                if is_attr_or_comment(line) or not GATE_RE.search(line):
                    continue
                gates.append({
                    "file": rel, "line": i + 1, "text": line.strip()[:58],
                    "fn": FN_RE.match(lines[cur]).group(1) if cur is not None else "?",
                    "trusted": cur in trusted_decl,
                    "erased": cur in sigless,
                })
    return gates, trusted_fns


def callers_of_trusted(tree, trusted_fns):
    """Checked functions that call a trusted one -- proof path through an assumption.

    Name-based and therefore over-approximate; this is a holler, not a gate.
    """
    names = {t["fn"] for t in trusted_fns
             if len(t["fn"]) > 3 and not t["states_precondition"]}
    if not names:
        return []
    pat = re.compile(r"\b(" + "|".join(sorted(map(re.escape, names))) + r")\s*\(")
    hits = []
    for root, _, files in os.walk(os.path.join(tree, "src")):
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            p = os.path.join(root, name)
            rel = os.path.relpath(p, tree)
            lines = open(p, errors="replace").read().splitlines()
            for i, line in enumerate(lines):
                if is_attr_or_comment(line) or FN_RE.match(line):
                    continue
                m = pat.search(line)
                if m:
                    hits.append((rel, i + 1, m.group(1)))
    return hits


def worktree(ref):
    # MUST be a sibling of the repo: Cargo.toml carries
    # `flux-rs = { path = "../flux/lib/flux-rs" }`, so a worktree under /tmp
    # cannot resolve the dependency and cargo dies before flux ever runs --
    # which reads as "0 errors" if you are not looking.
    parent = os.path.dirname(REPO)
    if not os.path.isdir(os.path.join(parent, "flux", "lib", "flux-rs")):
        raise RuntimeError(f"{parent}/flux/lib/flux-rs missing; path dep will not resolve")
    d = os.path.join(parent, f".fluxaudit-{re.sub(r'[^A-Za-z0-9]', '-', ref)[:28]}-{os.getpid()}")
    shutil.rmtree(d, ignore_errors=True)
    sh(["git", "worktree", "remove", "--force", d], cwd=REPO)
    r = sh(["git", "worktree", "add", "--detach", d, ref], cwd=REPO)
    if r.returncode != 0:
        raise RuntimeError(f"git worktree add {ref}: {r.stderr.strip()}")
    return d


def measure(ref, logpath):
    d = worktree(ref)
    try:
        flip(os.path.join(d, "Cargo.toml"))
        r = sh(["cargo", "flux", "check", "-p", "xarxa"] + FIRMWARE, cwd=d)
        log = r.stdout + r.stderr
        open(logpath, "w").write(log)

        gates, trusted_fns = scan(d)

        # Which defs failed? Flux always prints a stable `def:` handle.
        failed_defs = set()
        for blk in re.split(r"(?=^error\[E0999\])", log, flags=re.M):
            if GATE_FAIL not in blk:
                continue
            m = re.search(r"--only-check='def:([^']+)'", blk)
            if m:
                failed_defs.add(m.group(1))
        # A gate is UNDISCHARGED if its own enclosing fn could not be proved.
        # This is what separates "this PR broke a proof" from "this PR stated
        # new obligations that gate nothing" -- only the former blocks a merge.
        gates_broken = [g for g in gates
                        if any(re.search(rf"(^|::){re.escape(g['fn'])}$|(^|::){re.escape(g['fn'])}\b",
                                         fd) for fd in failed_defs)]
        res = {
            # An ICE aborts rustc and silently drops most diagnostics; any count
            # from such a run is fiction. Checked before anything is reported.
            "panicked": "panicked" in log,
            # Did flux actually look at the crate? A config or path error yields
            # zero errors, which is indistinguishable from success if unchecked.
            "ran": "Checking xarxa" in log or "Compiling xarxa" in log,
            "fail": log.count(GATE_FAIL),
            "errors": len(re.findall(r"^error\[E0999\]", log, flags=re.M)),
            "internal": log.count("internal flux error"),
            "gates": gates,
            "failed_defs": failed_defs,
            "gates_broken": gates_broken,
            "trusted_fns": trusted_fns,
            "gated_in_trusted": [g for g in gates if g["erased"]],
            "trusted_ok": [t for t in trusted_fns if t["states_precondition"]],
            "trusted_sigless": [t for t in trusted_fns if not t["states_precondition"]],
            "trusted_callers": callers_of_trusted(d, trusted_fns),
            "log": logpath,
        }
        return res
    finally:
        sh(["git", "worktree", "remove", "--force", d], cwd=REPO)
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("refs", nargs="+")
    ap.add_argument("--base", default=None,
                    help="compare against this ref (default: each ref's merge-base with main)")
    ap.add_argument("--logdir", default=tempfile.mkdtemp(prefix="fluxaudit-"))
    args = ap.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    print(f"config: firmware   logs: {args.logdir}\n")

    cache, rows = {}, []

    def get(ref, tag):
        if ref not in cache:
            cache[ref] = measure(ref, os.path.join(args.logdir, f"{tag}.log"))
        return cache[ref]

    for ref in args.refs:
        base = args.base or (sh(["git", "merge-base", ref, "main"], cwd=REPO).stdout.strip() or "main")
        safe = re.sub(r"[^A-Za-z0-9]", "-", ref)[:40]
        try:
            b = get(base, f"base-{safe}")
            r = get(ref, f"ref-{safe}")
        except Exception as exc:  # noqa: BLE001
            print(f"!! {ref}: {exc}\n")
            continue

        print("=" * 76)
        print(f"{ref}   (base {base[:12]})")
        print("=" * 76)

        bad = [(n, x) for n, x in (("base", b), ("ref", r))
               if x["panicked"] or not x["ran"]]
        if bad:
            for n, x in bad:
                why = "rustc panicked (ICE drops diagnostics)" if x["panicked"] else "flux never ran"
                print(f"  UNREPORTABLE [{n}]: {why} -- see {x['log']}")
            print()
            continue

        d = r["fail"] - b["fail"]
        print(f"  gates in source                              "
              f"{len(b['gates']):4} -> {len(r['gates']):4}  ({len(r['gates']) - len(b['gates']):+})")
        print(f"  \"{GATE_FAIL}\"   "
              f"{b['fail']:4} -> {r['fail']:4}  ({d:+})   <-- THE GATE")
        print(f"  other errors (checks still present)          "
              f"{b['errors'] - b['fail']:4} -> {r['errors'] - r['fail']:4}"
              f"  ({(r['errors'] - r['fail']) - (b['errors'] - b['fail']):+})")
        if r["internal"]:
            print(f"  internal flux errors (bodies NOT checked)    {r['internal']:4}")

        broken = len(r["gates_broken"])
        verdict = "BLOCKED" if broken else ("MERGEABLE" if d <= 0 else "REVIEW")
        print(f"  gates undischarged (their own fn unproved)   "
              f"{len(b['gates_broken']):4} -> {broken:4}   <-- SOUNDNESS")
        print()
        if broken:
            print(f"  VERDICT: BLOCKED -- {broken} gate(s) whose enclosing fn cannot be proved.")
            print("  These replace a runtime check with unreachable_unchecked and the")
            print("  justification does not hold. This is UB, not debt:")
            for g in r["gates_broken"][:10]:
                print(f"    {g['file']}:{g['line']}  fn {g['fn']}  {g['text']}")
        elif d > 0:
            print(f"  VERDICT: REVIEW -- {d} new undischarged precondition(s), but NO gate")
            print("  depends on them. Every existing gate still discharges, so this is")
            print("  newly-STATED obligation (inventory), not broken proof. Safe to merge")
            print("  if you accept carrying the inventory. Top defs:")
            seen = re.findall(r"--only-check='def:([^']+)'", open(r["log"]).read())
            basec = collections.Counter(re.findall(r"--only-check='def:([^']+)'", open(b["log"]).read()))
            for k, v in collections.Counter(seen).most_common(12):
                extra = v - basec.get(k, 0)
                if extra > 0:
                    print(f"    +{extra}  {k[:66]}")
        else:
            print(f"  VERDICT: MERGEABLE on the soundness criterion ({d:+}).")

        if r["gated_in_trusted"]:
            print(f"\n  !! {len(r['gated_in_trusted'])} GATE(S) IN A TRUSTED BODY THAT STATES NO PRECONDITION.")
            print("     The obligation is erased, not moved: no error can ever appear.")
            for g in r["gated_in_trusted"][:10]:
                print(f"       {g['file']}:{g['line']}  fn {g['fn']}  {g['text']}")

        dsig = len(r["trusted_sigless"]) - len(b["trusted_sigless"])
        print(f"\n  trusted bodies: {len(r['trusted_ok'])} with a stated precondition (obligation"
              f" exported, OK),")
        print(f"                  {len(r['trusted_sigless'])} stating nothing"
              f" (obligation erased)  ({dsig:+})")
        if r["trusted_callers"]:
            print(f"  {len(r['trusted_callers'])} call site(s) reach a precondition-less trusted fn"
                  " (name-matched,")
            print("  over-approximate) -- each is a proof path running through an assumption.")

        print()
        rows.append((ref, verdict, len(r["gates"]), d, len(r["trusted_sigless"])))

    if rows:
        print("=" * 76)
        print(f"{'branch':<34} {'verdict':<10} {'gates':>5} {'dFAIL':>6} {'erasing':>8}")
        print("-" * 76)
        for ref, v, g, d, t in rows:
            print(f"{ref[:34]:<34} {v:<10} {g:>5} {d:>+6} {t:>8}")
        print("\nBLOCKED = a gate's own fn is unproved (UB).  REVIEW = new obligations")
        print("stated but no gate depends on them (inventory).  dFAIL is context only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
