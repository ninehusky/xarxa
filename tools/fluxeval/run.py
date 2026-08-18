#!/usr/bin/env python3
"""Build the nRF52840 `usb_ethernet` example twice and measure both ELFs.

    ./run.py                          # upstream vs ninehusky/embassy main
    ./run.py --xarxa ~/research/xarxa # ...but with your local xarxa, edits and all
    ./run.py --modified-rev <sha>     # ...pinned to a specific embassy commit

Clones and cargo target dirs go in ./work (gitignored, ~2 GB); measurements go
in ./results, which is also gitignored -- rerun this to regenerate them.

The two configurations
----------------------
baseline
    Upstream embassy at BASE_REV, the commit ninehusky/embassy was forked from.
    Deliberately pinned rather than tracking upstream main: it is the point the
    fork diverged from, so holding it fixed is what makes the delta attributable
    to the fork.  Its embassy-net/Cargo.toml pins upstream xarxa as a git
    dependency, so cargo fetches the matching xarxa on its own.

modified
    ninehusky/embassy, by default whatever `main` points at right now, resolved
    at run time so nothing here has to be edited when the fork moves.  The
    resolved SHA is written to results/refs.txt, so the inputs float but the
    record of what was measured does not.  That checkout records ninehusky/xarxa
    as the third_party/xarxa submodule pin, and `git submodule update --init`
    is what selects it -- unless --xarxa overrides it with a local checkout.
"""

import argparse
import os
import shutil
import subprocess
import sys

BASE_URL = "https://github.com/embassy-rs/embassy"
BASE_REV = "7c2eac8a1450dbfbcc138a03c79aef4b880aff7b"
MOD_URL = "https://github.com/ninehusky/embassy"
MOD_BRANCH = "main"

# Identical for both builds.  1.97 is what both repos' rust-toolchain.toml asks
# for; naming it explicitly stops either build drifting onto another toolchain.
TOOLCHAIN = "1.97"
TARGET = "thumbv7em-none-eabi"
EXAMPLE_DIR = "examples/nrf52840"
BIN = "usb_ethernet"

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get("WORK", os.path.join(HERE, "work"))
RESULTS = os.path.join(HERE, "results")


def run(cmd, cwd=None, quiet=False, **kw):
    return subprocess.run(cmd, cwd=cwd, check=True, text=True,
                          stdout=subprocess.DEVNULL if quiet else None, **kw)


def out(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, text=True,
                          capture_output=True).stdout.strip()


def llvm_bin():
    """The llvm-tools shipped with the same toolchain that compiles the ELFs."""
    host = next(l.split()[1] for l in out(["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
                if l.startswith("host:"))
    sysroot = out(["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"])
    return os.path.join(sysroot, "lib", "rustlib", host, "bin")


def resolve(url, branch):
    """SHA that `branch` points at right now, without cloning."""
    return out(["git", "ls-remote", url, f"refs/heads/{branch}"]).split()[0]


def checkout(name, url, rev):
    """Fetch exactly `rev` into work/<name> and check it out. Returns the path."""
    d = os.path.join(WORK, name)
    if not os.path.isdir(os.path.join(d, ".git")):
        os.makedirs(d, exist_ok=True)
        run(["git", "init", "-q", d])
        run(["git", "remote", "add", "origin", url], cwd=d)
    run(["git", "fetch", "-q", "--depth", "1", "origin", rev], cwd=d)
    run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=d)
    # No-op for the upstream checkout (it has no submodules); for the fork this
    # is what pulls in third_party/xarxa and third_party/flux at their pins.
    run(["git", "submodule", "update", "--init", "-q"], cwd=d)
    apply_benchmark_config(d)
    return d


# --- LOCAL, UNCOMMITTED: benchmark definition -------------------------------
# The nRF52840 usb_ethernet device is USB Ethernet (CDC-NCM). It never runs
# 802.15.4, but the example enabled `medium-ieee802154` anyway, which compiled
# xarxa's whole 6LoWPAN dispatch path into the image: ~143 panic sites and
# 23,780 bytes of flash that no verification work could ever be credited with.
#
# `checkout()` does `git checkout --detach FETCH_HEAD`, so editing the file by
# hand does not survive a run. Applying it here is what makes the benchmark
# reproducible.
#
# Nothing else about the build is touched -- no opt-level, lto, or
# codegen-units. The result is about panic verification, not Cargo tuning.
def apply_benchmark_config(repo):
    import re
    f = os.path.join(repo, "examples", "nrf52840", "Cargo.toml")
    if not os.path.isfile(f):
        return
    src = open(f).read()
    out = re.sub(r'("medium-ethernet","udp", )"medium-ieee802154", ', r'\1', src)
    if out != src:
        open(f, "w").write(out)
        print("   benchmark config: dropped medium-ieee802154")


def use_local_xarxa(repo, src):
    """Replace the third_party/xarxa submodule with a copy of a local checkout.

    Copies rather than symlinks so cargo sees a normal path dependency, and
    copies the working tree as-is -- uncommitted edits included, which is the
    entire point of --xarxa.  target/ and .git are skipped because they are
    large and cargo does not need them.
    """
    dst = os.path.join(repo, "third_party", "xarxa")
    shutil.rmtree(dst, ignore_errors=True)
    # copy_function=shutil.copy, NOT the copytree default copy2: copy2 preserves the
    # source mtimes, and cargo fingerprints path dependencies by mtime.  A checkout whose
    # files are not newer than the last build is silently treated as up to date, so the
    # run re-measures the PREVIOUS binary and reports a delta of exactly zero.
    shutil.copytree(src, dst, symlinks=True, copy_function=shutil.copy,
                    ignore=shutil.ignore_patterns(".git", "target"))


def build(repo):
    env = dict(os.environ, CARGO_INCREMENTAL="0")
    run(["cargo", f"+{TOOLCHAIN}", "build", "--release", "--bin", BIN,
         "--target", TARGET], cwd=os.path.join(repo, EXAMPLE_DIR), env=env)
    return os.path.join(repo, EXAMPLE_DIR, "target", TARGET, "release", BIN)


def describe_xarxa(repo, local):
    if local:
        dirty = out(["git", "status", "--porcelain"], cwd=local)
        return (f"local {local} @ {out(['git', 'rev-parse', 'HEAD'], cwd=local)}"
                f"{' (DIRTY: uncommitted edits included)' if dirty else ''}")
    sub = os.path.join(repo, "third_party", "xarxa")
    return f"https://github.com/ninehusky/xarxa @ {out(['git', 'rev-parse', 'HEAD'], cwd=sub)}"


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--xarxa", metavar="PATH",
                   help="build the modified config against this local xarxa checkout "
                        "instead of the submodule pin (uncommitted edits included)")
    p.add_argument("--modified-rev", metavar="SHA",
                   help=f"pin the modified embassy instead of tracking {MOD_BRANCH}")
    args = p.parse_args()

    os.environ["LLVM_BIN"] = llvm_bin()
    os.makedirs(RESULTS, exist_ok=True)
    local_xarxa = os.path.abspath(os.path.expanduser(args.xarxa)) if args.xarxa else None
    if local_xarxa and not os.path.isdir(os.path.join(local_xarxa, "src")):
        sys.exit(f"--xarxa {local_xarxa} does not look like a xarxa checkout")

    mod_rev = args.modified_rev or resolve(MOD_URL, MOD_BRANCH)

    print(f"== baseline: upstream embassy {BASE_REV[:12]} + upstream xarxa")
    base_repo = checkout("baseline", BASE_URL, BASE_REV)
    base_elf = build(base_repo)

    print(f"== modified: ninehusky/embassy {mod_rev[:12]}"
          f"{' + local xarxa ' + local_xarxa if local_xarxa else ''}")
    mod_repo = checkout("modified", MOD_URL, mod_rev)
    if local_xarxa:
        use_local_xarxa(mod_repo, local_xarxa)
    mod_elf = build(mod_repo)

    print("== measuring")
    for elf, name in ((base_elf, "baseline"), (mod_elf, "modified")):
        run([sys.executable, os.path.join(HERE, "measure.py"), elf,
             os.path.join(RESULTS, name)])

    # Record what was actually built.  The baseline xarxa rev is read out of
    # upstream's own Cargo.toml rather than duplicated here.
    base_xarxa = next(
        (l.split('"')[1] for l in open(os.path.join(base_repo, "embassy-net/Cargo.toml"))
         if "rev = " in l), "?")
    refs = "\n".join([
        f"toolchain {TOOLCHAIN}   target {TARGET}   profile release   bin {BIN}",
        f"baseline  embassy {BASE_URL} @ {BASE_REV}",
        f"baseline  xarxa   https://github.com/embassy-rs/xarxa @ {base_xarxa}",
        f"modified  embassy {MOD_URL} @ {mod_rev}",
        f"modified  xarxa   {describe_xarxa(mod_repo, local_xarxa)}",
    ]) + "\n"
    open(os.path.join(RESULTS, "refs.txt"), "w").write(refs)

    table = subprocess.run(
        [sys.executable, os.path.join(HERE, "compare.py"),
         os.path.join(RESULTS, "baseline.json"), os.path.join(RESULTS, "modified.json")],
        check=True, text=True, capture_output=True).stdout
    body = (f"# usb_ethernet, nRF52840: upstream vs ninehusky\n\n"
            f"Produced by `./run.py`. See ../README.md for what the numbers mean.\n\n"
            f"```\n{refs}```\n\n{table}")
    open(os.path.join(RESULTS, "RESULTS.md"), "w").write(body)
    print(body)


if __name__ == "__main__":
    main()
