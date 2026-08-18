# fluxopt-evaluation

Builds the nRF52840 `usb_ethernet` example twice — against upstream
embassy + xarxa, and against the `ninehusky` forks — and diffs section sizes and
panic counts. Issue: ninehusky/fluxopt-evaluation#2.

## Run

```sh
./run.py                            # upstream vs ninehusky/embassy main
./run.py --xarxa ~/research/xarxa   # against a local xarxa, uncommitted edits included
./run.py --modified-rev <sha>       # pinned to one embassy commit
```

Needs rustup toolchain `1.97` with the `thumbv7em-none-eabi` target and
`llvm-tools`, plus network access. Clones and cargo target dirs go in `./work`
(~2 GB); measurements go in `./results`. Both are gitignored — rerun to
regenerate. Re-running reuses the clones.

## What it compares

**Baseline** is upstream embassy pinned at `7c2eac8a`, the commit
`ninehusky/embassy` branched from; that commit pins its own xarxa as a git
dependency. **Modified** is `ninehusky/embassy` `main`, resolved fresh on every
run, which pins `ninehusky/xarxa` as the `third_party/xarxa` submodule.

Baseline is pinned and modified floats on purpose: holding the fork point fixed
is what makes the delta attributable to the fork, and nothing here has to be
edited when the fork moves. Both resolved SHAs are written to
`results/refs.txt`. `--xarxa` is the one way to override the submodule; it flags
the checkout dirty in `refs.txt` if you have uncommitted edits.

Both repos ask for toolchain `1.97` and set `[profile.release] debug = 2`, so
the two builds run the same command with the same profile.

## Reading the results

`results/RESULTS.md` is the table; `results/*.json` has everything behind it.

**Sizes.** `total_flash` is what gets programmed onto the device. `total_ram` is
`.data + .bss + .uninit`. `total_elf` is the whole file including DWARF, which
`debug = 2` makes ~45× the firmware — it is reported only so the `Total` row in
`llvm-size -A` is not mistaken for the firmware size.

**Panics.** A *panic call site* is a branch into one of core's panic entry
points from code that is not itself panic machinery; that is the number to
compare across builds. A *panicking function* is a function containing at least
one such branch — call-graph depth 1, not everything that can reach a panic.

Compare builds using `panic_sites_by_crate`. The panicking-function *lists* move
around between builds because inlining decides which symbol holds a given
branch, so a function appearing on one side only is usually the same panic
attributed elsewhere, not one added or removed.

`unmatched_panic_refs` is a coverage check and should be `[]`. If it is not,
some instruction reaches a panic in a way the site count missed — an indirect
call, a linker veneer — and the count is an undercount. The JSON and the
comparison table both say so rather than being quietly wrong.

To check a classification by hand:

```sh
column -t -s $'\t' results/modified.panic-call-sites.txt   # address, caller, panic symbol
jq '.panic_targets' results/modified.json                  # which panic symbols matched
llvm-nm --demangle <elf> | grep -iE 'panic|unwind|_fail'   # is PANIC_RE still complete?
```

Each row of `panic-call-sites.txt` is one instruction, in the direction
caller → callee, findable at that address in `llvm-objdump -d --demangle`.

## Caveats

* The `.text` delta is small (−504 B) largely because 307 of the ~660 sites are
* The modified example additionally depends on `flux-rs` and sets
  `[package.metadata.flux]`. Plain `cargo build` does not run Flux and the
  attributes expand to nothing, but it is a real difference between the two
  `Cargo.toml`s.
* One build per side, no determinism check here. `sweep.py` does one.
