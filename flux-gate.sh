#!/usr/bin/env bash
# The merge gate. Exit 0 = every panic we already removed is justified.
#
#   ./flux-gate.sh              gate the working tree
#   ./flux-gate.sh <ref>        gate a branch
#   ./flux-gate.sh --grade <ref>...   grade branches against their merge-base
#
# Runs under `default_trusted = false` + `no_panic = false`, so every body in the
# crate is checked and no trusted caller can absorb an obligation. Fails ONLY on
# a gate whose enclosing fn cannot be proved -- i.e. a runtime check that is
# already gone with a justification that does not hold. Everything else (the
# ~200 remaining `assertion might fail`) is a panic not yet removed, not a bug.
#
# Requires: `cargo flux` on PATH and a sibling `../flux` checkout (Cargo.toml
# carries `flux-rs = { path = "../flux/lib/flux-rs" }`).
set -euo pipefail
cd "$(dirname "$0")"
if [ "${1:-}" = "--grade" ]; then shift; exec python3 tools/flux_audit.py "$@"; fi
exec python3 tools/flux_audit.py --gate "${1:-HEAD}"
