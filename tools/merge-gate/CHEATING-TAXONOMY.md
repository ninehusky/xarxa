# What counts as cheating

The criterion, from `ninehusky/xarxa` issue #16. It supersedes any byte-based rule.

> If the no-panic condition **is provable** and you need to alter the code to make that
> condition **visible** to Flux — that is OK.
> Changing the **semantics** so the panic condition cannot arise — that is cheating.

Ranjit's rule, same thing from the other side: **verification cannot remove a panic you
cannot prove.**

The test: **would a user observe any difference?** If yes, it is cheating even if every
Flux check passes and the tests are green.

## The three buckets

Every behaviour-affecting edit lands in exactly one.

### (i) makes a provable fact visible

Same values, same bytes, no new branch. Fine. This class is signed off **broadly, not
narrowly** — it is not limited to annotations:

- adding a `requires`; changing a signature; splitting a function so a precondition is
  statable
- hoisting a byte out of a buffer into a refined field so Flux can track it
- adding ghost/refinement parameters (`#[refined_by]`, `#[invariant]`, assoc refinements)
  — erased at runtime, cost nothing
- adding **real** fields to a struct to make a fact visible, e.g. caching a length or tag
  that was previously only derivable
- modelling a data structure in a richer sort — a `Map<int, bool>` ghost field for
  per-element occupancy, refining a type by a variant tag
- `let`-shadowing instead of `mut` reassignment; lifting a closure to a named `fn`;
  binding a value once instead of reading it through `&mut` twice

Representation changes are the shape of progress. Reporting a wall instead is the worse
outcome.

### (ii) semantics change — CHEATING. Lead with it.

- a guard, a clamp, a silent truncation
- a branch that drops a packet where a value would have panicked
- widening a type to make a bad input unrepresentable when that input really does arrive
  off the wire
- weakening an assertion so it no longer checks the thing it was checking
- turning a documented panic into a different observable behaviour

### (iii) new path proved, old panicking path still public and reachable

Not cheating, but the honest claim is **"unreached from inside the crate,"** not
"removed." The original stays `pub`, still carries its assumption, still panics — its
callers just moved.

**This is the bucket that gets missed, because it looks like success.** A PR that adds
`_with_*` sibling functions and reports no (iii) rows did not look for them.

## Related traps

- **Obligation erasure.** A `trusted` helper with **no `requires`** does not move the
  obligation to a caller — it deletes it. A trusted function must state a precondition or
  explicitly justify why none is needed.
- **Boundary vs internal assumption.** A precondition a *caller owes* (`TxToken::consume`)
  is legitimate, and the panic above it is removable. A `trusted` assertion a function
  makes *about itself*, that nobody owes (`ip_mtu`'s `20 <= v`), evaporates.
- **Real field cost.** A ghost field is free. A real field costs bytes, shows up as
  `B - A != 0`, and must be reported separately from the verification result `C - B` —
  never rolled into it. If it must be maintained, say in one sentence what keeps it in
  sync and confirm every mutation path updates it.
- **A new `requires` is not itself cheating.** Pushing an obligation caller-ward is the
  mechanism of bottom-up proof. The cheat is the conjunction: an existing runtime check
  removed, a `requires` added in its place, and nothing discharging it. A partial proof
  keeps the check (or leaves the caller panicking) and records the obligation.
