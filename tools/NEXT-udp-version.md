# Next: discharge `IpRepr::new`'s version precondition at `udp::Socket::dispatch`

Target: `src/socket/udp.rs:574`, the `refinement type error` in `flux.log:244`.

## Why this is not cosmetic

`IpRepr::new` (ip.rs:645) replaced upstream smoltcp's `panic!` with
`assert(false)` + `unreachable_unchecked`, licensed by
`fn(Address[@v], Address[v], ...)`. That precondition is undischarged at udp.rs:574,
so the UB is reachable from safe public API. Verified:

```rust
socket.bind(IpListenEndpoint { addr: Some(IpAddress::v4(192,168,1,1)), port: 53 })?;  // Ok
socket.send_slice(b"abcdef", IpEndpoint { addr: IpAddress::v6(0xfe80,0,0,0,0,0,0,2), port: 49500 })?;  // Ok
socket.dispatch(cx, |_,_,_| Ok::<_,()>(()));
// panicked at src/wire/ip.rs:672: hint::unreachable_unchecked must never be reached
```

Under `--release` there is no debug check. Land the regression test either way.

## The invariant

Not "one socket, one family" — `bind(port)` with `addr: None` is legitimately
dual-stack. The fields in play:

```
Socket<'a> {
    endpoint:  IpListenEndpoint { addr: Option<Address>, port: u16 },   // ip.rs:469
    tx_buffer: PacketBuffer<'a, UdpMetadata>,                           // udp.rs:120
}
UdpMetadata {                                                           // udp.rs:16
    endpoint:      IpEndpoint { addr: Address, port: u16 },   // the DESTINATION
    local_address: Option<IpAddress>,                         // the SOURCE, if pinned
}
```

"Bound to a specific address" = `self.endpoint.addr == Some(a)` on the
`IpListenEndpoint`. `bind(53)` gives `None`; `bind(IpListenEndpoint{addr: Some(a), ..})`
gives `Some(a)`.

### Derivation — one clause per branch

`dispatch` picks `src_addr` from one of three branches (udp.rs:544-561), then calls
`IpRepr::new(src_addr, e.endpoint.addr, ..)` for the dequeued element `e`. The
obligation is always `src_addr.ver == e.endpoint.addr.ver`:

| branch | `src_addr` | reached when | obligation | discharged by |
|---|---|---|---|---|
| A (544) | `e.local_address` unwrapped | `e.local_address.is_some()` | `l.ver == e.endpoint.addr.ver` | **clause 2** |
| B (548) | `self.endpoint.addr` unwrapped | A's guard false **and** `self.endpoint.addr == Some(a)` | `a.ver == e.endpoint.addr.ver` | **clause 1** |
| C (550) | `cx.get_source_address(&e.endpoint.addr)` | both none | — | free, from step 2's sig |

So:

| # | scope | statement |
|---|---|---|
| 1 | socket ↔ element, conditional | `self.endpoint.addr == Some(a)` ⟹ for every `tx_buffer` element `e`, `e.endpoint.addr.ver == a.ver` |
| 2 | per element | `e.local_address == Some(l)` ⟹ `l.ver == e.endpoint.addr.ver` |

Reading off the table:

- **Clause 2 never mentions the socket.** Branch A's source and destination both come
  from the *same element* — pure per-element well-formedness.
- **Clause 1 is conditional because branch B is.** Branch B is only reachable when
  `self.endpoint.addr == Some(a)`, the same test as clause 1's antecedent. A bare-port
  socket never enters branch B, so nothing is asked of it. Dual-stack falls out; it is
  not carved out.
- **Clause 1 relates the socket's bound address to each element's *destination*.** It
  does not touch `local_address`. Elements may still disagree with each other.

Neither clause narrows legitimate use — there is no IP packet with a v4 source and a
v6 destination. Supporting evidence: the RX path builds both fields from one `IpRepr`
(udp.rs:504-519), `From<T: Into<IpEndpoint>>` sets `local_address: None` (udp.rs:29-37),
and `tcp::connect` already returns `ConnectError::Unaddressable` on the same mismatch
(tcp.rs:1060).

### Established / consumed

| point | cost |
|---|---|
| `bind` | **free**. `bind` refuses when `is_open()` (223); `is_open()` is `port != 0` (257); `send` refuses when `self.endpoint.port == 0` (309); re-bind needs `close()`, which does `tx_buffer.reset()` (244). So `tx_buffer` is empty at every `bind` and clause 1 re-establishes vacuously. |
| `send` / `send_with` | the only enqueue points. Add a Flux precondition — **not** a runtime check. Conforming callers pay nothing; the obligation is exported to embassy-net, same shape as `check_hardware_addr`. |
| `dispatch` | consumes both clauses. Cannot take a precondition: its only non-test caller is `socket_egress` (mod.rs:772), which pulls sockets from a heterogeneous `SocketSet` and could never discharge one. |

## Step 0 — DONE, all four probes PASS

Probe crate (left in the all-pass state):
`/private/tmp/claude-501/-Users-andrew-research-xarxa-src-wire/43f19ad0-ac0c-4a34-8b3c-e1da88468fd7/scratchpad/probes`

| probe | result | working syntax |
|---|---|---|
| P1 | PASS, both positions | sig: `fn(&mut Buf<Meta{m: m.a == m.b}>)` · field: `#[flux_rs::field(Buf<Meta{m: m.a == m.b}>)]`. The enclosing struct must carry `#[flux_rs::refined_by(..)]` or rustc rejects the `field` attr outright. |
| P2 | PASS | unannotated generic `Buf<H>` preserves the refinement through `enqueue` → `peek`. |
| P3 | PASS | survives `dequeue_with`'s `FnOnce` — refinement flows into the closure param. **No peek-then-dequeue restructure needed.** |
| P4 | PASS, with a caveat | see below. |

Evidence: `assert(false)` canary planted in all 6 probe fns, all 6 failed. Negative
controls fail correctly — `S[true, 2]` and `S[false, 1]` are both rejected, so the
guard is not vacuous. `grep -c panicked` = 0 on every run. Final combined run:
`summary. 11 functions processed: 8 checked; 3 trusted; 0 ignored. 10 constraints solved.`

**P4's caveat, which lands on step 5.** Refinement params referenced from inside a
generic argument must be *value-determined*. The naive scaffold fails:

```
error[E0999]: parameter `ty` cannot be determined
```

Two fixes, both verified: (A) back the param with a real field
(`#[flux_rs::field(i32[ty])] ty: i32`), or (B) declare it horn-mode
(`#[flux_rs::refined_by(bound: bool, hrn ty: int)]`, no extra field). For `Socket`,
(A) is natural — the `endpoint: IpListenEndpoint` field determines both `bound` and
`addr_ty`.

### Original probe scaffold, for reference

`src/storage/` has **zero** Flux annotations. Clause 2 has to ride on `H` through
`PacketBuffer<'a, H>` and out of `dequeue_with`'s `FnOnce(&mut H, _)` callback
(packet_buffer.rs:183). Standalone file, no xarxa:

```rust
#[flux_rs::refined_by(a: int, b: int)]
struct Meta { #[flux_rs::field(i32[a])] a: i32, #[flux_rs::field(i32[b])] b: i32 }

struct Buf<H> { items: Vec<H> }                     // no annotations, mirrors PacketBuffer
impl<H> Buf<H> {
    fn enqueue(&mut self, h: H) { self.items.push(h) }
    fn dequeue_with<R, E, F>(&mut self, f: F) -> Result<R, E>
        where F: FnOnce(&mut H) -> Result<R, E> { f(&mut self.items[0]) }
}

#[flux_rs::sig(fn(i32[@x], i32[x]))] fn needs_eq(_: i32, _: i32) {}
```

| probe | question | needed for |
|---|---|---|
| P1 | Does `Buf<Meta{m: m.a == m.b}>` parse in a sig, and hold in a struct **field** position? | both clauses |
| P2 | Does an unannotated generic container preserve it? enqueue → get → `needs_eq(m.a, m.b)`. | both clauses |
| P3 | Does it survive `dequeue_with`'s closure? Same call, inside the `FnOnce`. | both clauses |
| P4 | Can a field's generic arg mention the **enclosing struct's own** refinement param? | clause 1 only |

P4 is the one that is easy to miss. Clause 2 only mentions the element, so it fits a
refined generic arg directly. Clause 1 mentions `self.endpoint.addr` — a *sibling
field* — so the target encoding is:

```rust
#[flux_rs::refined_by(bound: bool, addr_ty: int)]
pub struct Socket<'a> {
    #[flux_rs::field(IpListenEndpoint[bound, addr_ty])]
    endpoint: IpListenEndpoint,
    #[flux_rs::field(PacketBuffer<'a, UdpMetadata{m: (!m.has_local || m.local_ty == m.dst_ty)
                                                    && (!bound || m.dst_ty == addr_ty)}>)]
    tx_buffer: PacketBuffer<'a>,
}
```

`bound` and `addr_ty` there are the parent's indices, referenced from inside a generic
argument. **This is the encoding to write**, subject to P4's value-determined caveat
above — `endpoint` backs both params, so it should be fine as written.

Decision table, kept for the record. Taken branch: **P1-P4 pass → run the plan as written.**

- **P3 fails, P2 passes** → restructure `dispatch` to peek-then-dequeue instead of
  passing a closure. Not a guard, not a semantics change. `flux.log:236` already shows
  `FnOnce::call_once ... MightPanic(NotInCallGraph)` on this exact call, so expect this.
  *(Did not happen — P3 passed.)*
- **P4 fails, P1-P3 pass** → clause 2 still lands, which kills branch A. Clause 1 has no
  home, so branch B stays open; keep `dispatch` `trusted(no)`-suppressed and write up
  the partial result honestly rather than reaching for a guard. Alternative worth one
  hour: hoist the check into `send` by *rejecting* at enqueue, i.e. make clause 1 a
  `send` precondition phrased only over the element and the socket index, no container
  quantification. Try that before conceding.
- **P2 fails** → refining the container is out. Fall back to version-tagging
  `UdpMetadata` (`V4 { local: Option<Ipv4Address>, endpoint: … }` / `V6 { … }`), which
  makes the bad pair unconstructible. Public API break; get Andrew's call before starting.

## Steps

1. ~~**Probes P1-P4.**~~ Done, all pass — see Step 0.

**Syntax gotcha, hit already:** `#[flux_rs::field(..)]` takes a **type only**. Not
`#[flux_rs::field(endpoint: IpEndpoint)]` (parsed as a type named `endpoint` →
`cannot find type 'endpoint' in this scope`), not `#[flux_rs::field(pub endpoint: ..)]`
(→ `syntax error`). Write `#[flux_rs::field(IpEndpoint[endpoint])]`. Same for
constrained generic args: `#[flux_rs::field(Option<IpAddress{v: ..}>)]`.

2. **`InterfaceInner::get_source_address`** (mod.rs:868) — *already done in the working
   tree.* `fn(&Self, &IpAddress[@v]) -> Option<IpAddress[v]>`, `map`/`into` expanded to
   matches because Flux sees through neither. Kills dispatch's third branch for free.
   Confirm it checks before building on it.
3. **`UdpMetadata`** (udp.rs:16) — constrain the `Option`'s *payload* rather than
   indexing the `Option` itself. That expresses clause 2 directly and sidesteps needing
   a `has_local` bool at all:

   ```rust
   #[flux_rs::refined_by(dst_ty: int)]
   pub struct UdpMetadata {
       #[flux_rs::field(IpEndpoint[dst_ty])]
       pub endpoint: IpEndpoint,
       #[flux_rs::field(Option<IpAddress{v: v == dst_ty}>)]
       pub local_address: Option<IpAddress>,
       pub meta: PacketMeta,
   }
   ```

   `refined_by(endpoint: IpEndpoint)` with an ADT sort and `endpoint.addr_ty`
   projections is the alternative; the plain `int` above avoids the record projection.
   Fields stay `pub`; the refinement rides on the attrs.
4. **`IpListenEndpoint`** (ip.rs:469) — `refined_by(bound: bool, addr_ty: int)`,
   mirroring the `Option<Address>`. `addr_ty` is meaningless when `!bound`.
   `IpEndpoint`'s existing `refined_by(addr_ty)` (ip.rs:389) is the template, minus the
   `Option`.
5. **`Socket<'a>`** (udp.rs:117) — the encoding in the P4 section above. Clause 2 rides
   on the generic arg alone; clause 1 needs the parent's `bound`/`addr_ty` in scope
   there.
6. **`send` / `send_with`** — Flux precondition for both clauses, over the incoming
   `meta` and the socket index. No new `SendError`, no runtime check.
7. **`dispatch`** — drop `#[flux_rs::trusted(no, reason = "calls IpRepr::new")]`
   (udp.rs:535) and confirm it checks. The `error jumping to join point` at
   udp.rs:550 (flux.log:259) may or may not survive; if it does, restructure the
   `if let` / `match` chain into a single match.
8. **Regression test** — the repro above, plus the `local_address` variant, as
   `#[should_panic]` before the fix and compile-fail after.

## Verifying

```sh
FLUXFLAGS="-Fno-panic=true" cargo flux check -p xarxa --only-check="def:socket::udp::Socket::<'a>::dispatch"
```

Traps, all hit this session:

- **The crate is trusted-by-default** (commit eaff51e). A function without
  `#[flux_rs::trusted(no, reason = "...")]` is silently skipped. First run of the new
  `get_source_address` sig reported `2714 trusted; 0 checked` and looked like a pass.
- **Read the `summary` line, not the error count.** `0 checked` = skipped, not passed.
- **Quote `--only-check` with double quotes.** The form flux prints in its `to rerun`
  note (`'\''a>`) does not survive a copy-paste into zsh.
- **A full run is truncated by an ICE in `lookup_hardware_addr`** — see
  `tools/NEXT.md`. `#[flux_rs::trusted]` does not fix it (the ICE is in a closure);
  use `#[flux_rs::ignore]`. Grep the log for `panicked` before quoting any count.
- Default features pull in `log`, which adds `NoMIRAvailable` noise absent from
  `flux.log`. Match `flux.log`'s feature set when diffing counts.

## Not in scope

`IpRepr::new`'s other callers — `dns.rs:626`, `tcp.rs:1458`, `tcp.rs:2474` — are still
`trusted(no)`-suppressed via the `IpRepr::new fan-in cone` markers. Closing udp does
not close the cone.

---

# STATUS — end of session

`panicked` = 0 on every run quoted below.

## Landed and verified

**Clause 2 — done.** `UdpMetadata` is `#[flux_rs::refined_by(endpoint: IpEndpoint)]` with
`#[flux_rs::field(Option<IpAddress{v : v == endpoint}>)]` on `local_address`. Constraining
the Option *payload* (rather than indexing the Option) sidesteps needing `has_local` and
needs no extern specs. Established at every non-test construction site — `Socket::process`
and `From<T: Into<IpEndpoint>>`, both `trusted(no)` and clean. Test-only sites
(`remote_metadata_with_local`, `tests/{mod,ipv4,sixlowpan}.rs`) aren't compiled under
`cargo flux check`.

**Branch attribution — verified, not inferred.** Isolated each `src_addr` source in
`dispatch` by stubbing the others (copy at `scratchpad/branchA`):

| variant | src from | refinement errors |
|---|---|---|
| A | `packet_meta.local_address` | 0 |
| B | `self.endpoint.addr` | **1**, at `IpRepr::new` |
| C | `cx.get_source_address` | 0 |

So clause 2 pays for branch A, `get_source_address`'s sig pays for branch C, and branch B
is the entire remaining gap. B failing while A and C pass is its own negative control.

**`ListenEndpoint` — opaque route works.** `#[flux_rs::opaque]` +
`#[flux_rs::refined_by(addr_ty: int)]`, `-1` == unbound. No determination error, **no ICE**.
Trusted surface is four one-liners: `unspecified() -> [-1]`, `has_addr() -> bool[t != -1]`,
`addr() -> Option<Address{v: v == t}>`, `port() -> u16`. Five call sites moved to
accessors: udp `bind`/`send`/`send_with`/`dispatch`, tcp `connect`.

**`Socket` — refined, and the invariant is live.** `refined_by(addr_ty: int)`, with
`#[flux_rs::field(crate::storage::PacketBuffer<UdpMetadata{m: addr_ty == -1 || m.endpoint == addr_ty}>)]`
on `tx_buffer`. `rx_buffer` deliberately unconstrained. `addr_ty` is determined by the
`endpoint` field's bare index, so no `hrn` at this level either.

Note: Flux's field-type grammar rejects lifetime arguments —
`PacketBuffer<'a, UdpMetadata{..}>` is a syntax error, `PacketBuffer<UdpMetadata{..}>` works.

## Routes ruled out (do not retry)

- **`hrn`**: verifiable and non-vacuous (`send`'s precondition IS expressible and rejects
  mismatched calls), but any *checked* construction of a struct with an `hrn <n>: int` param
  ICEs — `expected 'Sort::Func'`, infer.rs:344. Root cause: `fresh_infer_var` calls
  `sort.expect_func()` under `InferMode::KVar`; `hrn` is built for func-sorted abstract
  predicates. Would force every constructor trusted = clause 1 assumed, not proven.
- **Sentinel without `opaque`**: an index *expression* (`[addr_ty != -1]`) does not
  value-determine, nor does a bare index nested in a generic arg. Still needs `hrn`.
- **`hdl`**: reverts to the determination error.
- **Companion field** (`pub addr_ty: i32`): public API break on a wire type.
- **`#[flux_rs::invariant]`**: does not feed determination. `check_invariants`
  (wf/mod.rs:67-86) only sort-checks the expr as Bool; it never enters `xi` in
  `param_usage.rs`.

## Remaining errors

| site | fn | error | root cause |
|---|---|---|---|
| udp.rs:254 | `bind` | type invariant may not hold (folded) | unbound→bound *strengthens* the element constraint; needs the buffer known empty |
| udp.rs:264 | `close` | refinement type error | `&mut` is **invariant** in Flux, so `reset` cannot weaken the element predicate by subtyping |
| udp.rs:340 | `send` | refinement type error | needs clause 1 as a precondition |
| udp.rs:374/377/380/392 | `send_with` | join point + refinement | same |
| udp.rs:571/602/621 | `dispatch` | refinement | branch B, blocked on the above |
| tcp.rs:1041 | `connect` | invalid use of opaque struct | span points at a `return Err`, undiagnosed; `connect` is only `trusted(no)` from the earlier cone work, so reverting it is legitimate |
| mod.rs:726 | — | internal flux error | pre-existing, unrelated |

## Next mechanism

`bind` and `close` both need U2's `&strg` re-typing on `reset` — **proven to work** in the
probe (`scratchpad/probes/src/u2.rs`):

```rust
#[flux_rs::trusted]
#[flux_rs::sig(fn(x: &strg Buf<Meta{m: true}>) ensures x: Buf<Meta{m: m.a == 1}>)]
pub fn reset(x: &mut Buf<Meta>) { x.clear() }
```

Complication not yet solved: `storage::PacketBuffer::reset` is generic over `H`, and a Flux
sig cannot be polymorphic over the element *predicate*. So it likely needs a UDP-specific
monomorphic wrapper. Unresolved: how the wrapper names the target predicate, since
`addr_ty` is a refinement param with no runtime value to pass. **Stopped here rather than
guess at spellings.**

`bind` additionally has no `reset` call today. Adding one is behaviour-preserving (the
buffer is provably empty at every `bind` — `bind` refuses when `is_open()` (223), `is_open`
is `port != 0` (257), `send` refuses when `self.endpoint.port == 0` (309), and re-binding
requires `close()` which resets (244)) — but it is still added code, so it is Andrew's call.

---

# CYCLE 2 — end state

`panicked` = 0. `cargo test --lib`: **674 passed, 0 failed**.

## Non-MightPanic errors remaining, whole crate

| site | fn | error |
|---|---|---|
| udp.rs:572 | `dispatch` | refinement type error, at the `dequeue_with` call |
| udp.rs:603 | `dispatch` | refinement type error, at `IpRepr::new` (branch B) |
| tcp.rs:1041 | `connect` | invalid use of opaque struct (undiagnosed) |
| mod.rs:726 | — | internal flux error (pre-existing, unrelated) |

Down from 12 in cycle 1. `new`, `bind`, `close`, `send*`, `process`, and the whole
`recv`/`peek` surface are clean.

## The governing constraint, learned the hard way

**`&mut T` is invariant in the refinement index.** This showed up three times and explains
most of what did and didn't work:

1. A socket's `addr_ty` **cannot change through `&mut self`**. So `bind` and `close`, which
   move the socket between `-1` and a concrete version, are not expressible as checked
   `&mut self` methods. `&strg` would work but requires callers to own the place, which
   breaks `sockets.get_mut::<udp::Socket>(h).bind(..)`.
2. Re-typing `tx_buffer` before assigning `endpoint` leaves `self` inconsistent at the call
   boundary, so the intermediate-state approach fails too. A `&strg` helper taking the
   endpoint by value (which *does* value-determine `t` — no runtime int needed) was tried
   and abandoned for this reason; see git history if needed.
3. udp.rs:572 is the same thing on the read side: `dequeue_with`'s `H` resolves from the
   Rust type alias to bare `UdpMetadata`, and passing `&mut PacketBuffer<UdpMetadata{P}>`
   needs both `P => true` and `true => P`. The second fails. **This is a diagnosis from the
   error plus (1) and (2), not independently verified.**

## Decision taken: bind/close/send are the trust boundary

`bind`, `close`, `send`, `send_with`, `send_slice` are now plain `#[flux_rs::trusted]` with
per-method reasons. Everything internal stays checked. This is the "contract at the
boundary" shape, and it also sidesteps constraint (1), which has no in-language fix.

Note `send`/`send_with`/`send_slice` could not have carried a Flux precondition anyway:
they take `meta: impl Into<UdpMetadata>`, and the `.into()` result is unconstrained — Flux
cannot express a precondition on the *output* of a generic conversion. Closing that would
need a refined inner `send_meta(&mut self, usize, UdpMetadata{..})` with the public methods
as thin trusted wrappers. Not attempted.

## Next step for udp.rs:572

Make `dequeue_with` instantiate `H` at the refined type. Either give
`storage::PacketBuffer::dequeue_with` an explicit Flux sig that is polymorphic in `H`, or
spell `tx_buffer`'s Rust type so the refined argument is the one method resolution sees.
Untested — this is where cycle 2 stopped.

## What did work, worth keeping

- `#[flux_rs::sig(fn(self: &mut Socket[@t], &mut Context, F) -> Result<(), E>)]` on
  `dispatch` removed the "type invariant may not hold (when place is folded)" error at the
  function's closing brace. Binding the socket index explicitly is what let the unfold
  carry the predicate.
- `IpListenEndpoint::unspecified() -> ListenEndpoint[-1]`, because the derived `Default`
  cannot carry an index through an opaque struct.
- Flux's field-type grammar rejects lifetime arguments: `PacketBuffer<'a, UdpMetadata{..}>`
  is a syntax error; `PacketBuffer<UdpMetadata{..}>` works.

---

# CYCLE 3 — `dispatch` verifies

`panicked` = 0. `cargo test --lib`: **674 passed, 0 failed**.

## Result

Non-MightPanic errors crate-wide: **2**, neither in udp:

| site | error |
|---|---|
| tcp.rs:1041 | invalid use of opaque struct (undiagnosed) |
| mod.rs:726 | internal flux error (pre-existing, unrelated) |

`udp::Socket::dispatch` is clean. All three branches discharge.

## READ THIS FIRST — the UB is still reachable

Verified, not assumed. The original repro still aborts:

```
thread '...probe_mixed_version_bind' panicked at src/wire/ip.rs:721:30:
unsafe precondition(s) violated: hint::unreachable_unchecked must never be reached
```

`dispatch` verifies *given* the `Socket` invariant. The invariant is **assumed** at `bind`
and `send`, which are `#[flux_rs::trusted]` — see cycle 2 for why (`&mut self` cannot change
a refinement index, and `send` takes `impl Into<UdpMetadata>` whose output cannot be
constrained). So a caller can still violate it and get UB at runtime.

What changed is the *attribution*: the obligation is now precisely stated and discharged
everywhere inside the crate, with a documented contract at two public methods. Same shape as
`check_hardware_addr`. It is **not** "the panic was removed" — do not write that.

Clause 2 is stronger than clause 1 here: clause 2 is *proven* at every construction site,
clause 1 is *assumed* at the two mutators.

## The `dequeue_with` finding

`H`'s position decides whether the element predicate survives. Measured, one variant per run:

| API | `H` position | predicate |
|---|---|---|
| `peek()` | `&H` returned | **survives** |
| `dequeue()` | `H` by value | **survives** |
| `dequeue_with()` | `&mut H` inside the `FnOnce` bound | **erased** |

Discriminated against the obvious alternative: a *capture-free trivial closure* still fails,
so it is not the closure body or its captures — it is `&mut H` in higher-order position,
i.e. the same `&mut`-invariance that blocked `bind`/`close` in cycle 2.

A probe fn demanding `&mut PacketBuffer<UdpMetadata{m: t == -1 || m.endpoint == t}>` **passes**
when handed `&mut self.tx_buffer`, so the unfolded field does carry the predicate. The loss
is specific to generic instantiation through the closure bound.

## What `dispatch` looks like now

1. `peek()` the metadata and copy the whole `UdpMetadata` out (it is `Copy`). Copying the
   two fields separately would lose clause 2, which relates them.
2. Choose `src_addr` — all three branches — out here, where the predicate is live.
3. Build the `IpRepr` out here too, with `payload_len: 0`. **The version relation does not
   survive into the closure**, so `IpRepr::new`'s precondition must be discharged outside.
4. `dequeue_payload(endpoint, &mut self.tx_buffer, |payload_buf| ...)` — a trusted wrapper
   whose callback never receives the header, so it cannot observe or modify it.
5. Inside, `ip_repr.set_payload_len(..)`. `payload_len` is not part of `IpRepr`'s refinement,
   so this preserves the version index.

Do **not** take the payload length from `peek`: `RingBuffer::get_allocated` clamps at the
ring wrap (ring_buffer.rs:352-369), so `peek`'s slice can be shorter than `metadata.size`.
Using it would emit a malformed `IpRepr` whenever the ring wraps.

## The axiom that was missing

`addr()` originally returned `Option<Address{v: v == t}>`. A `Some` arm then proves `v == t`
but leaves `t == -1` open, so `t == -1 || m.endpoint == t` never collapses. Fixed by putting
it in the payload constraint rather than indexing the `Option` (which would need
`-Fstd-extern-specs`):

```rust
#[flux_rs::sig(fn(&ListenEndpoint[@t]) -> Option<Address{v: v == t && t != -1}>)]
```

## Non-vacuity — every piece is load-bearing

- **Canary**: `flux_rs::assert(false)` in `dispatch` → 10 errors. It is genuinely checked.
- **Neg control 1**: drop clause 1 from `Socket`'s field predicate → `IpRepr::new` fails.
- **Neg control 2**: weaken `addr()` to `{v: v == t}` → `IpRepr::new` fails.
- **Neg control 3**: weaken clause 2 on `UdpMetadata` → `IpRepr::new` fails.

## Trusted surface, complete

| fn | why |
|---|---|
| `ListenEndpoint::{unspecified, has_addr, addr, port}` | opaque projections + the sentinel axiom |
| `udp::dequeue_payload` | `&mut H` erases the predicate; callback cannot touch the header |
| `udp::Socket::{bind, close}` | `&mut self` cannot change a refinement index |
| `udp::Socket::{send, send_with, send_slice}` | precondition not expressible through `impl Into` |

## Next, if this is picked up again

1. Close the boundary: refined inner `send_meta(&mut self, usize, UdpMetadata{..})` with the
   public `send*` as thin trusted wrappers. Shrinks the assumption to the `.into()` step.
2. `bind` remains genuinely blocked without changing its public signature to `&strg`.
3. Diagnose tcp.rs:1041.

---

# CORRECTION to cycle 3 — clause 1 is UNSOUND as encoded

Cycle 3 said the obligation was "discharged everywhere inside the crate, with a documented
contract at two public methods". **That is wrong.** There is no contract on the caller:
`bind`'s signature raises no obligation, and `dispatch`'s proof leans on a premise that
`bind` makes false. Both facts below were measured, not reasoned.

## A Flux-CHECKED caller can hit the UB with no obligation raised

```rust
#[flux_rs::trusted(no, reason = "probe")]
fn probe_checked_caller(sock: &mut Socket<'_>) {
    let _ = sock.bind((IpAddress::v4(192, 168, 1, 1), 53u16));
    let _ = sock.send_slice(b"abcdef",
        IpEndpoint { addr: IpAddress::v6(0xfe80,0,0,0,0,0,0,2), port: 49500 });
}
```
→ `summary. 2720 functions processed: 1 checked; ... 0 errors`

(An `IpListenEndpoint { .. }` *literal* is correctly rejected — `invalid use of opaque
struct` — so `opaque` does force checked code through constructors. But the trusted
`From<(T, u16)>` impl in ip.rs is the ordinary path and hands back an unconstrained index.)

## The mechanism, verified

```rust
#[flux_rs::sig(fn(&IpListenEndpoint[-1]))]
fn probe_some_dead_at_unbound(e: &IpListenEndpoint) {
    match e.addr() { Some(_) => flux_rs::assert(false), None => {} }
}
```
→ `1 checked; 1 constraints solved`, **no error**. The `Some` arm is *proved dead* at
`t == -1`, because `addr()` returns `Option<Address{v: v == t && t != -1}>`.

Chain:

1. `Socket::new` → `Socket[-1]` (checked; `endpoint` is `unspecified()`).
2. `bind` is trusted, inferred sig `fn(&mut Socket, T) -> Result<..>`. **`&mut` is invariant
   in the index**, so the caller's socket stays `Socket[-1]` even though at runtime it is
   now bound to v4.
3. At `Socket[-1]` the `tx_buffer` predicate is vacuous, so enqueuing a v6 datagram is
   unconstrained.
4. In `dispatch` at `t == -1`, branch B is discharged **as dead code** — per the probe above.
5. At runtime branch B is live: the endpoint really is `Some(v4)`, the destination is v6,
   `IpRepr::new(v4, v6)` → `unreachable_unchecked`.

So the trusted `bind` is not a benign axiom. It asserts something false, and step 4 consumes
it. `dispatch` verifying is conditionally valid at best; the condition never holds for any
socket a caller can actually produce.

## What this costs

Clause 2 stands — proven at every construction site, three negative controls, unaffected by
any of this. Branches A and C are genuinely discharged.

Clause 1 does not stand. Do not claim `dispatch` is verified without stating that its
`Socket[t]` premise is unreachable for `t != -1` and false for `t == -1` after `bind`.

## The real fix set

The root cause is (2): a refinement index cannot change through `&mut self`. Options:

1. **`bind` takes `&strg self`** and returns/ensures `Socket[t]`. Sound, no runtime cost.
   Breaks `sockets.get_mut::<udp::Socket>(h).bind(..)` — callers must own the place. Public
   API change, needs a look at embassy-net.
2. **Runtime check in `send`** returning a new `SendError` on version mismatch. Sound and
   self-contained, but it is the guard that was explicitly ruled out.
3. **Do not index `Socket` by `addr_ty`.** Would need the buffer predicate to reference the
   endpoint field without a refinement param — no known encoding.

Option 1 is the only one that keeps the "no guards" property. Its cost is a public signature
change on `bind`, which is Andrew's call and was never scoped.
