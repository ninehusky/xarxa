use flux_rs::*;

#[extern_spec(core::convert)]
trait AsRef<T> {
    #[no_panic]
    fn as_ref(&self) -> &T;
}

#[extern_spec(core::convert)]
trait AsMut<T> {
    #[no_panic]
    fn as_mut(&mut self) -> &mut T;
}

// `From`/`Into` carry no refinement in vanilla Flux: `flux-core` specs `TryFrom`/
// `TryInto` but not these, so a refinement is silently dropped crossing `.into()`.
//
// The associated refinement defaults to `true`, i.e. "says nothing", so existing
// `From` impls are unaffected; an impl opts in by overriding `from_val`. The blanket
// `Into` spec forwards to it, which is what makes `.into()` transparent. Mirrors the
// shape flux-core already uses for `TryFrom`/`TryInto`.
#[extern_spec(core::convert)]
#[assoc(fn from_val(s: T, into: Self) -> bool { true })]
trait From<T> {
    #[sig(fn(T[@s]) -> Self{v: <Self as From<T>>::from_val(s, v)})]
    fn from(value: T) -> Self;
}

#[extern_spec(core::convert)]
#[assoc(fn into_val(s: T, into: U) -> bool { <U as From<T>>::from_val(s, into) })]
impl<T, U: From<T>> Into<U> for T {
    #[sig(fn(T[@s]) -> U{v: <U as From<T>>::from_val(s, v)})]
    fn into(self) -> U;
}
