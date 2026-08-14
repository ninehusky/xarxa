use flux_rs::*;

#[extern_spec(core::convert)]
#[assoc(fn as_ref_reft(source: Self) -> T)]
trait AsRef<T: ?Sized> {
    #[no_panic]
    #[spec(
        fn(self: &Self[@source])
            -> &T[Self::as_ref_reft(source)]
    )]
    fn as_ref(&self) -> &T;
}

#[extern_spec(core::convert)]
#[assoc(fn as_mut_reft(source: Self) -> T)]
trait AsMut<T: ?Sized> {
    #[no_panic]
    #[spec(
        fn(self: &mut Self[@source])
            -> &mut T[Self::as_mut_reft(source)]
    )]
    fn as_mut(&mut self) -> &mut T;
}

#[extern_spec(core::slice)]
impl<T> [T] {
    #[no_panic]
    #[spec(fn(self: &Self[@n]) -> usize[n])]
    fn len(&self) -> usize;
}

#[extern_spec(core::convert)]
#[assoc(fn from_val(s: T, into: Self) -> bool { true })]
trait From<T> {
    #[sig(fn(T[@s]) -> Self{v: <Self as From<T>>::from_val(s, v)})]
    fn from(value: T) -> Self;
}

#[extern_spec(core::convert)]
impl<T, U: From<T>> Into<U> for T {
    #[sig(fn(T[@s]) -> U{v: <U as From<T>>::from_val(s, v)})]
    fn into(self) -> U;
}
