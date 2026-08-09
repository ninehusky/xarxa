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
