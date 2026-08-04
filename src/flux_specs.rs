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
