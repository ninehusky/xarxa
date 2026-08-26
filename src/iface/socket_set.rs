use core::fmt;
use managed::ManagedSlice;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'a> {
    inner: Option<Item<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// Borrow the storage slot at `i`, with the bounds check discharged by the caller.
///
/// `trusted(yes)` because the body *is* the unchecked primitive, but the obligation is not
/// erased: `requires i < n` states it in the signature, so it moves to every call site, where
/// flux checks it against the enclosing function's own `requires`.
#[flux_rs::trusted(yes, reason = "unchecked indexing; `i < n` is discharged at the call site")]
#[flux_rs::sig(fn(&[T][@n], i: usize) -> &T requires i < n)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
fn slot<T>(slots: &[T], i: usize) -> &T {
    // SAFETY: `i < n` is a precondition flux discharges at every call site.
    unsafe { slots.get_unchecked(i) }
}

/// Mutable counterpart of [`slot`].
#[flux_rs::trusted(yes, reason = "unchecked indexing; `i < n` is discharged at the call site")]
#[flux_rs::sig(fn(&mut [T][@n], i: usize) -> &mut T requires i < n)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
fn slot_mut<T>(slots: &mut [T], i: usize) -> &mut T {
    // SAFETY: `i < n` is a precondition flux discharges at every call site.
    unsafe { slots.get_unchecked_mut(i) }
}

/// A handle, identifying a socket in an Interface.
///
/// Refined by the index it names, so that [`SocketSet`]'s accessors can require it to be in
/// range rather than bounds-checking it at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(idx: int)]
#[flux_rs::invariant(idx >= 0)]
pub struct SocketHandle(#[flux_rs::field(usize[idx])] usize);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
#[flux_rs::refined_by(len: int)]
#[flux_rs::invariant(len >= 0)]
pub struct SocketSet<'a> {
    #[flux_rs::field(ManagedSlice<SocketStorage>[len])]
    sockets: ManagedSlice<'a, SocketStorage<'a>>,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    #[flux_rs::no_panic_if(<SocketsT as Into<ManagedSlice<SocketStorage>>>::into_no_panic())]
    #[flux_rs::sig(fn(sockets: SocketsT) -> SocketSet)]
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let sockets = sockets.into();
        SocketSet { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a>(index: usize, slot: &mut SocketStorage<'a>, socket: Socket<'a>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the socket has the wrong type.
    ///
    /// The handle being in range is a *precondition*, not a run-time check: flux discharges
    /// `handle.idx < self.len` at every call site, so the bounds check is gone from the
    /// generated code. The slot being occupied and holding a `T` are still checked at run
    /// time -- stating either would need element-level refinement of the socket storage,
    /// which flux cannot express for a primitive slice.
    #[flux_rs::trusted(no, reason = "discharges the bounds check on the socket storage")]
    #[flux_rs::sig(fn(&SocketSet[@set], SocketHandle[@h]) -> &T requires h.idx < set.len)]
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match slot(&self.sockets, handle.0).inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the socket has the wrong type.
    ///
    /// See [`SocketSet::get`] for why the handle bound is a precondition rather than a
    /// run-time check.
    #[flux_rs::trusted(no, reason = "discharges the bounds check on the socket storage")]
    #[flux_rs::sig(fn(&mut SocketSet[@set], SocketHandle[@h]) -> &mut T requires h.idx < set.len)]
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        match slot_mut(&mut self.sockets, handle.0).inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not refer to an occupied slot.
    ///
    /// See [`SocketSet::get`] for why the handle bound is a precondition rather than a
    /// run-time check.
    #[flux_rs::trusted(no, reason = "discharges the bounds check on the socket storage")]
    #[flux_rs::sig(fn(&mut SocketSet[@set], SocketHandle[@h]) -> Socket requires h.idx < set.len)]
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match slot_mut(&mut self.sockets, handle.0).inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }
}
