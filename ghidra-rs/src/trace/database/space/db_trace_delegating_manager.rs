//! Port of `ghidra.trace.database.space.DBTraceDelegatingManager`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::generic::util::flattened_iterator::FlattenedIterator;
use crate::program::model::address::{AddressSet, AddressSetView, AddressSpace};
use crate::util::lock_hold::{Lock, LockHold};

/// Mixin for managers that delegate to a per-address-space sub-manager `M`.
///
/// Port of `ghidra.trace.database.space.DBTraceDelegatingManager<M>`. This interface was
/// selected as a dependency-cycle cut-point, so only the three methods an implementor must
/// supply (`read_lock`, `write_lock`, `get_for_space`) are required; every `delegateXxx` helper
/// from the Java source is a default method here. Those defaults are generic over the closure
/// and error types (mirroring Java's `ExcFunction`/`ExcConsumer`/etc. throwing a checked
/// exception `E`), so they are opted out of the vtable with `Self: Sized` — the three required
/// methods keep the trait usable as `Box<dyn DBTraceDelegatingManager<M>>`/`Arc<dyn ...>`.
pub trait DBTraceDelegatingManager<M> {
    /// The lock guarding reads of the per-space delegates.
    fn read_lock(&self) -> &dyn Lock;

    /// The lock guarding writes to the per-space delegates.
    fn write_lock(&self) -> &dyn Lock;

    /// Look up (or, if `create_if_absent`, create) the delegate for `space`.
    ///
    /// Returns `None` when `create_if_absent` is `false` and no delegate exists yet for `space`.
    fn get_for_space(&self, space: &Arc<AddressSpace>, create_if_absent: bool) -> Option<M>;

    /// Port of `delegateWrite`: run `func` against the (created-if-absent) delegate for `space`,
    /// holding the write lock for the duration.
    fn delegate_write<T, E, F>(&self, space: &Arc<AddressSpace>, func: F) -> Result<T, E>
    where
        F: FnOnce(M) -> Result<T, E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        let m = self
            .get_for_space(space, true)
            .expect("get_for_space(_, create_if_absent = true) must return Some");
        func(m)
    }

    /// Port of `delegateWriteV`: like [`delegate_write`](Self::delegate_write), but for a
    /// side-effecting `func` with no result.
    fn delegate_write_v<E, F>(&self, space: &Arc<AddressSpace>, func: F) -> Result<(), E>
    where
        F: FnOnce(M) -> Result<(), E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        let m = self
            .get_for_space(space, true)
            .expect("get_for_space(_, create_if_absent = true) must return Some");
        func(m)
    }

    /// Port of `delegateWriteI`: like [`delegate_write`](Self::delegate_write), but for a
    /// non-throwing `func` returning `i32`.
    fn delegate_write_i<F>(&self, space: &Arc<AddressSpace>, mut func: F) -> i32
    where
        F: FnMut(M) -> i32,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        let m = self
            .get_for_space(space, true)
            .expect("get_for_space(_, create_if_absent = true) must return Some");
        func(m)
    }

    /// Port of `delegateWriteAll`: run `func` against every delegate in `spaces`, holding the
    /// write lock for the duration.
    fn delegate_write_all<Spaces, E, F>(&self, spaces: Spaces, mut func: F) -> Result<(), E>
    where
        Spaces: IntoIterator<Item = M>,
        F: FnMut(M) -> Result<(), E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        for m in spaces {
            func(m)?;
        }
        Ok(())
    }

    /// Port of `delegateRead(AddressSpace, ExcFunction)`: run `func` against the delegate for
    /// `space` if one already exists, holding the read lock for the duration. Returns `None`
    /// (mirroring Java's `ifNull = null` overload) if no delegate exists.
    fn delegate_read<T, E, F>(&self, space: &Arc<AddressSpace>, func: F) -> Result<Option<T>, E>
    where
        F: FnOnce(M) -> Result<T, E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => Ok(None),
            Some(m) => func(m).map(Some),
        }
    }

    /// Port of `delegateRead(AddressSpace, ExcFunction, T ifNull)`: like
    /// [`delegate_read`](Self::delegate_read), but returns `if_null` in place of `None` when no
    /// delegate exists.
    fn delegate_read_with_default<T, E, F>(
        &self,
        space: &Arc<AddressSpace>,
        func: F,
        if_null: T,
    ) -> Result<T, E>
    where
        F: FnOnce(M) -> Result<T, E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => Ok(if_null),
            Some(m) => func(m),
        }
    }

    /// Port of `delegateReadOr`: like
    /// [`delegate_read_with_default`](Self::delegate_read_with_default), but the fallback is
    /// computed lazily (and may itself fail) via `if_null`.
    fn delegate_read_or<T, E, F, S>(
        &self,
        space: &Arc<AddressSpace>,
        func: F,
        if_null: S,
    ) -> Result<T, E>
    where
        F: FnOnce(M) -> Result<T, E>,
        S: FnOnce() -> Result<T, E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => if_null(),
            Some(m) => func(m),
        }
    }

    /// Port of `delegateReadI(AddressSpace, ToIntFunction, int ifNull)`.
    fn delegate_read_i<F>(&self, space: &Arc<AddressSpace>, mut func: F, if_null: i32) -> i32
    where
        F: FnMut(M) -> i32,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => if_null,
            Some(m) => func(m),
        }
    }

    /// Port of `delegateReadI(AddressSpace, ToIntFunction, IntSupplier ifNull)`.
    fn delegate_read_i_or_else<F, S>(
        &self,
        space: &Arc<AddressSpace>,
        mut func: F,
        if_null: S,
    ) -> i32
    where
        F: FnMut(M) -> i32,
        S: FnOnce() -> i32,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => if_null(),
            Some(m) => func(m),
        }
    }

    /// Port of `delegateReadB`.
    fn delegate_read_b<F>(&self, space: &Arc<AddressSpace>, func: F, if_null: bool) -> bool
    where
        F: FnOnce(M) -> bool,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(space, false) {
            None => if_null,
            Some(m) => func(m),
        }
    }

    /// Port of `delegateDeleteV`: run `func` against the delegate for `space` if one already
    /// exists, holding the write lock for the duration.
    fn delegate_delete_v<E, F>(&self, space: &Arc<AddressSpace>, func: F) -> Result<(), E>
    where
        F: FnOnce(M) -> Result<(), E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        match self.get_for_space(space, false) {
            None => Ok(()),
            Some(m) => func(m),
        }
    }

    /// Port of `delegateDeleteB`.
    fn delegate_delete_b<F>(&self, space: &Arc<AddressSpace>, func: F, if_null: bool) -> bool
    where
        F: FnOnce(M) -> bool,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.write_lock());
        match self.get_for_space(space, false) {
            None => if_null,
            Some(m) => func(m),
        }
    }

    /// Port of `delegateFirst`: return the first non-`None` result of applying `func` to each
    /// delegate in `spaces`, holding the read lock for the duration.
    fn delegate_first<Spaces, T, F>(&self, spaces: Spaces, mut func: F) -> Option<T>
    where
        Spaces: IntoIterator<Item = M>,
        F: FnMut(M) -> Option<T>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        for m in spaces {
            if let Some(t) = func(m) {
                return Some(t);
            }
        }
        None
    }

    /// Port of `delegateCollection`: compose the elements `func` returns for each delegate in
    /// `spaces`, using [`FlattenedIterator`] to chain them.
    ///
    /// Unlike the Java original (which returns a lazy `Collection` view backed by the still-live
    /// `spaces`/`func`, taking the read lock only inside `size()`/`isEmpty()`), this eagerly
    /// materializes the result under a single read-lock hold — simpler, and no less safe than a
    /// view that could otherwise be traversed unlocked.
    fn delegate_collection<Spaces, T, C, F>(&self, spaces: Spaces, mut func: F) -> Vec<T>
    where
        Spaces: IntoIterator<Item = M>,
        C: IntoIterator<Item = T>,
        F: FnMut(M) -> C,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        FlattenedIterator::new(spaces.into_iter(), move |m| Some(func(m).into_iter())).collect()
    }

    /// Port of `delegateHashSet`: union the elements `func` returns for each delegate in
    /// `spaces`, holding the read lock for the duration.
    fn delegate_hash_set<Spaces, T, C, F>(&self, spaces: Spaces, mut func: F) -> HashSet<T>
    where
        Spaces: IntoIterator<Item = M>,
        C: IntoIterator<Item = T>,
        F: FnMut(M) -> C,
        T: Eq + std::hash::Hash,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        let mut result = HashSet::new();
        for m in spaces {
            result.extend(func(m));
        }
        result
    }

    /// Port of `delegateAddressSet`: union the address sets `func` returns for each delegate in
    /// `spaces`, holding the read lock for the duration.
    fn delegate_address_set<Spaces, E, F, R>(&self, spaces: Spaces, mut func: F) -> Result<AddressSet, E>
    where
        Spaces: IntoIterator<Item = M>,
        F: FnMut(M) -> Result<R, E>,
        R: AddressSetView,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        let mut result = AddressSet::new();
        for m in spaces {
            let set = func(m)?;
            result.add_set(&set);
        }
        Ok(result)
    }

    /// Port of `delegateAny`: return `true` if `func` is true for any delegate in `spaces`,
    /// holding the read lock for the duration.
    fn delegate_any<Spaces, E, F>(&self, spaces: Spaces, mut func: F) -> Result<bool, E>
    where
        Spaces: IntoIterator<Item = M>,
        F: FnMut(M) -> Result<bool, E>,
        Self: Sized,
    {
        let _hold = LockHold::lock(self.read_lock());
        for m in spaces {
            if func(m)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    /// A tiny per-space delegate: just counts how many times it was touched.
    #[derive(Clone, Default, PartialEq, Debug)]
    struct SpaceCounter {
        hits: i32,
    }

    struct MockDelegatingManager {
        read_lock: NoopLock,
        write_lock: NoopLock,
        delegates: RefCell<HashMap<String, SpaceCounter>>,
    }

    impl DBTraceDelegatingManager<SpaceCounter> for MockDelegatingManager {
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }

        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }

        fn get_for_space(
            &self,
            space: &Arc<AddressSpace>,
            create_if_absent: bool,
        ) -> Option<SpaceCounter> {
            let mut delegates = self.delegates.borrow_mut();
            if create_if_absent {
                Some(
                    delegates
                        .entry(space.name().to_string())
                        .or_insert_with(SpaceCounter::default)
                        .clone(),
                )
            } else {
                delegates.get(space.name()).cloned()
            }
        }
    }

    fn ram_space(name: &str) -> Arc<AddressSpace> {
        AddressSpace::new(name, 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn delegate_write_creates_and_delegate_read_sees_it() {
        let mgr = MockDelegatingManager {
            read_lock: NoopLock,
            write_lock: NoopLock,
            delegates: RefCell::new(HashMap::new()),
        };
        let space = ram_space("ram");

        // No delegate yet: a read returns None.
        let seen: Option<i32> = mgr
            .delegate_read::<i32, (), _>(&space, |c| Ok(c.hits))
            .unwrap();
        assert_eq!(seen, None);

        // A write creates the delegate.
        let hits: i32 = mgr
            .delegate_write::<i32, (), _>(&space, |c| Ok(c.hits + 1))
            .unwrap();
        assert_eq!(hits, 1);

        // Now a read sees it exists (though this mock's delegates are stateless copies).
        let seen_after: Option<i32> = mgr
            .delegate_read::<i32, (), _>(&space, |c| Ok(c.hits))
            .unwrap();
        assert_eq!(seen_after, Some(0));
    }

    #[test]
    fn delegate_read_with_default_and_delegate_any_and_delegate_first() {
        let mgr = MockDelegatingManager {
            read_lock: NoopLock,
            write_lock: NoopLock,
            delegates: RefCell::new(HashMap::new()),
        };
        let ram = ram_space("ram");
        let other = ram_space("other");

        let fallback: i32 = mgr
            .delegate_read_with_default::<i32, (), _>(&ram, |c| Ok(c.hits), -1)
            .unwrap();
        assert_eq!(fallback, -1);

        mgr.delegate_write_v::<(), _>(&ram, |_| Ok(())).unwrap();
        mgr.delegate_write_v::<(), _>(&other, |_| Ok(())).unwrap();

        let any: bool = mgr
            .delegate_any::<_, (), _>(
                [
                    mgr.get_for_space(&ram, false).unwrap(),
                    mgr.get_for_space(&other, false).unwrap(),
                ],
                |_| Ok(true),
            )
            .unwrap();
        assert!(any);

        let first = mgr.delegate_first(
            vec![
                mgr.get_for_space(&ram, false).unwrap(),
                mgr.get_for_space(&other, false).unwrap(),
            ],
            |c| if c.hits == 0 { Some("found") } else { None },
        );
        assert_eq!(first, Some("found"));
    }

    #[test]
    fn delegate_collection_and_delegate_hash_set_flatten_all_spaces() {
        let mgr = MockDelegatingManager {
            read_lock: NoopLock,
            write_lock: NoopLock,
            delegates: RefCell::new(HashMap::new()),
        };
        let ram = ram_space("ram");
        let other = ram_space("other");
        let a = mgr.get_for_space(&ram, true).unwrap();
        let b = mgr.get_for_space(&other, true).unwrap();

        let collected = mgr.delegate_collection(vec![a.clone(), b.clone()], |_| vec![1, 2]);
        assert_eq!(collected, vec![1, 2, 1, 2]);

        let set = mgr.delegate_hash_set(vec![a, b], |_| vec![1, 2]);
        let mut set: Vec<i32> = set.into_iter().collect();
        set.sort();
        assert_eq!(set, vec![1, 2]);
    }

    /// Proves the required trio (`read_lock`/`write_lock`/`get_for_space`) is object-safe.
    #[test]
    fn usable_as_trait_object() {
        let mgr = MockDelegatingManager {
            read_lock: NoopLock,
            write_lock: NoopLock,
            delegates: RefCell::new(HashMap::new()),
        };
        let obj: &dyn DBTraceDelegatingManager<SpaceCounter> = &mgr;
        let space = ram_space("ram");
        assert_eq!(obj.get_for_space(&space, false), None);
        obj.write_lock().lock();
        obj.write_lock().unlock();
    }
}
