use crate::util::seam_stubs::WeakSet;

/// Factory for creating containers to use in various threading environments.
///
/// Port of `ghidra.util.datastruct.WeakDataStructureFactory`, cut to a trait to break a
/// dependency cycle: the original class's static methods return `WeakSet<T>` and construct
/// `ThreadUnsafeWeakSet`, `CopyOnReadWeakSet`, and `CopyOnWriteWeakSet`, none of which are
/// ported yet. Each method here returns a boxed [`WeakSet`] placeholder trait object rather
/// than naming those concrete, not-yet-ported types; implementors supply the concrete
/// construction once the `WeakSet` family is ported.
pub trait WeakDataStructureFactory<T> {
    /// Use when all access are on a single thread, such as the Swing thread.
    fn create_single_thread_access_weak_set(&self) -> Box<dyn WeakSet<T>>;

    /// Use when mutations outweigh iterations.
    fn create_copy_on_read_weak_set(&self) -> Box<dyn WeakSet<T>>;

    /// Use when iterations outweigh mutations.
    fn create_copy_on_write_weak_set(&self) -> Box<dyn WeakSet<T>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock `WeakSet` proving the placeholder is object-safe.
    struct MockWeakSet<T> {
        items: Vec<T>,
    }

    impl<T> WeakSet<T> for MockWeakSet<T> {}

    /// Trivial mock factory proving `WeakDataStructureFactory` is object-safe and
    /// usable behind `Box<dyn WeakDataStructureFactory<T>>`.
    struct MockFactory;

    impl WeakDataStructureFactory<i32> for MockFactory {
        fn create_single_thread_access_weak_set(&self) -> Box<dyn WeakSet<i32>> {
            Box::new(MockWeakSet { items: Vec::new() })
        }

        fn create_copy_on_read_weak_set(&self) -> Box<dyn WeakSet<i32>> {
            Box::new(MockWeakSet { items: Vec::new() })
        }

        fn create_copy_on_write_weak_set(&self) -> Box<dyn WeakSet<i32>> {
            Box::new(MockWeakSet { items: Vec::new() })
        }
    }

    #[test]
    fn factory_creates_weak_sets_behind_trait_object() {
        let factory: Box<dyn WeakDataStructureFactory<i32>> = Box::new(MockFactory);

        let _single_thread = factory.create_single_thread_access_weak_set();
        let _copy_on_read = factory.create_copy_on_read_weak_set();
        let _copy_on_write = factory.create_copy_on_write_weak_set();
    }
}
