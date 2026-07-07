/// Implemented by resources that must be explicitly released.
///
/// Port of `ghidra.util.Disposable`.
pub trait Disposable {
    /// Release any resources held by this object.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter {
        disposed: bool,
    }

    impl Disposable for Counter {
        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    #[test]
    fn dispose_is_called() {
        let mut c = Counter { disposed: false };
        assert!(!c.disposed);
        c.dispose();
        assert!(c.disposed);
    }

    #[test]
    fn dispose_is_idempotent_to_caller() {
        let mut c = Counter { disposed: false };
        c.dispose();
        c.dispose();
        assert!(c.disposed);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut c = Counter { disposed: false };
        let obj: &mut dyn Disposable = &mut c;
        obj.dispose();
        assert!(c.disposed);
    }
}
