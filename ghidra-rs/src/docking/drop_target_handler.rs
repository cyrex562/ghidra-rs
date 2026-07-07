/// A basic interface for holding onto drop handlers.
///
/// Corresponds to `docking.DropTargetHandler`.
pub trait DropTargetHandler {
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler {
        disposed: bool,
    }

    impl DropTargetHandler for TestHandler {
        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    #[test]
    fn dispose_is_called() {
        let mut h = TestHandler { disposed: false };
        assert!(!h.disposed);
        h.dispose();
        assert!(h.disposed);
    }
}
