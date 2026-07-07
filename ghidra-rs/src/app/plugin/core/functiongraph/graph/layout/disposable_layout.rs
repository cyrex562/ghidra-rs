/// A layout that can release its resources when no longer needed.
///
/// Maps to `ghidra.app.plugin.core.functiongraph.graph.layout.DisposableLayout`.
pub trait DisposableLayout {
    /// Releases resources held by this layout.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TrackingLayout {
        disposed: bool,
    }

    impl DisposableLayout for TrackingLayout {
        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    #[test]
    fn dispose_is_called() {
        let mut layout = TrackingLayout { disposed: false };
        assert!(!layout.disposed);
        layout.dispose();
        assert!(layout.disposed);
    }

    #[test]
    fn dispose_can_be_called_multiple_times() {
        let mut layout = TrackingLayout { disposed: false };
        layout.dispose();
        layout.dispose();
        assert!(layout.disposed);
    }

    #[test]
    fn trait_object_dispatch_works() {
        let mut layout: Box<dyn DisposableLayout> = Box::new(TrackingLayout { disposed: false });
        layout.dispose();
    }
}
