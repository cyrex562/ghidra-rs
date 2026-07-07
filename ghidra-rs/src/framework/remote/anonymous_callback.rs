/// Callback used to request anonymous read-only server access.
///
/// If `anonymous_access_requested` is set to `true`, the client will attempt
/// to authenticate without credentials, obtaining read-only access.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnonymousCallback {
    anonymous_access_requested: bool,
}

impl AnonymousCallback {
    /// Create a new `AnonymousCallback` with anonymous access not requested.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether anonymous read-only access should be requested.
    pub fn set_anonymous_access_requested(&mut self, state: bool) {
        self.anonymous_access_requested = state;
    }

    /// Returns `true` if anonymous access has been requested.
    pub fn anonymous_access_requested(&self) -> bool {
        self.anonymous_access_requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_not_requested() {
        let cb = AnonymousCallback::new();
        assert!(!cb.anonymous_access_requested());
    }

    #[test]
    fn test_set_true() {
        let mut cb = AnonymousCallback::new();
        cb.set_anonymous_access_requested(true);
        assert!(cb.anonymous_access_requested());
    }

    #[test]
    fn test_set_false_after_true() {
        let mut cb = AnonymousCallback::new();
        cb.set_anonymous_access_requested(true);
        cb.set_anonymous_access_requested(false);
        assert!(!cb.anonymous_access_requested());
    }

    #[test]
    fn test_clone_preserves_state() {
        let mut cb = AnonymousCallback::new();
        cb.set_anonymous_access_requested(true);
        let cb2 = cb.clone();
        assert!(cb2.anonymous_access_requested());
    }

    #[test]
    fn test_equality() {
        let mut a = AnonymousCallback::new();
        let mut b = AnonymousCallback::new();
        assert_eq!(a, b);
        a.set_anonymous_access_requested(true);
        assert_ne!(a, b);
        b.set_anonymous_access_requested(true);
        assert_eq!(a, b);
    }

    #[test]
    fn test_debug() {
        let cb = AnonymousCallback::new();
        assert!(format!("{:?}", cb).contains("AnonymousCallback"));
    }
}
