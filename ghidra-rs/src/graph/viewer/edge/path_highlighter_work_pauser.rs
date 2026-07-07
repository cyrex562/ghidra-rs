/// Signals whether path highlighting work should be suppressed.
pub trait PathHighlighterWorkPauser {
    /// Returns `true` if work should not happen; `false` for normal path highlighting operations.
    fn is_paused(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysPaused;

    impl PathHighlighterWorkPauser for AlwaysPaused {
        fn is_paused(&self) -> bool {
            true
        }
    }

    struct NeverPaused;

    impl PathHighlighterWorkPauser for NeverPaused {
        fn is_paused(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_paused() {
        let p = AlwaysPaused;
        assert!(p.is_paused());
    }

    #[test]
    fn test_not_paused() {
        let p = NeverPaused;
        assert!(!p.is_paused());
    }

    #[test]
    fn test_trait_object() {
        let p: Box<dyn PathHighlighterWorkPauser> = Box::new(AlwaysPaused);
        assert!(p.is_paused());
    }
}
