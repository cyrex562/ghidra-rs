/// Possible sources that drive actions or method invocations.
///
/// Primarily used to determine where and how errors should be reported.
/// Actions taken automatically should not cause disruptive error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionSource {
    /// The action was requested by the user, usually via a UI action.
    /// It is acceptable to display an error message.
    Manual,
    /// The action was requested automatically, usually by some background thread.
    /// Error messages should be delivered to the log or Debug Console rather than
    /// a pop-up, since they would otherwise appear to "come from nowhere."
    Automatic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(ActionSource::Manual, ActionSource::Automatic);
    }

    #[test]
    fn clone_and_copy() {
        let src = ActionSource::Manual;
        let cloned = src;
        assert_eq!(src, cloned);

        let src2 = ActionSource::Automatic;
        let cloned2 = src2;
        assert_eq!(src2, cloned2);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ActionSource::Manual), "Manual");
        assert_eq!(format!("{:?}", ActionSource::Automatic), "Automatic");
    }
}
