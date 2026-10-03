/// Identifies the cause of an event emitted by JDI.
///
/// This is not a concept native to JDI. Rather, it is a means to distinguish events that result
/// from commands issued by the JDI manager from those issued by the user or some other means. For
/// example, an internal `addInferior` call will emit an `inferiorAdded` event identifying a
/// pending command as the cause; a console-driven "add-inferior" command emits the same event
/// but with [`Causes::Unclaimed`] as the cause.
pub trait JdiCause: Send + Sync {}

/// Built-in causes for JDI events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Causes {
    /// The cause is not claimed by any known command; typically a user or external action.
    Unclaimed,
}

impl JdiCause for Causes {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes_unclaimed_implements_jdi_cause() {
        fn accepts(_: &dyn JdiCause) {}
        accepts(&Causes::Unclaimed);
    }

    #[test]
    fn causes_unclaimed_is_copy() {
        let a = Causes::Unclaimed;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn causes_unclaimed_debug() {
        assert_eq!(format!("{:?}", Causes::Unclaimed), "Unclaimed");
    }

    #[test]
    fn causes_unclaimed_eq() {
        assert_eq!(Causes::Unclaimed, Causes::Unclaimed);
    }

    #[test]
    fn jdi_cause_as_trait_object() {
        let cause: &dyn JdiCause = &Causes::Unclaimed;
        let _ = cause;
    }
}
