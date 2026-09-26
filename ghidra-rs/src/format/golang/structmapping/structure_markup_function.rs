use std::io;

use super::markup_session::MarkupSession;
use super::structure_context::StructureContext;
use super::structure_mapped::StructureMapped;

/// A function that decorates a Ghidra structure.
///
/// This is the Rust equivalent of the Java `StructureMarkupFunction<T>` functional interface
/// from `ghidra.app.util.bin.format.golang.structmapping`:
/// ```java
/// void markupStructure(StructureContext<T> context, MarkupSession markupSession)
///     throws IOException, CancelledException;
/// ```
/// Java reaches the instance through `context.getStructureInstance()`; the Rust
/// [`StructureContext`] does not point back at its instance, so the instance is passed
/// alongside it. Any matching closure or `fn` is a `StructureMarkupFunction`.
pub trait StructureMarkupFunction<T: StructureMapped> {
    /// Decorates the specified structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the markup operation fails or is cancelled.
    fn markup_structure(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        markup_session: &mut MarkupSession<'_>,
    ) -> io::Result<()>;
}

impl<T, F> StructureMarkupFunction<T> for F
where
    T: StructureMapped,
    F: Fn(&StructureContext<T>, &T, &mut MarkupSession<'_>) -> io::Result<()>,
{
    fn markup_structure(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        markup_session: &mut MarkupSession<'_>,
    ) -> io::Result<()> {
        self(context, instance, markup_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::structmapping::mapping_tests::{read_test_functab, TestFunctab};
    use crate::util::task::DummyMonitor;

    struct NoOpMarkupFunction;

    impl StructureMarkupFunction<TestFunctab> for NoOpMarkupFunction {
        fn markup_structure(
            &self,
            _context: &StructureContext<TestFunctab>,
            _instance: &TestFunctab,
            _markup_session: &mut MarkupSession<'_>,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn markup_function_no_op_succeeds() {
        let (mapper, ft) = read_test_functab();
        let monitor = DummyMonitor;
        let mut session = mapper.create_markup_session(&monitor);
        let ctx = ft.structure_context().unwrap();
        assert!(NoOpMarkupFunction.markup_structure(ctx, &ft, &mut session).is_ok());
    }

    #[test]
    fn markup_function_error_propagates() {
        let (mapper, ft) = read_test_functab();
        let monitor = DummyMonitor;
        let mut session = mapper.create_markup_session(&monitor);
        let failing = |_: &StructureContext<TestFunctab>, _: &TestFunctab, _: &mut MarkupSession<'_>| {
            Err(io::Error::other("markup failed"))
        };
        let err = failing.markup_structure(ft.structure_context().unwrap(), &ft, &mut session).unwrap_err();
        assert!(err.to_string().contains("markup failed"));
    }

    #[test]
    fn markup_function_calls_session_method() {
        let (mapper, ft) = read_test_functab();
        let monitor = DummyMonitor;
        let mut session = mapper.create_markup_session(&monitor);
        // the session call is observable: the test program has no listing, so a comment
        // through the session reports that
        let commenting = |ctx: &StructureContext<TestFunctab>, _: &TestFunctab, s: &mut MarkupSession<'_>| {
            s.append_comment_at_structure(ctx, crate::program::model::listing::CommentType::Plate, None, "x", "\n")
        };
        let err = commenting.markup_structure(ft.structure_context().unwrap(), &ft, &mut session).unwrap_err();
        assert_eq!(err.to_string(), "Program has no listing to add comments to");
    }
}
