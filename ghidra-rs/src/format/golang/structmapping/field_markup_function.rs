use std::io;

use super::field_context::FieldContext;
use super::markup_session::MarkupSession;
use super::structure_mapped::StructureMapped;

/// A function that decorates a field in a structure mapped class.
///
/// This is the Rust equivalent of the Java `FieldMarkupFunction<T>` functional interface
/// from `ghidra.app.util.bin.format.golang.structmapping`:
/// ```java
/// void markupField(FieldContext<T> fieldContext, MarkupSession markupSession)
///     throws IOException, CancelledException;
/// ```
/// Any matching closure or `fn` is a `FieldMarkupFunction`.
pub trait FieldMarkupFunction<T: StructureMapped> {
    /// Decorates the specified field.
    ///
    /// # Errors
    ///
    /// Returns an error if the markup operation fails or is cancelled.
    fn markup_field(&self, field_context: &FieldContext<'_, T>, markup_session: &mut MarkupSession<'_>) -> io::Result<()>;
}

impl<T, F> FieldMarkupFunction<T> for F
where
    T: StructureMapped,
    F: Fn(&FieldContext<'_, T>, &mut MarkupSession<'_>) -> io::Result<()>,
{
    fn markup_field(&self, field_context: &FieldContext<'_, T>, markup_session: &mut MarkupSession<'_>) -> io::Result<()> {
        self(field_context, markup_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::structmapping::mapping_tests::{read_test_functab, TestFunctab};
    use crate::format::golang::structmapping::StructureMapped as _;
    use crate::util::task::DummyMonitor;

    struct NoOpMarkupFunction;

    impl FieldMarkupFunction<TestFunctab> for NoOpMarkupFunction {
        fn markup_field(&self, _field_context: &FieldContext<'_, TestFunctab>, _markup_session: &mut MarkupSession<'_>) -> io::Result<()> {
            Ok(())
        }
    }

    fn with_field_context(f: impl FnOnce(&FieldContext<'_, TestFunctab>, &mut MarkupSession<'_>)) {
        let (mapper, ft) = read_test_functab();
        let monitor = DummyMonitor;
        let mut session = mapper.create_markup_session(&monitor);
        let ctx = ft.structure_context().unwrap();
        let fmi = ctx.get_mapping_info().get_field_info("funcoff").unwrap();
        let field_ctx = ctx.create_field_context(&ft, fmi, None).unwrap();
        f(&field_ctx, &mut session);
    }

    #[test]
    fn markup_function_no_op_succeeds() {
        with_field_context(|fc, session| {
            assert!(NoOpMarkupFunction.markup_field(fc, session).is_ok());
            // the field context locates the field: structure at 4, funcOff at +8
            assert_eq!(fc.get_address().offset(), 12);
            assert_eq!(fc.get_structure_instance().funcoff, 0xffff_fffe);
        });
    }

    #[test]
    fn markup_function_error_propagates() {
        with_field_context(|fc, session| {
            let failing = |_: &FieldContext<'_, TestFunctab>, _: &mut MarkupSession<'_>| -> io::Result<()> {
                Err(io::Error::other("markup failed"))
            };
            let err = failing.markup_field(fc, session).unwrap_err();
            assert!(err.to_string().contains("markup failed"));
        });
    }

    #[test]
    fn markup_function_calls_session_method() {
        with_field_context(|fc, session| {
            let adding_ref = |fc: &FieldContext<'_, TestFunctab>, s: &mut MarkupSession<'_>| {
                let dest = fc.get_address();
                s.add_reference(fc, dest)
            };
            // reached the session: the test program has no reference manager
            let err = adding_ref.markup_field(fc, session).unwrap_err();
            assert_eq!(err.to_string(), "Program has no reference manager");
        });
    }
}
