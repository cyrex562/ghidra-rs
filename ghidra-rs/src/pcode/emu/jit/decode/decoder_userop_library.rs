//! Port of `ghidra.pcode.emu.jit.decode.DecoderUseropLibrary`.
//!
//! The decoder's wrapper around the emulator's userop library.
//!
//! This library serves two purposes: 1) to override the emulator's built-in `emu_exec_decoded`/
//! `emu_skip_decoded` userops, and 2) to check and inline p-code userops that
//! [`PcodeUseropDefinition::can_inline_pcode`] allows it.
//!
//! We accomplish the first purpose simply by adding the two userops using the usual annotated
//! mechanism ([`AnnotatedPcodeUseropDefinition`]). Java's bodies for those two userops cast the
//! generic `PcodeExecutor<Object>` they receive down to `DecoderExecutor`. This port's
//! [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor) is a
//! standalone struct, not a `PcodeExecutor<T>` (see its module docs), so a generic userop callback
//! here has nothing it could downcast to; both bodies panic if ever invoked. That cannot currently
//! happen: `DecoderExecutor::execute_callother` already panics before inlining *any* userop's
//! p-code -- and both of these are always inlinable -- so it never reaches this callback.
//!
//! We accomplish the second purpose by accepting the emulator's userop library and individually
//! wrapping each of its userops, excluding the two above, in [`WrappedUseropDefinition`]. Every
//! attribute other than `execute` simply passes through to the wrapped userop; when executed as
//! its "raw" op, the wrapper inlines the wrapped userop's p-code if the wrapped userop allows it,
//! and otherwise does nothing (the `callother` op has already been logged and will be compiled
//! later).

use std::any::TypeId;
use std::sync::Arc;

use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, PcodeUserop, UseropInputs, UseropValueKind,
};
use crate::pcode::exec::default_pcode_userop_library::DefaultPcodeUseropLibrary;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
};
use crate::program::model::pcode::{PcodeOp, Varnode};

/// The wrapper around one of the emulator's userops.
///
/// Port of the inner class `DecoderUseropLibrary.WrappedUseropDefinition`.
struct WrappedUseropDefinition {
    rt_op: Arc<dyn PcodeUseropDefinition<Vec<u8>>>,
}

impl WrappedUseropDefinition {
    /// Wrap the given userop.
    fn new(rt_op: Arc<dyn PcodeUseropDefinition<Vec<u8>>>) -> Self {
        Self { rt_op }
    }
}

impl PcodeUseropDefinition<Vec<u8>> for WrappedUseropDefinition {
    fn get_name(&self) -> &str {
        self.rt_op.get_name()
    }

    fn get_input_count(&self) -> i32 {
        self.rt_op.get_input_count()
    }

    /// Java: `throw new AssertionError()`. Only the raw overload
    /// ([`execute_raw`](Self::execute_raw)) is ever actually invoked -- see the module docs.
    fn execute(
        &self,
        _executor: &PcodeExecutor<Vec<u8>>,
        _library: &dyn PcodeUseropLibrary<Vec<u8>>,
        _op: &PcodeOp,
        _out_var: Option<&Varnode>,
        _in_vars: &[Varnode],
    ) {
        unreachable!("WrappedUseropDefinition::execute is never called; only execute_raw is")
    }

    /// If the wrapped userop can be inlined, we assume its `execute` simply produces p-code and
    /// feeds it to the executor -- in which case the target type does not matter, so Java casts
    /// everything to raw types. The user is responsible for applying `canInlinePcode` correctly.
    fn execute_raw(
        &self,
        executor: &PcodeExecutor<Vec<u8>>,
        library: &dyn PcodeUseropLibrary<Vec<u8>>,
        op: &PcodeOp,
    ) {
        if self.rt_op.can_inline_pcode() {
            self.rt_op.execute_raw(executor, library, op);
        }
        // Nothing to do. CALLOTHER is logged and will be compiled later.
    }

    fn is_functional(&self) -> bool {
        self.rt_op.is_functional()
    }

    fn has_side_effects(&self) -> bool {
        self.rt_op.has_side_effects()
    }

    fn modifies_context(&self) -> bool {
        self.rt_op.modifies_context()
    }

    fn can_inline_pcode(&self) -> bool {
        self.rt_op.can_inline_pcode()
    }

    fn get_output_type(&self) -> Option<TypeId> {
        self.rt_op.get_output_type()
    }

    fn get_java_method(&self) -> Option<()> {
        None
    }

    fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
        self.rt_op.get_defining_library()
    }
}

/// The decoder's wrapper around the emulator's userop library.
///
/// Port of `ghidra.pcode.emu.jit.decode.DecoderUseropLibrary`.
pub struct DecoderUseropLibrary {
    ops: DefaultPcodeUseropLibrary<Vec<u8>>,
}

impl DecoderUseropLibrary {
    /// Wrap the given userop library.
    ///
    /// Port of `new DecoderUseropLibrary(PcodeUseropLibrary<byte[]>)`.
    pub fn new(rt_lib: Arc<dyn PcodeUseropLibrary<Vec<u8>>>) -> Self {
        let mut ops = DefaultPcodeUseropLibrary::new();
        for definition in Self::own_definitions() {
            ops.put_op(Arc::new(definition));
        }
        for rt_op in rt_lib.get_userops().values() {
            let name = rt_op.get_name();
            if ops.get_userops().contains_key(name) {
                // Allow our annotations to override stuff in rtLib
                continue;
            }
            ops.put_op(Arc::new(WrappedUseropDefinition::new(Arc::clone(rt_op))));
        }
        Self { ops }
    }

    /// The two userops this library exports itself, overriding the emulator's built-in
    /// `emu_exec_decoded`/`emu_skip_decoded`.
    ///
    /// Port of the `@PcodeUserop`-annotated `emu_exec_decoded`/`emu_skip_decoded` methods. See the
    /// module docs for why both callback bodies panic rather than reimplementing the Java logic.
    fn own_definitions() -> Vec<AnnotatedPcodeUseropDefinition<Vec<u8>>> {
        vec![
            AnnotatedPcodeUseropDefinition::new(
                "emu_exec_decoded",
                PcodeUserop { can_inline: true, ..Default::default() },
                UseropInputs::Fixed(Vec::new()),
                UseropValueKind::Void,
                Box::new(|_ctx, _args| {
                    unimplemented!(
                        "DecoderUseropLibrary::emu_exec_decoded needs a DecoderExecutor, which \
                         this userop's generic callback has no way to reach; see \
                         DecoderExecutor::execute_callother"
                    )
                }),
            ),
            AnnotatedPcodeUseropDefinition::new(
                "emu_skip_decoded",
                PcodeUserop { can_inline: true, ..Default::default() },
                UseropInputs::Fixed(Vec::new()),
                UseropValueKind::Void,
                Box::new(|_ctx, _args| {
                    unimplemented!(
                        "DecoderUseropLibrary::emu_skip_decoded needs a DecoderExecutor, which \
                         this userop's generic callback has no way to reach; see \
                         DecoderExecutor::execute_callother"
                    )
                }),
            ),
        ]
    }

    /// Look up a userop by name.
    ///
    /// Port of `library().getUserops().get(name)`.
    pub(crate) fn get_userop(&self, name: &str) -> Option<Arc<dyn PcodeUseropDefinition<Vec<u8>>>> {
        self.ops.get_userops().get(name).cloned()
    }
}

impl ErasedPcodeUseropLibrary for DecoderUseropLibrary {}

impl PcodeUseropLibrary<Vec<u8>> for DecoderUseropLibrary {
    fn get_userops(&self) -> &UseropMap<Vec<u8>> {
        self.ops.get_userops()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRuntimeUserop {
        name: &'static str,
        input_count: i32,
        can_inline: bool,
        modifies_context: bool,
        has_side_effects: bool,
        is_functional: bool,
    }

    impl PcodeUseropDefinition<Vec<u8>> for FakeRuntimeUserop {
        fn get_name(&self) -> &str {
            self.name
        }
        fn get_input_count(&self) -> i32 {
            self.input_count
        }
        fn execute(
            &self,
            _executor: &PcodeExecutor<Vec<u8>>,
            _library: &dyn PcodeUseropLibrary<Vec<u8>>,
            _op: &PcodeOp,
            _out_var: Option<&Varnode>,
            _in_vars: &[Varnode],
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn is_functional(&self) -> bool {
            self.is_functional
        }
        fn has_side_effects(&self) -> bool {
            self.has_side_effects
        }
        fn modifies_context(&self) -> bool {
            self.modifies_context
        }
        fn can_inline_pcode(&self) -> bool {
            self.can_inline
        }
        fn get_output_type(&self) -> Option<TypeId> {
            None
        }
        fn get_java_method(&self) -> Option<()> {
            None
        }
        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    struct RtLib {
        userops: UseropMap<Vec<u8>>,
    }
    impl ErasedPcodeUseropLibrary for RtLib {}
    impl PcodeUseropLibrary<Vec<u8>> for RtLib {
        fn get_userops(&self) -> &UseropMap<Vec<u8>> {
            &self.userops
        }
    }

    fn rt_lib(ops: Vec<Arc<dyn PcodeUseropDefinition<Vec<u8>>>>) -> Arc<dyn PcodeUseropLibrary<Vec<u8>>> {
        let userops = ops.into_iter().map(|op| (op.get_name().to_string(), op)).collect();
        Arc::new(RtLib { userops })
    }

    #[test]
    fn own_userops_export_emu_exec_and_skip_decoded_as_inlinable() {
        // Java: both are annotated `@PcodeUserop(canInline = true)`, with no fixed inputs (only
        // the @OpExecutor parameter) and a void return.
        let library = DecoderUseropLibrary::new(rt_lib(vec![]));

        for name in ["emu_exec_decoded", "emu_skip_decoded"] {
            let op = library.get_userop(name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(op.get_name(), name);
            assert_eq!(op.get_input_count(), 0);
            assert!(op.can_inline_pcode());
            assert!(!op.modifies_context());
            assert!(!op.is_functional(), "PcodeUserop.functional defaults to false");
            assert!(op.has_side_effects(), "PcodeUserop.hasSideEffects defaults to true");
        }
    }

    #[test]
    fn wrapped_userop_delegates_every_attribute_to_the_runtime_definition() {
        let rt_op: Arc<dyn PcodeUseropDefinition<Vec<u8>>> = Arc::new(FakeRuntimeUserop {
            name: "my_userop",
            input_count: 3,
            can_inline: true,
            modifies_context: true,
            has_side_effects: false,
            is_functional: true,
        });
        let library = DecoderUseropLibrary::new(rt_lib(vec![rt_op]));

        let wrapped = library.get_userop("my_userop").expect("wrapped userop present");
        assert_eq!(wrapped.get_input_count(), 3);
        assert!(wrapped.can_inline_pcode());
        assert!(wrapped.modifies_context());
        assert!(!wrapped.has_side_effects());
        assert!(wrapped.is_functional());
    }

    #[test]
    fn own_annotated_userops_take_precedence_over_a_runtime_userop_of_the_same_name() {
        // Java: `if (ops.containsKey(opDef.getName())) continue;` -- our own annotations win.
        let rt_op: Arc<dyn PcodeUseropDefinition<Vec<u8>>> = Arc::new(FakeRuntimeUserop {
            name: "emu_exec_decoded",
            input_count: 5,
            can_inline: false,
            modifies_context: true,
            has_side_effects: true,
            is_functional: true,
        });
        let library = DecoderUseropLibrary::new(rt_lib(vec![rt_op]));

        let op = library.get_userop("emu_exec_decoded").unwrap();
        // Our own definition, not the runtime one: input count 0, not the runtime's 5.
        assert_eq!(op.get_input_count(), 0);
        assert!(op.can_inline_pcode());
    }

    #[test]
    fn library_exposes_every_wrapped_and_own_userop_via_get_userops() {
        let rt_op: Arc<dyn PcodeUseropDefinition<Vec<u8>>> = Arc::new(FakeRuntimeUserop {
            name: "custom_op",
            input_count: 1,
            can_inline: false,
            modifies_context: false,
            has_side_effects: false,
            is_functional: false,
        });
        let library = DecoderUseropLibrary::new(rt_lib(vec![rt_op]));

        let mut names: Vec<&str> = library.get_userops().keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, vec!["custom_op", "emu_exec_decoded", "emu_skip_decoded"]);
    }
}
