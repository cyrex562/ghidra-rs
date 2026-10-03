//! Port of `ghidra.app.util.pcodeInject.InjectMultiANewArray`.
//!
//! Generates the p-code for the JVM `multianewarray` bytecode (creating a new multi-dimensional
//! array), by delegating to [`array_methods::get_pcode_for_multi_a_new_array`]. Unlike most
//! `InjectPayloadJava` subclasses, this one overrides `getPcode` completely rather than compiling
//! a sleigh source string via `inject`.
//!
//! # Preserved quirk: single-dimension arrays crash
//!
//! `ArrayMethods.getPcodeForMultiANewArray` hardcodes its `multianewarrayOp` CALLOTHER call to
//! reference dimension varnodes `"dim1"` and `"dim2"` unconditionally, regardless of the actual
//! `dimensions` count it was given. For a `multianewarray` instruction with exactly one dimension
//! -- legal JVM bytecode -- `"dim2"` is never popped/defined, so the call panics (mirroring
//! Java's `IllegalArgumentException("Register must already exist: dim2")`). This is a real bug
//! in upstream Ghidra, faithfully reproduced (not fixed) here; see
//! `get_pcode_panics_for_a_single_dimension_array_mirroring_a_real_ghidra_bug` below.
//!
//! # Shape
//!
//! Java's `InjectMultiANewArray extends InjectPayloadJava extends InjectPayloadCallother extends
//! InjectPayloadSleigh`. This crate's [`InjectPayloadJavaBase`] only models the
//! `InjectPayloadJava` layer (the `language`/`unique_base` fields `getPcode` needs) -- its own
//! `base` field is [`crate::program::seam_stubs::InjectPayloadCallother`], an old placeholder
//! with just a `source_name` string, not the real, now-ported
//! [`InjectPayloadCallother`](crate::program::model::lang::inject_payload_callother::InjectPayloadCallother).
//! So this struct composes *both*: [`java_base`](Self::java_base) for the `getPcode` override,
//! and a real [`InjectPayloadCallother`] for every other [`InjectPayload`] method (name, type,
//! param shift, input/output parameters, `inject`, `encode`, `restoreXml`, ...) -- exactly what
//! Java gets for free by inheriting from that class, and exactly the fields `getPcode` itself
//! does *not* need.
//!
//! # Deviations
//!
//! * The constructor takes an extra `emitter_language` parameter beyond Java's three
//!   (`sourceName`, `language`, `uniqBase`). [`PcodeOpEmitter::new`] needs a
//!   [`PcodeOpEmitterLanguage`] -- a register table, address-space lookups, and a userop symbol
//!   table -- but [`InjectPayloadJavaBase`]'s `language` field is this crate's *other*,
//!   lower-level `.sla`-decoding [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage),
//!   which (per that module's own doc comment) has none of those. Rather than block this port on
//!   reconciling the two -- explicitly called out as follow-up work in
//!   `pcode_op_emitter`'s module doc -- a real
//!   [`PcodeOpEmitterLanguage`] implementor is threaded through as its own field.
//! * `getConstantPool(Program)`'s `ClassFileAnalysisState.getState(program)` call needs an owned
//!   `Program` reference for its per-program cache key; `InjectPayload::get_pcode` only provides
//!   `&dyn Program`. This port instead calls
//!   [`class_file_analysis_state::parse_class_file`], which does the same parse without the
//!   cache. Since a class file's bytes -- and hence its constant pool -- never change once
//!   loaded, and `ArrayMethods.getPcodeForMultiANewArray`'s `constantPool` parameter is unused
//!   either way (see that port's own doc comment), this is behaviorally identical to Java's
//!   cached lookup for every purpose this class needs it for.
//! * `ArrayMethods::get_pcode_for_multi_a_new_array` was ported against
//!   [`crate::app::seam_stubs::PcodeOpEmitter`], a placeholder trait with `&self` methods taking
//!   `&[String]`, pending the real [`PcodeOpEmitter`] struct's port landing. That struct did
//!   land, but with incompatible `&mut self`/`&[&str]` signatures (also called out as
//!   unreconciled in that module's doc comment). [`SeamEmitterAdapter`] bridges the two locally,
//!   via a [`std::sync::Mutex`] for the interior mutability the seam trait's `&self` methods
//!   need.

use std::sync::Arc;

use crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit;
use crate::app::seam_stubs::PcodeOpEmitter as SeamPcodeOpEmitter;
use crate::app::util::pcode_inject::array_methods;
use crate::app::util::pcode_inject::inject_payload_java::{InjectPayloadJava, InjectPayloadJavaBase};
use crate::app::util::pcode_inject::pcode_op_emitter::{PcodeOpEmitter, PcodeOpEmitterLanguage};
use crate::format::javaclass::class_file_analysis_state::parse_class_file;
use crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava;
use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{InjectParameter, InjectPayload, InjectPayloadError};
use crate::program::model::lang::inject_payload_callother::InjectPayloadCallother;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::{Encoder, PcodeOp};
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Adapts an owned, `Mutex`-guarded [`PcodeOpEmitter`] to
/// [`crate::app::seam_stubs::PcodeOpEmitter`] (aliased here as `SeamPcodeOpEmitter`), the trait
/// [`array_methods::get_pcode_for_multi_a_new_array`] is generic over. See this module's own doc
/// comment for why the two `PcodeOpEmitter`s are unreconciled, unrelated items that happen to
/// share a name. A `Mutex` is used rather than a `RefCell` because `SeamPcodeOpEmitter` requires
/// `Send + Sync`, which `RefCell` (being single-threaded-only interior mutability) cannot satisfy.
struct SeamEmitterAdapter<'a, 'lang> {
    inner: &'a std::sync::Mutex<PcodeOpEmitter<'lang>>,
}

impl<'a, 'lang> SeamPcodeOpEmitter for SeamEmitterAdapter<'a, 'lang> {
    fn emit_push_cat1_value(&self, value_name: &str) {
        self.inner.lock().unwrap().emit_push_cat1_value(value_name);
    }

    fn emit_pop_cat1_value(&self, dest_name: &str) {
        self.inner.lock().unwrap().emit_pop_cat1_value(dest_name);
    }

    fn emit_assign_varnode_from_pcode_op_call(
        &self,
        varnode_name: &str,
        size: i32,
        pcodeop: &str,
        args: &[String],
    ) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.inner
            .lock()
            .unwrap()
            .emit_assign_varnode_from_pcode_op_call(varnode_name, size, pcodeop, &args);
    }

    fn emit_void_pcode_op_call(&self, pcodeop: &str, args: &[String]) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.inner.lock().unwrap().emit_void_pcode_op_call(pcodeop, &args);
    }
}

/// Generates p-code for the `multianewarray` bytecode.
///
/// Port of `ghidra.app.util.pcodeInject.InjectMultiANewArray`.
pub struct InjectMultiANewArray {
    /// The `extends InjectPayloadJava` layer: `language` and `unique_base`, which
    /// [`Self::get_pcode`] needs directly.
    java_base: InjectPayloadJavaBase,
    /// The rest of the real Java inheritance chain (`InjectPayloadCallother`/`InjectPayloadSleigh`)
    /// that [`InjectPayloadJavaBase`] does not itself model. Supplies every [`InjectPayload`]
    /// method except `get_pcode`, which this struct overrides completely -- exactly as Java's
    /// `InjectMultiANewArray` overrides `getPcode` while inheriting everything else.
    callother_base: InjectPayloadCallother,
    /// Bridges [`java_base`](Self::java_base)'s `language` to the real [`PcodeOpEmitterLanguage`]
    /// [`PcodeOpEmitter`] needs. See this module's "Deviations" doc for why this is a separate
    /// field rather than derived from `java_base.language`.
    emitter_language: Arc<dyn PcodeOpEmitterLanguage>,
}

impl InjectMultiANewArray {
    /// Port of `InjectMultiANewArray(String sourceName, SleighLanguage language, long uniqBase)`,
    /// plus the extra `emitter_language` parameter described in this module's "Deviations" doc.
    pub fn new(
        source_name: impl Into<String>,
        language: SleighLanguage,
        unique_base: u64,
        emitter_language: Arc<dyn PcodeOpEmitterLanguage>,
    ) -> Self {
        let source_name = source_name.into();
        InjectMultiANewArray {
            java_base: InjectPayloadJavaBase::new(source_name.clone(), language, unique_base),
            callother_base: InjectPayloadCallother::new(source_name),
            emitter_language,
        }
    }
}

impl InjectPayloadJava for InjectMultiANewArray {
    fn get_base(&self) -> &InjectPayloadJavaBase {
        &self.java_base
    }
}

impl InjectPayload for InjectMultiANewArray {
    fn get_name(&self) -> String {
        self.callother_base.get_name()
    }

    fn get_type(&self) -> i32 {
        self.callother_base.get_type()
    }

    fn get_source(&self) -> String {
        self.callother_base.get_source()
    }

    fn get_param_shift(&self) -> i32 {
        self.callother_base.get_param_shift()
    }

    fn get_input(&self) -> Vec<InjectParameter> {
        self.callother_base.get_input()
    }

    fn get_output(&self) -> Vec<InjectParameter> {
        self.callother_base.get_output()
    }

    fn is_error_placeholder(&self) -> bool {
        self.callother_base.is_error_placeholder()
    }

    fn inject(
        &self,
        context: &InjectContext,
        emit: &mut dyn PcodeEmit,
    ) -> Result<(), InjectPayloadError> {
        self.callother_base.inject(context, emit)
    }

    /// Port of `InjectMultiANewArray.getPcode(Program, InjectContext)`.
    ///
    /// # Panics
    ///
    /// Java reads `con.inputlist.get(0)`/`.get(1)` unconditionally; a `null` `inputlist` or one
    /// with fewer than two entries throws an unchecked `NullPointerException`/
    /// `IndexOutOfBoundsException` that is not part of `getPcode`'s declared `throws` clause and
    /// simply propagates. This port reproduces that crash-on-malformed-context behavior with
    /// `expect` rather than silently tolerating it.
    fn get_pcode(
        &self,
        program: &dyn Program,
        context: &InjectContext,
    ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
        // Java: `getConstantPool(program)`, which returns `null` on any `IOException`. See this
        // module's "Deviations" doc for why this calls `parse_class_file` directly rather than
        // `ClassFileAnalysisState::getState`, and why either way is fine here: `ArrayMethods`
        // never actually reads its `constantPool` parameter.
        let class_file = parse_class_file(program).ok();
        let constant_pool: &[AbstractConstantPoolInfoJava] =
            class_file.as_ref().map(|cf| cf.get_constant_pool()).unwrap_or(&[]);

        let input_list = context.input_list.as_ref().expect(
            "InjectMultiANewArray.getPcode requires an input list (constant pool index, dimensions)",
        );
        let constant_pool_index = input_list
            .get(0)
            .expect("InjectMultiANewArray.getPcode requires at least 2 input varnodes")
            .get_offset() as i32;
        let dimensions = input_list
            .get(1)
            .expect("InjectMultiANewArray.getPcode requires at least 2 input varnodes")
            .get_offset() as i32;

        let emitter = std::sync::Mutex::new(PcodeOpEmitter::new(
            self.emitter_language.as_ref(),
            context.base_addr.clone(),
            self.java_base.unique_base as i64,
        ));
        let adapter = SeamEmitterAdapter { inner: &emitter };
        array_methods::get_pcode_for_multi_a_new_array(
            &adapter,
            constant_pool_index,
            constant_pool,
            dimensions,
        );
        Ok(emitter.into_inner().unwrap().get_pcode_ops())
    }

    fn is_fall_thru(&self) -> bool {
        self.callother_base.is_fall_thru()
    }

    fn is_incidental_copy(&self) -> bool {
        self.callother_base.is_incidental_copy()
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        self.callother_base.encode(encoder)
    }

    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        self.callother_base.restore_xml(parser)
    }

    /// Port of `InjectPayloadJava.isEquivalent(InjectPayload)`: real Java also checks
    /// `this.getClass() != obj.getClass()` and `uniqueBase != op2.uniqueBase` before delegating
    /// to `super.isEquivalent(obj)`. Neither check has a clean Rust equivalent here: `getClass`
    /// needs downcasting that `InjectPayload` (deliberately) doesn't support, and `uniqueBase` is
    /// `InjectPayloadJava`-specific state the trait doesn't expose on `other`. Consistent with
    /// this crate's other `InjectPayload::is_equivalent` ports (e.g.
    /// [`InjectPayloadCallother::is_equivalent`]), this compares by the field values the trait
    /// *does* expose.
    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
        self.callother_base.is_equivalent(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, Varnode};
    use std::collections::HashMap;

    /// A minimal [`PcodeOpEmitterLanguage`], mirroring `pcode_op_emitter`'s own test
    /// `MockLanguage`: one register (`"SP"`, required by [`PcodeOpEmitter::new`]) and the two
    /// userops [`array_methods::get_pcode_for_multi_a_new_array`] actually invokes for a small
    /// dimension count (`"cpool"` and `"multianewarrayOp"`).
    struct MockLanguage {
        register_space: Arc<AddressSpace>,
        const_space: Arc<AddressSpace>,
        default_space: Arc<AddressSpace>,
        unique_space: Arc<AddressSpace>,
        userops: HashMap<&'static str, i32>,
    }

    impl MockLanguage {
        fn new() -> Self {
            let mut userops = HashMap::new();
            userops.insert("cpool", 0);
            userops.insert("multianewarrayOp", 1);
            userops.insert("multianewarrayProcessAdditionalDimensionsOp", 2);

            MockLanguage {
                register_space: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0),
                const_space: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0),
                default_space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
                unique_space: AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 0),
                userops,
            }
        }
    }

    impl PcodeOpEmitterLanguage for MockLanguage {
        fn get_constant_space(&self) -> Arc<AddressSpace> {
            self.const_space.clone()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.default_space.clone()
        }
        fn get_unique_space(&self) -> Arc<AddressSpace> {
            self.unique_space.clone()
        }
        fn get_address_space(&self, name: &str) -> Arc<AddressSpace> {
            panic!("unexpected address space lookup: {name}")
        }
        fn get_register(&self, name: &str) -> Option<crate::app::util::pcode_inject::pcode_op_emitter::RegisterInfo> {
            (name == "SP").then(|| crate::app::util::pcode_inject::pcode_op_emitter::RegisterInfo {
                address: self.register_space.address(0),
                bit_length: 32,
            })
        }
        fn find_userop_index(&self, name: &str) -> Option<i32> {
            self.userops.get(name).copied()
        }
    }

    fn op_addr(lang: &MockLanguage) -> Address {
        lang.default_space.address(0x1000)
    }

    /// Builds a real [`SleighLanguage`] via its `decode` entry point -- its only public
    /// constructor -- from the same known-good packed-binary byte sequence used by
    /// `inject_payload_segment.rs`'s own `test_language` helper. This crate's
    /// `InjectPayloadJavaBase` needs *some* `SleighLanguage` value to hold, even though (per this
    /// module's "Deviations" doc) `get_pcode` never actually reads it -- it drives emission
    /// through the separate `emitter_language` field instead.
    fn dummy_sleigh_language() -> SleighLanguage {
        use crate::program::model::pcode::PackedDecode;

        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).expect("test language should decode")
    }

    fn make_payload(unique_base: u64) -> (InjectMultiANewArray, Arc<MockLanguage>) {
        let lang = Arc::new(MockLanguage::new());
        let payload = InjectMultiANewArray::new(
            "multianewarray",
            dummy_sleigh_language(),
            unique_base,
            lang.clone() as Arc<dyn PcodeOpEmitterLanguage>,
        );
        (payload, lang)
    }

    fn context_with_inputs(base_addr: Address, constant_pool_index: i64, dimensions: i64) -> InjectContext {
        let mut ctx = InjectContext::new();
        ctx.base_addr = base_addr;
        ctx.input_list = Some(vec![
            Varnode::new(ctx.base_addr.space().address(constant_pool_index), 4),
            Varnode::new(ctx.base_addr.space().address(dimensions), 4),
        ]);
        ctx
    }

    struct NoOpProgram;
    impl crate::framework::model::DomainObject for NoOpProgram {}
    impl Program for NoOpProgram {
        fn get_name(&self) -> String {
            "no_constant_pool".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[test]
    fn get_pcode_emits_pops_cpool_lookup_and_multianewarray_call() {
        let (payload, _lang) = make_payload(0x100);
        let program = NoOpProgram;
        let ctx = context_with_inputs(op_addr(&MockLanguage::new()), 7, 2);

        let ops = payload.get_pcode(&program, &ctx).expect("getPcode should succeed");

        // 2 pops (dim2, dim1) + 1 cpool CALLOTHER + 1 multianewarrayOp CALLOTHER + 1 push, each
        // pop/push itself made of 2 ops (INT_SUB/STORE or LOAD/INT_ADD): matches
        // `get_pcode_for_multi_a_new_array_two_dimensions_matches_java_sequence` in
        // `array_methods`'s own tests, just now materialized as real `PcodeOp`s.
        assert_eq!(ops.len(), 8);
        // Two pops (LOAD then INT_ADD each) followed by the CALLOTHER used to fetch the class
        // reference from the constant pool.
        assert_eq!(ops[0].get_opcode(), OpCode::Load);
        assert_eq!(ops[1].get_opcode(), OpCode::IntAdd);
        assert_eq!(ops[2].get_opcode(), OpCode::Load);
        assert_eq!(ops[3].get_opcode(), OpCode::IntAdd);
        assert_eq!(ops[4].get_opcode(), OpCode::CallOther);
        assert_eq!(ops[5].get_opcode(), OpCode::CallOther);
        // Final push of the array reference: INT_SUB then STORE.
        assert_eq!(ops[6].get_opcode(), OpCode::IntSub);
        assert_eq!(ops[7].get_opcode(), OpCode::Store);
    }

    #[test]
    fn get_pcode_uses_the_constant_pool_index_from_the_first_input_varnode() {
        let (payload, _lang) = make_payload(0x100);
        let program = NoOpProgram;
        let ctx = context_with_inputs(op_addr(&MockLanguage::new()), 42, 3);

        let ops = payload.get_pcode(&program, &ctx).expect("getPcode should succeed");

        // The CPOOL CALLOTHER's second input constant is the constant pool index (42), the third
        // is the fixed CPOOL_MULTIANEWARRAY opcode (12); see `array_methods`'s own assertions on
        // the equivalent generated sequence.
        let cpool_call = ops.iter().find(|op| op.get_opcode() == OpCode::CallOther).unwrap();
        assert_eq!(cpool_call.get_input(2).unwrap().get_offset(), 42);
    }

    /// Real, preserved Java bug: `ArrayMethods.getPcodeForMultiANewArray` hardcodes the
    /// `multianewarrayOp` CALLOTHER's dimension arguments to `"dim1"`/`"dim2"` regardless of the
    /// actual `dimensions` count (see that port's own doc comment on the dropped, dead
    /// `multianewarrayOpArgs` computation -- which in *real* Java built the correctly-sized arg
    /// list, right before the very next line ignores it and hardcodes `"dim1"`/`"dim2"` anyway).
    /// For a `multianewarray` with exactly one dimension -- a perfectly legal JVM bytecode
    /// instruction (the JVM spec allows 1..=255 dimensions) -- only `"dim1"` ever gets popped off
    /// the stack and registered; `"dim2"` was never defined, so `PcodeOpEmitter::find_register`
    /// (mirroring Java's `PcodeOpEmitter.findRegister`, which throws
    /// `IllegalArgumentException("Register must already exist: " + name)`) panics. Real Ghidra
    /// has this same crash for single-dimension `multianewarray` injection; it is reproduced here
    /// rather than silently working around it.
    #[test]
    #[should_panic(expected = "Register must already exist: dim2")]
    fn get_pcode_panics_for_a_single_dimension_array_mirroring_a_real_ghidra_bug() {
        let (payload, _lang) = make_payload(0x100);
        let program = NoOpProgram;
        let ctx = context_with_inputs(op_addr(&MockLanguage::new()), 7, 1);

        let _ = payload.get_pcode(&program, &ctx);
    }

    #[test]
    #[should_panic(expected = "requires an input list")]
    fn get_pcode_panics_without_an_input_list_mirroring_javas_npe() {
        let (payload, _lang) = make_payload(0x100);
        let program = NoOpProgram;
        let mut ctx = InjectContext::new();
        ctx.base_addr = op_addr(&MockLanguage::new());
        ctx.input_list = None;

        let _ = payload.get_pcode(&program, &ctx);
    }

    #[test]
    #[should_panic(expected = "requires at least 2 input varnodes")]
    fn get_pcode_panics_with_too_few_input_varnodes() {
        let (payload, _lang) = make_payload(0x100);
        let program = NoOpProgram;
        let mut ctx = InjectContext::new();
        ctx.base_addr = op_addr(&MockLanguage::new());
        ctx.input_list = Some(vec![Varnode::new(ctx.base_addr.clone(), 4)]);

        let _ = payload.get_pcode(&program, &ctx);
    }

    #[test]
    fn inject_payload_delegates_metadata_to_the_real_callother_base() {
        let (payload, _lang) = make_payload(0x100);
        assert_eq!(payload.get_source(), "multianewarray");
        assert_eq!(payload.get_type(), crate::program::model::lang::inject_payload::CALLOTHERFIXUP_TYPE);
        assert!(!payload.is_error_placeholder());
    }
}
