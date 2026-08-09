//! Shared state and behavior for Sleigh userop definitions.
//!
//! Corresponds to `ghidra.pcode.exec.AbstractSleighPcodeUseropDefinition`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::sleigh_pcode_userop_definition::{
    BodyFunc, BuilderStage1, BuilderStage2, SignatureDef, SleighPcodeUseropDefinition, OUT_SYMBOL_NAME,
};
use crate::pcode::seam_stubs::{
    FixedSleighPcodeUseropDefinition, OverloadedSleighPcodeUseropDefinition, PcodeExecutor, PcodeProgram,
    PcodeUseropLibrary,
};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// The shared state and concrete (non-abstract) behavior of a Sleigh userop definition.
///
/// Java's `AbstractSleighPcodeUseropDefinition<T>` is an abstract class: it carries the
/// `language`/`name`/`cacheByArgs` fields and implements every method of
/// `SleighPcodeUseropDefinition` except `getBody`/`programFor`, which it leaves abstract for its
/// two subclasses ([`FixedSleighPcodeUseropDefinition`](crate::pcode::seam_stubs::FixedSleighPcodeUseropDefinition)
/// and [`OverloadedSleighPcodeUseropDefinition`](crate::pcode::seam_stubs::OverloadedSleighPcodeUseropDefinition),
/// not yet ported -- see `seam_stubs`). Rust has no field inheritance, so this struct holds the
/// shared fields plus the concrete logic; a concrete definition embeds it and implements
/// [`SleighPcodeUseropDefinition`] (equivalently, [`AbstractSleighPcodeUseropDefinition`], its
/// marker supertrait) for the two methods that remain abstract.
pub struct AbstractSleighPcodeUseropDefinitionBase {
    language: Arc<SleighLanguage>,
    name: String,
    /// Cache of compiled programs keyed by argument list (output at index 0, or `None`, then
    /// inputs). Java's `Map<List<Varnode>, PcodeProgram>`; `Varnode` has no `Hash` impl in this
    /// port, so this is a linear association list rather than a `HashMap`.
    ///
    /// Unused by this base itself -- only by the (not yet ported) subclasses that implement
    /// `program_for` -- but carried here since Java declares it on the abstract class.
    #[allow(dead_code)]
    cache_by_args: Vec<(Vec<Option<Varnode>>, Box<dyn PcodeProgram>)>,
}

impl AbstractSleighPcodeUseropDefinitionBase {
    /// Port of the protected constructor `AbstractSleighPcodeUseropDefinition(SleighLanguage, String)`.
    pub fn new(language: Arc<SleighLanguage>, name: impl Into<String>) -> Self {
        Self {
            language,
            name: name.into(),
            cache_by_args: Vec::new(),
        }
    }

    /// The Sleigh language this userop is defined for.
    pub fn language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }

    /// Port of `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Port of `isFunctional()`: Sleigh userops are never purely functional.
    pub fn is_functional(&self) -> bool {
        false
    }

    /// Port of `hasSideEffects()`: Sleigh userops are assumed to have side effects.
    pub fn has_side_effects(&self) -> bool {
        true
    }

    /// Port of `modifiesContext()`.
    ///
    /// We could scan the p-code ops for any that write to the contextreg; however, at the
    /// moment, that is highly unconventional and perhaps even considered an error. If that
    /// becomes more common, or even recommended, then we can detect it and behave accordingly
    /// during interpretation (whether for execution or translation).
    pub fn modifies_context(&self) -> bool {
        false
    }

    /// Port of `canInlinePcode()`.
    pub fn can_inline_pcode(&self) -> bool {
        true
    }

    /// Port of `getJavaMethod()`. Rust has no analog of `java.lang.reflect.Method`; this always
    /// returns `None`, matching Java always returning `null` here.
    pub fn get_java_method(&self) -> Option<()> {
        None
    }

    /// Port of `getDefiningLibrary()`: a plain Sleigh userop is not defined by a Java library.
    pub fn get_defining_library(&self) -> Option<Box<dyn PcodeUseropLibrary>> {
        None
    }

    /// Port of `execute(PcodeExecutor<T>, PcodeUseropLibrary<T>, PcodeOp, Varnode, List<Varnode>)`.
    ///
    /// A free function generic over the concrete definition, rather than a method on this base,
    /// since it must dispatch to the abstract `program_for` -- which this base does not
    /// implement -- to build the program it hands to the executor. `op` is accepted (matching
    /// the Java signature) but unused, exactly as in the original.
    pub fn execute<D: SleighPcodeUseropDefinition + ?Sized>(
        definition: &D,
        executor: &dyn PcodeExecutor,
        library: &dyn PcodeUseropLibrary,
        _op: &PcodeOp,
        out_arg: Option<Varnode>,
        in_args: &[Option<Varnode>],
    ) {
        let mut args = Vec::with_capacity(in_args.len() + 1);
        args.push(out_arg);
        args.extend_from_slice(in_args);
        let program = definition.program_for(&args, library);
        executor.execute(program.as_ref(), library);
    }
}

/// The abstract operations a concrete Sleigh userop definition must still supply.
///
/// Port of the effectively-abstract part of `ghidra.pcode.exec.AbstractSleighPcodeUseropDefinition`:
/// every other method has a conventional implementation on
/// [`AbstractSleighPcodeUseropDefinitionBase`] (mirroring the Java class's bodies). The two
/// methods Java leaves abstract, `getBody`/`programFor`, are already declared by
/// [`SleighPcodeUseropDefinition`] (the interface this class implements), so this trait is a
/// marker supertrait rather than redeclaring them.
pub trait AbstractSleighPcodeUseropDefinition: SleighPcodeUseropDefinition {}

/// A builder for a particular userop.
///
/// Port of `AbstractSleighPcodeUseropDefinition.Builder`. Implements the already-ported
/// [`BuilderStage1`]/[`BuilderStage2`] traits from [`SleighPcodeUseropDefinition::Factory`].
pub struct Builder {
    language: Arc<SleighLanguage>,
    name: String,
    definitions: HashMap<i32, SignatureDef>,
    params: Vec<String>,
    body: Vec<Box<dyn BodyFunc>>,
}

impl Builder {
    /// Port of `new Builder(Factory, String)`. Java's constructor takes the enclosing `Factory`
    /// only to reach `factory.language`, so this takes the language directly.
    pub fn new(language: Arc<SleighLanguage>, name: impl Into<String>) -> Box<Self> {
        Box::new(Self {
            language,
            name: name.into(),
            definitions: HashMap::new(),
            params: vec![OUT_SYMBOL_NAME.to_string()],
            body: Vec::new(),
        })
    }

    /// Finalize the current signature into `definitions`, then reset `params`/`body` for the
    /// next one.
    ///
    /// Port of the body of `Builder.overload()`, kept as a private inherent method (rather than
    /// solely on the `BuilderStage2::overload` trait method) so `build()` can call it directly
    /// without losing the concrete type through `Box<dyn BuilderStage1>` erasure -- mirroring how
    /// Java's `build()` calls `overload()` as a plain instance method, not through the interface.
    fn finish_signature(&mut self) {
        let params = std::mem::replace(&mut self.params, vec![OUT_SYMBOL_NAME.to_string()]);
        let body = std::mem::take(&mut self.body);
        let key = params.len() as i32;
        let def = SignatureDef { signature: params, body };
        let exists = self.definitions.insert(key, def);
        if exists.is_some() {
            panic!("Definition for this signature already exists");
        }
    }
}

impl BuilderStage2 for Builder {
    fn body(mut self: Box<Self>, additional_body: Box<dyn BodyFunc>) -> Box<dyn BuilderStage2> {
        self.body.push(additional_body);
        self
    }

    fn overload(mut self: Box<Self>) -> Box<dyn BuilderStage1> {
        self.finish_signature();
        self
    }

    fn build(mut self: Box<Self>) -> Box<dyn SleighPcodeUseropDefinition> {
        self.finish_signature();
        if self.definitions.len() == 1 {
            let definition = self.definitions.into_values().next().unwrap();
            Box::new(FixedSleighPcodeUseropDefinition::new(self.language, self.name, definition))
        } else {
            Box::new(OverloadedSleighPcodeUseropDefinition::new(self.language, self.name, self.definitions))
        }
    }
}

impl BuilderStage1 for Builder {
    fn params(mut self: Box<Self>, additional_params: Vec<String>) -> Box<dyn BuilderStage1> {
        self.params.extend(additional_params);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::pcode::PackedDecode;

    /// Builds a minimal but real `SleighLanguage`, by feeding a hand-assembled packed-binary
    /// `<sleigh>` document through the crate's real `PackedDecode`. Identical to the fixture used
    /// by `abstract_assembly_tree_resolver`'s own `test_language`; `SleighLanguage`'s fields are
    /// private outside its module, so a literal construction isn't available here.
    fn test_language() -> Arc<SleighLanguage> {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>
        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap())
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    fn varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(test_address(offset), size)
    }

    #[test]
    fn base_reports_java_constant_flags() {
        let base = AbstractSleighPcodeUseropDefinitionBase::new(test_language(), "myop");
        assert_eq!(base.get_name(), "myop");
        assert!(!base.is_functional());
        assert!(base.has_side_effects());
        assert!(!base.modifies_context());
        assert!(base.can_inline_pcode());
        assert!(base.get_java_method().is_none());
        assert!(base.get_defining_library().is_none());
    }

    #[test]
    fn builder_single_signature_produces_fixed_definition() {
        let builder = Builder::new(test_language(), "myop");
        let built = builder.build();
        // A single signature (just the implicit OUT_SYMBOL_NAME param) collapses to Fixed.
        assert_eq!(built.get_body(&[None]), "");
    }

    #[test]
    #[should_panic(expected = "Definition for this signature already exists")]
    fn builder_overload_rejects_duplicate_signature() {
        let builder = Builder::new(test_language(), "myop");
        let stage1 = builder.overload();
        stage1.overload();
    }

    #[test]
    fn execute_builds_program_and_dispatches_to_executor() {
        use std::cell::Cell;

        struct RecordingProgram;
        impl PcodeProgram for RecordingProgram {}

        struct RecordingLibrary;
        impl PcodeUseropLibrary for RecordingLibrary {
            fn compose(self: Box<Self>, _other: Box<dyn PcodeUseropLibrary>) -> Box<dyn PcodeUseropLibrary> {
                self
            }
        }

        struct RecordingDefinition;
        impl SleighPcodeUseropDefinition for RecordingDefinition {
            fn get_body(&self, _args: &[Option<Varnode>]) -> String {
                String::new()
            }
            fn program_for(&self, args: &[Option<Varnode>], _library: &dyn PcodeUseropLibrary) -> Box<dyn PcodeProgram> {
                // The output goes at index 0, followed by the inputs (empty here), matching
                // Java's `args.add(outArg); args.addAll(inArgs);`.
                assert_eq!(args.len(), 1);
                assert!(args[0].is_some());
                Box::new(RecordingProgram)
            }
        }

        thread_local! {
            static EXECUTED: Cell<bool> = Cell::new(false);
        }

        struct RecordingExecutor;
        impl PcodeExecutor for RecordingExecutor {
            fn execute(&self, _program: &dyn PcodeProgram, _library: &dyn PcodeUseropLibrary) {
                EXECUTED.with(|e| e.set(true));
            }
        }

        let definition = RecordingDefinition;
        let executor = RecordingExecutor;
        let library = RecordingLibrary;
        let op = PcodeOp::new(
            crate::program::model::pcode::OpCode::CallOther,
            crate::program::model::pcode::SequenceNumber::new(test_address(0), 0),
            Vec::new(),
            None,
        );

        AbstractSleighPcodeUseropDefinitionBase::execute(
            &definition,
            &executor,
            &library,
            &op,
            Some(varnode(0x1000, 4)),
            &[],
        );

        EXECUTED.with(|e| assert!(e.get()));
    }
}
