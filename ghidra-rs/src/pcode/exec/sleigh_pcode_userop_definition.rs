//! A p-code userop defined using Sleigh source.
//!
//! Corresponds to `ghidra.pcode.exec.SleighPcodeUseropDefinition`.

use std::sync::Arc;

use crate::pcode::seam_stubs::{
    AbstractSleighPcodeUseropDefinition as UnportedAbstractSleighPcodeUseropDefinition, PcodeProgram, PcodeUseropLibrary,
};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::Varnode;

/// The name of the output symbol.
pub const OUT_SYMBOL_NAME: &str = "__op_output";

/// An argument list standing in for "no output, no inputs": a single `None`, mirroring Java's
/// `EMPTY_ARGS`, a one-element list holding a `null` `Varnode`.
pub fn empty_args() -> Vec<Option<Varnode>> {
    vec![None]
}

/// A p-code userop defined using Sleigh source.
///
/// Java's `<T>` type parameter exists only to match whatever executor implements it; none of
/// this trait's own methods depend on it, so the Rust port drops it.
pub trait SleighPcodeUseropDefinition {
    /// Get the Sleigh source that defines this userop.
    ///
    /// The body may or may not actually depend on the arguments. Ideally, it does not, but
    /// sometimes the body may vary depending on the *sizes* of the arguments. When the arguments
    /// are required, index 0 must be the output varnode; if the userop has no output, index 0 is
    /// `None`.
    fn get_body(&self, args: &[Option<Varnode>]) -> String;

    /// Get the p-code program implementing this userop for the given arguments and library.
    ///
    /// This will compile and cache a program for each new combination of arguments seen. `args`
    /// gives the operands, output at index 0 (or `None` if there is no output), and inputs
    /// following.
    fn program_for(&self, args: &[Option<Varnode>], library: &dyn PcodeUseropLibrary) -> Box<dyn PcodeProgram>;
}

/// A function body, as it depends on the given arguments.
pub trait BodyFunc {
    /// Generate the body, given the arguments.
    ///
    /// In general, to refer to an argument, the source can use the corresponding parameter by
    /// name. Where it's useful to have the varnode, e.g., is when the size of the argument needs
    /// to be known. In this case, the argument can be retrieved by index, where 0 is the output
    /// varnode, and 1-n is each respective input varnode.
    fn generate(&self, args: &[Option<Varnode>]) -> String;
}

/// One definition for a userop for a given signature (parameters, including output).
pub struct SignatureDef {
    /// The names of the arguments, index 0 being the output.
    pub signature: Vec<String>,
    /// The body source, possibly a function of the arguments.
    pub body: Vec<Box<dyn BodyFunc>>,
}

impl SignatureDef {
    /// Generate the body's source code for the given arguments.
    pub fn generate_body(&self, args: &[Option<Varnode>]) -> String {
        self.body.iter().map(|b| b.generate(args)).collect()
    }
}

/// Stage two of the builder, where parameters can no longer be added.
///
/// To remain object-safe (so [`Factory::define`] can hand back "some builder" without exposing
/// the concrete, not-yet-ported implementation), chaining methods consume `self: Box<Self>` and
/// return `Box<dyn ...>` rather than `Self`, mirroring Java's covariant `Builder`-returns-`Builder`
/// pattern seen only through these interface types.
pub trait BuilderStage2 {
    /// Add Sleigh source to the body.
    fn body(self: Box<Self>, additional_body: Box<dyn BodyFunc>) -> Box<dyn BuilderStage2>;

    /// Start a new definition for a different signature.
    fn overload(self: Box<Self>) -> Box<dyn BuilderStage1>;

    /// Build the actual definition.
    ///
    /// NOTE: Compilation of the sleigh source is delayed until the first invocation, since the
    /// compiler must know about the varnodes used as parameters.
    fn build(self: Box<Self>) -> Box<dyn SleighPcodeUseropDefinition>;
}

/// Stage one of the builder, where any operation is allowed.
pub trait BuilderStage1: BuilderStage2 {
    /// Add parameters with the given names (to the end).
    fn params(self: Box<Self>, additional_params: Vec<String>) -> Box<dyn BuilderStage1>;
}

/// A factory for building [`SleighPcodeUseropDefinition`]s.
pub struct Factory {
    language: Arc<SleighLanguage>,
}

impl Factory {
    /// Construct a factory for the given language.
    pub fn new(language: Arc<SleighLanguage>) -> Self {
        Self { language }
    }

    /// Begin building the definition for a userop with the given name.
    ///
    /// CYCLE NOTE: Java constructs `new AbstractSleighPcodeUseropDefinition.Builder(this, name)`
    /// here. `AbstractSleighPcodeUseropDefinition` (and the `FixedSleighPcodeUseropDefinition` /
    /// `OverloadedSleighPcodeUseropDefinition` its builder ultimately delegates to) are not yet
    /// ported, so this currently delegates to a stub that panics if actually invoked; see
    /// `AbstractSleighPcodeUseropDefinition` in `seam_stubs`.
    pub fn define(&self, name: impl Into<String>) -> Box<dyn BuilderStage1> {
        UnportedAbstractSleighPcodeUseropDefinition::builder(Arc::clone(&self.language), name.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct StaticBody(&'static str);

    impl BodyFunc for StaticBody {
        fn generate(&self, _args: &[Option<Varnode>]) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn out_symbol_name_matches_java_constant() {
        assert_eq!(OUT_SYMBOL_NAME, "__op_output");
    }

    #[test]
    fn empty_args_is_a_single_null_output() {
        assert_eq!(empty_args(), vec![None]);
    }

    #[test]
    fn signature_def_generate_body_concatenates_in_order() {
        // Mirrors SignatureDef.generateBody's `body.stream().map(...).collect(joining())`: plain
        // concatenation, no separator, in declaration order.
        let def = SignatureDef {
            signature: vec![OUT_SYMBOL_NAME.to_string(), "a".to_string()],
            body: vec![Box::new(StaticBody("local x;")), Box::new(StaticBody(" x = a;"))],
        };
        assert_eq!(def.generate_body(&[]), "local x; x = a;");
    }

    /// A minimal builder that reproduces `AbstractSleighPcodeUseropDefinition.Builder`'s
    /// params/body/overload bookkeeping (keying finished [`SignatureDef`]s by parameter count),
    /// so the [`BuilderStage1`]/[`BuilderStage2`] shape can be exercised end to end without the
    /// unported `AbstractSleighPcodeUseropDefinition`.
    struct TestBuilder {
        definitions: HashMap<i32, SignatureDef>,
        params: Vec<String>,
        body: Vec<Box<dyn BodyFunc>>,
    }

    impl TestBuilder {
        fn new() -> Box<Self> {
            Box::new(Self {
                definitions: HashMap::new(),
                params: vec![OUT_SYMBOL_NAME.to_string()],
                body: Vec::new(),
            })
        }

        fn finish_signature(&mut self) {
            let def = SignatureDef {
                signature: std::mem::take(&mut self.params),
                body: std::mem::take(&mut self.body),
            };
            self.definitions.insert(def.signature.len() as i32, def);
            self.params.push(OUT_SYMBOL_NAME.to_string());
        }
    }

    impl BuilderStage2 for TestBuilder {
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
            Box::new(TestDefinition { definitions: self.definitions })
        }
    }

    impl BuilderStage1 for TestBuilder {
        fn params(mut self: Box<Self>, additional_params: Vec<String>) -> Box<dyn BuilderStage1> {
            self.params.extend(additional_params);
            self
        }
    }

    struct TestDefinition {
        definitions: HashMap<i32, SignatureDef>,
    }

    impl SleighPcodeUseropDefinition for TestDefinition {
        fn get_body(&self, args: &[Option<Varnode>]) -> String {
            self.definitions
                .get(&(args.len() as i32))
                .map(|def| def.generate_body(args))
                .unwrap_or_default()
        }

        fn program_for(&self, _args: &[Option<Varnode>], _library: &dyn PcodeUseropLibrary) -> Box<dyn PcodeProgram> {
            unimplemented!("test double has no PcodeProgram")
        }
    }

    #[test]
    fn builder_chain_dispatches_by_signature_like_java_builder() {
        let builder: Box<dyn BuilderStage1> = TestBuilder::new();
        let built = builder
            .params(vec!["a".to_string()])
            .body(Box::new(StaticBody("local x;")))
            .overload()
            .params(vec!["b".to_string(), "c".to_string()])
            .body(Box::new(StaticBody("local y;")))
            .build();

        // 2-arg signature (output, a) resolves to the first overload's body.
        assert_eq!(built.get_body(&[None, None]), "local x;");
        // 3-arg signature (output, b, c) resolves to the second overload's body.
        assert_eq!(built.get_body(&[None, None, None]), "local y;");
        // An arity with no matching overload has no body.
        assert_eq!(built.get_body(&[None, None, None, None]), "");
    }
}
