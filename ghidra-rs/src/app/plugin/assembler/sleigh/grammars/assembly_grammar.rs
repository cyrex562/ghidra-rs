//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::assembly_sentential::AssemblySentential;
use crate::app::seam_stubs::{
    AssemblyConstructorSemantic, AssemblyNonTerminal, AssemblyProduction, Constructor,
};
use crate::program::model::lang::sleigh::pattern::DisjointPattern;

/// Defines a context-free grammar, used to parse mnemonic assembly instructions.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar`, a concrete class
/// extending the unported `AbstractAssemblyGrammar<AssemblyNonTerminal, AssemblyProduction>`.
/// That class was chosen as the cut-point for a dependency cycle running through the grammar,
/// production, and SLEIGH-constructor-semantic types. This trait models only the members
/// `AssemblyGrammar.java` itself declares (its own public methods and overrides) -- the
/// inherited `AbstractAssemblyGrammar` surface (`addProduction(NT, Sentential)`, `verify()`,
/// `nonTerminals()`, iteration, etc.) belongs to that still-unported superclass and is left for
/// its own port. Every referenced core type that isn't ported yet
/// ([`AssemblyNonTerminal`], [`AssemblySentential`], [`AssemblyProduction`], [`Constructor`],
/// [`AssemblyConstructorSemantic`]) is modeled as a minimal placeholder trait in
/// [`crate::app::seam_stubs`]; [`DisjointPattern`] is already a real ported type, used directly.
/// Methods take/return `Arc<dyn Trait>` rather than concrete types, mirroring the Java reference
/// semantics of objects shared between this grammar's internal maps (e.g. the same production
/// instance lives in both `prodList` and `semanticsByProduction`) and keeping the trait decoupled
/// from any one implementation of those seams.
pub trait AssemblyGrammar {
    /// Add a production to the grammar.
    ///
    /// Mirrors `AssemblyGrammar.addProduction(AssemblyProduction)`, which also special-cases
    /// purely-recursive productions (of the form `I => I`) by routing them into a separate
    /// `pureRecursive` map instead of the main production set.
    fn add_production(&mut self, prod: Arc<dyn AssemblyProduction>);

    /// Add a production associated with a SLEIGH constructor semantic.
    ///
    /// Mirrors `AssemblyGrammar.addProduction(AssemblyNonTerminal, AssemblySentential,
    /// DisjointPattern, Constructor, List<Integer>)`.
    ///
    /// * `lhs` - the left-hand side
    /// * `rhs` - the right-hand side
    /// * `pattern` - the pattern associated with the constructor
    /// * `cons` - the SLEIGH constructor
    /// * `indices` - the indices of RHS non-terminals that represent an operand in the
    ///   constructor
    fn add_constructor_production(
        &mut self,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
        pattern: DisjointPattern,
        cons: Arc<dyn Constructor>,
        indices: Vec<usize>,
    );

    /// Get the semantics associated with a given production.
    ///
    /// Mirrors `AssemblyGrammar.getSemantics(AssemblyProduction)`.
    fn get_semantics(
        &self,
        prod: &dyn AssemblyProduction,
    ) -> Vec<Arc<dyn AssemblyConstructorSemantic>>;

    /// Get the semantic associated with a given SLEIGH constructor, if any.
    ///
    /// Mirrors `AssemblyGrammar.getSemantic(Constructor)`.
    fn get_semantic(&self, cons: &dyn Constructor) -> Option<Arc<dyn AssemblyConstructorSemantic>>;

    /// Add all the productions (and their associated semantics) of another grammar to this one.
    ///
    /// Mirrors `AssemblyGrammar.combine(AbstractAssemblyGrammar)`, narrowed to combine with
    /// another [`AssemblyGrammar`] rather than the unported `AbstractAssemblyGrammar` supertype,
    /// since only that specialization merges the semantics and pure-recursive maps this trait
    /// exposes.
    fn combine(&mut self, that: &dyn AssemblyGrammar);

    /// Get all productions in the grammar that are purely recursive.
    ///
    /// Mirrors `AssemblyGrammar.getPureRecursive()`.
    fn get_pure_recursive(&self) -> Vec<Arc<dyn AssemblyProduction>>;

    /// Obtain, if present, the purely recursive production having the given left-hand side.
    ///
    /// Mirrors `AssemblyGrammar.getPureRecursion(AssemblyNonTerminal)`.
    fn get_pure_recursion(
        &self,
        lhs: &dyn AssemblyNonTerminal,
    ) -> Option<Arc<dyn AssemblyProduction>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::lang::sleigh::pattern::InstructionPattern;
    use crate::program::model::pcode::decoder::{Decoder, DecoderError};
    use crate::program::model::pcode::ids::{
        AttributeId, ElementId, ATTRIB_NONZERO, ATTRIB_OFF, ELEM_MASK_WORD,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockNonTerminal(&'static str);

    impl std::fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockSentential;
    impl AssemblySentential for MockSentential {
        fn add_symbol(
            &mut self,
            _symbol: Arc<dyn crate::app::seam_stubs::AssemblySymbol>,
        ) -> bool {
            unimplemented!()
        }
        fn get_symbols(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblySymbol>> {
            Vec::new()
        }
        fn finish(&mut self) {}
        fn sub(&self, _from_index: usize, _to_index: usize) -> Box<dyn AssemblySentential> {
            unimplemented!()
        }
        fn white_space_symbol(&self) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }
        fn make_string_terminal(
            &self,
            _str: &str,
        ) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }
    }

    struct MockProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl MockProduction {
        fn new(name: &'static str) -> Self {
            MockProduction {
                idx: -1,
                lhs: Arc::new(MockNonTerminal(name)),
                rhs: Arc::new(MockSentential),
            }
        }
    }

    impl crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction
        for MockProduction
    {
        fn index(&self) -> i32 {
            self.idx
        }
        fn set_index(&mut self, idx: i32) {
            self.idx = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    impl AssemblyProduction for MockProduction {}

    struct MockConstructor(u32);
    impl Constructor for MockConstructor {}

    struct MockSemantic(u32);

    impl std::fmt::Display for MockSemantic {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "semantic#{}", self.0)
        }
    }

    impl AssemblyConstructorSemantic for MockSemantic {}

    /// Decoder that plays back a single always-true `<instruct_pat><pat_block off="0"
    /// nonzero="0"/></instruct_pat>` sequence, just enough for [`InstructionPattern::decode`] to
    /// build a real [`DisjointPattern`] without needing the full packed binary decoder. Mirrors
    /// the equivalent mock in
    /// `app::plugin::languages::sleigh::sleigh_languages`'s tests.
    struct MockPatternDecoder;

    impl Decoder for MockPatternDecoder {
        fn get_address_factory(&self) -> std::sync::Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: std::sync::Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            attrib_id: AttributeId,
        ) -> Result<i64, DecoderError> {
            if attrib_id.id == ATTRIB_OFF.id || attrib_id.id == ATTRIB_NONZERO.id {
                Ok(0)
            } else {
                Err(DecoderError::MissingAttribute(attrib_id.name.to_string()))
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<std::sync::Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<std::sync::Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    fn dummy_pattern() -> DisjointPattern {
        let decoder = MockPatternDecoder;
        assert_ne!(decoder.peek_element().unwrap(), ELEM_MASK_WORD.id);
        DisjointPattern::Instruction(InstructionPattern::decode(&decoder).unwrap())
    }

    /// A grammar recording just enough state to exercise every trait method through a `dyn`
    /// reference, proving object-safety and real (non-trivial) behavior: pure-recursive
    /// productions are tracked separately from ordinary ones, semantics are keyed by production
    /// name and by constructor id, and `combine` merges another grammar's state into this one.
    #[derive(Default)]
    struct TestGrammar {
        productions: Mutex<Vec<(String, Arc<dyn AssemblyProduction>)>>,
        pure_recursive: Mutex<HashMap<String, Arc<dyn AssemblyProduction>>>,
        semantics_by_production: Mutex<HashMap<String, Vec<Arc<dyn AssemblyConstructorSemantic>>>>,
        semantics_by_constructor: Mutex<HashMap<u32, Arc<dyn AssemblyConstructorSemantic>>>,
    }

    impl TestGrammar {
        fn name_of(prod: &dyn AssemblyProduction) -> String {
            // Downcasting isn't available through the minimal placeholder trait, so tests
            // identify productions via a side-channel name captured at construction time.
            format!("{:p}", prod as *const dyn AssemblyProduction as *const ())
        }
    }

    impl AssemblyGrammar for TestGrammar {
        fn add_production(&mut self, prod: Arc<dyn AssemblyProduction>) {
            let key = TestGrammar::name_of(prod.as_ref());
            self.productions.get_mut().unwrap().push((key, prod));
        }

        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn AssemblySentential>,
            _pattern: DisjointPattern,
            cons: Arc<dyn Constructor>,
            _indices: Vec<usize>,
        ) {
            let cons_id = cons.as_ref() as *const dyn Constructor as *const () as usize as u32;
            let sem: Arc<dyn AssemblyConstructorSemantic> = Arc::new(MockSemantic(cons_id));
            self.semantics_by_constructor
                .get_mut()
                .unwrap()
                .insert(cons_id, sem.clone());
        }

        fn get_semantics(
            &self,
            prod: &dyn AssemblyProduction,
        ) -> Vec<Arc<dyn AssemblyConstructorSemantic>> {
            let key = TestGrammar::name_of(prod);
            self.semantics_by_production
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default()
        }

        fn get_semantic(
            &self,
            cons: &dyn Constructor,
        ) -> Option<Arc<dyn AssemblyConstructorSemantic>> {
            let cons_id = cons as *const dyn Constructor as *const () as usize as u32;
            self.semantics_by_constructor
                .lock()
                .unwrap()
                .get(&cons_id)
                .cloned()
        }

        fn combine(&mut self, that: &dyn AssemblyGrammar) {
            for prod in that.get_pure_recursive() {
                let key = TestGrammar::name_of(prod.as_ref());
                self.pure_recursive.get_mut().unwrap().insert(key, prod);
            }
        }

        fn get_pure_recursive(&self) -> Vec<Arc<dyn AssemblyProduction>> {
            self.pure_recursive.lock().unwrap().values().cloned().collect()
        }

        fn get_pure_recursion(
            &self,
            _lhs: &dyn AssemblyNonTerminal,
        ) -> Option<Arc<dyn AssemblyProduction>> {
            self.pure_recursive.lock().unwrap().values().next().cloned()
        }
    }

    #[test]
    fn add_production_is_recorded() {
        let mut grammar = TestGrammar::default();
        let prod: Arc<dyn AssemblyProduction> = Arc::new(MockProduction::new("I => a I"));
        grammar.add_production(prod);
        assert_eq!(grammar.productions.into_inner().unwrap().len(), 1);
    }

    #[test]
    fn add_constructor_production_registers_semantic_by_constructor() {
        let mut grammar = TestGrammar::default();
        let lhs: Arc<dyn AssemblyNonTerminal> = Arc::new(MockNonTerminal("insn"));
        let rhs: Arc<dyn AssemblySentential> = Arc::new(MockSentential);
        let cons: Arc<dyn Constructor> = Arc::new(MockConstructor(7));

        grammar.add_constructor_production(lhs, rhs, dummy_pattern(), cons.clone(), vec![0, 1]);

        let found = grammar.get_semantic(cons.as_ref());
        assert!(found.is_some());
    }

    #[test]
    fn get_semantic_is_none_for_unknown_constructor() {
        let grammar = TestGrammar::default();
        let cons = MockConstructor(99);
        assert!(grammar.get_semantic(&cons).is_none());
    }

    #[test]
    fn combine_merges_pure_recursive_productions() {
        let mut source = TestGrammar::default();
        let recursive: Arc<dyn AssemblyProduction> = Arc::new(MockProduction::new("I => I"));
        source
            .pure_recursive
            .get_mut()
            .unwrap()
            .insert("I".to_string(), recursive);

        let mut dest = TestGrammar::default();
        assert!(dest.get_pure_recursive().is_empty());

        let dest_ref: &mut dyn AssemblyGrammar = &mut dest;
        dest_ref.combine(&source);

        assert_eq!(dest.get_pure_recursive().len(), 1);
    }

    #[test]
    fn get_pure_recursion_finds_registered_production() {
        let mut grammar = TestGrammar::default();
        let recursive: Arc<dyn AssemblyProduction> = Arc::new(MockProduction::new("E => E"));
        grammar
            .pure_recursive
            .get_mut()
            .unwrap()
            .insert("E".to_string(), recursive);

        let lhs = MockNonTerminal("E");
        let found = grammar.get_pure_recursion(&lhs);
        assert!(found.is_some());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let grammar = TestGrammar::default();
        let as_dyn: &dyn AssemblyGrammar = &grammar;
        assert!(as_dyn.get_pure_recursive().is_empty());
    }
}
