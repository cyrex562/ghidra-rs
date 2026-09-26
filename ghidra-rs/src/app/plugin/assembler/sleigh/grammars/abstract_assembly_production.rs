//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::assembly_sentential::AssemblySentential;
use crate::app::seam_stubs::AssemblyNonTerminal;

/// Defines a production in a context-free grammar, usually for parsing mnemonic assembly.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction<NT extends
/// AssemblyNonTerminal>`, chosen as the cut-point for a dependency cycle running through the
/// grammar, production, and symbol types. As with
/// [`AssemblySentential`](crate::app::plugin::assembler::sleigh::grammars::AssemblySentential)
/// (itself a cut-point for the same cycle), Java's `NT` generic parameter is dropped: it appears
/// in the class body only as a compile-time bound on `getLHS`/`compareTo`'s parameter type, never
/// as runtime data, so [`lhs`](Self::lhs) returns the crate's existing
/// [`AssemblyNonTerminal`](crate::app::seam_stubs::AssemblyNonTerminal) placeholder directly
/// rather than threading a type parameter through the trait.
///
/// This class has exactly two concrete Java subclasses, `AssemblyProduction` and
/// `AssemblyExtendedProduction` -- but neither is referenced *by*
/// `AbstractAssemblyProduction.java` itself (only `AssemblyNonTerminal` and the already-ported
/// [`AssemblySentential`] are), so this port leaves the crate's existing
/// [`AssemblyProduction`](crate::app::seam_stubs::AssemblyProduction) and
/// [`AssemblyExtendedProduction`](crate::app::seam_stubs::AssemblyExtendedProduction) placeholders
/// untouched; wiring them to extend this trait is a decision for whichever future port actually
/// needs their fuller surface.
///
/// [`lhs`](Self::lhs), [`rhs`](Self::rhs), [`index`](Self::index), and
/// [`set_index`](Self::set_index) are required hooks standing in for the constructor-assigned
/// `lhs`/`rhs` fields and the package-visible, grammar-mutated `idx` field (Java code outside this
/// class assigns `prod.idx` directly, e.g. `AbstractAssemblyGrammar.addProduction`; this port
/// exposes that mutation as a method since Rust has no package-private field access). `get_name`
/// and `display_string` (named per the `display_string`/`fixed_display_string` convention used
/// elsewhere in this crate for ported `toString()` overrides) are ported as default methods built
/// on those hooks, mirroring `getName()` and `toString()`. `compareTo` is ported as
/// [`compare_to`](Self::compare_to), comparing `lhs` the same LAZY, `toString()`-based way
/// `AssemblySymbol.compareTo` does (`AssemblyNonTerminal` never overrides it), then falling back to
/// [`AssemblySentential::compare_to`] for `rhs`.
///
/// `equals()`/`hashCode()` are not mapped: Java's override combines a LAZY, `toString()`-based
/// `lhs.equals()` (inherited from `AssemblySymbol`) with an IDENTITY-based `rhs.equals()`
/// (`AssemblySentential` never overrides `Object`'s default), the same unsound
/// value/identity mismatch already noted on [`AssemblySentential`] itself -- reproducing it here
/// would be equally meaningless. Callers wanting `lhs` value-equality can compare
/// `lhs().to_string()` directly (available via its `Display` bound); callers wanting `rhs`
/// identity-equality can call `Arc::ptr_eq` on two [`rhs`](Self::rhs) results.
pub trait AbstractAssemblyProduction {
    /// Get the index of the production.
    ///
    /// Mirrors `AbstractAssemblyProduction.getIndex()`.
    ///
    /// Instead of using deep comparison, the index is often used as the identity of the
    /// production within a grammar.
    fn index(&self) -> i32;

    /// Set the index of the production.
    ///
    /// Stands in for direct assignment to the package-visible `idx` field, as performed by
    /// `AbstractAssemblyGrammar.addProduction` (`prod.idx = prodList.size()`) before that class is
    /// ported.
    fn set_index(&mut self, idx: i32);

    /// Get the left-hand side.
    ///
    /// Mirrors `AbstractAssemblyProduction.getLHS()`.
    fn lhs(&self) -> Arc<dyn AssemblyNonTerminal>;

    /// Get the right-hand side.
    ///
    /// Mirrors `AbstractAssemblyProduction.getRHS()`.
    fn rhs(&self) -> Arc<dyn AssemblySentential>;

    /// Get the "name" of this production.
    ///
    /// Mirrors `AbstractAssemblyProduction.getName()`. This is mostly just notional and for
    /// debugging. The name is taken as the name of the LHS.
    fn get_name(&self) -> String {
        self.lhs().get_name()
    }

    /// Render this production as `"<index>. <lhs> => <rhs>"`.
    ///
    /// Mirrors `AbstractAssemblyProduction.toString()`.
    fn display_string(&self) -> String {
        format!("{}. {} => {}", self.index(), self.lhs(), self.rhs().display_string())
    }

    /// Compare this production to another, first by LHS, then by RHS.
    ///
    /// Mirrors `AbstractAssemblyProduction.compareTo(AbstractAssemblyProduction<NT>)`, which
    /// itself calls the LAZY `AssemblySymbol.compareTo` (`toString().compareTo(that.toString())`)
    /// for `lhs` -- reproduced here via [`AssemblyNonTerminal`]'s `Display` bound -- then
    /// [`AssemblySentential::compare_to`] for `rhs`.
    fn compare_to(&self, that: &dyn AbstractAssemblyProduction) -> std::cmp::Ordering {
        let lhs_ord = self.lhs().to_string().cmp(&that.lhs().to_string());
        if lhs_ord != std::cmp::Ordering::Equal {
            return lhs_ord;
        }
        let that_rhs = that.rhs();
        self.rhs().compare_to(&*that_rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl crate::app::seam_stubs::AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    #[derive(Default, Clone)]
    struct MockSentential {
        symbols: Vec<Arc<dyn crate::app::seam_stubs::AssemblySymbol>>,
    }

    impl AssemblySentential for MockSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn crate::app::seam_stubs::AssemblySymbol>) -> bool {
            self.symbols.push(symbol);
            true
        }

        fn get_symbols(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblySymbol>> {
            self.symbols.clone()
        }

        fn finish(&mut self) {}

        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(MockSentential { symbols: self.symbols[from_index..to_index].to_vec() })
        }

        fn white_space_symbol(&self) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }

        fn make_string_terminal(&self, _str: &str) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }
    }

    /// A minimal implementer, proving object-safety and exercising the default methods' real
    /// (non-trivial) behavior rather than trivially-true assertions.
    struct MockProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl AbstractAssemblyProduction for MockProduction {
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

    fn make(name: &'static str) -> MockProduction {
        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol(name)));
        MockProduction { idx: -1, lhs: Arc::new(MockNonTerminal(name)), rhs: Arc::new(rhs) }
    }

    #[test]
    fn index_defaults_and_can_be_set() {
        let mut prod = make("insn");
        assert_eq!(prod.index(), -1);
        prod.set_index(3);
        assert_eq!(prod.index(), 3);
    }

    #[test]
    fn get_name_delegates_to_lhs() {
        let prod = make("insn");
        assert_eq!(prod.get_name(), "insn");
    }

    #[test]
    fn display_string_matches_java_format() {
        let mut prod = make("insn");
        prod.set_index(2);
        assert_eq!(prod.display_string(), "2. [insn] => insn");
    }

    #[test]
    fn compare_to_orders_by_lhs_then_rhs() {
        let a = make("a");
        let b = make("b");
        assert_eq!(
            AbstractAssemblyProduction::compare_to(&a, &b),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            AbstractAssemblyProduction::compare_to(&b, &a),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            AbstractAssemblyProduction::compare_to(&a, &a),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let prod = make("insn");
        let as_dyn: &dyn AbstractAssemblyProduction = &prod;
        assert_eq!(as_dyn.get_name(), "insn");
        assert_eq!(as_dyn.index(), -1);
    }
}
