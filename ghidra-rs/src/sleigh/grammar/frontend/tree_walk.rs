//! Tree-walk scaffold for the SLEIGH compile pass.
//!
//! `SleighCompiler.g` (1833 lines) is the ANTLR tree grammar that walks the
//! parsed AST and drives the `pcodeCPort` back-end (`SleighCompile`,
//! `PcodeCompile`, symbol tables, etc.). This module provides the Rust
//! skeleton for that pass: a [`SpecVisitor`] trait with one hook per AST node
//! and a [`walk_spec`] driver that performs the traversal in source order.
//!
//! // TODO(sleigh-frontend): flesh out `SleighCompileDriver` to call into the
//! // separately-ported pcodeCPort backend (endian/alignment/space/varnode
//! // registration, token/field symbol creation, constructor building,
//! // p-code semantic compilation). Each visitor hook corresponds to a rule
//! // in SleighCompiler.g (noted per method).

use super::ast::*;

/// Visitor over a parsed [`Spec`], mirroring the rule structure of
/// `SleighCompiler.g`. All methods default to no-ops so implementations only
/// override what they need.
#[allow(unused_variables)]
pub trait SpecVisitor {
    /// `endiandef` rule.
    fn visit_endian(&mut self, endian: &EndianDef) {}

    /// `aligndef` rule.
    fn visit_align(&mut self, align: &AlignDef) {}

    /// `tokendef` rule.
    fn visit_token_def(&mut self, token: &TokenDef) {}

    /// `contextdef` rule.
    fn visit_context_def(&mut self, context: &ContextDef) {}

    /// `spacedef` rule.
    fn visit_space_def(&mut self, space: &SpaceDef) {}

    /// `varnodedef` rule.
    fn visit_varnode_def(&mut self, varnode: &VarnodeDef) {}

    /// `bitrangedef` rule.
    fn visit_bitrange_def(&mut self, bitrange: &BitrangeDef) {}

    /// `pcodeopdef` rule.
    fn visit_pcodeop_def(&mut self, pcodeop: &PcodeOpDef) {}

    /// `valueattach` rule.
    fn visit_value_attach(&mut self, attach: &ValueAttach) {}

    /// `nameattach` rule.
    fn visit_name_attach(&mut self, attach: &NameAttach) {}

    /// `varattach` rule.
    fn visit_var_attach(&mut self, attach: &VarAttach) {}

    /// `macrodef` rule.
    fn visit_macro_def(&mut self, macro_def: &MacroDef) {}

    /// `withblock` rule; called before the block's body items are walked.
    fn enter_with_block(&mut self, with: &WithBlock) {}

    /// Called after the block's body items have been walked.
    fn exit_with_block(&mut self, with: &WithBlock) {}

    /// `constructor` rule.
    fn visit_constructor(&mut self, constructor: &Constructor) {}
}

/// Walks `spec` in source order, dispatching each node to `visitor`.
/// `with` blocks are entered/exited around their nested items.
pub fn walk_spec(spec: &Spec, visitor: &mut dyn SpecVisitor) {
    visitor.visit_endian(&spec.endian);
    walk_items(&spec.items, visitor);
}

fn walk_items(items: &[SpecItem], visitor: &mut dyn SpecVisitor) {
    for item in items {
        match item {
            SpecItem::Definition(def) => walk_definition(def, visitor),
            SpecItem::Constructorlike(c) => walk_constructorlike(c, visitor),
        }
    }
}

fn walk_definition(def: &Definition, visitor: &mut dyn SpecVisitor) {
    match def {
        Definition::Align(a) => visitor.visit_align(a),
        Definition::Token(t) => visitor.visit_token_def(t),
        Definition::Context(c) => visitor.visit_context_def(c),
        Definition::Space(s) => visitor.visit_space_def(s),
        Definition::Varnode(v) => visitor.visit_varnode_def(v),
        Definition::Bitrange(b) => visitor.visit_bitrange_def(b),
        Definition::PcodeOp(p) => visitor.visit_pcodeop_def(p),
        Definition::ValueAttach(a) => visitor.visit_value_attach(a),
        Definition::NameAttach(a) => visitor.visit_name_attach(a),
        Definition::VarAttach(a) => visitor.visit_var_attach(a),
    }
}

fn walk_constructorlike(c: &Constructorlike, visitor: &mut dyn SpecVisitor) {
    match c {
        Constructorlike::Macro(m) => visitor.visit_macro_def(m),
        Constructorlike::With(w) => {
            visitor.enter_with_block(w);
            walk_items(&w.body, visitor);
            visitor.exit_with_block(w);
        }
        Constructorlike::Constructor(ctor) => visitor.visit_constructor(ctor),
    }
}

/// Placeholder for the compile pass that will drive the pcodeCPort backend.
///
/// // TODO(sleigh-frontend): this is a stub. The real driver (mirroring the
/// // actions in SleighCompiler.g) needs the ported `SleighCompile` /
/// // `PcodeCompile` types to register spaces/varnodes/tokens, build
/// // constructor tables, and compile p-code semantic sections.
#[derive(Debug, Default)]
pub struct SleighCompileDriver {
    /// Count of nodes visited; a temporary stand-in so the scaffold is
    /// testable until real backend calls exist.
    pub visited: usize,
}

impl SpecVisitor for SleighCompileDriver {
    fn visit_endian(&mut self, _endian: &EndianDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::set_endian(...)
    }

    fn visit_align(&mut self, _align: &AlignDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::set_alignment(...)
    }

    fn visit_space_def(&mut self, _space: &SpaceDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::new_space(...)
    }

    fn visit_token_def(&mut self, _token: &TokenDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::define_token(...) + fields
    }

    fn visit_context_def(&mut self, _context: &ContextDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::add_context_field(...)
    }

    fn visit_varnode_def(&mut self, _varnode: &VarnodeDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::define_varnodes(...)
    }

    fn visit_bitrange_def(&mut self, _bitrange: &BitrangeDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::define_bitrange(...)
    }

    fn visit_pcodeop_def(&mut self, _pcodeop: &PcodeOpDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::add_user_op(...)
    }

    fn visit_value_attach(&mut self, _attach: &ValueAttach) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::attach_values(...)
    }

    fn visit_name_attach(&mut self, _attach: &NameAttach) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::attach_names(...)
    }

    fn visit_var_attach(&mut self, _attach: &VarAttach) {
        self.visited += 1;
        // TODO(sleigh-frontend): SleighCompile::attach_varnodes(...)
    }

    fn visit_macro_def(&mut self, _macro_def: &MacroDef) {
        self.visited += 1;
        // TODO(sleigh-frontend): PcodeCompile macro compilation
    }

    fn enter_with_block(&mut self, _with: &WithBlock) {
        self.visited += 1;
        // TODO(sleigh-frontend): push with-block table/pattern/context scope
    }

    fn visit_constructor(&mut self, _constructor: &Constructor) {
        self.visited += 1;
        // TODO(sleigh-frontend): build Constructor, display pieces, pattern
        // equation, context mutations, and compile the semantic body.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::frontend::parser::SleighParser;

    #[test]
    fn walk_visits_all_nodes_in_order() {
        #[derive(Default)]
        struct Recorder(Vec<&'static str>);
        impl SpecVisitor for Recorder {
            fn visit_endian(&mut self, _: &EndianDef) {
                self.0.push("endian");
            }
            fn visit_space_def(&mut self, _: &SpaceDef) {
                self.0.push("space");
            }
            fn enter_with_block(&mut self, _: &WithBlock) {
                self.0.push("with-enter");
            }
            fn exit_with_block(&mut self, _: &WithBlock) {
                self.0.push("with-exit");
            }
            fn visit_constructor(&mut self, _: &Constructor) {
                self.0.push("ctor");
            }
        }

        let spec = SleighParser::parse_str(
            "define endian=little; define space ram size=2; \
             with : a=1 [ ] { :nop is b=2 { } }",
        )
        .unwrap();
        let mut rec = Recorder::default();
        walk_spec(&spec, &mut rec);
        assert_eq!(
            rec.0,
            vec!["endian", "space", "with-enter", "ctor", "with-exit"]
        );
    }

    #[test]
    fn compile_driver_stub_counts_nodes() {
        let spec = SleighParser::parse_str(
            "define endian=little; define alignment=1; :nop is a=1 { }",
        )
        .unwrap();
        let mut driver = SleighCompileDriver::default();
        walk_spec(&spec, &mut driver);
        assert_eq!(driver.visited, 3);
    }
}
