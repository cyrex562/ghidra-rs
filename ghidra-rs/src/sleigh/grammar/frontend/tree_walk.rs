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

    /// `display`/`pieces` rules (DisplayParser.g `OP_DISPLAY` subtree);
    /// called right after [`SpecVisitor::visit_constructor`] with the same
    /// constructor's structured printpieces.
    fn visit_display(&mut self, display: &DisplaySection) {}

    /// `semanticbody`/`semantic` rules (SemanticParser.g `OP_SEMANTIC`
    /// subtree); called after [`SpecVisitor::visit_macro_def`] with a
    /// macro's body, and after [`SpecVisitor::visit_display`] with a
    /// constructor's body (not called for `unimpl` constructors). The
    /// body's statements are then walked via
    /// [`SpecVisitor::visit_pcode_stmt`].
    fn visit_semantic_body(&mut self, body: &SemanticBody) {}

    /// One `statement` of a semantic body, in source order (the
    /// per-statement rules of SemanticParser.g / SleighCompiler.g's
    /// `code_block` walk).
    fn visit_pcode_stmt(&mut self, stmt: &PcodeStmt) {}
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
        Constructorlike::Macro(m) => {
            visitor.visit_macro_def(m);
            walk_semantic_body(&m.body, visitor);
        }
        Constructorlike::With(w) => {
            visitor.enter_with_block(w);
            walk_items(&w.body, visitor);
            visitor.exit_with_block(w);
        }
        Constructorlike::Constructor(ctor) => {
            visitor.visit_constructor(ctor);
            visitor.visit_display(&ctor.display);
            if let CtorSemantic::Body(body) = &ctor.semantic {
                walk_semantic_body(body, visitor);
            }
        }
    }
}

fn walk_semantic_body(body: &SemanticBody, visitor: &mut dyn SpecVisitor) {
    visitor.visit_semantic_body(body);
    for stmt in &body.statements {
        visitor.visit_pcode_stmt(stmt);
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
        // TODO(sleigh-frontend): build Constructor, pattern equation,
        // context mutations, and compile the semantic body.
    }

    fn visit_display(&mut self, _display: &DisplaySection) {
        self.visited += 1;
        // TODO(sleigh-frontend): feed the structured printpieces to the
        // backend Constructor (mnemonic/addSyntax/addOperand equivalents of
        // SleighCompiler.g's display rule); '^' pieces suppress the
        // separating whitespace, whitespace pieces collapse to one space.
    }

    fn visit_semantic_body(&mut self, _body: &SemanticBody) {
        self.visited += 1;
        // TODO(sleigh-frontend): open the PcodeCompile section context
        // (SleighCompiler.g's `semantic` rule: pcode.newSectionSymbol /
        // ConstructTpl assembly for the constructor or macro).
    }

    fn visit_pcode_stmt(&mut self, _stmt: &PcodeStmt) {
        self.visited += 1;
        // TODO(sleigh-frontend): compile the statement via the ported
        // pcodeCPort backend (PcodeCompile::createOp / newOutput /
        // assignBitRange / createStore / matchers for goto/call/return/
        // export/build/crossbuild, label symbol resolution, macro
        // invocation expansion).
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
            "define endian=little; define alignment=1; :nop is a=1 { A = 1; }",
        )
        .unwrap();
        let mut driver = SleighCompileDriver::default();
        walk_spec(&spec, &mut driver);
        // endian + alignment + constructor + its display section + its
        // semantic body + the body's one statement.
        assert_eq!(driver.visited, 6);
    }

    #[test]
    fn semantic_hooks_fire_for_macros_and_constructors() {
        #[derive(Default)]
        struct SemGrabber {
            bodies: usize,
            stmts: Vec<PcodeStmt>,
        }
        impl SpecVisitor for SemGrabber {
            fn visit_semantic_body(&mut self, _body: &SemanticBody) {
                self.bodies += 1;
            }
            fn visit_pcode_stmt(&mut self, stmt: &PcodeStmt) {
                self.stmts.push(stmt.clone());
            }
        }

        let spec = SleighParser::parse_str(
            "define endian=little; \
             macro set(a) { a = 1; } \
             :nop is a=1 { goto inst_next; } \
             :bad is a=2 unimpl",
        )
        .unwrap();
        let mut grabber = SemGrabber::default();
        walk_spec(&spec, &mut grabber);
        // Macro body + one constructor body; unimpl has none.
        assert_eq!(grabber.bodies, 2);
        assert_eq!(grabber.stmts.len(), 2);
        assert!(matches!(grabber.stmts[0], PcodeStmt::Assign { .. }));
        assert!(matches!(
            grabber.stmts[1],
            PcodeStmt::Goto {
                dest: JumpDest::Symbol(_)
            }
        ));
    }

    #[test]
    fn display_hook_sees_structured_pieces() {
        #[derive(Default)]
        struct DisplayGrabber(Vec<Vec<PrintPiece>>);
        impl SpecVisitor for DisplayGrabber {
            fn visit_display(&mut self, display: &DisplaySection) {
                self.0.push(display.pieces.clone());
            }
        }

        let spec = SleighParser::parse_str(
            "define endian=little; :J^cc addr is a=1 { }",
        )
        .unwrap();
        let mut grabber = DisplayGrabber::default();
        walk_spec(&spec, &mut grabber);
        assert_eq!(grabber.0.len(), 1);
        assert_eq!(
            grabber.0[0],
            vec![
                PrintPiece::Identifier("J".into()),
                PrintPiece::Concatenate,
                PrintPiece::Identifier("cc".into()),
                PrintPiece::Whitespace(" ".into()),
                PrintPiece::Identifier("addr".into()),
                PrintPiece::Whitespace(" ".into()),
            ]
        );
    }
}
