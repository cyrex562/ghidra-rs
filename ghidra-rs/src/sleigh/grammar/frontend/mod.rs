//! Hand-written native-Rust front-end for the SLEIGH spec compiler.
//!
//! This module replaces the ANTLR-3 generated code from
//! `Ghidra/Framework/SoftwareModeling/src/main/antlr/ghidra/sleigh/grammar/`
//! with hand-written Rust. Increments 1 and 2 provide:
//!
//! 1. [`preprocessor`] -- full port of `SleighPreprocessor.java` semantics
//!    (`@define`/`@undef`/`@include`/`@if*`/`@else`/`@endif`, `$(VAR)`
//!    expansion, comment handling, `\x08file###line\x08` position markers).
//! 2. [`boolean_expression`] -- hand-written lexer + recursive-descent
//!    evaluator for `BooleanExpression.g` (used by `@if`/`@elif`).
//! 3. [`lexer`] -- tokenizer over the preprocessed stream covering the
//!    `BaseLexer.g` (base mode) token set.
//! 4. [`display_lexer`] -- the DISPLAY sub-lexer mode (`DisplayLexer.g`):
//!    whitespace-significant lexing for constructor display sections, with
//!    `is` reserved and `@$?#` displayable.
//! 5. [`ast`] + [`parser`] -- AST types for the top-level grammar
//!    (`SleighParser.g`) and a recursive-descent parser; constructor display
//!    sections parse to structured printpieces (`DisplayParser.g`), while
//!    semantic bodies remain raw token runs pending the semantic sub-lexer
//!    mode.
//! 6. [`tree_walk`] -- visitor/driver scaffold for the pass that will drive
//!    the separately-ported `pcodeCPort` backend (`SleighCompiler.g`).
//!
//! // TODO(sleigh-frontend): the semantic-mode sub-lexer (SemanticLexer.g)
//! // and its parser (SemanticParser.g) are not yet ported.

pub mod ast;
pub mod boolean_expression;
pub mod display_lexer;
pub mod lexer;
pub mod parser;
pub mod preprocessor;
pub mod preprocessor_definitions;
pub mod tree_walk;

pub use ast::*;
pub use boolean_expression::{evaluate_boolean_expression, BooleanExpressionEnvironment};
pub use display_lexer::DisplayLexer;
pub use lexer::{BaseLexer, TokenType, HIDDEN_CHANNEL};
pub use parser::{ParseError, SleighParser};
pub use preprocessor::{PreprocessorError, PreprocessorWriter, SleighPreprocessor};
pub use preprocessor_definitions::{HashMapPreprocessorDefinitions, PreprocessorDefinitions};
pub use tree_walk::{walk_spec, SpecVisitor};

#[cfg(test)]
mod smoke_tests {
    //! End-to-end checks against real specs from `orig_src` (skipped when the
    //! reference sources are not checked out next to the crate).

    use std::path::PathBuf;

    use super::lexer::{BaseLexer, TokenType};
    use super::parser::SleighParser;
    use super::preprocessor::SleighPreprocessor;
    use super::preprocessor_definitions::HashMapPreprocessorDefinitions;
    use crate::sleigh::grammar::LineArrayListWriter;

    fn orig_src(rel: &str) -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("orig_src")
            .join(rel);
        p.is_file().then_some(p)
    }

    #[test]
    fn preprocess_lex_and_parse_8085_slaspec() {
        let Some(path) = orig_src("Ghidra/Processors/8085/data/languages/8085.slaspec") else {
            eprintln!("skipping: orig_src not present");
            return;
        };
        let mut defs = HashMapPreprocessorDefinitions::new();
        let mut pp = SleighPreprocessor::new(&mut defs, &path);
        let mut writer = LineArrayListWriter::new();
        pp.process(&mut writer).expect("preprocess 8085.slaspec");
        let text = writer
            .get_lines()
            .join("\n");

        let mut lexer = BaseLexer::new(&text);
        let tokens = lexer.tokenize_default_channel();
        assert!(
            lexer.errors().is_empty(),
            "base-mode lexing errors: {:?}",
            lexer.errors()
        );
        assert!(tokens.len() > 1000, "unexpectedly few tokens: {}", tokens.len());

        // Position markers must have been routed off the default channel.
        assert!(tokens
            .iter()
            .all(|t| t.token_type() != TokenType::PpPosition.as_i32()));

        let spec = SleighParser::parse_str(&text).expect("parse 8085.slaspec");
        assert!(spec.items.len() > 100, "items: {}", spec.items.len());

        // Display sections come out as structured printpieces now.
        use super::ast::{Constructorlike, PrintPiece, SpecItem};
        let ctors: Vec<_> = spec
            .items
            .iter()
            .filter_map(|i| match i {
                SpecItem::Constructorlike(Constructorlike::Constructor(c)) => Some(c),
                _ => None,
            })
            .collect();
        assert!(ctors.len() > 50, "constructors: {}", ctors.len());

        // ':MOV reg3_3,reg0_3  is ...' -- identifiers, literal comma, and
        // significant whitespace (including the trailing run before 'is').
        let mov = ctors
            .iter()
            .find(|c| c.display.pieces.first() == Some(&PrintPiece::Identifier("MOV".into())))
            .expect("a MOV constructor");
        assert_eq!(
            mov.display.pieces,
            vec![
                PrintPiece::Identifier("MOV".into()),
                PrintPiece::Whitespace(" ".into()),
                PrintPiece::Identifier("reg3_3".into()),
                PrintPiece::Literal(",".into()),
                PrintPiece::Identifier("reg0_3".into()),
                PrintPiece::Whitespace("  ".into()),
            ]
        );

        // ':J^cc Addr16  is ...' -- '^' concatenation survives as a piece.
        let jcc = ctors
            .iter()
            .find(|c| c.display.pieces.first() == Some(&PrintPiece::Identifier("J".into())))
            .expect("the J^cc constructor");
        assert_eq!(
            jcc.display.pieces,
            vec![
                PrintPiece::Identifier("J".into()),
                PrintPiece::Concatenate,
                PrintPiece::Identifier("cc".into()),
                PrintPiece::Whitespace(" ".into()),
                PrintPiece::Identifier("Addr16".into()),
                PrintPiece::Whitespace("  ".into()),
            ]
        );
    }

    #[test]
    fn preprocess_skel_slaspec_with_include() {
        let Some(path) = orig_src("GhidraBuild/Skeleton/data/languages/skel.slaspec") else {
            eprintln!("skipping: orig_src not present");
            return;
        };
        let mut defs = HashMapPreprocessorDefinitions::new();
        let mut pp = SleighPreprocessor::new(&mut defs, &path);
        let mut writer = LineArrayListWriter::new();
        pp.process(&mut writer).expect("preprocess skel.slaspec");
        // skel.slaspec @defines C_flag et al. and @includes skel.sinc.
        assert_eq!(
            super::preprocessor_definitions::PreprocessorDefinitions::lookup(&defs, "C_flag")
                .as_deref(),
            Some("F[0,1]")
        );
        let text = writer.get_lines().join("\n");
        assert!(text.contains("define endian=little;"));
    }
}
