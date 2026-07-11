//! Hand-written native-Rust front-end for the SLEIGH spec compiler.
//!
//! This module replaces the ANTLR-3 generated code from
//! `Ghidra/Framework/SoftwareModeling/src/main/antlr/ghidra/sleigh/grammar/`
//! with hand-written Rust. Increment 1 provides:
//!
//! 1. [`preprocessor`] -- full port of `SleighPreprocessor.java` semantics
//!    (`@define`/`@undef`/`@include`/`@if*`/`@else`/`@endif`, `$(VAR)`
//!    expansion, comment handling, `\x08file###line\x08` position markers).
//! 2. [`boolean_expression`] -- hand-written lexer + recursive-descent
//!    evaluator for `BooleanExpression.g` (used by `@if`/`@elif`).
//! 3. [`lexer`] -- tokenizer over the preprocessed stream covering the
//!    `BaseLexer.g` (base mode) token set.
//! 4. [`ast`] + [`parser`] -- AST types for the top-level grammar
//!    (`SleighParser.g`) and a recursive-descent parser; simple definitions
//!    are implemented, constructor display/semantic bodies are captured as
//!    raw token runs pending the display/semantic sub-lexer modes.
//! 5. [`tree_walk`] -- visitor/driver scaffold for the pass that will drive
//!    the separately-ported `pcodeCPort` backend (`SleighCompiler.g`).
//!
//! // TODO(sleigh-frontend): display-mode and semantic-mode sub-lexers
//! // (DisplayLexer.g / SemanticLexer.g) and their parsers are not yet ported.

pub mod ast;
pub mod boolean_expression;
pub mod lexer;
pub mod parser;
pub mod preprocessor;
pub mod preprocessor_definitions;
pub mod tree_walk;

pub use ast::*;
pub use boolean_expression::{evaluate_boolean_expression, BooleanExpressionEnvironment};
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

        let spec = SleighParser::new(tokens)
            .parse_spec()
            .expect("parse 8085.slaspec");
        assert!(spec.items.len() > 100, "items: {}", spec.items.len());
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
