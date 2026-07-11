//! Port of `ghidra.sleigh.grammar.SleighPreprocessor`.
//!
//! Processes a `.slaspec`/`.sinc` file line by line, handling:
//!
//! - `@include "file"` (recursive, relative to the including file)
//! - `@define KEY "value"` / `@define KEY value` / `@define KEY`
//! - `@undef KEY`
//! - `@ifdef KEY` / `@ifndef KEY` / `@if <expr>` / `@elif <expr>` /
//!   `@else` / `@endif`
//! - `$(VAR)` macro expansion
//! - comment handling (full-line comments are blanked; directive lines are
//!   echoed back commented out; suppressed lines are emitted as `#`-prefixed
//!   lines so line numbering is preserved)
//! - `\x08filename###lineno\x08` position markers (unless `compatible`),
//!   which the lexer's `PP_POSITION` rule later consumes to rebuild
//!   original-source locations.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::sleigh::grammar::{
    ConditionalHelper, FakeLineArrayListWriter, LineArrayListWriter, PreprocessorException,
};
use crate::util::Msg;

use super::boolean_expression::{evaluate_boolean_expression, BooleanExpressionEnvironment};
use super::preprocessor_definitions::PreprocessorDefinitions;

// Directive patterns, mirroring the Java `Pattern` constants. Java uses
// `Matcher.matches()` (whole-string match), so the patterns are anchored here.
static INCLUDE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*@include\s+"(.*)"\s*$"#).unwrap());
static DEFINE1: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^\s*@define\s+([0-9A-Z_a-z]+)\s+"(.*)"\s*$"#).unwrap());
static DEFINE2: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*@define\s+([0-9A-Z_a-z]+)\s+(\S+)\s*$").unwrap());
static DEFINE3: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*@define\s+([0-9A-Z_a-z]+)\s*$").unwrap());
static UNDEF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@undef\s+([0-9A-Z_a-z]+)\s*$").unwrap());
static IFDEF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@ifdef\s+([0-9A-Z_a-z]+)\s*$").unwrap());
static IFNDEF: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*@ifndef\s+([0-9A-Z_a-z]+)\s*$").unwrap());
static IF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@if\s+(.*)$").unwrap());
static ELIF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@elif\s+(.*)$").unwrap());
static ENDIF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@endif\s*$").unwrap());
static ELSE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@else\s*$").unwrap());
static FULL_LINE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*#.*").unwrap());
static DIRECTIVE_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"#.*").unwrap());
static ABSOLUTE_DRIVE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z_0-9]+:.*").unwrap());
static EXPANSION: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\$\(([0-9A-Z_a-z]+)\))").unwrap());

/// Error produced while preprocessing.
#[derive(Debug, thiserror::Error)]
pub enum PreprocessorError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Preprocessor(#[from] PreprocessorException),
}

/// Line-oriented output sink for the preprocessor.
///
/// Decouples the preprocessor from a concrete writer, mirroring the Java
/// `LineArrayListWriter` / `FakeLineArrayListWriter` split (the fake writer is
/// used by [`SleighPreprocessor::scan_for_timestamp`]).
pub trait PreprocessorWriter {
    fn write(&mut self, s: &str);
    fn new_line(&mut self);
    fn flush(&mut self) {}
}

impl PreprocessorWriter for LineArrayListWriter {
    fn write(&mut self, s: &str) {
        LineArrayListWriter::write(self, s);
    }

    fn new_line(&mut self) {
        LineArrayListWriter::new_line(self);
    }
}

impl PreprocessorWriter for FakeLineArrayListWriter {
    fn write(&mut self, _s: &str) {}

    fn new_line(&mut self) {}
}

/// Adapter that resolves `@if`-expression macros from the definitions store
/// and counts reported errors, standing in for the Java pattern where
/// `SleighPreprocessor` itself implements `ExpressionEnvironment`.
struct DefinitionsExprEnv<'a> {
    definitions: &'a dyn PreprocessorDefinitions,
    filename: String,
    lineno: i32,
    errors: usize,
}

impl BooleanExpressionEnvironment for DefinitionsExprEnv<'_> {
    fn lookup_variable(&self, variable: &str) -> Option<String> {
        self.definitions.lookup(variable)
    }

    fn report_expression_error(&mut self, msg: &str) {
        self.errors += 1;
        Msg::error(
            "SleighPreprocessor",
            &format!("{}:{}: {}", self.filename, self.lineno, msg),
        );
    }
}

/// Per-file processing state (Java keeps one `SleighPreprocessor` instance per
/// file; this port keeps one struct and a per-file state frame instead).
struct FileState {
    filename: String,
    lineno: i32,
    overall_lineno: i32,
    ifstack: Vec<ConditionalHelper>,
    error_count: usize,
}

impl FileState {
    fn err(&self, message: &str, line: &str) -> PreprocessorException {
        PreprocessorException::new(
            message,
            self.filename.clone(),
            self.lineno,
            self.overall_lineno,
            line,
        )
    }

    fn top(&mut self) -> &mut ConditionalHelper {
        self.ifstack.last_mut().expect("ifstack never empty")
    }

    fn is_copy(&self) -> bool {
        self.ifstack.iter().all(ConditionalHelper::copy)
    }

    fn enterif(&mut self) {
        let copy = self.is_copy();
        self.ifstack.push(ConditionalHelper::new(true, false, false, copy));
    }

    fn leaveif(&mut self, line: &str) -> Result<(), PreprocessorException> {
        if !self.top().inif() {
            return Err(self.err("not in IF* directive", line));
        }
        self.ifstack.pop();
        Ok(())
    }

    fn enterelse(&mut self, line: &str) -> Result<(), PreprocessorException> {
        if !self.top().inif() {
            return Err(self.err("else outside of IF* directive", line));
        }
        if self.top().sawelse() {
            return Err(self.err("duplicate else directive", line));
        }
        self.top().set_sawelse(true);
        Ok(())
    }

    fn enterelif(&mut self, line: &str) -> Result<(), PreprocessorException> {
        if !self.top().inif() {
            return Err(self.err("elif outside of IF* directive", line));
        }
        if self.top().sawelse() {
            return Err(self.err("already saw else directive", line));
        }
        Ok(())
    }
}

/// Native-Rust port of `SleighPreprocessor.java`.
pub struct SleighPreprocessor<'d> {
    definitions: &'d mut dyn PreprocessorDefinitions,
    file: PathBuf,
    compatible: bool,
    latest_timestamp: u64,
}

impl<'d> SleighPreprocessor<'d> {
    pub fn new(definitions: &'d mut dyn PreprocessorDefinitions, input_file: impl Into<PathBuf>) -> Self {
        let file = input_file.into();
        let mut pp = Self {
            definitions,
            file,
            compatible: false,
            latest_timestamp: 0,
        };
        let file = pp.file.clone();
        pp.update_latest_date(&file);
        pp
    }

    /// Mirrors `setCompatible`: when compatible, no `\x08` position markers or
    /// expansion markers are emitted.
    pub fn set_compatible(&mut self, compatible: bool) {
        self.compatible = compatible;
    }

    pub fn is_compatible(&self) -> bool {
        self.compatible
    }

    /// Preprocesses the input file (and its includes) into `writer`.
    pub fn process(&mut self, writer: &mut dyn PreprocessorWriter) -> Result<(), PreprocessorError> {
        let file = self.file.clone();
        self.process_internal(writer, &file, 1)
    }

    /// Mirrors `scanForTimestamp`: runs the full preprocess against a
    /// discarding writer and returns the latest modification time (millis
    /// since the Unix epoch) across the file and everything it includes.
    pub fn scan_for_timestamp(&mut self) -> Result<u64, PreprocessorError> {
        let mut fake = FakeLineArrayListWriter::new();
        let file = self.file.clone();
        self.process_internal(&mut fake, &file, 1)?;
        Ok(self.latest_timestamp)
    }

    fn update_latest_date(&mut self, file: &Path) {
        if let Ok(meta) = std::fs::metadata(file) {
            if let Ok(modified) = meta.modified() {
                if let Ok(dur) = modified.duration_since(UNIX_EPOCH) {
                    let millis = dur.as_millis() as u64;
                    if millis > self.latest_timestamp {
                        self.latest_timestamp = millis;
                    }
                }
            }
        }
    }

    fn process_internal(
        &mut self,
        writer: &mut dyn PreprocessorWriter,
        file: &Path,
        overall_line: i32,
    ) -> Result<(), PreprocessorError> {
        self.update_latest_date(file);

        let filename = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());

        let mut state = FileState {
            filename: filename.clone(),
            lineno: 1,
            overall_lineno: overall_line,
            ifstack: vec![ConditionalHelper::new(false, false, false, true)],
            error_count: 0,
        };

        // Java reads with ISO-8859-1; every byte maps 1:1 to the first 256
        // Unicode code points.
        let bytes = std::fs::read(file)?;
        let content: String = bytes.iter().map(|&b| b as char).collect();

        self.output_position(writer, &state);

        for raw_line in read_lines(&content) {
            let orig_line = raw_line;

            // Remove confirmed full-line comments.
            let line = FULL_LINE_COMMENT.replace(raw_line, "").into_owned();

            if line.starts_with('@') {
                // Remove any comments in the preprocessor directive.
                let line = DIRECTIVE_COMMENT.replace(&line, "").into_owned();

                if let Some(m) = INCLUDE.captures(&line) {
                    if state.is_copy() {
                        let include_file_name = self.handle_variables(&m[1], true, &state, &line)?;
                        let is_absolute = include_file_name.starts_with('/')
                            || include_file_name.starts_with('\\')
                            || ABSOLUTE_DRIVE.is_match(&include_file_name);
                        let include_file = if is_absolute {
                            PathBuf::from(&include_file_name)
                        } else {
                            file.parent()
                                .unwrap_or_else(|| Path::new(""))
                                .join(&include_file_name)
                        };
                        // TODO(sleigh-frontend): Java also verifies the path is
                        // case-dependent-correct (FileUtilities.existsAndIsCaseDependent);
                        // only plain existence is checked here.
                        if !include_file.is_file() {
                            return Err(state
                                .err(
                                    &format!(
                                        "included file \"{}\": file does not exist",
                                        include_file.display()
                                    ),
                                    &line,
                                )
                                .into());
                        }
                        self.process_internal(writer, &include_file, state.overall_lineno)?;
                        // Increment the position now because we already
                        // replaced the include.
                        state.lineno += 1;
                        state.overall_lineno += 1;
                        self.output_position(writer, &state);
                        // The one directive we skip printing a blank line for.
                        continue;
                    }
                } else if let Some(m) = DEFINE1.captures(&line) {
                    if state.is_copy() {
                        self.definitions.set(&m[1], &m[2]);
                    }
                } else if let Some(m) = DEFINE2.captures(&line) {
                    if state.is_copy() {
                        self.definitions.set(&m[1], &m[2]);
                    }
                } else if let Some(m) = DEFINE3.captures(&line) {
                    if state.is_copy() {
                        self.definitions.set(&m[1], "");
                    }
                } else if let Some(m) = UNDEF.captures(&line) {
                    if state.is_copy() {
                        self.definitions.undefine(&m[1]);
                    }
                } else if let Some(m) = IFDEF.captures(&line) {
                    state.enterif();
                    if self.definitions.lookup(&m[1]).is_none() {
                        state.top().set_copy(false);
                    } else {
                        state.top().set_handled(true);
                    }
                } else if let Some(m) = IFNDEF.captures(&line) {
                    state.enterif();
                    if self.definitions.lookup(&m[1]).is_some() {
                        state.top().set_copy(false);
                    } else {
                        state.top().set_handled(true);
                    }
                } else if let Some(m) = IF.captures(&line) {
                    state.enterif();
                    self.handle_expression(&m[1], &mut state, &line)?;
                } else if let Some(m) = ELIF.captures(&line) {
                    state.enterelif(&line)?;
                    self.handle_expression(&m[1], &mut state, &line)?;
                } else if ENDIF.is_match(&line) {
                    state.leaveif(&line)?;
                } else if ELSE.is_match(&line) {
                    state.enterelse(&line)?;
                    let handled = state.top().handled();
                    state.top().set_copy(!handled);
                } else {
                    return Err(state.err("unrecognized preprocessor directive", &line).into());
                }
                // Comment the directive out in the output.
                writer.write(&format!("#{orig_line}"));
                writer.new_line();
            } else if state.is_copy() {
                let expanded = self.handle_variables(&line, self.compatible, &state, &line)?;
                writer.write(&expanded);
                writer.new_line();
            } else {
                // Replace non-copied text with a commented-out line so that
                // line numbering is preserved.
                writer.write(&format!("#{line}"));
                writer.new_line();
            }
            state.lineno += 1;
            state.overall_lineno += 1;
        }

        writer.flush();
        if state.error_count > 0 {
            return Err(PreprocessorException::new(
                "Errors during preprocessing",
                filename,
                overall_line,
                0,
                "",
            )
            .into());
        }
        Ok(())
    }

    /// Mirrors `handleExpression`: evaluates an `@if`/`@elif` expression and
    /// updates the top conditional frame.
    fn handle_expression(
        &mut self,
        expression: &str,
        state: &mut FileState,
        line: &str,
    ) -> Result<(), PreprocessorError> {
        if state.top().handled() {
            state.top().set_copy(false);
            return Ok(());
        }
        let mut env = DefinitionsExprEnv {
            definitions: &*self.definitions,
            filename: state.filename.clone(),
            lineno: state.lineno,
            errors: 0,
        };
        let result = evaluate_boolean_expression(expression, &mut env);
        state.error_count += env.errors;
        match result {
            // Syntax errors surface as PreprocessorExceptions (Java lets the
            // ANTLR RecognitionException propagate instead).
            Err(msg) => Err(state.err(&msg, line).into()),
            Ok(false) => {
                state.top().set_copy(false);
                Ok(())
            }
            Ok(true) => {
                state.top().set_copy(true);
                state.top().set_handled(true);
                Ok(())
            }
        }
    }

    /// Mirrors `handleVariables`: expands every `$(VAR)` occurrence. Unless
    /// `be_compatible`, each expansion is preceded by a
    /// `\x08$(VAR)\x08` marker so downstream tooling can recover the original
    /// text.
    fn handle_variables(
        &self,
        input: &str,
        be_compatible: bool,
        state: &FileState,
        line: &str,
    ) -> Result<String, PreprocessorException> {
        let mut input = input.to_string();
        let mut sb = String::new();
        while let Some(m) = EXPANSION.captures(&input) {
            let whole = m.get(1).unwrap();
            let variable = &m[2];
            let value = self.definitions.lookup(variable).ok_or_else(|| {
                state.err(&format!("unknown variable: {variable}"), line)
            })?;
            sb.push_str(&input[..whole.start()]);
            if !be_compatible {
                sb.push('\u{8}');
                sb.push_str(whole.as_str());
                sb.push('\u{8}');
            }
            sb.push_str(&value);
            input = input[whole.end()..].to_string();
        }
        sb.push_str(&input);
        Ok(sb)
    }

    /// Mirrors `outputPosition`: emits a `\x08filename###lineno\x08` marker
    /// (consumed later by the lexer's `PP_POSITION` rule) unless compatible.
    fn output_position(&self, writer: &mut dyn PreprocessorWriter, state: &FileState) {
        if !self.compatible {
            writer.write(&format!("\u{8}{}###{}\u{8}", state.filename, state.lineno));
        }
    }
}

/// Splits `content` the way Java's `BufferedReader.readLine` does: lines are
/// terminated by `\n`, `\r`, or `\r\n`, terminators are dropped, and a final
/// unterminated line is still yielded.
fn read_lines(content: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = content.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(&content[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&content[start..i]);
                i += 1;
                if i < bytes.len() && bytes[i] == b'\n' {
                    i += 1;
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        lines.push(&content[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::frontend::preprocessor_definitions::HashMapPreprocessorDefinitions;
    use std::io::Write as IoWrite;

    /// Writes `content` to `name` inside `dir` and returns the path.
    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    /// Preprocesses `content` (as file `main.slaspec` in a temp dir, with
    /// optional sibling files) and returns the output lines.
    fn preprocess_with(
        content: &str,
        siblings: &[(&str, &str)],
        compatible: bool,
    ) -> Result<Vec<String>, PreprocessorError> {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in siblings {
            write_file(dir.path(), name, text);
        }
        let main = write_file(dir.path(), "main.slaspec", content);
        let mut defs = HashMapPreprocessorDefinitions::new();
        let mut pp = SleighPreprocessor::new(&mut defs, &main);
        pp.set_compatible(compatible);
        let mut writer = LineArrayListWriter::new();
        pp.process(&mut writer)?;
        Ok(writer.get_lines())
    }

    fn preprocess(content: &str) -> Vec<String> {
        preprocess_with(content, &[], true).unwrap()
    }

    #[test]
    fn plain_text_is_copied() {
        let lines = preprocess("define endian=little;\n");
        assert_eq!(lines[0], "define endian=little;");
    }

    #[test]
    fn define_and_expand() {
        let lines = preprocess("@define FOO 42\nvalue is $(FOO);\n");
        assert_eq!(lines[0], "#@define FOO 42");
        assert_eq!(lines[1], "value is 42;");
    }

    #[test]
    fn define_quoted_value_keeps_spaces() {
        let lines = preprocess("@define REG \"F[0,1]\"\nx $(REG) y\n");
        assert_eq!(lines[1], "x F[0,1] y");
    }

    #[test]
    fn define_without_value_defines_empty() {
        let lines = preprocess("@define FLAG\na$(FLAG)b\n");
        assert_eq!(lines[1], "ab");
    }

    #[test]
    fn multiple_expansions_on_one_line() {
        let lines = preprocess("@define A 1\n@define B 2\n$(A)+$(B)=$(A)$(B)\n");
        assert_eq!(lines[2], "1+2=12");
    }

    #[test]
    fn undef_removes_definition() {
        let err = preprocess_with("@define FOO 1\n@undef FOO\n$(FOO)\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("unknown variable: FOO"), "{err}");
    }

    #[test]
    fn unknown_variable_is_error() {
        let err = preprocess_with("$(NOPE)\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("unknown variable: NOPE"), "{err}");
    }

    #[test]
    fn ifdef_true_copies_and_false_suppresses() {
        let src = "@define FOO 1\n@ifdef FOO\nyes\n@endif\n@ifdef BAR\nno\n@endif\n";
        let lines = preprocess(src);
        assert_eq!(lines[0], "#@define FOO 1");
        assert_eq!(lines[1], "#@ifdef FOO");
        assert_eq!(lines[2], "yes");
        assert_eq!(lines[3], "#@endif");
        assert_eq!(lines[4], "#@ifdef BAR");
        assert_eq!(lines[5], "#no");
        assert_eq!(lines[6], "#@endif");
    }

    #[test]
    fn ifndef_inverts() {
        let lines = preprocess("@ifndef FOO\nvisible\n@else\nhidden\n@endif\n");
        assert_eq!(lines[1], "visible");
        assert_eq!(lines[3], "#hidden");
    }

    #[test]
    fn else_takes_unhandled_branch() {
        let lines = preprocess("@ifdef FOO\nthen\n@else\nelse\n@endif\n");
        assert_eq!(lines[1], "#then");
        assert_eq!(lines[3], "else");
    }

    #[test]
    fn elif_chain_selects_first_true_branch() {
        let src = "@define MODE b\n\
                   @if MODE == \"a\"\nbranch-a\n\
                   @elif MODE == \"b\"\nbranch-b\n\
                   @elif defined(MODE)\nbranch-c\n\
                   @else\nbranch-d\n@endif\n";
        let lines = preprocess(src);
        assert_eq!(lines[2], "#branch-a");
        assert_eq!(lines[4], "branch-b");
        assert_eq!(lines[6], "#branch-c");
        assert_eq!(lines[8], "#branch-d");
    }

    #[test]
    fn if_with_boolean_operators() {
        let src = "@define A 1\n@if defined(A) && !(defined(B))\nboth\n@endif\n";
        let lines = preprocess(src);
        assert_eq!(lines[2], "both");
    }

    #[test]
    fn nested_conditionals_respect_outer_suppression() {
        let src = "@ifdef MISSING\n@ifndef ALSO_MISSING\ninner\n@endif\n@endif\nafter\n";
        let lines = preprocess(src);
        assert_eq!(lines[2], "#inner");
        assert_eq!(lines[5], "after");
    }

    #[test]
    fn defines_inside_suppressed_region_are_ignored() {
        let src = "@ifdef MISSING\n@define FOO 1\n@endif\n@ifdef FOO\nno\n@endif\n";
        let lines = preprocess(src);
        assert_eq!(lines[4], "#no");
    }

    #[test]
    fn endif_without_if_is_error() {
        let err = preprocess_with("@endif\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("not in IF* directive"), "{err}");
    }

    #[test]
    fn else_without_if_is_error() {
        let err = preprocess_with("@else\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("else outside of IF* directive"), "{err}");
    }

    #[test]
    fn duplicate_else_is_error() {
        let err =
            preprocess_with("@ifdef X\n@else\n@else\n@endif\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("duplicate else directive"), "{err}");
    }

    #[test]
    fn elif_after_else_is_error() {
        let err = preprocess_with(
            "@ifdef X\n@else\n@elif defined(X)\n@endif\n",
            &[],
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already saw else directive"), "{err}");
    }

    #[test]
    fn unrecognized_directive_is_error() {
        let err = preprocess_with("@bogus stuff\n", &[], true).unwrap_err();
        assert!(
            err.to_string().contains("unrecognized preprocessor directive"),
            "{err}"
        );
    }

    #[test]
    fn full_line_comments_are_blanked() {
        let lines = preprocess("# a comment with $(UNDEFINED)\ntext\n");
        assert_eq!(lines[0], "");
        assert_eq!(lines[1], "text");
    }

    #[test]
    fn comments_in_directives_are_stripped() {
        let lines = preprocess("@define FOO 1 # trailing comment\n$(FOO)\n");
        assert_eq!(lines[1], "1");
    }

    #[test]
    fn include_splices_file_contents() {
        let lines = preprocess_with(
            "before\n@include \"inc.sinc\"\nafter\n",
            &[("inc.sinc", "included-line\n")],
            true,
        )
        .unwrap();
        assert_eq!(lines[0], "before");
        assert_eq!(lines[1], "included-line");
        // Include directive itself produces no echoed line; "after" follows.
        assert_eq!(lines[2], "after");
    }

    #[test]
    fn include_sees_definitions_and_exports_them() {
        let lines = preprocess_with(
            "@define OUTER out\n@include \"inc.sinc\"\n$(INNER)\n",
            &[("inc.sinc", "@define INNER in\n$(OUTER)\n")],
            true,
        )
        .unwrap();
        assert_eq!(lines[2], "out");
        assert_eq!(lines[3], "in");
    }

    #[test]
    fn include_missing_file_is_error() {
        let err =
            preprocess_with("@include \"nope.sinc\"\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("included file"), "{err}");
    }

    #[test]
    fn include_filename_supports_expansion() {
        let lines = preprocess_with(
            "@define NAME inc\n@include \"$(NAME).sinc\"\nend\n",
            &[("inc.sinc", "spliced\n")],
            true,
        )
        .unwrap();
        assert_eq!(lines[1], "spliced");
    }

    #[test]
    fn include_inside_false_branch_is_skipped() {
        let lines = preprocess_with(
            "@ifdef MISSING\n@include \"nope.sinc\"\n@endif\nend\n",
            &[],
            true,
        )
        .unwrap();
        // Skipped include is echoed as a comment like any other directive.
        assert_eq!(lines[1], "#@include \"nope.sinc\"");
        assert_eq!(lines[3], "end");
    }

    #[test]
    fn position_markers_emitted_when_not_compatible() {
        let lines = preprocess_with("text\n", &[], false).unwrap();
        assert_eq!(lines[0], "\u{8}main.slaspec###1\u{8}text");
    }

    #[test]
    fn position_markers_after_include_in_incompatible_mode() {
        let lines = preprocess_with(
            "@include \"inc.sinc\"\nafter\n",
            &[("inc.sinc", "inner\n")],
            false,
        )
        .unwrap();
        // Line 0: main position marker then (line 1 was the include) the
        // included file's own position marker and content.
        assert_eq!(lines[0], "\u{8}main.slaspec###1\u{8}\u{8}inc.sinc###1\u{8}inner");
        // After the include, the parent re-emits its position (lineno 2).
        assert_eq!(lines[1], "\u{8}main.slaspec###2\u{8}after");
    }

    #[test]
    fn expansion_markers_in_incompatible_mode() {
        let lines =
            preprocess_with("@define A 7\nx=$(A)\n", &[], false).unwrap();
        // Position markers only appear at file start and after includes; the
        // expansion itself is bracketed by \x08$(A)\x08.
        assert_eq!(lines[0], "\u{8}main.slaspec###1\u{8}#@define A 7");
        assert_eq!(lines[1], "x=\u{8}$(A)\u{8}7");
    }

    #[test]
    fn undefined_macro_in_if_expression_reports_error() {
        let err = preprocess_with("@if NOPE == \"x\"\n@endif\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("Errors during preprocessing"), "{err}");
    }

    #[test]
    fn if_syntax_error_is_reported() {
        let err = preprocess_with("@if &&\n@endif\n", &[], true).unwrap_err();
        assert!(err.to_string().contains("main.slaspec:1"), "{err}");
    }

    #[test]
    fn elif_not_evaluated_after_handled_branch() {
        // The branch was handled, so the @elif expression must be skipped
        // without evaluation (an undefined macro there must not error).
        let src = "@define A 1\n@if defined(A)\nyes\n@elif NOPE == \"x\"\nno\n@endif\n";
        let lines = preprocess(src);
        assert_eq!(lines[2], "yes");
        assert_eq!(lines[4], "#no");
    }

    #[test]
    fn scan_for_timestamp_returns_nonzero_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let inc = write_file(dir.path(), "inc.sinc", "inner\n");
        let main = write_file(dir.path(), "main.slaspec", "@include \"inc.sinc\"\n");
        let mut defs = HashMapPreprocessorDefinitions::new();
        let mut pp = SleighPreprocessor::new(&mut defs, &main);
        let ts = pp.scan_for_timestamp().unwrap();
        assert!(ts > 0);
        // Sanity: both files exist and contributed to the scan.
        assert!(inc.is_file());
    }

    #[test]
    fn directives_must_start_at_column_zero() {
        // Java gates on line.charAt(0) == '@'; indented directives are text.
        let lines = preprocess("  @define FOO 1\n");
        assert_eq!(lines[0], "  @define FOO 1");
    }

    #[test]
    fn crlf_input_is_handled() {
        let lines = preprocess("a\r\nb\r\n");
        assert_eq!(lines[0], "a");
        assert_eq!(lines[1], "b");
    }

    #[test]
    fn read_lines_handles_all_terminators() {
        assert_eq!(read_lines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(read_lines(""), Vec::<&str>::new());
        assert_eq!(read_lines("x"), vec!["x"]);
    }
}
