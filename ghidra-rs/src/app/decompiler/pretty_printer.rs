//! Port of `ghidra.app.decompiler.PrettyPrinter`.
//!
//! This type is used to convert a C/C++ language token group into readable C/C++ code.
//!
//! [`ClangToken`]/[`DecompilerUtils`] are minimal placeholders (see [`crate::app::seam_stubs`])
//! since the real classes aren't ported yet -- this file sits on a dependency cycle with them.
//! In particular, [`find_signature`](PrettyPrinter::find_signature)
//! can never recover a `ClangFuncProto` child today: `ClangTokenGroup::decode`'s existing port
//! already collapses `ELEM_FUNCPROTO` (like its sibling element ids) into a plain nested
//! `ClangTokenGroup`, so that distinction is lost before `PrettyPrinter` ever sees it.

use std::sync::Arc;

use crate::app::decompiler::clang_line::ClangLine;
use crate::app::decompiler::clang_token_group::ClangTokenGroup;
use crate::app::decompiler::decompiled_function::DecompiledFunction;
use crate::app::seam_stubs::{ClangToken, ClangTokenKind, DecompilerUtils};
use crate::program::model::listing::function::Function;
use crate::program::model::symbol::name_transformer::{IdentityNameTransformer, NameTransformer};
use crate::util::string_utilities::line_separator;

/// The string used for one level of source code indentation.
///
/// Mirrors `PrettyPrinter.INDENT_STRING`.
pub const INDENT_STRING: &str = " ";

/// Converts a C/C++ language token group into readable C/C++ code.
///
/// Port of `ghidra.app.decompiler.PrettyPrinter`.
pub struct PrettyPrinter {
    function: Arc<dyn Function>,
    tokgroup: ClangTokenGroup,
    lines: Vec<ClangLine>,
    transformer: Box<dyn NameTransformer>,
}

impl PrettyPrinter {
    /// Constructs a new pretty printer using the specified C language token group.
    ///
    /// The printer takes a [`NameTransformer`] that will be applied to symbols, which can replace
    /// illegal characters in the symbol name for instance. `None` indicates no transform is
    /// applied (mirrors `IdentityNameTransformer`).
    ///
    /// Port of `PrettyPrinter(Function, ClangTokenGroup, NameTransformer)`.
    pub fn new(
        function: Arc<dyn Function>,
        tokgroup: ClangTokenGroup,
        transformer: Option<Box<dyn NameTransformer>>,
    ) -> Self {
        let lines = DecompilerUtils::to_lines(&tokgroup);
        let mut printer = Self {
            function,
            tokgroup,
            lines,
            transformer: transformer.unwrap_or_else(|| Box::new(IdentityNameTransformer)),
        };
        printer.pad_empty_lines();
        printer
    }

    /// Port of `PrettyPrinter.padEmptyLines()`.
    fn pad_empty_lines(&mut self) {
        for line in &mut self.lines {
            let indent = line.get_indent();
            let tokens = line.get_all_tokens_mut();
            if tokens.is_empty() {
                tokens.insert(0, ClangToken::build_spacer(indent, INDENT_STRING));
            }
        }
    }

    /// Port of `PrettyPrinter.getFunction()`.
    pub fn get_function(&self) -> Arc<dyn Function> {
        self.function.clone()
    }

    /// Returns the C language lines contained in the C language token group.
    ///
    /// Port of `PrettyPrinter.getLines()`.
    pub fn get_lines(&self) -> &[ClangLine] {
        &self.lines
    }

    /// Prints the C language token group into a string of C code.
    ///
    /// Port of `PrettyPrinter.print()`.
    pub fn print(&self) -> DecompiledFunction {
        let mut buff = String::new();
        for line in &self.lines {
            Self::write_text(&mut buff, line, self.transformer.as_ref());
            buff.push_str(line_separator());
        }
        DecompiledFunction::new(self.find_signature().unwrap_or_default(), buff)
    }

    /// Port of the private `PrettyPrinter.getText(StringBuilder, ClangLine, NameTransformer)`.
    fn write_text(buff: &mut String, line: &ClangLine, transformer: &dyn NameTransformer) {
        buff.push_str(&line.get_indent_string());

        for token in line.get_all_tokens() {
            let mut is_token_to_clean = matches!(
                token.kind(),
                ClangTokenKind::FuncName
                    | ClangTokenKind::Variable
                    | ClangTokenKind::Type
                    | ClangTokenKind::Field
                    | ClangTokenKind::Label
            );

            // do not clean constant variable tokens
            if is_token_to_clean && token.get_syntax_type() == ClangToken::CONST_COLOR {
                is_token_to_clean = false;
            }

            if is_token_to_clean {
                buff.push_str(&transformer.simplify(token.get_text()));
            } else {
                buff.push_str(token.get_text());
            }
        }
    }

    /// Returns the text of the given line as seen in the UI.
    ///
    /// Port of `PrettyPrinter.getText(ClangLine)`.
    pub fn get_text(line: &ClangLine) -> String {
        let mut buff = String::new();
        Self::write_text(&mut buff, line, &IdentityNameTransformer);
        buff
    }

    /// Port of `PrettyPrinter.findSignature()`.
    ///
    /// Always returns `None`: see the module docs for why a `ClangFuncProto` child can't be
    /// distinguished from any other nested `ClangTokenGroup` with the current port.
    fn find_signature(&self) -> Option<String> {
        let _ = &self.tokgroup;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::Namespace;
    use std::borrow::Cow;

    struct TestFunction;

    impl Namespace for TestFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Function for TestFunction {
        fn get_name(&self) -> String {
            "test_func".to_string()
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            unimplemented!("not exercised by these tests")
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by these tests")
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by these tests")
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_entry_point(&self) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!("not exercised by these tests")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!("not exercised by these tests")
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!("not exercised by these tests")
        }
        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            unimplemented!("not exercised by these tests")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!("not exercised by these tests")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!("not exercised by these tests")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Parameter>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Parameter>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by these tests")
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException>
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Variable>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {
            unimplemented!("not exercised by these tests")
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!("not exercised by these tests")
        }
        fn has_var_args(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn is_inline(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn has_no_return(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn is_thunk(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            unimplemented!("not exercised by these tests")
        }
        fn is_external(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!("not exercised by these tests")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
    }

    fn printer_with(tokgroup: ClangTokenGroup) -> PrettyPrinter {
        PrettyPrinter::new(Arc::new(TestFunction), tokgroup, None)
    }

    /// A transformer that upper-cases its input, so tests can tell whether a token actually went
    /// through it (mirrors how a real `NameTransformer` might mangle illegal characters).
    struct ShoutingTransformer;
    impl NameTransformer for ShoutingTransformer {
        fn simplify<'a>(&self, input: &'a str) -> Cow<'a, str> {
            Cow::Owned(input.to_uppercase())
        }
    }

    #[test]
    fn get_function_returns_constructor_argument() {
        let printer = printer_with(ClangTokenGroup::new(None));
        assert_eq!(Function::get_name(printer.get_function().as_ref()), "test_func");
    }

    #[test]
    fn empty_token_group_has_no_lines() {
        let printer = printer_with(ClangTokenGroup::new(None));
        assert!(printer.get_lines().is_empty());
    }

    #[test]
    fn print_joins_tokens_with_indent_and_line_separator() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(crate::app::seam_stubs::ClangToken::new(
            "int x;",
            ClangTokenKind::Generic,
            ClangToken::DEFAULT_COLOR,
        )));

        let printer = printer_with(group);
        let decompiled = printer.print();
        assert_eq!(decompiled.c(), format!("int x;{}", line_separator()));
        // findSignature() can't identify a ClangFuncProto through the current
        // ClangTokenGroup port (see the module docs), so it's always empty.
        assert_eq!(decompiled.signature(), "");
    }

    #[test]
    fn get_text_simplifies_cleanable_kinds_but_not_others() {
        let mut line = ClangLine::new(0, 0);
        line.add_token(ClangToken::new("my", ClangTokenKind::Variable, ClangToken::DEFAULT_COLOR));
        line.add_token(ClangToken::new(" + ", ClangTokenKind::Generic, ClangToken::DEFAULT_COLOR));
        line.add_token(ClangToken::new("field", ClangTokenKind::Field, ClangToken::DEFAULT_COLOR));

        let text = PrettyPrinter::get_text(&line);
        // IdentityNameTransformer never changes anything, so cleaning is a no-op here.
        assert_eq!(text, "my + field");
    }

    #[test]
    fn get_text_skips_cleaning_const_colored_tokens() {
        let mut line = ClangLine::new(0, 1);
        line.add_token(ClangToken::new(
            "CONST",
            ClangTokenKind::Variable,
            ClangToken::CONST_COLOR,
        ));

        let mut buff = String::new();
        PrettyPrinter::write_text(&mut buff, &line, &ShoutingTransformer);
        // Indented by one level, and left untouched by the transformer despite being a
        // "cleanable" kind, because its syntax type is CONST_COLOR.
        assert_eq!(buff, format!("{INDENT_STRING}CONST"));
    }

    #[test]
    fn get_text_applies_transformer_to_cleanable_kinds() {
        let mut line = ClangLine::new(0, 0);
        line.add_token(ClangToken::new(
            "bad$name",
            ClangTokenKind::FuncName,
            ClangToken::DEFAULT_COLOR,
        ));

        let mut buff = String::new();
        PrettyPrinter::write_text(&mut buff, &line, &ShoutingTransformer);
        assert_eq!(buff, "BAD$NAME");
    }

    #[test]
    fn pad_empty_lines_inserts_spacer_matching_indent() {
        let mut group = ClangTokenGroup::new(None);
        // An empty-text leaf token flattens into one line with one empty token -- not an
        // *empty* line -- so build the empty-line case directly against a printer's lines
        // instead, mirroring what padEmptyLines actually guards against.
        group.add_token_group(Box::new(crate::app::seam_stubs::ClangToken::new(
            "",
            ClangTokenKind::Generic,
            ClangToken::DEFAULT_COLOR,
        )));
        let mut printer = printer_with(group);
        printer.lines = vec![ClangLine::new(0, 2)];
        printer.pad_empty_lines();

        assert_eq!(printer.get_lines().len(), 1);
        let tokens = printer.get_lines()[0].get_all_tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].get_text(), format!("{INDENT_STRING}{INDENT_STRING}"));
    }
}
