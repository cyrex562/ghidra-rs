//! The demangler driver/worker every `MDParsableItem` carries a reference to: it owns the
//! character cursor over the mangled text, the backreference context stack, and the set of
//! rendering-specialization hooks (`MDMANG SPECIALIZATION`) that `MDMangVS2015` and friends
//! override to produce interpretation-specific output.
//!
//! Mirrors `mdemangler.MDMang`, cut to a trait to break a dependency cycle: it is a cut-point
//! between the demangler's own grammar-dispatch pair (`MDMangObjectParser`/`MDDataTypeParser`,
//! `mdemangler.object`/`mdemangler.datatype`, neither ported yet), its context-stack type
//! (`MDContext`, `mdemangler`, not ported), and the already-ported leaf types it renders through
//! (`MDCharacterIterator`, `MDObjectCPP`, `MDQualification`). A narrower rendering-only seam for
//! this same class already exists as [`crate::demangler::seam_stubs::MdMangLike`] (a supertrait of
//! this trait) and [`crate::demangler::md_mang_genericize::MdMangGenericize`] models a *subclass*
//! of it; this trait is the base class itself.
//!
//! The grammar-dispatch methods (`MDMangObjectParser.determineItemAndParse(this)`,
//! `MDDataTypeParser.determineAndParseDataType(this, false)`) and the context-stack bookkeeping
//! (`MDContext` push/pop/backreferences) are declared as required (implementor-supplied) methods
//! rather than given real defaults, since both depend on types not yet ported. Everything else --
//! the character cursor, the simple option/state fields, and the specialization hooks whose default
//! behavior doesn't depend on an unported type -- is given a real default, built on
//! [`MdMang::state`]/[`MdMang::state_mut`].

use crate::demangler::md_character_iterator::{MdCharacterIterator, DONE};
use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::seam_stubs::{
    MdCvModLike, MdDataTypeLike, MdExceptionLike, MdFragmentNameLike, MdMangLike,
    MdOutputOptionsLike, MdParsableItemLike, MdStringLike, MdTemplateArgumentsListLike,
};

/// Mirrors the nested `MDMang.ProcessingMode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingMode {
    DefaultStandard,
    Llvm,
}

/// Trivial, always-default implementor of [`MdOutputOptionsLike`], used as the initial value of
/// [`MdMangState::output_options`].
///
/// Mirrors the fact that `MDMang`'s own field initializer (`new MDOutputOptions()`) always starts
/// from the type's defaults; since [`MdOutputOptionsLike`] declares no methods yet (see its docs),
/// any implementor is behaviorally identical to any other, so this unit struct is as good a
/// default as a real one.
#[derive(Debug, Default)]
pub struct NoOutputOptions;

impl MdOutputOptionsLike for NoOutputOptions {}

/// Owned state backing [`MdMang`]'s own (non-context-stack) fields.
///
/// Mirrors the private/protected fields `mangled`, `architectureSize`, `isFunction`,
/// `outputOptions`, `errorOnRemainingChars`, `errorMessage`, `processingMode`, and `iter`. Kept as
/// a plain data struct (rather than a placeholder trait) since these are this class's own fields,
/// not a reference to some other not-yet-ported type -- the same treatment
/// [`crate::demangler::md_mang_genericize::GenericFragmentState`] gives
/// `MDMangGenericize`'s own fields.
pub struct MdMangState {
    /// Mirrors `MDMang.mangled`.
    pub mangled: Option<String>,
    /// Mirrors `MDMang.architectureSize` (default `32`, matching the field initializer -- the
    /// class doc comment claiming a default of 64 bits is stale).
    pub architecture_size: i32,
    /// Mirrors `MDMang.isFunction`.
    pub is_function: bool,
    /// Mirrors `MDMang.outputOptions`.
    pub output_options: Box<dyn MdOutputOptionsLike>,
    /// Mirrors `MDMang.errorOnRemainingChars`.
    pub error_on_remaining_chars: bool,
    /// Mirrors `MDMang.errorMessage`.
    pub error_message: String,
    /// Mirrors `MDMang.processingMode`. `None` before [`MdMang::init_state`] has run, matching the
    /// Java field's `null` value before that point.
    pub processing_mode: Option<ProcessingMode>,
    /// Mirrors `MDMang.iter`.
    pub iter: MdCharacterIterator,
}

impl Default for MdMangState {
    fn default() -> Self {
        Self {
            mangled: None,
            architecture_size: 32,
            is_function: false,
            output_options: Box::new(NoOutputOptions),
            error_on_remaining_chars: false,
            error_message: String::new(),
            processing_mode: None,
            iter: MdCharacterIterator::new(""),
        }
    }
}

/// The demangler driver/worker every `MDParsableItem` carries a reference to.
///
/// Mirrors `mdemangler.MDMang`. See the module docs for the cycle this cuts and which parts of the
/// original are given real defaults versus left as required (implementor-supplied) hooks.
pub trait MdMang: MdMangLike {
    /// Read access to this trait's own (non-context-stack) state.
    fn state(&self) -> &MdMangState;

    /// Mutable access to this trait's own (non-context-stack) state.
    fn state_mut(&mut self) -> &mut MdMangState;

    // ===== Mangled context =====================================================================

    /// Sets the mangled string to be demangled.
    ///
    /// Mirrors `setMangledSymbol(String)`.
    fn set_mangled_symbol(&mut self, mangled: String) {
        self.state_mut().mangled = Some(mangled);
    }

    /// Gets the mangled string being demangled.
    ///
    /// Mirrors `getMangledSymbol()`.
    fn mangled_symbol(&self) -> Option<&str> {
        self.state().mangled.as_deref()
    }

    /// Sets the architecture size.
    ///
    /// Mirrors `setArchitectureSize(int)`.
    fn set_architecture_size(&mut self, size: i32) {
        self.state_mut().architecture_size = size;
    }

    /// Returns the architecture size (bits).
    ///
    /// Mirrors `getArchitectureSize()`.
    fn architecture_size(&self) -> i32 {
        self.state().architecture_size
    }

    /// Sets whether the symbol is known to be for a function.
    ///
    /// Mirrors `setIsFunction(boolean)`.
    fn set_is_function(&mut self, is_function: bool) {
        self.state_mut().is_function = is_function;
    }

    /// Returns whether the symbol is known to be for a function.
    ///
    /// Mirrors `isFunction()`.
    fn is_function(&self) -> bool {
        self.state().is_function
    }

    // ===== Output options =======================================================================

    /// Mirrors `getOutputOptions()`.
    fn output_options(&self) -> &dyn MdOutputOptionsLike {
        self.state().output_options.as_ref()
    }

    // ===== Demangling options ====================================================================

    /// Controls whether an exception is thrown if there are remaining characters after
    /// demangling. Default is `false`.
    ///
    /// Mirrors `setErrorOnRemainingChars(boolean)`.
    fn set_error_on_remaining_chars(&mut self, error_on_remaining_chars: bool) {
        self.state_mut().error_on_remaining_chars = error_on_remaining_chars;
    }

    /// Returns `true` if the process will throw an exception if characters remain after
    /// demangling.
    ///
    /// Mirrors `errorOnRemainingChars()`.
    fn error_on_remaining_chars(&self) -> bool {
        self.state().error_on_remaining_chars
    }

    /// Returns the error message when `demangle()` returns an error.
    ///
    /// Mirrors `getErrorMessage()`.
    fn error_message(&self) -> &str {
        &self.state().error_message
    }

    /// Sets the error message.
    ///
    /// Stands in for direct assignment to the protected `MDMang.errorMessage` field (there is no
    /// public setter in the original).
    fn set_error_message(&mut self, error_message: String) {
        self.state_mut().error_message = error_message;
    }

    /// Returns the number of unprocessed mangled characters.
    ///
    /// Mirrors `getNumCharsRemaining()`.
    fn num_chars_remaining(&self) -> usize {
        self.char_iter().get_length() - self.char_iter().get_index()
    }

    // ===== Processing ============================================================================

    /// Creates the exception type used to report errors from this trait's default methods.
    ///
    /// Required since `MDException`'s placeholder ([`MdExceptionLike`]) declares no constructor
    /// (see its docs) -- the concrete exception type is left to the implementor.
    fn make_exception(&self, message: String) -> Box<dyn MdExceptionLike>;

    /// Parses the item for the mangled string at the cursor's current (fresh) position.
    ///
    /// Mirrors `MDMangObjectParser.determineItemAndParse(this)`. Required since that call needs
    /// the full (unported) `MDMang` grammar-dispatch surface to implement for real; see
    /// [`crate::demangler::seam_stubs::MdMangObjectParserLike`].
    fn parse_item(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>>;

    /// Parses the mangled "type" name at the cursor's current (fresh) position.
    ///
    /// Mirrors `MDDataTypeParser.determineAndParseDataType(this, false)`. Required for the same
    /// reason as [`MdMang::parse_item`]: `MDDataTypeParser` needs the full grammar-dispatch surface.
    fn parse_data_type(&mut self) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>>;

    /// Demangles the string already stored and returns a parsed item.
    ///
    /// Mirrors `demangle()`. The `MDMANG SPECIALIZATION USED` substitution
    /// (`item = getEmbeddedObject((MDObjectCPP) item)`) is elided here: expressing it against the
    /// returned `Box<dyn MdParsableItemLike>` would require downcasting a trait object, which Rust
    /// doesn't support, and the substitution it stands in for is a no-op identity in the base
    /// `MDMang` this trait models anyway (see [`MdMang::get_embedded_object`]'s default) -- the
    /// other eight call sites of `getEmbeddedObject` (`MDObjectBracket`, `MDSpecialName`,
    /// `MDNestedName`, ...) remain fully modeled via that method.
    fn demangle(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
        self.init_state()?;
        let item = self.parse_item()?;
        let num_chars_remaining = self.num_chars_remaining();
        if self.error_on_remaining_chars() && num_chars_remaining > 0 {
            return Err(self.make_exception(format!(
                "MDMang: characters remain after demangling: {num_chars_remaining}."
            )));
        }
        Ok(item)
    }

    /// Demangles the mangled "type" name already stored and returns the parsed data type.
    ///
    /// Mirrors `demangleType()`.
    fn demangle_type(&mut self) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
        self.init_state()?;
        let data_type = self.parse_data_type()?;
        let num_chars_remaining = self.num_chars_remaining();
        if self.error_on_remaining_chars() && num_chars_remaining > 0 {
            return Err(self.make_exception(format!(
                "MDMang: characters remain after demangling: {num_chars_remaining}."
            )));
        }
        Ok(data_type)
    }

    // ===== Internal processing control ==========================================================

    /// Mirrors `setProcessingMode(ProcessingMode)`.
    fn set_processing_mode(&mut self, processing_mode: ProcessingMode) {
        self.state_mut().processing_mode = Some(processing_mode);
    }

    /// Mirrors `getProcessingMode()`.
    fn processing_mode(&self) -> Option<ProcessingMode> {
        self.state().processing_mode
    }

    /// Mirrors `isLlvmProcessingModeIndex0()`.
    fn is_llvm_processing_mode_index0(&self) -> bool {
        self.processing_mode() == Some(ProcessingMode::Llvm) && self.get_index() == 0
    }

    /// Mirrors `isLlvmProcessingMode()`.
    fn is_llvm_processing_mode(&self) -> bool {
        self.processing_mode() == Some(ProcessingMode::Llvm)
    }

    /// Variables that get set at the very beginning of a demangle pass.
    ///
    /// Mirrors `initState()`.
    fn init_state(&mut self) -> Result<(), Box<dyn MdExceptionLike>> {
        let is_blank = self.mangled_symbol().map(|s| s.trim().is_empty()).unwrap_or(true);
        if is_blank {
            return Err(self.make_exception("MDMang: Mangled string is null or blank.".to_string()));
        }
        self.set_error_message(String::new());
        self.set_processing_mode(ProcessingMode::DefaultStandard);
        let mangled = self.mangled_symbol().unwrap().to_string();
        self.set_char_iter(MdCharacterIterator::new(mangled));
        self.reset_state();
        Ok(())
    }

    /// Variables that can get reset for a second (or more?) passes with different modes.
    ///
    /// Mirrors `resetState()`.
    fn reset_state(&mut self) {
        self.reset_context_stack();
        self.set_index(0);
    }

    // ===== Character cursor ======================================================================

    /// Read access to the character cursor over the mangled string.
    ///
    /// Stands in for direct access to `MDMang.iter`.
    fn char_iter(&self) -> &MdCharacterIterator {
        &self.state().iter
    }

    /// Mutable access to the character cursor over the mangled string.
    ///
    /// Stands in for direct access to `MDMang.iter`.
    fn char_iter_mut(&mut self) -> &mut MdCharacterIterator {
        &mut self.state_mut().iter
    }

    /// Replaces the character cursor wholesale, as `initState()` does when it computes
    /// `iter = new MDCharacterIterator(mangled)`.
    fn set_char_iter(&mut self, iter: MdCharacterIterator) {
        self.state_mut().iter = iter;
    }

    /// Returns the current index.
    ///
    /// Mirrors `getIndex()`.
    fn get_index(&self) -> usize {
        self.char_iter().get_index()
    }

    /// Sets the current index.
    ///
    /// Mirrors `setIndex(int)`.
    fn set_index(&mut self, index: usize) {
        self.char_iter_mut().set_index(index);
    }

    /// Returns `true` if there are no more characters to iterate.
    ///
    /// Mirrors `done()`.
    fn done(&self) -> bool {
        self.peek() == DONE
    }

    /// Returns the next character without incrementing the current index.
    ///
    /// Mirrors `peek()`.
    fn peek(&self) -> char {
        self.char_iter().peek()
    }

    /// Peeks at the character at the current index plus `look_ahead`.
    ///
    /// Mirrors `peek(int)`.
    fn peek_ahead(&self, look_ahead: usize) -> char {
        self.char_iter().peek_ahead(look_ahead)
    }

    /// Increments the current index by one and returns the character at the new index.
    ///
    /// Mirrors `next()`.
    fn next(&mut self) -> char {
        self.char_iter_mut().next()
    }

    /// Returns the character at the current index, then increments the index by one.
    ///
    /// Mirrors `getAndIncrement()`.
    fn get_and_increment(&mut self) -> char {
        self.char_iter_mut().get_and_increment()
    }

    /// Increments the index by one.
    ///
    /// Mirrors `increment()`.
    fn increment(&mut self) {
        self.char_iter_mut().increment();
    }

    /// Moves ahead by `count` characters.
    ///
    /// Mirrors `increment(int)`.
    fn increment_by(&mut self, count: usize) {
        self.char_iter_mut().increment_by(count);
    }

    /// Returns `true` if `substring` is found at the current index.
    ///
    /// Mirrors `positionStartsWith(String)`.
    fn position_starts_with(&self, substring: &str) -> bool {
        self.char_iter().position_starts_with(substring)
    }

    // ===== Context stack (backreferences) =======================================================
    //
    // `MDContext` (mdemangler.MDContext) is not ported, so the whole subsystem is declared as
    // required (implementor-supplied) operations rather than modeled with a placeholder type: no
    // method here takes or returns anything shaped like `MDContext` itself, only the primitive
    // (String/MDDataType-backreference) data grammar productions read and write through it.

    /// Resets the context stack to empty.
    ///
    /// Mirrors the `contextStack = new ArrayList<>();` half of `resetState()`.
    fn reset_context_stack(&mut self);

    /// Pushes a fresh, unrelated context.
    ///
    /// Mirrors `pushContext()`.
    fn push_context(&mut self);

    /// Pushes a context copied from the current one for a `MODIFIER` sub-parse.
    ///
    /// Mirrors `pushModifierContext()`.
    fn push_modifier_context(&mut self);

    /// Pushes a context copied from the current one for a `FUNCTION` sub-parse.
    ///
    /// Mirrors `pushFunctionContext()`.
    fn push_function_context(&mut self);

    /// Pushes a context copied from the current one for a `TEMPLATE` sub-parse.
    ///
    /// Mirrors `pushTemplateContext()`.
    fn push_template_context(&mut self);

    /// Pops the current context.
    ///
    /// Mirrors `popContext()`.
    fn pop_context(&mut self);

    /// Adds a backreference name to the current context.
    ///
    /// Mirrors `addBackrefName(String)`.
    fn add_backref_name(&mut self, name: String);

    /// Returns the backreference name at `index` in the current context.
    ///
    /// Mirrors `getBackreferenceName(int)`.
    fn backref_name(&self, index: usize) -> Result<String, Box<dyn MdExceptionLike>>;

    /// Adds a backreference function-parameter data type to the current context.
    ///
    /// Mirrors `addBackrefFunctionParameterMDDataType(MDDataType)`.
    fn add_backref_function_parameter_data_type(&mut self, data_type: Box<dyn MdDataTypeLike>);

    /// Adds a backreference template-parameter data type to the current context.
    ///
    /// Mirrors `addBackrefTemplateParameterMDDataType(MDDataType)`.
    fn add_backref_template_parameter_data_type(&mut self, data_type: Box<dyn MdDataTypeLike>);

    /// Returns the backreference function-parameter data type at `index` in the current context.
    ///
    /// Mirrors `getBackreferenceFunctionParameterMDDataType(int)`.
    fn backref_function_parameter_data_type(
        &self,
        index: usize,
    ) -> Result<&dyn MdDataTypeLike, Box<dyn MdExceptionLike>>;

    /// Returns the backreference template-parameter data type at `index` in the current context.
    ///
    /// Mirrors `getBackreferenceTemplateParameterMDDataType(int)`.
    fn backref_template_parameter_data_type(
        &self,
        index: usize,
    ) -> Result<&dyn MdDataTypeLike, Box<dyn MdExceptionLike>>;

    // ===== Parse-info hooks =======================================================================
    //
    // Purposefully empty for the base class; contents exist only for a derived
    // `MDMangParseInfo`-style extension, none of which is in scope here.

    /// Mirrors `parseInfoPushPop(int, String)`.
    fn parse_info_push_pop(&mut self, _start_index_offset: i32, _object_name: &str) {}

    /// Mirrors `parseInfoPush(int, String)`.
    fn parse_info_push(&mut self, _start_index_offset: i32, _object_name: &str) {}

    /// Mirrors `parseInfoPop()`.
    fn parse_info_pop(&mut self) {}

    // ===== StringBuilder helpers ==================================================================
    //
    // `insertSpacedString`/`insertString`/`appendString`/`cleanOutput` are inherited from
    // `MdMangLike` (this trait's supertrait), which already carries their real implementations.

    /// Returns `true` if `builder` is empty.
    ///
    /// Mirrors `isEffectivelyEmpty(StringBuilder)`.
    fn is_effectively_empty(&self, builder: &str) -> bool {
        builder.is_empty()
    }

    // ===== Specialization methods (MDMANG SPECIALIZATION) ========================================

    /// Inserts the rendered text of `mdstring` into `builder`.
    ///
    /// Mirrors `insert(StringBuilder, MDString)`.
    fn insert_mdstring(&self, builder: &mut String, mdstring: &dyn MdStringLike) {
        self.insert_string(builder, &mdstring.as_display_string());
    }

    /// Inserts the rendered text of `qualification` into `builder`.
    ///
    /// Mirrors `insert(StringBuilder, MDQualification)`. The base-vs-VS2015 dispatch this performs
    /// (`insert_MdVersion` vs `insert_VSAll`) is already collapsed onto
    /// [`MdMangLike::use_vs_all_qualification`] inside [`MdQualification::insert`] itself, so this
    /// simply delegates.
    ///
    /// Requires `Self: Sized` (like [`MdObjectCpp::embedded_object`]) so `self` can coerce to
    /// `&dyn MdMangLike`; call this only through a concrete type, not through a `dyn MdMang`.
    fn insert_qualification(&self, builder: &mut String, qualification: &dyn MdQualification)
    where
        Self: Sized,
    {
        qualification.insert(self, builder);
    }

    /// Mirrors `emptyFirstArgComma(MDTemplateArgumentsList)`.
    fn empty_first_arg_comma(&self, _args: &dyn MdTemplateArgumentsListLike) -> bool {
        false
    }

    /// Mirrors `templateBackrefComma(MDTemplateArgumentsList)`.
    fn template_backref_comma(&self, _args: &dyn MdTemplateArgumentsListLike) -> bool {
        true
    }

    /// Inserts `cv_mod`'s managed-properties suffix into `builder`.
    ///
    /// Mirrors `insertManagedPropertiesSuffix(StringBuilder, MDCVMod)`.
    ///
    /// Requires `Self: Sized` (like [`MdObjectCpp::embedded_object`]) so `self` can coerce to
    /// `&dyn MdMangLike`; call this only through a concrete type, not through a `dyn MdMang`.
    fn insert_managed_properties_suffix(&self, builder: &mut String, cv_mod: &dyn MdCvModLike)
    where
        Self: Sized,
    {
        cv_mod.insert_managed_properties_suffix(self, builder);
    }

    /// Consumes a trailing `@` at the current cursor position, if present.
    ///
    /// Mirrors `parseEmbeddedObjectSuffix()`.
    fn parse_embedded_object_suffix(&mut self) {
        if self.peek() == '@' {
            self.increment();
        }
    }

    /// Parses `fragment`'s name using the base (`MD`) fragment-name grammar.
    ///
    /// Mirrors `parseFragmentName(MDFragmentName)`.
    ///
    /// Requires `Self: Sized` (like [`MdObjectCpp::embedded_object`]) so `self` can coerce to
    /// `&mut dyn MdMang`; call this only through a concrete type, not through a `dyn MdMang`.
    fn parse_fragment_name(
        &mut self,
        fragment: &mut dyn MdFragmentNameLike,
    ) -> Result<String, Box<dyn MdExceptionLike>>
    where
        Self: Sized,
    {
        Ok(fragment.parse_fragment_name_md(self))
    }

    /// Mirrors `allowMDTypeInfoParserDefault()`.
    fn allow_md_type_info_parser_default(&self) -> bool {
        false
    }

    /// Mirrors `allowCVModLRefRRef()`.
    fn allow_cv_mod_lref_rref(&self) -> bool {
        true
    }

    /// Mirrors `processQualCAsSpecialFragment()`.
    fn process_qual_c_as_special_fragment(&self) -> bool {
        false
    }

    /// Returns the embedded object for `obj` if this specialization has one, else `obj` itself.
    ///
    /// Mirrors `getEmbeddedObject(MDObjectCPP)`. The base `MDMang` behavior (returning `obj`
    /// unchanged) is a real, faithful default; only `MDMangVS2015` overrides it (to call
    /// `obj.getEmbeddedObject()`), which is out of scope for this trait-only seam.
    fn get_embedded_object<'a>(&self, obj: &'a dyn MdObjectCpp) -> &'a dyn MdObjectCpp {
        obj
    }

    /// Processes `obj` as a hashed object.
    ///
    /// Mirrors `processHashedObject(MDObjectCPP)`. Required (no default) since the base behavior
    /// delegates to `MDObjectCPP.processHashedObject()`, whose real (parsing) implementation is
    /// intentionally out of scope on the already-ported [`MdObjectCpp`] (see its module docs) --
    /// only its sibling "always fails" choice, [`MdObjectCpp::process_hashed_object_msvc`], is
    /// modeled there.
    fn process_hashed_object(&self, obj: &dyn MdObjectCpp) -> Result<(), Box<dyn MdExceptionLike>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::naming::md_qualifier::MdQualifier;

    #[derive(Debug)]
    struct MockException(String);

    impl std::fmt::Display for MockException {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl MdExceptionLike for MockException {}

    struct MockParsableItem;
    impl MdParsableItemLike for MockParsableItem {}

    struct MockDataType {
        signed: bool,
    }
    impl MdDataTypeLike for MockDataType {
        fn is_specified_signed(&self) -> bool {
            self.signed
        }
        fn is_unsigned(&self) -> bool {
            !self.signed
        }
    }

    #[derive(Default)]
    struct MockContext {
        backref_names: Vec<String>,
        backref_function_params: Vec<Box<dyn MdDataTypeLike>>,
        backref_template_params: Vec<Box<dyn MdDataTypeLike>>,
    }

    #[derive(Default)]
    struct MockMdMang {
        state: MdMangState,
        context_stack: Vec<MockContext>,
        push_context_calls: usize,
        parse_should_fail: bool,
    }

    impl MdMangLike for MockMdMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            if builder.is_empty() || s.is_empty() {
                builder.insert_str(0, s);
                return;
            }
            builder.insert(0, ' ');
            builder.insert_str(0, s);
        }
    }

    impl MdMang for MockMdMang {
        fn state(&self) -> &MdMangState {
            &self.state
        }

        fn state_mut(&mut self) -> &mut MdMangState {
            &mut self.state
        }

        fn make_exception(&self, message: String) -> Box<dyn MdExceptionLike> {
            Box::new(MockException(message))
        }

        fn parse_item(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
            if self.parse_should_fail {
                return Err(self.make_exception("parse failed".to_string()));
            }
            // Consume a name fragment up to '@', mirroring a grammar production calling back
            // into parse_fragment_name for a name component.
            let mut dummy = MockFragmentName::default();
            let _ = self.parse_fragment_name(&mut dummy);
            if self.peek() == '@' {
                self.increment();
            }
            Ok(Box::new(MockParsableItem))
        }

        fn parse_data_type(&mut self) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
            if self.parse_should_fail {
                return Err(self.make_exception("parse failed".to_string()));
            }
            Ok(Box::new(MockDataType { signed: true }))
        }

        fn reset_context_stack(&mut self) {
            self.context_stack.clear();
        }

        fn push_context(&mut self) {
            self.push_context_calls += 1;
            self.context_stack.push(MockContext::default());
        }

        fn push_modifier_context(&mut self) {
            self.push_context();
        }

        fn push_function_context(&mut self) {
            self.push_context();
        }

        fn push_template_context(&mut self) {
            self.push_context();
        }

        fn pop_context(&mut self) {
            self.context_stack.pop();
        }

        fn add_backref_name(&mut self, name: String) {
            self.context_stack.last_mut().expect("no context").backref_names.push(name);
        }

        fn backref_name(&self, index: usize) -> Result<String, Box<dyn MdExceptionLike>> {
            self.context_stack
                .last()
                .and_then(|c| c.backref_names.get(index))
                .cloned()
                .ok_or_else(|| self.make_exception("Backref Names stack violation".to_string()))
        }

        fn add_backref_function_parameter_data_type(&mut self, data_type: Box<dyn MdDataTypeLike>) {
            self.context_stack
                .last_mut()
                .expect("no context")
                .backref_function_params
                .push(data_type);
        }

        fn add_backref_template_parameter_data_type(&mut self, data_type: Box<dyn MdDataTypeLike>) {
            self.context_stack
                .last_mut()
                .expect("no context")
                .backref_template_params
                .push(data_type);
        }

        fn backref_function_parameter_data_type(
            &self,
            index: usize,
        ) -> Result<&dyn MdDataTypeLike, Box<dyn MdExceptionLike>> {
            self.context_stack
                .last()
                .and_then(|c| c.backref_function_params.get(index))
                .map(|dt| dt.as_ref())
                .ok_or_else(|| self.make_exception("Parameter stack violation".to_string()))
        }

        fn backref_template_parameter_data_type(
            &self,
            index: usize,
        ) -> Result<&dyn MdDataTypeLike, Box<dyn MdExceptionLike>> {
            self.context_stack
                .last()
                .and_then(|c| c.backref_template_params.get(index))
                .map(|dt| dt.as_ref())
                .ok_or_else(|| {
                    self.make_exception("Template parameter stack violation".to_string())
                })
        }

        fn process_hashed_object(
            &self,
            _obj: &dyn MdObjectCpp,
        ) -> Result<(), Box<dyn MdExceptionLike>> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockFragmentName {
        name: Option<String>,
    }

    impl MdFragmentNameLike for MockFragmentName {
        fn get_name(&self) -> String {
            self.name.clone().unwrap_or_default()
        }

        fn set_name(&mut self, name: String) {
            self.name = Some(name);
        }

        fn insert(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
    }

    struct MockObjectCpp;
    impl MdObjectCpp for MockObjectCpp {
        fn qualified_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdQualifiedBasicNameLike> {
            None
        }
        fn type_info(&self) -> Option<&dyn crate::demangler::seam_stubs::MdTypeInfoLike> {
            None
        }
        fn hashed_object(&self) -> Option<&dyn crate::demangler::object::md_object_cpp::MdHashedObject> {
            None
        }
        fn embedded_object_flag(&self) -> bool {
            false
        }
    }

    fn mangled(mock: &mut MockMdMang, s: &str) {
        mock.set_mangled_symbol(s.to_string());
    }

    #[test]
    fn init_state_rejects_blank_mangled_symbol() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "   ");

        let err = mock.init_state();

        assert!(err.is_err());
    }

    #[test]
    fn init_state_installs_cursor_and_resets_processing_mode() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "Foo@@bar");

        mock.init_state().unwrap();

        assert_eq!(mock.peek(), 'F');
        assert_eq!(mock.processing_mode(), Some(ProcessingMode::DefaultStandard));
        assert_eq!(mock.num_chars_remaining(), 8);
    }

    #[test]
    fn demangle_consumes_name_fragment_and_leaves_remainder() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "Foo@bar");

        let item = mock.demangle().unwrap();

        // parse_item's mock consumes "Foo" via parse_fragment_name (stopping at '@') then the
        // single '@' via parse_embedded_object_suffix-style increment, leaving "bar" unconsumed.
        let _: Box<dyn MdParsableItemLike> = item;
        assert_eq!(mock.num_chars_remaining(), 3);
        assert_eq!(mock.get_index(), 4);
    }

    #[test]
    fn demangle_errors_on_remaining_chars_when_flag_set() {
        let mut mock = MockMdMang::default();
        mock.set_error_on_remaining_chars(true);
        mangled(&mut mock, "Foo@bar");

        let result = mock.demangle();

        assert!(result.is_err());
    }

    #[test]
    fn demangle_propagates_parse_item_error() {
        let mut mock = MockMdMang::default();
        mock.parse_should_fail = true;
        mangled(&mut mock, "Foo@bar");

        assert!(mock.demangle().is_err());
    }

    #[test]
    fn demangle_type_returns_parsed_data_type() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "H");

        let dt = mock.demangle_type().unwrap();

        assert!(dt.is_specified_signed());
    }

    #[test]
    fn context_stack_backref_round_trips_through_push_and_add() {
        let mut mock = MockMdMang::default();
        mock.push_context();
        mock.add_backref_name("Foo".to_string());
        mock.add_backref_name("Bar".to_string());

        assert_eq!(mock.backref_name(0).unwrap(), "Foo");
        assert_eq!(mock.backref_name(1).unwrap(), "Bar");
        assert!(mock.backref_name(2).is_err());
    }

    #[test]
    fn context_stack_data_type_backrefs_round_trip() {
        let mut mock = MockMdMang::default();
        mock.push_function_context();
        mock.add_backref_function_parameter_data_type(Box::new(MockDataType { signed: true }));

        assert!(mock.backref_function_parameter_data_type(0).unwrap().is_specified_signed());
        assert!(mock.backref_template_parameter_data_type(0).is_err());
    }

    #[test]
    fn pop_context_removes_most_recently_pushed_context() {
        let mut mock = MockMdMang::default();
        mock.push_context();
        mock.add_backref_name("Inner".to_string());
        mock.push_modifier_context();

        mock.pop_context();

        assert_eq!(mock.backref_name(0).unwrap(), "Inner");
    }

    #[test]
    fn reset_state_clears_context_stack_and_index() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "abc");
        mock.init_state().unwrap();
        mock.set_index(2);
        mock.push_context();

        mock.reset_state();

        assert_eq!(mock.get_index(), 0);
        assert!(mock.backref_name(0).is_err());
    }

    #[test]
    fn is_llvm_processing_mode_tracks_mode_and_index() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "abc");
        mock.init_state().unwrap();

        assert!(!mock.is_llvm_processing_mode());
        assert!(!mock.is_llvm_processing_mode_index0());

        mock.set_processing_mode(ProcessingMode::Llvm);

        assert!(mock.is_llvm_processing_mode());
        assert!(mock.is_llvm_processing_mode_index0());
        mock.increment();
        assert!(!mock.is_llvm_processing_mode_index0());
    }

    #[test]
    fn cursor_helpers_delegate_to_character_iterator() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "abcd");
        mock.init_state().unwrap();

        assert_eq!(mock.peek_ahead(2), 'c');
        assert_eq!(mock.get_and_increment(), 'a');
        assert_eq!(mock.next(), 'c');
        mock.increment();
        assert!(mock.position_starts_with("d"));
        mock.increment();
        assert!(mock.done());
    }

    #[test]
    fn parse_embedded_object_suffix_consumes_trailing_at() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "@rest");
        mock.init_state().unwrap();

        mock.parse_embedded_object_suffix();

        assert_eq!(mock.peek(), 'r');
    }

    #[test]
    fn get_embedded_object_default_is_identity() {
        let mock = MockMdMang::default();
        let obj = MockObjectCpp;

        let resolved = mock.get_embedded_object(&obj);

        assert!(std::ptr::eq(resolved as *const dyn MdObjectCpp as *const (), &obj as *const MockObjectCpp as *const ()));
    }

    #[test]
    fn insert_helpers_delegate_to_supertrait() {
        let mock = MockMdMang::default();
        let mut builder = String::from("existing");

        mock.insert_string(&mut builder, "new ");

        assert_eq!(builder, "new existing");
        assert!(!mock.is_effectively_empty(&builder));
        assert!(mock.is_effectively_empty(""));
    }

    #[test]
    fn specialization_defaults_match_base_mdmang() {
        let mock = MockMdMang::default();

        assert!(!mock.allow_md_type_info_parser_default());
        assert!(mock.allow_cv_mod_lref_rref());
        assert!(!mock.process_qual_c_as_special_fragment());
    }

    #[test]
    fn qualification_insert_delegates_through_use_vs_all_flag() {
        #[derive(Default)]
        struct MockQualification {
            quals: Vec<Box<dyn MdQualifier>>,
        }
        impl MdQualification for MockQualification {
            fn qualifiers(&self) -> &[Box<dyn MdQualifier>] {
                &self.quals
            }
        }

        let mock = MockMdMang::default();
        let qual = MockQualification::default();
        let mut builder = String::new();

        mock.insert_qualification(&mut builder, &qual);

        assert!(builder.is_empty());
    }

    #[test]
    fn process_hashed_object_is_reachable_through_trait_object() {
        let mock: Box<dyn MdMang> = Box::new(MockMdMang::default());
        let obj = MockObjectCpp;

        assert!(mock.process_hashed_object(&obj).is_ok());
    }

    #[test]
    fn trait_object_is_usable() {
        let mut mock = MockMdMang::default();
        mangled(&mut mock, "xyz");
        let dmang: &mut dyn MdMang = &mut mock;

        dmang.init_state().unwrap();
        assert_eq!(dmang.get_and_increment(), 'x');
        assert_eq!(dmang.get_index(), 1);
    }
}
