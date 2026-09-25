//! Port of `ghidra.program.model.lang.BasicCompilerSpec`: a [`CompilerSpec`] built from the static
//! information in a `.cspec` file.
//!
//! # Known gaps
//! * **P-code text payloads.** `<callfixup>`, `<callotherfixup>` and a prototype's `<pcode>`
//!   injection are parsed and handed to the [`PcodeInjectLibrary`], which can only register
//!   payloads that need no compilation (`dynamic="true"`): compiling p-code source text needs the
//!   unported `PcodeParser`. Such payloads are skipped with a warning, so the spec loads but lacks
//!   them (and a prototype model that declares one cannot [`encode`](PrototypeModel::encode)).
//! * **Custom inject libraries.** A language naming a `pcodeInjectLibraryClass` property gets its
//!   class by reflection in Java; this port has only the default library and rejects the spec.
//!   Java's `language.getAdditionalInject()` payloads come from the unported `.pspec` reader, so
//!   there are none to register.
//! * **Schema validation.** Java validates the `.cspec` against its RelaxNG schema
//!   (`SleighLanguageValidator`, unported) before parsing; this port relies on the parser's own
//!   checks.
//! * **Overlay addresses.** [`CompilerSpec::is_global`] translates an overlay address to its
//!   base space first in Java; this crate's [`AddressSpace`] has no overlay form, so no
//!   translation applies.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Weak};

use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::lang::compiler_spec::{
    is_unknown_calling_convention, CompilerSpec, EvaluationModelType, CALLING_CONVENTION_DEFAULT,
    CALLING_CONVENTION_THISCALL,
};
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::context_setting::ContextSetting;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::lang::ghidra_language_property_keys::PCODE_INJECT_LIBRARY_CLASS;
use crate::program::model::lang::inject_payload::{CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE};
use crate::program::model::lang::inject_payload_segment::InjectPayloadSegment;
use crate::program::model::lang::inject_payload_sleigh::InjectPayloadSleigh;
use crate::program::model::lang::language::{Language, WeakLanguage};
use crate::program::model::lang::pcode_inject_library::{PcodeInjectLibrary, PcodeInjectLibraryError};
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::space_names::SpaceNames;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::parameter::Parameter;
use crate::program::model::pcode::address_xml::{self, AddressXml};
use crate::program::model::pcode::{
    Encoder, Varnode, ATTRIB_ALIGN, ATTRIB_DELAY, ATTRIB_FIRST, ATTRIB_GROWTH, ATTRIB_KEY, ATTRIB_LAST,
    ATTRIB_NAME, ATTRIB_REGISTER, ATTRIB_REVERSEJUSTIFY, ATTRIB_SIGNEXT, ATTRIB_SPACE, ATTRIB_STYLE,
    ATTRIB_VALUE, ELEM_AGGRESSIVETRIM, ELEM_COMPILER_SPEC, ELEM_DEADCODEDELAY, ELEM_DEFAULT_PROTO,
    ELEM_EVAL_CALLED_PROTOTYPE, ELEM_EVAL_CURRENT_PROTOTYPE, ELEM_FUNCPTR, ELEM_GLOBAL,
    ELEM_INFERPTRBOUNDS, ELEM_NOHIGHPTR, ELEM_PREFERSPLIT, ELEM_PROPERTIES, ELEM_PROPERTY, ELEM_RANGE,
    ELEM_READONLY, ELEM_RETURNADDRESS, ELEM_SPACEBASE, ELEM_STACKPOINTER, ELEM_VARNODE,
};
use crate::program::seam_stubs::PcodeInjectLibrary as PcodeInjectLibraryView;
use crate::util::msg::Msg;
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int, decode_long};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use crate::util::xml::xml_pull_parser_factory;

/// Java's `Function.UNKNOWN_CALLING_CONVENTION_STRING`.
const UNKNOWN_CALLING_CONVENTION_STRING: &str = "unknown";
/// Java's `Function.DEFAULT_CALLING_CONVENTION_STRING`.
const DEFAULT_CALLING_CONVENTION_STRING: &str = "default";

/// A [`CompilerSpec`] built from static information in a `.cspec` file.
///
/// Port of `ghidra.program.model.lang.BasicCompilerSpec`. The copy constructor is [`Clone`]:
/// like Java's, it shares the immutable parts (models, data organization) and copies the inject
/// library.
#[derive(Clone)]
pub struct BasicCompilerSpec {
    description: Arc<dyn CompilerSpecDescription>,
    source_name: String,
    /// The language this spec was built for. Weak because the language owns (caches) its specs;
    /// see [`WeakLanguage`] for the invariant that the language outlives every use of the spec.
    language: Weak<SleighLanguage>,
    data_organization: Arc<DataOrganizationImpl>,
    ctxsetting: Vec<ContextSetting>,
    default_model: Option<Arc<PrototypeModel>>,
    /// Default model used to evaluate the current function.
    eval_current_model: Option<Arc<PrototypeModel>>,
    /// Default model used to evaluate a called function.
    eval_called_model: Option<Arc<PrototypeModel>>,
    /// All models.
    allmodels: Vec<Arc<PrototypeModel>>,
    /// All models excluding merge models.
    models: Vec<Arc<PrototypeModel>>,
    /// Register holding the stack pointer.
    stack_pointer: Option<RegisterRef>,
    stack_space: Option<Arc<AddressSpace>>,
    stack_base_space: Option<Arc<AddressSpace>>,
    /// The internal space representing bonded registers (Java creates it on first request).
    join_space: Arc<AddressSpace>,
    stack_grows_negative: bool,
    reverse_justify_stack: bool,
    /// Space-base name to (base space, register name).
    space_bases: Option<BTreeMap<String, (Arc<AddressSpace>, String)>>,
    /// (`tag_spacename`, (first, last)) ranges in spaces named by a `<spacebase>`.
    extra_ranges: Option<Vec<(String, (i64, i64))>>,
    pcode_inject: PcodeInjectLibrary,
    /// Set of addresses the decompiler considers "global" in scope.
    global_set: AddressSet,
    /// Properties, in insertion order (Java's `LinkedHashMap`).
    properties: Vec<(String, String)>,
    calling_convention_map: HashMap<String, Arc<PrototypeModel>>,
    /// Does the decompiler aggressively trim sign extensions.
    aggressive_trim: bool,
    /// Registers the decompiler prefers to split.
    prefer_split: Option<Vec<Varnode>>,
    /// Memory regions the decompiler treats as not addressable.
    no_high_ptr: Option<AddressSet>,
    /// Additional memory ranges the decompiler treats as read-only.
    read_only_set: Option<AddressSet>,
    /// Where the decompiler expects the return address to be stored.
    return_address: Option<Varnode>,
    /// Alignment of function pointers, 0 = no alignment.
    func_ptr_align: i32,
    dead_code_delay: Option<Vec<(Arc<AddressSpace>, i32)>>,
    /// Restrictions on where the decompiler can infer pointers.
    infer_ptr_bounds: Option<Vec<AddressRange>>,
}

// A `SleighLanguage` (itself `Send + Sync`) caches its compiler specs, so a spec must be too.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BasicCompilerSpec>();
};

/// A failure while reading a `.cspec`. Java's reader throws `XmlParseException`, the unchecked
/// `SleighException` (unknown register/space, bad stack growth) and `DuplicateNameException`; all
/// are reported as this one type.
type RestoreError = XmlParseException;

impl BasicCompilerSpec {
    /// Build a spec by parsing the `.cspec` document `xml`.
    ///
    /// Port of `BasicCompilerSpec(CompilerSpecDescription, SleighLanguage, InputStream)`.
    ///
    /// # Errors
    /// Returns an error for malformed or inconsistent XML, an unknown register or space, a
    /// missing default prototype, or duplicate prototype model names.
    pub fn from_xml(
        description: Arc<dyn CompilerSpecDescription>,
        language: &Arc<SleighLanguage>,
        xml: &str,
    ) -> Result<Self, XmlParseException> {
        let mut spec = Self::uninitialized(description, language)?;
        let mut parser = xml_pull_parser_factory::create_from_str(xml, "testpath", None, false)
            .map_err(|e| XmlParseException::new(e.to_string()))?;
        spec.initialize("testpath", &mut parser)?;
        Ok(spec)
    }

    /// Build a spec by parsing the `.cspec` file `cspec_file`.
    ///
    /// Port of `BasicCompilerSpec(CompilerSpecDescription, SleighLanguage, ResourceFile)`.
    ///
    /// # Errors
    /// Every failure is reported as a [`CompilerSpecNotFoundException`] naming the file (and the
    /// line the parser reached), as in Java.
    pub fn from_file(
        description: Arc<dyn CompilerSpecDescription>,
        language: &Arc<SleighLanguage>,
        cspec_file: &ResourceFile,
    ) -> Result<Self, CompilerSpecNotFoundException> {
        let language_id = language.get_language_id();
        let spec_id = description.get_compiler_spec_id();
        let fail = |detail: String, cause: &dyn std::error::Error| {
            CompilerSpecNotFoundException::with_resource_read_error(&language_id, &spec_id, &detail, cause)
        };
        let mut spec = Self::uninitialized(description.clone(), language)
            .map_err(|e| fail(cspec_file.name(), &e))?;
        let stream = cspec_file.get_input_stream().map_err(|e| fail(cspec_file.name(), &e))?;
        let mut parser =
            xml_pull_parser_factory::create_from_reader(stream, &cspec_file.absolute_path(), None, false)
                .map_err(|e| fail(cspec_file.name(), &e))?;
        let result = spec.initialize(&cspec_file.absolute_path(), &mut parser).and_then(|()| {
            if spec.models.is_empty() {
                Err(XmlParseException::new("No prototype models defined"))
            } else {
                Ok(())
            }
        });
        match result {
            Ok(()) => Ok(spec),
            Err(e) => Err(fail(format!("{}:{}", cspec_file.name(), parser.get_line_number()), &e)),
        }
    }

    /// The field state both constructors start from, before the `.cspec` is read.
    fn uninitialized(
        description: Arc<dyn CompilerSpecDescription>,
        language: &Arc<SleighLanguage>,
    ) -> Result<Self, XmlParseException> {
        let pcode_inject = Self::build_inject_library(language)?;
        let data_organization = Arc::new(DataOrganizationImpl::get_default_organization(Some(language.as_ref())));
        Ok(BasicCompilerSpec {
            description,
            source_name: String::new(),
            data_organization,
            ctxsetting: Vec::new(),
            default_model: None,
            eval_current_model: None,
            eval_called_model: None,
            allmodels: Vec::new(),
            models: Vec::new(),
            stack_pointer: None,
            stack_space: None,
            stack_base_space: None,
            // This is a special address space that is only used internally to represent bonded
            // registers
            join_space: AddressSpace::new(SpaceNames::JOIN_SPACE_NAME, 64, 1, AddressSpaceType::Join, 10),
            stack_grows_negative: true,
            reverse_justify_stack: false,
            space_bases: None,
            extra_ranges: None,
            pcode_inject,
            global_set: AddressSet::new(),
            properties: Vec::new(),
            calling_convention_map: HashMap::new(),
            aggressive_trim: false,
            prefer_split: None,
            no_high_ptr: None,
            read_only_set: None,
            return_address: None,
            func_ptr_align: 0,
            dead_code_delay: None,
            infer_ptr_bounds: None,
            language: Arc::downgrade(language),
        })
    }

    /// Reset the `.cspec`-derived state and read `parser`.
    ///
    /// Port of the private `BasicCompilerSpec.initialize`.
    fn initialize<P: XmlPullParser>(&mut self, src_name: &str, parser: &mut P) -> Result<(), RestoreError> {
        self.source_name = src_name.to_string();
        self.space_bases = None;
        self.extra_ranges = None;
        self.global_set = AddressSet::new();
        self.prefer_split = None;
        self.no_high_ptr = None;
        self.read_only_set = None;
        self.default_model = None;
        self.allmodels.clear();
        self.models.clear();
        self.stack_pointer = None;
        self.aggressive_trim = false;
        self.return_address = None;
        self.func_ptr_align = 0;
        self.dead_code_delay = None;
        self.infer_ptr_bounds = None;
        self.restore_xml(parser)
    }

    /// The default p-code injection library for `language`.
    ///
    /// Port of the private `BasicCompilerSpec.buildInjectLibrary`; see the module docs for the
    /// custom-class and additional-inject gaps.
    fn build_inject_library(language: &Arc<SleighLanguage>) -> Result<PcodeInjectLibrary, XmlParseException> {
        if let Some(classname) = Language::get_property(language.as_ref(), PCODE_INJECT_LIBRARY_CLASS) {
            return Err(XmlParseException::new(format!(
                "Failed to instantiate {classname} for language {}: custom p-code inject libraries are \
                 not supported by this port",
                language.get_language_id()
            )));
        }
        Ok(PcodeInjectLibrary::new(language))
    }

    /// Record a default context register setting over the given address range.
    ///
    /// Port of the package-private `BasicCompilerSpec.addContextSetting`.
    pub fn add_context_setting(&mut self, reg: RegisterRef, value: u128, begad: Address, endad: Address) {
        self.ctxsetting.push(ContextSetting::new(reg, value, begad, endad));
    }

    /// The name of the model that appears more than once in `model_list`, if any, after
    /// rebuilding the model arrays, the name lookup and the default/evaluation models from it.
    ///
    /// Port of the protected `BasicCompilerSpec.modelXrefs`.
    ///
    /// # Errors
    /// Returns an error if no (non-merged) model is named `default_name`.
    pub fn model_xrefs(
        &mut self,
        model_list: Vec<Arc<PrototypeModel>>,
        default_name: Option<&str>,
        eval_current: Option<&str>,
        eval_called: Option<&str>,
    ) -> Result<Option<String>, XmlParseException> {
        let mut found_duplicate = None;
        self.build_model_arrays(model_list, default_name)?;
        self.calling_convention_map = HashMap::new();
        for model in &self.models {
            if let Some(name) = model.get_name() {
                if self.calling_convention_map.insert(name.clone(), model.clone()).is_some() {
                    found_duplicate = Some(name);
                }
            }
        }
        self.default_model = default_name.and_then(|n| self.calling_convention_map.get(n).cloned());
        // The default evaluation is to assume default model
        self.eval_current_model = self.default_model.clone();
        self.eval_called_model = self.default_model.clone();
        for evalmodel in &self.allmodels {
            let name = evalmodel.get_name();
            if eval_current.is_some() && name.as_deref() == eval_current {
                self.eval_current_model = Some(evalmodel.clone());
            }
            if eval_called.is_some() && name.as_deref() == eval_called {
                self.eval_called_model = Some(evalmodel.clone());
            }
        }
        Ok(found_duplicate)
    }

    /// Split `model_list` into `models` (non-merged, in order) and `allmodels` (the same,
    /// followed by the merged models).
    ///
    /// Port of the private `BasicCompilerSpec.buildModelArrays`.
    fn build_model_arrays(&mut self, model_list: Vec<Arc<PrototypeModel>>, putative_default_name: Option<&str>) -> Result<(), XmlParseException> {
        let Some(putative_default_name) = putative_default_name else {
            return Err(XmlParseException::new(format!(
                "Compiler Spec {} does not provide a default prototype",
                self.description.get_compiler_spec_name()
            )));
        };
        let found_default = model_list
            .iter()
            .any(|m| !m.is_merged() && m.get_name().as_deref() == Some(putative_default_name));
        if !found_default {
            return Err(XmlParseException::new(format!(
                "Could not find default model {putative_default_name}for Compiler Spec {}",
                self.description.get_compiler_spec_name()
            )));
        }
        let (merged, plain): (Vec<_>, Vec<_>) = model_list.into_iter().partition(|m| m.is_merged());
        self.models = plain.clone();
        self.allmodels = plain;
        self.allmodels.extend(merged);
        Ok(())
    }

    /// Remove the call-mechanism injections of the given models from the inject library.
    ///
    /// Port of the protected `BasicCompilerSpec.removeProgramMechanismPayloads`.
    pub fn remove_program_mechanism_payloads(&mut self, model_list: &[Arc<PrototypeModel>]) {
        for model in model_list {
            if model.has_injection() {
                self.pcode_inject.remove_mechanism_payload(&model.get_inject_name());
            }
        }
    }

    /// Register program-specific inject payloads with the inject library.
    ///
    /// Port of the protected `BasicCompilerSpec.registerProgramInject`.
    pub fn register_program_inject(&mut self, inject_extensions: Vec<Arc<dyn InjectPayloadSleigh>>) {
        self.pcode_inject.register_program_inject(inject_extensions);
    }

    /// Mark `model` as a Program specific extension.
    ///
    /// Port of the protected static `BasicCompilerSpec.markPrototypeAsExtension`.
    pub fn mark_prototype_as_extension(model: &mut PrototypeModel) {
        model.set_program_extension(true);
    }

    /// Give `model` this spec's `<returnaddress>` if it declares none of its own.
    ///
    /// Port of the protected `BasicCompilerSpec.setDefaultReturnAddressIfNeeded`.
    pub fn set_default_return_address_if_needed(&self, model: &mut PrototypeModel) {
        if model.get_return_address().is_none() {
            model.set_return_address(Some(self.return_address.iter().cloned().collect()));
        }
    }

    /// The real p-code injection library.
    pub fn pcode_inject_library(&self) -> &PcodeInjectLibrary {
        &self.pcode_inject
    }

    /// The language this spec was built for.
    ///
    /// # Panics
    /// If the language has been dropped: a spec must not outlive its language (see
    /// [`WeakLanguage`]).
    pub fn sleigh_language(&self) -> Arc<SleighLanguage> {
        self.language
            .upgrade()
            .expect("language dropped while its compiler spec is still in use")
    }

    /// Where the decompiler expects the return address, from `<returnaddress>`.
    pub fn get_return_address(&self) -> Option<&Varnode> {
        self.return_address.as_ref()
    }

    /// Whether the decompiler aggressively trims sign extensions.
    pub fn is_aggressive_trim(&self) -> bool {
        self.aggressive_trim
    }

    /// Alignment of function pointers (0 = none).
    pub fn get_func_ptr_align(&self) -> i32 {
        self.func_ptr_align
    }

    /// The registers the decompiler prefers to split, from `<prefersplit>`.
    pub fn get_prefer_split(&self) -> Option<&[Varnode]> {
        self.prefer_split.as_deref()
    }

    /// The source path of the `.cspec`.
    pub fn get_source_name(&self) -> &str {
        &self.source_name
    }

    /// Like [`CompilerSpec::get_address_space`], but with Java's error for an unknown name.
    /// (Java throws the unchecked `SleighException`; while reading a spec every failure is
    /// reported as an [`XmlParseException`].)
    fn address_space_or_err(&self, space_name: &str) -> Result<Arc<AddressSpace>, XmlParseException> {
        CompilerSpec::get_address_space(self, space_name)
            .ok_or_else(|| XmlParseException::new(format!("Unknown address space: {space_name}")))
    }

    /// Port of the private `BasicCompilerSpec.restoreXml`.
    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), RestoreError> {
        let mut model_list: Vec<Arc<PrototypeModel>> = Vec::new();
        let mut seen_default = false;
        let mut seen_this_call = false;
        let mut default_name: Option<String> = None;
        let mut eval_current_prototype: Option<String> = None;
        let mut eval_called_prototype: Option<String> = None;

        parser.start(&["compiler_spec"])?;
        while parser.peek().is_start() {
            let peeked = parser.peek();
            let name = peeked.get_name().to_string();
            match name.as_str() {
                "properties" => self.restore_properties(parser)?,
                "data_organization" => Arc::make_mut(&mut self.data_organization).restore_xml(parser)?,
                "callfixup" => {
                    let nm = peeked.get_attribute("name").unwrap_or_default();
                    self.restore_inject(nm, CALLFIXUP_TYPE, parser)?;
                }
                "callotherfixup" => {
                    let nm = peeked.get_attribute("targetop").unwrap_or_default();
                    self.restore_inject(nm, CALLOTHERFIXUP_TYPE, parser)?;
                }
                "context_data" => {
                    let mut settings = Vec::new();
                    ContextSetting::parse_context_data(&mut settings, parser, &*self)?;
                    self.ctxsetting.extend(settings);
                }
                "stackpointer" => self.set_stack_pointer(parser)?,
                "spacebase" => self.restore_space_base(parser)?,
                "global" => {
                    let mut global_set = std::mem::take(&mut self.global_set);
                    let res = self.restore_memory_tags("global", parser, &mut global_set);
                    self.global_set = global_set;
                    res?;
                }
                "default_proto" => {
                    parser.start(&[])?;
                    let model = self.add_prototype_model(&mut model_list, parser)?;
                    parser.end()?;
                    if !seen_default {
                        default_name = model.get_name();
                        seen_default = true;
                    }
                    if model.get_name().as_deref() == Some(CALLING_CONVENTION_THISCALL) {
                        seen_this_call = true;
                    }
                }
                "prototype" => {
                    let model = self.add_prototype_model(&mut model_list, parser)?;
                    if default_name.is_none() {
                        default_name = model.get_name();
                    }
                    if model.get_name().as_deref() == Some(CALLING_CONVENTION_THISCALL) {
                        seen_this_call = true;
                    }
                }
                "modelalias" => {
                    let el = parser.start(&[])?;
                    let alias_name = el.get_attribute("name").unwrap_or_default();
                    let parent_name = el.get_attribute("parent").unwrap_or_default();
                    parser.end_matching(&el)?;
                    Self::create_model_alias(&alias_name, &parent_name, &mut model_list)?;
                    if alias_name == CALLING_CONVENTION_THISCALL {
                        seen_this_call = true;
                    }
                }
                "resolveprototype" => {
                    self.add_prototype_model(&mut model_list, parser)?;
                }
                "eval_current_prototype" => {
                    eval_current_prototype = parser.start(&[])?.get_attribute("name");
                    parser.end()?;
                }
                "eval_called_prototype" => {
                    eval_called_prototype = parser.start(&[])?.get_attribute("name");
                    parser.end()?;
                }
                "segmentop" => {
                    let source = format!("cspec: {}", self.sleigh_language().get_language_id().get_id_as_string());
                    let mut payload = InjectPayloadSegment::new(source);
                    payload.restore_xml(parser, &self.sleigh_language())?;
                    self.register_payload(Arc::new(payload))?;
                }
                "aggressivetrim" => {
                    let el = parser.start(&[])?;
                    self.aggressive_trim = decode_boolean(&el.get_attribute("signext").unwrap_or_default());
                    parser.end_matching(&el)?;
                }
                "prefersplit" => self.restore_prefer_split(parser)?,
                "nohighptr" => {
                    let mut set = AddressSet::new();
                    self.restore_memory_tags("nohighptr", parser, &mut set)?;
                    self.no_high_ptr = Some(set);
                }
                "readonly" => {
                    let mut set = AddressSet::new();
                    self.restore_memory_tags("readonly", parser, &mut set)?;
                    self.read_only_set = Some(set);
                }
                "returnaddress" => self.restore_return_address(parser)?,
                "funcptr" => {
                    let subel = parser.start(&[])?;
                    self.func_ptr_align = decode_int(subel.get_attribute("align").as_deref());
                    parser.end_matching(&subel)?;
                }
                "deadcodedelay" => self.restore_dead_code_delay(parser)?,
                "inferptrbounds" => self.restore_infer_ptr_bounds(parser)?,
                _ => {
                    let el = parser.start(&[])?;
                    parser.discard_sub_tree_element(&el);
                }
            }
        }
        parser.end()?;
        if self.stack_pointer.is_none() {
            let default_space = self.sleigh_language().get_default_space();
            self.stack_space = Some(AddressSpace::new(
                SpaceNames::STACK_SPACE_NAME,
                default_space.size(),
                default_space.unit_size(),
                AddressSpaceType::Stack,
                0,
            ));
        }
        if !seen_this_call {
            if let Some(default_name) = &default_name {
                Self::create_model_alias(CALLING_CONVENTION_THISCALL, default_name, &mut model_list)?;
            }
        }
        let dup_name = self.model_xrefs(
            model_list,
            default_name.as_deref(),
            eval_current_prototype.as_deref(),
            eval_called_prototype.as_deref(),
        )?;
        if let Some(dup_name) = dup_name {
            // Java: DuplicateNameException
            return Err(XmlParseException::new(format!("Multiple prototype models with the name: {dup_name}")));
        }
        Ok(())
    }

    /// Restore a `<callfixup>`/`<callotherfixup>` into the inject library, skipping (with a
    /// warning) a payload whose p-code text needs the unported `PcodeParser`.
    fn restore_inject<P: XmlPullParser>(&mut self, name: String, tp: i32, parser: &mut P) -> Result<(), XmlParseException> {
        match self.pcode_inject.restore_xml_inject(self.source_name.clone(), name.clone(), tp, parser) {
            Ok(_) => Ok(()),
            Err(PcodeInjectLibraryError::Sleigh(e)) if PcodeInjectLibrary::is_unported_parser_error(&e) => {
                Msg::warn("BasicCompilerSpec", &format!("{name} not registered: {e}"));
                Ok(())
            }
            Err(PcodeInjectLibraryError::Sleigh(e)) => Err(XmlParseException::new(e.message().to_string())),
            Err(PcodeInjectLibraryError::Xml(e)) => Err(e),
        }
    }

    /// Register an already-restored payload, skipping one that needs the unported `PcodeParser`.
    fn register_payload(&mut self, payload: Arc<dyn InjectPayloadSleigh>) -> Result<(), XmlParseException> {
        let name = payload.get_name();
        match self.pcode_inject.register_inject(payload) {
            Ok(_) => Ok(()),
            Err(e) if PcodeInjectLibrary::is_unported_parser_error(&e) => {
                Msg::warn("BasicCompilerSpec", &format!("{name} not registered: {e}"));
                Ok(())
            }
            Err(e) => Err(XmlParseException::new(e.message().to_string())),
        }
    }

    /// Port of the private `BasicCompilerSpec.restoreProperties`.
    fn restore_properties<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        parser.start(&[])?;
        while parser.peek().is_start() {
            let el = parser.start(&[])?;
            if el.get_name() == "property" {
                let key = el.get_attribute("key").unwrap_or_default();
                let value = el.get_attribute("value").unwrap_or_default();
                match self.properties.iter_mut().find(|(k, _)| *k == key) {
                    Some(entry) => entry.1 = value,
                    None => self.properties.push((key, value)),
                }
                parser.end_matching(&el)?;
            } else {
                parser.discard_sub_tree_element(&el);
            }
        }
        parser.end()?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.restoreSpaceBase`.
    fn restore_space_base<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        let name = el.get_attribute("name").unwrap_or_default();
        let register_name = el.get_attribute("register").unwrap_or_default();
        let Some(reg) = self.sleigh_language().get_register_by_name(&register_name) else {
            return Err(XmlParseException::new(format!("Unknown register: {name}")));
        };
        let space_name = el.get_attribute("space").unwrap_or_default();
        let language = self.sleigh_language();
        let bases = self.space_bases.get_or_insert_with(BTreeMap::new);
        if language.get_address_factory().get_address_space_by_name(&name).is_some() || bases.contains_key(&name) {
            return Err(XmlParseException::new(format!("Duplicate space name: {name}")));
        }
        let space = self.address_space_or_err(&space_name)?;
        let reg_name = reg.name().to_string();
        self.space_bases.get_or_insert_with(BTreeMap::new).insert(name, (space, reg_name));
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.restoreReturnAddress`.
    fn restore_return_address<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        let subel = parser.start(&[])?;
        let addr_sized = address_xml::restore_xml(&subel, &*self)?;
        self.return_address = Some(addr_sized.get_varnode());
        parser.end_matching(&subel)?;
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Record a range in a space named by a `<spacebase>` (which has no address space of its own).
    ///
    /// Port of the private `BasicCompilerSpec.readExtraRange`.
    fn read_extra_range<E: XmlElement>(&mut self, el: &E, spc_name: &str, tag_name: &str) {
        let address_space = self.space_bases.as_ref().and_then(|b| b.get(spc_name)).map(|(s, _)| s.clone());
        let mut first: i64 = 0;
        let mut last: i64 = -1;
        let mut seen_last = false;
        if let Some(attrvalue) = el.get_attribute("first") {
            first = decode_long(Some(&attrvalue));
        }
        if let Some(attrvalue) = el.get_attribute("last") {
            last = decode_long(Some(&attrvalue));
            seen_last = true;
        }
        if !seen_last {
            if let Some(space) = address_space {
                last = space.max_address().unsigned_offset() as i64;
            }
        }
        self.extra_ranges
            .get_or_insert_with(Vec::new)
            .push((format!("{tag_name}_{spc_name}"), (first, last)));
    }

    /// Port of the private `BasicCompilerSpec.restoreMemoryTags`.
    fn restore_memory_tags<P: XmlPullParser>(&mut self, tag_name: &str, parser: &mut P, addr_set: &mut AddressSet) -> Result<(), XmlParseException> {
        parser.start(&[tag_name])?;
        while parser.peek().is_start() {
            let subel = parser.start(&[])?;
            let name = subel.get_name().to_string();
            if name == "range" || name == "register" {
                let spc_name = subel.get_attribute("space");
                match spc_name {
                    Some(spc) if self.space_bases.as_ref().is_some_and(|b| b.contains_key(&spc)) => {
                        self.read_extra_range(&subel, &spc, tag_name);
                    }
                    _ => {
                        let range = address_xml::restore_range_xml(&subel, &*self)?;
                        addr_set.add_range(&range.get_first_address(), &range.get_last_address());
                    }
                }
            } else {
                return Err(XmlParseException::new(format!("Unexpected <{tag_name}> sub-tag: {name}")));
            }
            parser.end_matching(&subel)?;
        }
        parser.end()?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.restorePreferSplit`.
    fn restore_prefer_split<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        if el.get_attribute("style").as_deref() != Some("inhalf") {
            return Err(XmlParseException::new("Unknown prefersplit strategy"));
        }
        let mut prefer_split = Vec::new();
        while parser.peek().is_start() {
            let subel = parser.start(&[])?;
            let addr_sized = address_xml::restore_xml(&subel, &*self)?;
            parser.end_matching(&subel)?;
            prefer_split.push(addr_sized.get_varnode());
        }
        self.prefer_split = Some(prefer_split);
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.restoreDeadCodeDelay`.
    fn restore_dead_code_delay<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        let space = self.address_space_or_err(&el.get_attribute("space").unwrap_or_default())?;
        let delay = decode_int(el.get_attribute("delay").as_deref());
        self.dead_code_delay.get_or_insert_with(Vec::new).push((space, delay));
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.restoreInferPtrBounds`.
    fn restore_infer_ptr_bounds<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        let mut bounds = self.infer_ptr_bounds.take().unwrap_or_default();
        while parser.peek().is_start() {
            let subel = parser.start(&[])?;
            let addr_sized = address_xml::restore_range_xml(&subel, &*self)?;
            bounds.push(AddressRange::new(addr_sized.get_first_address(), addr_sized.get_last_address()));
            parser.end_matching(&subel)?;
        }
        self.infer_ptr_bounds = Some(bounds);
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.setStackPointer`.
    fn set_stack_pointer<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let el = parser.start(&[])?;
        let reg_name = el.get_attribute("register").unwrap_or_default();
        let Some(stack_pointer) = self.sleigh_language().get_register_by_name(&reg_name) else {
            return Err(XmlParseException::new(format!("Unknown register: {reg_name}")));
        };
        let base_space_name = el.get_attribute("space").unwrap_or_default();
        let stack_base_space = self
            .address_space_or_err(&base_space_name)
            .map_err(|_| XmlParseException::new(format!("Undefined base stack space: {base_space_name}")))?;
        let stack_space_size = stack_pointer.bit_length().min(stack_base_space.size());
        self.stack_space = Some(AddressSpace::new(
            SpaceNames::STACK_SPACE_NAME,
            stack_space_size,
            stack_base_space.unit_size(),
            AddressSpaceType::Stack,
            0,
        ));
        self.stack_base_space = Some(stack_base_space);
        self.stack_pointer = Some(stack_pointer);
        if let Some(reverse_justify_str) = el.get_attribute("reversejustify") {
            self.reverse_justify_stack = reverse_justify_str == "1" || reverse_justify_str.eq_ignore_ascii_case("true");
        }
        match el.get_attribute("growth").as_deref() {
            None | Some("negative") => self.stack_grows_negative = true,
            Some("positive") => self.stack_grows_negative = false,
            Some(growth) => {
                return Err(XmlParseException::new(format!(
                    "Bad stack growth {growth} should be 'positive' or 'negative'"
                )))
            }
        }
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Add an alias named `alias_name` of the model named `parent_name` to `model_list`.
    ///
    /// Port of the private `BasicCompilerSpec.createModelAlias`.
    fn create_model_alias(alias_name: &str, parent_name: &str, model_list: &mut Vec<Arc<PrototypeModel>>) -> Result<(), XmlParseException> {
        let Some(parent_model) = model_list.iter().find(|m| m.get_name().as_deref() == Some(parent_name)).cloned() else {
            return Err(XmlParseException::new(format!("Parent for model alias does not exist: {parent_name}")));
        };
        if parent_model.is_merged() {
            return Err(XmlParseException::new(format!("Cannot make alias of merged model: {parent_name}")));
        }
        if parent_model.get_alias_parent().is_some() {
            return Err(XmlParseException::new(format!("Cannot make alias of an alias: {parent_name}")));
        }
        model_list.push(Arc::new(PrototypeModel::new_alias(alias_name, &parent_model)));
        Ok(())
    }

    /// Restore a `<prototype>` or `<resolveprototype>` and append it to `model_list`.
    ///
    /// Port of the private `BasicCompilerSpec.addPrototypeModel`.
    fn add_prototype_model<P: XmlPullParser>(&mut self, model_list: &mut Vec<Arc<PrototypeModel>>, parser: &mut P) -> Result<Arc<PrototypeModel>, XmlParseException> {
        let mut model = if parser.peek().get_name() == "resolveprototype" {
            let mut mergemodel = PrototypeModel::new_merged();
            mergemodel.restore_merged_xml(parser, model_list)?;
            mergemodel
        } else {
            let mut model = PrototypeModel::new();
            // The model registers its injection in this spec's library while reading this spec.
            let placeholder = PcodeInjectLibrary::new(&self.sleigh_language());
            let mut library = std::mem::replace(&mut self.pcode_inject, placeholder);
            let res = model.restore_xml(parser, &*self, Some(&mut library));
            self.pcode_inject = library;
            res?;
            model
        };
        self.set_default_return_address_if_needed(&mut model);
        let model = Arc::new(model);
        model_list.push(model.clone());
        Ok(model)
    }

    /// Port of the private `BasicCompilerSpec.encodeProperties`.
    fn encode_properties(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        if self.properties.is_empty() {
            return Ok(());
        }
        encoder.open_element(ELEM_PROPERTIES)?;
        for (key, value) in &self.properties {
            encoder.open_element(ELEM_PROPERTY)?;
            encoder.write_string(ATTRIB_KEY, key)?;
            encoder.write_string(ATTRIB_VALUE, value)?;
            encoder.close_element(ELEM_PROPERTY)?;
        }
        encoder.close_element(ELEM_PROPERTIES)
    }

    /// Port of the private `BasicCompilerSpec.encodeSpaceBases`.
    fn encode_space_bases(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let Some(space_bases) = &self.space_bases else {
            return Ok(());
        };
        for (name, (space, register)) in space_bases {
            encoder.open_element(ELEM_SPACEBASE)?;
            encoder.write_string(ATTRIB_NAME, name)?;
            encoder.write_string(ATTRIB_REGISTER, register)?;
            encoder.write_space(ATTRIB_SPACE, space)?;
            encoder.close_element(ELEM_SPACEBASE)?;
        }
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.encodeReturnAddress`.
    fn encode_return_address(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let Some(return_address) = &self.return_address else {
            return Ok(());
        };
        encoder.open_element(ELEM_RETURNADDRESS)?;
        encoder.open_element(ELEM_VARNODE)?;
        address_xml::encode_attributes_with_size(encoder, return_address.get_address(), return_address.get_size())?;
        encoder.close_element(ELEM_VARNODE)?;
        encoder.close_element(ELEM_RETURNADDRESS)
    }

    /// Port of the private `BasicCompilerSpec.encodeExtraRanges`.
    fn encode_extra_ranges(&self, encoder: &mut dyn Encoder, tag: &str) -> std::io::Result<()> {
        let Some(extra_ranges) = &self.extra_ranges else {
            return Ok(());
        };
        for (key, (first, last)) in extra_ranges {
            if !key.starts_with(tag) {
                continue;
            }
            let spc_name = &key[key.find('_').map_or(0, |i| i + 1)..];
            encoder.open_element(ELEM_RANGE)?;
            // Must use string encoding here, as address space may not exist
            encoder.write_string(ATTRIB_SPACE, spc_name)?;
            if *first != 0 {
                encoder.write_unsigned_integer(ATTRIB_FIRST, *first as u64)?;
            }
            if *last != -1 {
                encoder.write_unsigned_integer(ATTRIB_LAST, *last as u64)?;
            }
            encoder.close_element(ELEM_RANGE)?;
        }
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.encodeMemoryTags`.
    fn encode_memory_tags(
        &self,
        encoder: &mut dyn Encoder,
        tag: crate::program::model::pcode::ids::ElementId,
        addr_set: Option<&AddressSet>,
    ) -> std::io::Result<()> {
        let Some(addr_set) = addr_set else {
            return Ok(());
        };
        encoder.open_element(tag)?;
        for range in addr_set.to_list() {
            encoder.open_element(ELEM_RANGE)?;
            address_xml::encode_attributes_range(encoder, range.min_address(), range.max_address())?;
            encoder.close_element(ELEM_RANGE)?;
        }
        self.encode_extra_ranges(encoder, tag.name)?;
        encoder.close_element(tag)
    }

    /// Port of the private `BasicCompilerSpec.encodePreferSplit`.
    fn encode_prefer_split(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let Some(prefer_split) = self.prefer_split.as_ref().filter(|p| !p.is_empty()) else {
            return Ok(());
        };
        encoder.open_element(ELEM_PREFERSPLIT)?;
        encoder.write_string(ATTRIB_STYLE, "inhalf")?;
        for varnode in prefer_split {
            encoder.open_element(ELEM_VARNODE)?;
            address_xml::encode_attributes_with_size(encoder, varnode.get_address(), varnode.get_size())?;
            encoder.close_element(ELEM_VARNODE)?;
        }
        encoder.close_element(ELEM_PREFERSPLIT)
    }

    /// Port of the private `BasicCompilerSpec.encodeDeadCodeDelay`.
    fn encode_dead_code_delay(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        for (space, delay) in self.dead_code_delay.iter().flatten() {
            encoder.open_element(ELEM_DEADCODEDELAY)?;
            encoder.write_space(ATTRIB_SPACE, space)?;
            encoder.write_signed_integer(ATTRIB_DELAY, *delay as i64)?;
            encoder.close_element(ELEM_DEADCODEDELAY)?;
        }
        Ok(())
    }

    /// Port of the private `BasicCompilerSpec.encodeInferPtrBounds`.
    fn encode_infer_ptr_bounds(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let Some(bounds) = &self.infer_ptr_bounds else {
            return Ok(());
        };
        encoder.open_element(ELEM_INFERPTRBOUNDS)?;
        for range in bounds {
            encoder.open_element(ELEM_RANGE)?;
            address_xml::encode_attributes_range(encoder, range.min_address(), range.max_address())?;
            encoder.close_element(ELEM_RANGE)?;
        }
        encoder.close_element(ELEM_INFERPTRBOUNDS)
    }

    /// Port of `BasicCompilerSpec.isEquivalent` once `other` is known to be a
    /// `BasicCompilerSpec`.
    fn is_equivalent_spec(&self, other: &BasicCompilerSpec) -> bool {
        let same_name = |a: &Option<Arc<PrototypeModel>>, b: &Option<Arc<PrototypeModel>>| match (a, b) {
            (Some(a), Some(b)) => a.get_name() == b.get_name(),
            (None, None) => true,
            _ => false,
        };
        let same_register = |a: &Option<RegisterRef>, b: &Option<RegisterRef>| match (a, b) {
            (Some(a), Some(b)) => *a == *b,
            (None, None) => true,
            _ => false,
        };
        self.aggressive_trim == other.aggressive_trim
            && self.data_organization.is_equivalent(&other.data_organization)
            && self.ctxsetting.len() == other.ctxsetting.len()
            && self.ctxsetting.iter().zip(&other.ctxsetting).all(|(a, b)| a.is_equivalent(b))
            && self.dead_code_delay == other.dead_code_delay
            && same_name(&self.default_model, &other.default_model)
            && same_name(&self.eval_called_model, &other.eval_called_model)
            && same_name(&self.eval_current_model, &other.eval_current_model)
            && self.allmodels.len() == other.allmodels.len()
            && self.allmodels.iter().zip(&other.allmodels).all(|(a, b)| a.is_equivalent(b))
            && self.extra_ranges == other.extra_ranges
            && self.func_ptr_align == other.func_ptr_align
            && self.global_set == other.global_set
            && self.infer_ptr_bounds == other.infer_ptr_bounds
            && self.no_high_ptr == other.no_high_ptr
            && self.pcode_inject.is_equivalent(&other.pcode_inject)
            && self.prefer_split == other.prefer_split
            && self.properties == other.properties
            && self.read_only_set == other.read_only_set
            && self.return_address == other.return_address
            && self.reverse_justify_stack == other.reverse_justify_stack
            && self.space_bases == other.space_bases
            && self.stack_base_space == other.stack_base_space
            && self.stack_grows_negative == other.stack_grows_negative
            && same_register(&self.stack_pointer, &other.stack_pointer)
    }
}

impl CompilerSpec for BasicCompilerSpec {
    /// A non-owning handle (the language owns this spec; see [`WeakLanguage`]).
    fn get_language(&self) -> Box<dyn Language + Send + Sync> {
        Box::new(WeakLanguage::from_weak(self.language.clone()))
    }

    fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
        Box::new(self.description.clone())
    }

    fn get_compiler_spec_id(&self) -> CompilerSpecID {
        self.description.get_compiler_spec_id()
    }

    fn get_stack_pointer(&self) -> Option<RegisterRef> {
        self.stack_pointer.clone()
    }

    fn is_stack_right_justified(&self) -> bool {
        let big_endian = self.sleigh_language().is_big_endian();
        (big_endian && !self.reverse_justify_stack) || (!big_endian && self.reverse_justify_stack)
    }

    fn get_address_space(&self, space_name: &str) -> Option<Arc<AddressSpace>> {
        let space = if space_name == SpaceNames::STACK_SPACE_NAME {
            self.stack_space.clone()
        } else if space_name == SpaceNames::JOIN_SPACE_NAME {
            Some(self.join_space.clone())
        } else {
            self.sleigh_language().get_address_factory().get_address_space_by_name(space_name)
        };
        if space_name == SpaceNames::OTHER_SPACE_NAME {
            return Some(AddressSpace::new(
                SpaceNames::OTHER_SPACE_NAME,
                64,
                1,
                AddressSpaceType::Other,
                SpaceNames::OTHER_SPACE_INDEX as i32,
            ));
        }
        space
    }

    /// # Panics
    /// Before the `.cspec` has been read (never, for a constructed spec).
    fn get_stack_space(&self) -> Arc<AddressSpace> {
        self.stack_space.clone().expect("stack space is set when the .cspec is read")
    }

    /// Java returns `null` without a `<stackpointer>`; this trait's signature has no absent
    /// value, so the language's default space (where such a stack would live) is returned.
    fn get_stack_base_space(&self) -> Arc<AddressSpace> {
        self.stack_base_space.clone().unwrap_or_else(|| self.sleigh_language().get_default_space())
    }

    fn stack_grows_negative(&self) -> bool {
        self.stack_grows_negative
    }

    fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext) {
        for cs in &self.ctxsetting {
            let register_value = RegisterValue::with_value(cs.get_register().clone(), cs.get_value());
            ctx.set_default_value(Box::new(register_value), cs.get_start_address(), cs.get_end_address());
        }
    }

    fn get_calling_conventions(&self) -> Vec<Arc<PrototypeModel>> {
        self.models.clone()
    }

    fn get_calling_convention(&self, name: &str) -> Option<Arc<PrototypeModel>> {
        if name == UNKNOWN_CALLING_CONVENTION_STRING {
            return None;
        }
        if name == DEFAULT_CALLING_CONVENTION_STRING {
            return self.get_default_calling_convention();
        }
        self.calling_convention_map.get(name).cloned()
    }

    fn get_all_models(&self) -> Vec<Arc<PrototypeModel>> {
        self.allmodels.clone()
    }

    fn get_default_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
        self.default_model.clone()
    }

    fn get_decompiler_output_language(&self) -> DecompilerLanguage {
        DecompilerLanguage::CLanguage
    }

    /// # Panics
    /// Before the `.cspec` has been read (never, for a constructed spec).
    fn get_prototype_evaluation_model(&self, model_type: EvaluationModelType) -> Arc<PrototypeModel> {
        match model_type {
            EvaluationModelType::EvalCurrent => self.eval_current_model.clone(),
            EvaluationModelType::EvalCalled => self.eval_called_model.clone(),
        }
        .expect("evaluation models are set when the .cspec is read")
    }

    fn is_global(&self, addr: &Address) -> bool {
        self.global_set.contains(addr)
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.data_organization.clone()
    }

    fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibraryView> {
        Box::new(self.pcode_inject.clone())
    }

    /// # Panics
    /// Before the `.cspec` has been read (never, for a constructed spec).
    fn match_convention(&self, convention_name: &str) -> Arc<PrototypeModel> {
        let default_model = || self.default_model.clone().expect("default model is set when the .cspec is read");
        if is_unknown_calling_convention(Some(convention_name)) || convention_name == CALLING_CONVENTION_DEFAULT {
            return default_model();
        }
        self.models
            .iter()
            .find(|m| m.get_name().as_deref() == Some(convention_name))
            .cloned()
            .unwrap_or_else(default_model)
    }

    /// # Panics
    /// If the current evaluation model is merged and none of its candidates fits `params` (Java
    /// throws the unchecked `SleighException` from `PrototypeModelMerged.selectModel`).
    fn find_best_calling_convention(&self, params: &[&dyn Parameter]) -> Arc<PrototypeModel> {
        let eval_current = self.eval_current_model.clone().expect("evaluation models are set when the .cspec is read");
        if !eval_current.is_merged() {
            return eval_current;
        }
        eval_current.select_model(params).unwrap_or_else(|e| panic!("{}", e.message()))
    }

    fn has_property(&self, key: &str) -> bool {
        self.properties.iter().any(|(k, _)| k == key)
    }

    fn does_c_data_type_conversions(&self) -> bool {
        true // There are currently no compiler specs that do not need to do the conversion
    }

    /// # Panics
    /// If the property is not an integer (Java's `NumberFormatException`).
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32 {
        match self.get_property(key) {
            Some(v) => v.parse().unwrap_or_else(|_| panic!("property {key}={v} is not an integer")),
            None => default_int,
        }
    }

    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool {
        match self.get_property(key) {
            Some(v) => v.eq_ignore_ascii_case("true"),
            None => default_boolean,
        }
    }

    fn get_property_or(&self, key: &str, default_string: &str) -> String {
        self.get_property(key).unwrap_or_else(|| default_string.to_string())
    }

    fn get_property(&self, key: &str) -> Option<String> {
        self.properties.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    fn get_property_keys(&self) -> HashSet<String> {
        self.properties.iter().map(|(k, _)| k.clone()).collect()
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_COMPILER_SPEC)?;
        self.encode_properties(encoder)?;
        self.data_organization.encode(encoder)?;
        ContextSetting::encode_context_data(encoder, &self.ctxsetting)?;
        if self.aggressive_trim {
            encoder.open_element(ELEM_AGGRESSIVETRIM)?;
            encoder.write_bool(ATTRIB_SIGNEXT, self.aggressive_trim)?;
            encoder.close_element(ELEM_AGGRESSIVETRIM)?;
        }
        if let Some(stack_pointer) = &self.stack_pointer {
            encoder.open_element(ELEM_STACKPOINTER)?;
            encoder.write_string(ATTRIB_REGISTER, stack_pointer.name())?;
            encoder.write_space(ATTRIB_SPACE, &self.get_stack_base_space())?;
            if self.reverse_justify_stack {
                encoder.write_bool(ATTRIB_REVERSEJUSTIFY, self.reverse_justify_stack)?;
            }
            if !self.stack_grows_negative {
                encoder.write_string(ATTRIB_GROWTH, "positive")?;
            }
            encoder.close_element(ELEM_STACKPOINTER)?;
        }
        self.encode_space_bases(encoder)?;
        self.encode_memory_tags(encoder, ELEM_GLOBAL, Some(&self.global_set))?;
        self.encode_return_address(encoder)?; // Must come before PrototypeModels
        self.pcode_inject.encode_compiler_spec(encoder)?;
        if let Some(default_model) = &self.default_model {
            encoder.open_element(ELEM_DEFAULT_PROTO)?;
            default_model.encode(encoder, Some(&self.pcode_inject))?;
            encoder.close_element(ELEM_DEFAULT_PROTO)?;
        }
        for model in &self.allmodels {
            if self.default_model.as_ref().is_some_and(|d| Arc::ptr_eq(d, model)) {
                continue; // Already emitted
            }
            model.encode(encoder, Some(&self.pcode_inject))?;
        }
        let is_default = |m: &Arc<PrototypeModel>| self.default_model.as_ref().is_some_and(|d| Arc::ptr_eq(d, m));
        if let Some(model) = self.eval_current_model.as_ref().filter(|m| !is_default(m)) {
            encoder.open_element(ELEM_EVAL_CURRENT_PROTOTYPE)?;
            encoder.write_string(ATTRIB_NAME, model.get_name().as_deref().unwrap_or(""))?;
            encoder.close_element(ELEM_EVAL_CURRENT_PROTOTYPE)?;
        }
        if let Some(model) = self.eval_called_model.as_ref().filter(|m| !is_default(m)) {
            encoder.open_element(ELEM_EVAL_CALLED_PROTOTYPE)?;
            encoder.write_string(ATTRIB_NAME, model.get_name().as_deref().unwrap_or(""))?;
            encoder.close_element(ELEM_EVAL_CALLED_PROTOTYPE)?;
        }
        self.encode_prefer_split(encoder)?;
        self.encode_memory_tags(encoder, ELEM_NOHIGHPTR, self.no_high_ptr.as_ref())?;
        self.encode_memory_tags(encoder, ELEM_READONLY, self.read_only_set.as_ref())?;
        if self.func_ptr_align != 0 {
            encoder.open_element(ELEM_FUNCPTR)?;
            encoder.write_signed_integer(ATTRIB_ALIGN, self.func_ptr_align as i64)?;
            encoder.close_element(ELEM_FUNCPTR)?;
        }
        self.encode_dead_code_delay(encoder)?;
        self.encode_infer_ptr_bounds(encoder)?;
        encoder.close_element(ELEM_COMPILER_SPEC)
    }

    fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
        other.as_basic_compiler_spec().is_some_and(|other| self.is_equivalent_spec(other))
    }

    fn as_basic_compiler_spec(&self) -> Option<&BasicCompilerSpec> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_compiler_spec_description::SleighCompilerSpecDescription;
    use crate::program::model::lang::basic_compiler_spec_description::BasicCompilerSpecDescription;
    use crate::program::model::lang::cspec_test_support::{float_type, int_type, sleigh_x86_64_language, TestDataTypeManager};
    use crate::program::model::lang::inject_payload::CALLMECHANISM_TYPE;
    use crate::program::model::pcode::{AttributeId, ElementId};
    use crate::program::seam_stubs::PrototypePieces;

    /// A trimmed `x86-64-gcc.cspec`: every element kind `BasicCompilerSpec` reads, with the
    /// System V `__stdcall` default prototype and the Microsoft `MSABI` prototype.
    const X86_64_GCC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <properties>
    <property key="useOperandReferenceAnalyzerSwitchTables" value="true"/>
    <property key="stackAlign" value="16"/>
  </properties>
  <data_organization>
    <pointer_size value="8" />
    <long_size value="8" />
    <long_double_size value="16" />
    <size_alignment_map>
      <entry size="1" alignment="1" />
      <entry size="2" alignment="2" />
      <entry size="4" alignment="4" />
      <entry size="8" alignment="8" />
      <entry size="16" alignment="16" />
    </size_alignment_map>
  </data_organization>
  <global>
    <range space="ram"/>
  </global>
  <stackpointer register="RSP" space="ram"/>
  <returnaddress>
    <varnode space="stack" offset="0" size="8"/>
  </returnaddress>
  <funcptr align="2"/>
  <aggressivetrim signext="true"/>
  <prefersplit style="inhalf">
    <register name="XMM0"/>
  </prefersplit>
  <readonly>
    <range space="ram" first="0x1000" last="0x1fff"/>
  </readonly>
  <deadcodedelay space="register" delay="3"/>
  <inferptrbounds>
    <range space="ram" first="0x400000" last="0x7fffff"/>
  </inferptrbounds>
  <callfixup name="x86_return_thunk">
    <target name="__x86.get_pc_thunk.bx"/>
    <pcode>
      <body><![CDATA[
        RBX = * RSP;
        RSP = RSP + 8;
      ]]></body>
    </pcode>
  </callfixup>
  <callotherfixup targetop="syscall">
    <pcode dynamic="true">
      <input name="num"/>
    </pcode>
  </callotherfixup>
  <default_proto>
    <prototype name="__stdcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
        <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM1_Qa"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RSI"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R8"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R9"/></pentry>
        <pentry minsize="1" maxsize="500" align="8"><addr offset="8" space="stack"/></pentry>
      </input>
      <output>
        <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RAX"/></pentry>
        <pentry minsize="9" maxsize="16"><addr space="join" piece1="RDX" piece2="RAX"/></pentry>
      </output>
      <killedbycall>
        <register name="RAX"/>
        <register name="RDX"/>
        <register name="XMM0"/>
      </killedbycall>
      <unaffected>
        <register name="RBX"/>
        <register name="RSP"/>
        <register name="RBP"/>
        <register name="R12"/>
        <register name="R13"/>
        <register name="R14"/>
        <register name="R15"/>
      </unaffected>
    </prototype>
  </default_proto>
  <prototype name="MSABI" extrapop="8" stackshift="8">
    <input pointermax="8">
      <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
      <pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>
      <pentry minsize="1" maxsize="8"><register name="R8"/></pentry>
      <pentry minsize="1" maxsize="8"><register name="R9"/></pentry>
      <pentry minsize="1" maxsize="500" align="8"><addr offset="40" space="stack"/></pentry>
    </input>
    <output>
      <pentry minsize="1" maxsize="8"><register name="RAX"/></pentry>
    </output>
    <unaffected>
      <register name="RBX"/>
      <register name="RSP"/>
    </unaffected>
  </prototype>
  <modelalias name="__cdecl" parent="__stdcall"/>
  <resolveprototype name="__stdcall/MSABI">
    <model name="__stdcall"/>
    <model name="MSABI"/>
  </resolveprototype>
  <eval_current_prototype name="__stdcall/MSABI"/>
</compiler_spec>
"#;

    fn description() -> Arc<dyn CompilerSpecDescription> {
        Arc::new(BasicCompilerSpecDescription::new(CompilerSpecID::new(Some("gcc")), "gcc"))
    }

    /// The language the test specs are built for. A spec does not keep its language alive, so it
    /// is kept for the whole test run.
    fn x86_64_language() -> &'static Arc<SleighLanguage> {
        static LANGUAGE: std::sync::OnceLock<Arc<SleighLanguage>> = std::sync::OnceLock::new();
        LANGUAGE.get_or_init(|| sleigh_x86_64_language(None))
    }

    fn spec_from(xml: &str) -> Result<BasicCompilerSpec, XmlParseException> {
        BasicCompilerSpec::from_xml(description(), x86_64_language(), xml)
    }

    fn gcc() -> BasicCompilerSpec {
        spec_from(X86_64_GCC).unwrap()
    }

    fn names(models: &[Arc<PrototypeModel>]) -> Vec<String> {
        models.iter().map(|m| m.get_name().unwrap_or_default()).collect()
    }

    #[test]
    fn restores_models_aliases_and_evaluation_models() {
        let spec = gcc();
        assert_eq!(names(&spec.get_calling_conventions()), vec!["__stdcall", "MSABI", "__cdecl", "__thiscall"]);
        assert_eq!(names(&spec.get_all_models()), vec!["__stdcall", "MSABI", "__cdecl", "__thiscall", "__stdcall/MSABI"]);
        assert_eq!(spec.get_default_calling_convention().unwrap().get_name().as_deref(), Some("__stdcall"));
        // No <modelalias> for __thiscall, so one is made from the default model.
        let thiscall = spec.get_calling_convention("__thiscall").unwrap();
        assert!(thiscall.has_this_pointer());
        assert_eq!(thiscall.get_alias_parent().unwrap().get_name().as_deref(), Some("__stdcall"));
        assert!(spec.get_calling_convention("unknown").is_none());
        assert_eq!(spec.get_calling_convention("default").unwrap().get_name().as_deref(), Some("__stdcall"));
        assert!(spec.get_calling_convention("nope").is_none());
        assert_eq!(spec.match_convention("MSABI").get_name().as_deref(), Some("MSABI"));
        assert_eq!(spec.match_convention("nope").get_name().as_deref(), Some("__stdcall"));
        let current = spec.get_prototype_evaluation_model(EvaluationModelType::EvalCurrent);
        assert!(current.is_merged());
        assert_eq!(current.num_models(), 2);
        assert_eq!(
            spec.get_prototype_evaluation_model(EvaluationModelType::EvalCalled).get_name().as_deref(),
            Some("__stdcall")
        );
    }

    #[test]
    fn restores_sysv_model_details() {
        let spec = gcc();
        let model = spec.get_default_calling_convention().unwrap();
        assert_eq!(model.get_extrapop(), 8);
        assert_eq!(model.get_stackshift(), 8);
        let killed: Vec<(i64, i32)> = model.get_killed_by_call_list().iter().map(|v| (v.get_offset(), v.get_size())).collect();
        assert_eq!(killed, vec![(0x0, 8), (0x10, 8), (0x1200, 16)]);
        assert_eq!(model.get_unaffected_list().len(), 7);
        // The spec's <returnaddress> became the model's return address.
        let ret = model.get_return_address().unwrap();
        assert_eq!(ret.len(), 1);
        assert_eq!(ret[0].get_address().space().space_type(), AddressSpaceType::Stack);
        assert_eq!(ret[0].get_size(), 8);
        assert_eq!(model.get_stack_parameter_offset(), Some(8));
        assert_eq!(model.get_stack_parameter_alignment(), 8);
    }

    #[test]
    fn assigns_sysv_and_msabi_parameters() {
        let spec = gcc();
        let sysv = spec.get_default_calling_convention().unwrap();
        // long f(long, double, long, long, long, long, long, long)
        let mut intypes = vec![int_type(8), float_type(8)];
        intypes.extend((0..6).map(|_| int_type(8)));
        let proto = PrototypePieces { outtype: Some(int_type(8)), intypes, ..Default::default() };
        let mut res = Vec::new();
        sysv.assign_parameter_storage(&proto, &TestDataTypeManager, &mut res, true);
        let locs: Vec<(AddressSpaceType, i64)> = res
            .iter()
            .map(|p| {
                let a = p.address.as_ref().unwrap();
                (a.space().space_type(), a.offset())
            })
            .collect();
        use AddressSpaceType::{Register as R, Stack as S};
        // RAX; RDI, XMM0, RSI, RDX, RCX, R8, R9, then the first stack slot
        assert_eq!(
            locs,
            vec![(R, 0x0), (R, 0x38), (R, 0x1200), (R, 0x30), (R, 0x10), (R, 0x8), (R, 0x80), (R, 0x88), (S, 8)]
        );

        let ms = spec.get_calling_convention("MSABI").unwrap();
        // A 16-byte struct goes by reference (pointermax="8"): a pointer in RCX.
        let proto = PrototypePieces { outtype: Some(int_type(8)), intypes: vec![int_type(16), int_type(4)], ..Default::default() };
        let mut res = Vec::new();
        ms.assign_parameter_storage(&proto, &TestDataTypeManager, &mut res, true);
        assert_eq!(res[1].address.as_ref().unwrap().offset(), 0x8);
        assert!(res[1].is_indirect);
        assert_eq!(res[2].address.as_ref().unwrap().offset(), 0x10);
    }

    #[test]
    fn restores_spaces_stack_and_decompiler_settings() {
        let spec = gcc();
        assert_eq!(spec.get_stack_pointer().unwrap().name(), "RSP");
        assert!(spec.stack_grows_negative());
        assert!(!spec.is_stack_right_justified());
        assert_eq!(spec.get_stack_space().size(), 64);
        assert_eq!(spec.get_stack_space().space_type(), AddressSpaceType::Stack);
        assert_eq!(spec.get_stack_base_space().name(), "ram");
        assert_eq!(CompilerSpec::get_address_space(&spec, "join").unwrap().space_type(), AddressSpaceType::Join);
        assert_eq!(CompilerSpec::get_address_space(&spec, "OTHER").unwrap().space_type(), AddressSpaceType::Other);
        assert!(CompilerSpec::get_address_space(&spec, "nowhere").is_none());
        let ram = spec.get_stack_base_space();
        assert!(spec.is_global(&ram.address(0x1234)));
        assert!(spec.is_aggressive_trim());
        assert_eq!(spec.get_func_ptr_align(), 2);
        assert_eq!(spec.get_prefer_split().unwrap()[0].get_size(), 16);
        assert_eq!(spec.get_return_address().unwrap().get_size(), 8);
        assert_eq!(spec.get_data_organization().get_pointer_size(), 8);
        assert_eq!(spec.get_data_organization().get_long_double_size(), 16);
        assert_eq!(spec.get_property("stackAlign").as_deref(), Some("16"));
        assert_eq!(spec.get_property_as_int("stackAlign", 0), 16);
        assert!(spec.get_property_as_boolean("useOperandReferenceAnalyzerSwitchTables", false));
        assert_eq!(spec.get_property_or("missing", "x"), "x");
        assert!(spec.has_property("stackAlign"));
        assert_eq!(spec.get_property_keys().len(), 2);
        assert!(spec.does_c_data_type_conversions());
        assert_eq!(spec.get_compiler_spec_id(), CompilerSpecID::new(Some("gcc")));
    }

    #[test]
    fn inject_library_registers_dynamic_payloads_and_skips_pcode_text() {
        let spec = gcc();
        let library = spec.pcode_inject_library();
        // The dynamic callotherfixup needs no compilation and is registered.
        assert_eq!(library.get_callother_fixup_names(), vec!["syscall".to_string()]);
        // The callfixup's p-code body needs the unported PcodeParser, so it is skipped.
        assert!(library.get_call_fixup_names().is_empty());
        let view = spec.get_pcode_inject_library();
        assert!(view.get_payload(CALLOTHERFIXUP_TYPE, "syscall").is_some_and(|p| p.get_name() == "syscall"));
        assert!(view.get_payload(CALLMECHANISM_TYPE, "syscall").is_none());
    }

    #[test]
    fn restore_errors() {
        let err = |xml: &str| spec_from(xml).err().unwrap().message().to_string();
        assert!(err("<compiler_spec/>").contains("does not provide a default prototype"));
        let proto = r#"<prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype>"#;
        assert!(err(&format!("<compiler_spec>{proto}{proto}</compiler_spec>")).contains("Multiple prototype models with the name: p"));
        assert!(err(&format!(r#"<compiler_spec><stackpointer register="NOPE" space="ram"/>{proto}</compiler_spec>"#))
            .contains("Unknown register: NOPE"));
        assert!(err(&format!(r#"<compiler_spec><stackpointer register="RSP" space="ram" growth="up"/>{proto}</compiler_spec>"#))
            .contains("Bad stack growth up"));
        assert!(err(&format!(r#"<compiler_spec>{proto}<modelalias name="a" parent="missing"/></compiler_spec>"#))
            .contains("Parent for model alias does not exist: missing"));
        assert!(err(&format!(r#"<compiler_spec>{proto}<prefersplit style="odd"/></compiler_spec>"#))
            .contains("Unknown prefersplit strategy"));
    }

    #[test]
    fn positive_stack_growth_and_default_stack_space() {
        let proto = r#"<prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype>"#;
        let spec = spec_from(&format!(
            r#"<compiler_spec><stackpointer register="RSP" space="ram" growth="positive" reversejustify="true"/>{proto}</compiler_spec>"#
        ))
        .unwrap();
        assert!(!spec.stack_grows_negative());
        assert!(spec.is_stack_right_justified()); // little endian, reverse justified
        // Without <stackpointer>, the stack space is sized from the default space.
        let spec = spec_from(&format!("<compiler_spec>{proto}</compiler_spec>")).unwrap();
        assert!(spec.get_stack_pointer().is_none());
        assert_eq!(spec.get_stack_space().size(), 64);
    }

    #[test]
    fn clone_is_equivalent_and_differences_are_detected() {
        let spec = gcc();
        assert!(CompilerSpec::is_equivalent(&spec, &spec.clone()));
        assert!(CompilerSpec::is_equivalent(&spec, &gcc()));
        let other = spec_from(&X86_64_GCC.replace(r#"<funcptr align="2"/>"#, "")).unwrap();
        assert!(!CompilerSpec::is_equivalent(&spec, &other));
    }

    #[test]
    fn model_xrefs_and_mechanism_payloads() {
        let mut spec = gcc();
        let models = spec.get_all_models();
        let dup = spec.model_xrefs(vec![models[0].clone(), models[0].clone()], Some("__stdcall"), None, None).unwrap();
        assert_eq!(dup.as_deref(), Some("__stdcall"));
        assert!(spec.model_xrefs(vec![models[1].clone()], Some("__stdcall"), None, None).is_err());
        let mut model = PrototypeModel::new_alias("x", &models[0]);
        BasicCompilerSpec::mark_prototype_as_extension(&mut model);
        assert!(model.is_program_extension());
        spec.remove_program_mechanism_payloads(&models);
    }

    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.events.push(format!("<{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.events.push(format!("/{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> std::io::Result<()> {
            self.events.push(format!("{}={val}", attrib_id.name));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> std::io::Result<()> {
            self.events.push(format!("{}={val}", attrib_id.name));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> std::io::Result<()> {
            self.events.push(format!("{}={val:#x}", attrib_id.name));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> std::io::Result<()> {
            self.events.push(format!("{}={val}", attrib_id.name));
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> std::io::Result<()> {
            self.events.push(format!("{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_the_compiler_spec() {
        let spec = gcc();
        let mut enc = RecordingEncoder::default();
        spec.encode(&mut enc).unwrap();
        let ev = enc.events;
        assert_eq!(ev.first().map(String::as_str), Some("<compiler_spec"));
        assert_eq!(ev.last().map(String::as_str), Some("/compiler_spec"));
        for event in [
            "<properties", "key=stackAlign", "<data_organization", "<aggressivetrim", "signext=true",
            "<stackpointer", "register=RSP", "<global", "<returnaddress", "<callotherfixup",
            "<default_proto", "name=__stdcall", "<modelalias", "name=__cdecl", "<resolveprototype",
            "<eval_current_prototype", "name=__stdcall/MSABI", "<prefersplit", "style=inhalf", "<readonly",
            "<funcptr", "align=2", "<deadcodedelay", "delay=3", "<inferptrbounds",
        ] {
            assert!(ev.iter().any(|e| e == event), "missing {event}");
        }
        // The default model is written once, inside <default_proto>; the only other mention by
        // name is its entry in <resolveprototype> (aliases name it as parent=).
        assert_eq!(ev.iter().filter(|e| *e == "name=__stdcall").count(), 2);
        assert_eq!(ev.iter().filter(|e| *e == "parent=__stdcall").count(), 2);
        assert!(!ev.iter().any(|e| e == "<eval_called_prototype"));
    }

    #[test]
    fn from_file_reports_parse_failures_as_compiler_spec_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x86-64-gcc.cspec");
        std::fs::write(&path, X86_64_GCC).unwrap();
        let file = ResourceFile::new(path.clone());
        let spec = BasicCompilerSpec::from_file(description(), x86_64_language(), &file).unwrap();
        assert_eq!(spec.get_source_name(), file.absolute_path());
        assert_eq!(spec.get_calling_conventions().len(), 4);

        std::fs::write(&path, "<compiler_spec><stackpointer register=\"NOPE\" space=\"ram\"/></compiler_spec>").unwrap();
        let err = BasicCompilerSpec::from_file(description(), x86_64_language(), &file).err().unwrap();
        assert!(err.message().contains("x86-64-gcc.cspec"), "{}", err.message());
        assert!(err.message().contains("Unknown register: NOPE"), "{}", err.message());
    }

    /// The x86-64 test language, shared, with a description offering one compiler spec, `gcc`,
    /// read from `cspec` (as Java's `SleighLanguage` gets it from its `.ldefs` description).
    fn language_with_gcc_cspec(cspec: std::path::PathBuf) -> Arc<SleighLanguage> {
        use crate::app::plugin::processors::sleigh::sleigh_language_description::SleighLanguageDescription;
        use crate::app::plugin::processors::sleigh::sleigh_language_file::SleighLanguageFile;
        use crate::program::model::lang::endian::Endian;
        use crate::program::model::lang::language_description::LanguageDescription;
        use crate::program::model::lang::language_id::LanguageID;

        struct Description {
            cspec: ResourceFile,
        }
        impl LanguageDescription for Description {
            fn get_language_id(&self) -> LanguageID {
                LanguageID::new("x86:LE:64:default").unwrap()
            }
            fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
                unimplemented!("not needed to load a compiler spec")
            }
            fn get_endian(&self) -> Endian {
                Endian::Little
            }
            fn get_instruction_endian(&self) -> Endian {
                Endian::Little
            }
            fn get_size(&self) -> i32 {
                64
            }
            fn get_variant(&self) -> String {
                "default".to_string()
            }
            fn get_version(&self) -> i32 {
                1
            }
            fn get_minor_version(&self) -> i32 {
                0
            }
            fn get_description(&self) -> String {
                "x86-64".to_string()
            }
            fn is_deprecated(&self) -> bool {
                false
            }
            fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
                vec![Box::new(SleighCompilerSpecDescription::new(CompilerSpecID::new(Some("gcc")), "gcc", self.cspec.clone()))]
            }
            fn get_compiler_spec_description_by_id(
                &self,
                compiler_spec_id: &CompilerSpecID,
            ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
                self.get_compatible_compiler_spec_descriptions()
                    .into_iter()
                    .find(|d| &d.get_compiler_spec_id() == compiler_spec_id)
                    .ok_or_else(|| CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
            }
            fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
                None
            }
        }
        impl SleighLanguageDescription for Description {
            fn get_truncated_space_names(&self) -> HashSet<String> {
                HashSet::new()
            }
            fn get_truncated_space_size(&self, _space_name: &str) -> Option<i32> {
                None
            }
            fn get_defs_file(&self) -> Option<&ResourceFile> {
                None
            }
            fn set_defs_file(&mut self, _defs_file: Option<ResourceFile>) {}
            fn get_spec_file(&self) -> Option<&ResourceFile> {
                None
            }
            fn set_spec_file(&mut self, _spec_file: Option<ResourceFile>) {}
            fn get_manual_index_file(&self) -> Option<&ResourceFile> {
                None
            }
            fn set_manual_index_file(&mut self, _manual_index_file: Option<ResourceFile>) {}
            fn get_language_file(&self) -> Option<&dyn SleighLanguageFile> {
                None
            }
            fn set_language_file(&mut self, _language_file: Option<Box<dyn SleighLanguageFile>>) {}
        }

        sleigh_x86_64_language(Some(Arc::new(Description { cspec: ResourceFile::new(cspec) })))
    }

    /// A temporary directory holding `X86_64_GCC` as `x86-64-gcc.cspec`, and that file's path.
    fn gcc_cspec_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x86-64-gcc.cspec");
        std::fs::write(&path, X86_64_GCC).unwrap();
        (dir, path)
    }

    #[test]
    fn sleigh_language_loads_its_compiler_spec() {
        let (_dir, path) = gcc_cspec_file();
        let language = language_with_gcc_cspec(path);
        let spec = language.get_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        assert_eq!(spec.get_default_calling_convention().unwrap().get_name().as_deref(), Some("__stdcall"));
        assert!(spec.as_basic_compiler_spec().is_some());
        assert_eq!(spec.get_compiler_spec_description().get_compiler_spec_name(), "gcc");
        let default_spec = language.get_default_compiler_spec();
        assert_eq!(default_spec.get_compiler_spec_id(), CompilerSpecID::new(Some("gcc")));
        assert!(language.get_compiler_spec_by_id(&CompilerSpecID::new(Some("clang"))).is_err());
    }

    #[test]
    fn sleigh_language_caches_its_compiler_specs() {
        let (_dir, path) = gcc_cspec_file();
        let language = language_with_gcc_cspec(path);
        let gcc = CompilerSpecID::new(Some("gcc"));
        let first = language.get_basic_compiler_spec_by_id(&gcc).unwrap();
        let second = language.get_basic_compiler_spec_by_id(&gcc).unwrap();
        assert!(Arc::ptr_eq(&first, &second));

        // The `Language` trait hands out the same cached spec.
        let via_trait = Language::get_compiler_spec_by_id(language.as_ref(), &gcc).unwrap();
        assert!(std::ptr::eq(via_trait.as_basic_compiler_spec().unwrap(), first.as_ref()));

        // Java's getDefaultCompilerSpec goes through getCompilerSpecByID, and so the cache.
        let default_spec = language.get_default_compiler_spec();
        assert!(std::ptr::eq(default_spec.as_basic_compiler_spec().unwrap(), first.as_ref()));

        // An unknown id is still rejected, and is not cached.
        assert!(language.get_basic_compiler_spec_by_id(&CompilerSpecID::new(Some("clang"))).is_err());
    }

    #[test]
    fn cached_spec_refers_back_to_its_language() {
        let (_dir, path) = gcc_cspec_file();
        let language = language_with_gcc_cspec(path);
        let spec = language.get_basic_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        assert!(Arc::ptr_eq(&spec.sleigh_language(), &language));
        assert_eq!(spec.get_language().get_language_id(), language.get_language_id());
        // A parameter list's language is the spec's language too.
        let model = spec.get_default_calling_convention().unwrap();
        let param_language = model.get_input_params().unwrap().get_language().unwrap();
        assert_eq!(param_language.get_language_id(), language.get_language_id());
    }

    #[test]
    fn dropping_the_language_frees_it_and_its_cached_specs() {
        let (_dir, path) = gcc_cspec_file();
        let language = language_with_gcc_cspec(path);
        let spec = language.get_basic_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        let weak_language = Arc::downgrade(&language);
        let weak_spec = Arc::downgrade(&spec);
        drop(spec);
        drop(language);
        // No `Arc` cycle through the spec (or its inject library or parameter lists) keeps
        // either alive.
        assert!(weak_language.upgrade().is_none());
        assert!(weak_spec.upgrade().is_none());
    }

    #[test]
    fn a_spec_does_not_keep_its_language_alive() {
        let (_dir, path) = gcc_cspec_file();
        let language = language_with_gcc_cspec(path);
        let spec = language.get_basic_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        let weak_language = Arc::downgrade(&language);
        drop(language);
        assert!(weak_language.upgrade().is_none());
        // The language's handle held by the spec reports the language as gone.
        let handle = spec.get_language();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle.get_language_id()));
        assert!(result.is_err());
    }

    #[test]
    fn basic_compiler_spec_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BasicCompilerSpec>();
        assert_send_sync::<Arc<BasicCompilerSpec>>();
        assert_send_sync::<SleighLanguage>();
    }
}
