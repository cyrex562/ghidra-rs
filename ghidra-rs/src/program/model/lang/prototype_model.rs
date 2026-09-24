//! Port of `ghidra.program.model.lang.PrototypeModel`.
//!
//! A function calling convention model: the formal specification of how a compiler passes
//! arguments between functions.
//!
//! Java's `PrototypeModel` is a concrete class with two subclasses, `PrototypeModelError` (a copy
//! of another model that only reports `isErrorPlaceholder() == true`) and `PrototypeModelMerged`
//! (a model standing for a set of candidate models). Every place a model is handed out --
//! `CompilerSpec.getAllModels()`, `Function.getCallingConvention()` -- may hand out any of the
//! three, so they are one Rust type, [`PrototypeModel`], whose private `kind` records which Java
//! class it is. The subclass-specific constructors and methods live in
//! [`prototype_model_error`](super::prototype_model_error) and
//! [`prototype_model_merged`](super::prototype_model_merged).

use std::fmt;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::{CompilerSpec, CALLING_CONVENTION_THISCALL};
use crate::program::model::lang::inject_payload::CALLMECHANISM_TYPE;
use crate::program::model::lang::input_list_type::InputListType;
use crate::program::model::lang::param_list::{ParamList, WithSlotRec};
use crate::program::model::lang::param_list_register_out::ParamListRegisterOut;
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::model::lang::param_list_standard_out::ParamListStandardOut;
use crate::program::model::lang::pcode_inject_library::{PcodeInjectLibrary, PcodeInjectLibraryError};
use crate::util::msg::Msg;
use crate::program::model::lang::program_architecture::ProgramArchitecture;
use crate::program::model::listing::parameter::Parameter;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::address_xml::{self, AddressXml};
use crate::program::model::pcode::{
    Encoder, Varnode, ATTRIB_CONSTRUCTOR, ATTRIB_EXTRAPOP, ATTRIB_FIRST, ATTRIB_HASTHIS,
    ATTRIB_INJECT, ATTRIB_LAST, ATTRIB_NAME, ATTRIB_PARENT, ATTRIB_SPACE, ATTRIB_STACKSHIFT,
    ATTRIB_STRATEGY, ELEM_INPUT, ELEM_INTERNAL_STORAGE, ELEM_KILLEDBYCALL, ELEM_LIKELYTRASH,
    ELEM_LOCALRANGE, ELEM_MODELALIAS, ELEM_OUTPUT, ELEM_PARAMRANGE, ELEM_PCODE, ELEM_PROTOTYPE,
    ELEM_RANGE, ELEM_RETURNADDRESS, ELEM_UNAFFECTED, ELEM_VARNODE,
};
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces, SpecExtension};
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Special [`PrototypeModel::get_extrapop`] value indicating the number of extra bytes popped
/// from the stack on return is unknown.
///
/// Port of `PrototypeModel.UNKNOWN_EXTRAPOP`.
pub const UNKNOWN_EXTRAPOP: i32 = 0x8000;

/// Which Java class a [`PrototypeModel`] value is.
#[derive(Clone)]
pub(crate) enum ModelKind {
    /// `PrototypeModel` itself.
    Standard,
    /// `PrototypeModelError`: a substitute for a model that failed to parse.
    ErrorPlaceholder,
    /// `PrototypeModelMerged`: the candidate models being distinguished between
    /// (`PrototypeModelMerged.modellist`).
    Merged(Vec<Arc<PrototypeModel>>),
}

/// A function calling convention model.
///
/// Built from a `<prototype>` tag of a compiler specification by
/// [`restore_xml`](Self::restore_xml); an alias (`<modelalias>`) is built with
/// [`new_alias`](Self::new_alias), which shares the parent's parameter lists as Java's copy
/// constructor does.
///
/// Port of `ghidra.program.model.lang.PrototypeModel`.
#[derive(Clone)]
pub struct PrototypeModel {
    /// Name of model (`PrototypeModel.name`).
    pub(crate) name: Option<String>,
    /// True if this model is a Program specific extension (`PrototypeModel.isExtension`).
    pub(crate) is_extension: bool,
    /// Change in stack pointer across function calls.
    extrapop: i32,
    /// Change in stack pointer due to call mechanism.
    stackshift: i32,
    /// (Possible) parameter locations; shared with aliases of this model.
    input_params: Option<Arc<ParamList>>,
    /// (Possible) return value locations; shared with aliases of this model.
    output_params: Option<Arc<ParamList>>,
    /// Memory ranges unaffected by calls.
    unaffected: Option<Vec<Varnode>>,
    /// Memory ranges definitely affected by calls.
    killedbycall: Option<Vec<Varnode>>,
    /// Memory used to store the return address.
    returnaddress: Option<Vec<Varnode>>,
    /// Memory likely to be meaningless on input.
    likelytrash: Option<Vec<Varnode>>,
    /// Registers holding internal compiler constants.
    internalstorage: Option<Vec<Varnode>>,
    /// The model this is an alias of (`PrototypeModel.compatModel`).
    compat_model: Option<Arc<PrototypeModel>>,
    /// Range on the stack considered for local storage.
    local_range: Option<AddressSet>,
    /// Range on the stack considered for parameter storage.
    param_range: Option<AddressSet>,
    input_list_type: InputListType,
    /// Convention has a this (auto-parameter).
    has_this: bool,
    /// Convention is used for object construction.
    is_construct: bool,
    /// Does this have an uponentry injection.
    has_upon_entry: bool,
    /// Does this have an uponreturn injection.
    has_upon_return: bool,
    /// Which Java class this value is.
    pub(crate) kind: ModelKind,
}

impl Default for PrototypeModel {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PrototypeModel {
    /// Port of `PrototypeModel.toString()`: the model's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name.as_deref().unwrap_or("null"))
    }
}

impl PrototypeModel {
    /// An unconfigured model, ready for [`restore_xml`](Self::restore_xml).
    ///
    /// Port of `PrototypeModel()`.
    pub fn new() -> Self {
        PrototypeModel {
            name: None,
            is_extension: false,
            extrapop: UNKNOWN_EXTRAPOP,
            stackshift: -1,
            input_params: None,
            output_params: None,
            unaffected: None,
            killedbycall: None,
            returnaddress: None,
            likelytrash: None,
            internalstorage: None,
            compat_model: None,
            local_range: None,
            param_range: None,
            input_list_type: InputListType::Standard,
            has_this: false,
            is_construct: false,
            has_upon_entry: false,
            has_upon_return: false,
            kind: ModelKind::Standard,
        }
    }

    /// Create a named alias of `model`: identical storage behaviour (the parameter lists are
    /// shared), a different name, and `model` recorded as the alias parent.
    ///
    /// Port of `PrototypeModel(String, PrototypeModel)`.
    pub fn new_alias(name: impl Into<String>, model: &Arc<PrototypeModel>) -> Self {
        let name = name.into();
        let has_this = model.has_this || name == CALLING_CONVENTION_THISCALL;
        PrototypeModel {
            name: Some(name),
            is_extension: false,
            extrapop: model.extrapop,
            stackshift: model.stackshift,
            input_params: model.input_params.clone(),
            output_params: model.output_params.clone(),
            unaffected: model.unaffected.clone(),
            killedbycall: model.killedbycall.clone(),
            returnaddress: model.returnaddress.clone(),
            likelytrash: model.likelytrash.clone(),
            internalstorage: model.internalstorage.clone(),
            compat_model: Some(model.clone()),
            local_range: Some(model.local_range.clone().unwrap_or_default()),
            param_range: Some(model.param_range.clone().unwrap_or_default()),
            input_list_type: model.input_list_type,
            has_this,
            is_construct: model.is_construct,
            has_upon_entry: model.has_upon_entry,
            has_upon_return: model.has_upon_return,
            kind: ModelKind::Standard,
        }
    }

    /// List of registers unaffected by called functions.
    ///
    /// Port of `PrototypeModel.getUnaffectedList()`.
    pub fn get_unaffected_list(&self) -> Vec<Varnode> {
        self.unaffected.clone().unwrap_or_default()
    }

    /// List of registers definitely affected by called functions.
    ///
    /// Port of `PrototypeModel.getKilledByCallList()`.
    pub fn get_killed_by_call_list(&self) -> Vec<Varnode> {
        self.killedbycall.clone().unwrap_or_default()
    }

    /// List of registers whose input value is likely meaningless.
    ///
    /// Port of `PrototypeModel.getLikelyTrash()`.
    pub fn get_likely_trash(&self) -> Vec<Varnode> {
        self.likelytrash.clone().unwrap_or_default()
    }

    /// List of registers used to store internal compiler constants.
    ///
    /// Port of `PrototypeModel.getInternalStorage()`.
    pub fn get_internal_storage(&self) -> Vec<Varnode> {
        self.internalstorage.clone().unwrap_or_default()
    }

    /// Registers/memory used to store the return address, or `None` if not recorded.
    ///
    /// Port of `PrototypeModel.getReturnAddress()`.
    pub fn get_return_address(&self) -> Option<Vec<Varnode>> {
        self.returnaddress.clone()
    }

    /// Port of the protected `PrototypeModel.setReturnAddress(Varnode[])`.
    pub(crate) fn set_return_address(&mut self, returnaddress: Option<Vec<Varnode>>) {
        self.returnaddress = returnaddress;
    }

    /// True if this model is an artificial merge of other models.
    ///
    /// Port of `PrototypeModel.isMerged()` (overridden by `PrototypeModelMerged`).
    pub fn is_merged(&self) -> bool {
        matches!(self.kind, ModelKind::Merged(_))
    }

    /// True if this model is a Program specific extension to the `CompilerSpec`.
    ///
    /// Port of `PrototypeModel.isProgramExtension()`.
    pub fn is_program_extension(&self) -> bool {
        self.is_extension
    }

    /// Mark this model as a Program specific extension (Java's `BasicCompilerSpec` sets the
    /// protected `isExtension` field directly).
    pub(crate) fn set_program_extension(&mut self, is_extension: bool) {
        self.is_extension = is_extension;
    }

    /// The formal name of the model, or `None` for an unconfigured model.
    ///
    /// Port of `PrototypeModel.getName()`.
    pub fn get_name(&self) -> Option<String> {
        self.name.clone()
    }

    /// The number of extra bytes popped from the stack on return, or [`UNKNOWN_EXTRAPOP`].
    ///
    /// Port of `PrototypeModel.getExtrapop()`.
    pub fn get_extrapop(&self) -> i32 {
        self.extrapop
    }

    /// The number of bytes on the stack used by this model to store the return value.
    ///
    /// Port of `PrototypeModel.getStackshift()`.
    pub fn get_stackshift(&self) -> i32 {
        self.stackshift
    }

    /// True if this model has an implied "this" parameter for referencing class data.
    ///
    /// Port of `PrototypeModel.hasThisPointer()`.
    pub fn has_this_pointer(&self) -> bool {
        self.has_this
    }

    /// True if this model is used specifically for class constructors.
    ///
    /// Port of `PrototypeModel.isConstructor()`.
    pub fn is_constructor(&self) -> bool {
        self.is_construct
    }

    /// The allocation strategy for this model.
    ///
    /// Port of `PrototypeModel.getInputListType()`.
    pub fn get_input_list_type(&self) -> InputListType {
        self.input_list_type
    }

    /// True if this model has an "uponentry" or "uponreturn" p-code injection.
    ///
    /// Port of `PrototypeModel.hasInjection()`.
    pub fn has_injection(&self) -> bool {
        self.has_upon_entry || self.has_upon_return
    }

    /// The input parameter list, if configured.
    pub fn get_input_params(&self) -> Option<&ParamList> {
        self.input_params.as_deref()
    }

    /// The output parameter list, if configured.
    pub fn get_output_params(&self) -> Option<&ParamList> {
        self.output_params.as_deref()
    }

    /// The storage that would hold a return value of `data_type`, if any.
    ///
    /// Port of the deprecated `PrototypeModel.getReturnLocation(DataType, Program)`.
    #[deprecated(note = "use get_storage_locations")]
    pub fn get_return_location(&self, data_type: &dyn DataType, program: &dyn Program) -> Option<Box<dyn VariableStorage>> {
        let dt_manager = program.get_data_type_manager()?;
        let output_params = self.output_params.as_ref()?;
        let clone: Arc<dyn DataType> = Arc::from(data_type.clone_data_type(dt_manager.as_ref()));
        let proto = PrototypePieces::with_out_type(None, Some(clone));
        let mut res = Vec::new();
        output_params.assign_map(&proto, dt_manager.as_ref(), &mut res, false);
        res.first_mut().map(|piece| piece.get_variable_storage(program))
    }

    /// The storage of the next argument after `params`, for an argument of `data_type`.
    ///
    /// Port of the deprecated `PrototypeModel.getNextArgLocation(Parameter[], DataType, Program)`.
    #[deprecated(note = "use get_storage_locations")]
    #[allow(deprecated)]
    pub fn get_next_arg_location(
        &self,
        params: Option<&[Box<dyn Parameter>]>,
        data_type: Option<&dyn DataType>,
        program: &dyn Program,
    ) -> Option<Box<dyn VariableStorage>> {
        self.get_arg_location(params.map_or(0, <[_]>::len), params, data_type, program)
    }

    /// The storage of argument `arg_index`, given the (possibly partial) existing `params`, for
    /// an argument of `data_type`. Parameters beyond `params` are assumed to be one-byte
    /// integers, and the return type void.
    ///
    /// Port of the deprecated `PrototypeModel.getArgLocation(int, Parameter[], DataType, Program)`.
    #[deprecated(note = "use get_storage_locations")]
    pub fn get_arg_location(
        &self,
        arg_index: usize,
        params: Option<&[Box<dyn Parameter>]>,
        data_type: Option<&dyn DataType>,
        program: &dyn Program,
    ) -> Option<Box<dyn VariableStorage>> {
        let dt_manager = program.get_data_type_manager()?;
        let mut arr: Vec<Arc<dyn DataType>> = Vec::with_capacity(arg_index + 2);
        arr.push(Arc::new(VoidStandIn)); // Assume the return type is void
        for i in 0..arg_index {
            match params.and_then(|p| p.get(i)) {
                // Copy in current types if we have them
                Some(param) => arr.push(Arc::from(param.get_data_type())),
                // Otherwise assume 1-byte (integer) type
                None => arr.push(Arc::new(Undefined1StandIn)),
            }
        }
        match data_type {
            Some(dt) => arr.push(Arc::from(dt.clone_data_type(dt_manager.as_ref()))),
            // Java passes `null`, which the storage computation treats as `DataType.DEFAULT`
            None => arr.push(Arc::new(Undefined1StandIn)),
        }
        self.get_storage_locations(program, &arr, false, false).pop()
    }

    /// Calculate input and output storage locations given a function prototype. Output storage
    /// is pushed to `res` first, then the inputs; the model may insert a hidden return value
    /// pointer among the inputs and, with `add_auto_params`, marks the `this` parameter.
    ///
    /// Port of `PrototypeModel.assignParameterStorage`. An unconfigured model assigns nothing
    /// (Java throws `NullPointerException`).
    pub fn assign_parameter_storage(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let (Some(output_params), Some(input_params)) = (&self.output_params, &self.input_params) else {
            return;
        };
        output_params.assign_map(proto, dt_manager, res, add_auto_params);
        input_params.assign_map(proto, dt_manager, res, add_auto_params);
        if self.has_this && add_auto_params && res.len() > 1 {
            let mut this_index = 1;
            if res[1].hidden_return_ptr && res.len() > 2 {
                if input_params.is_this_before_ret_pointer() {
                    // pointer has been bumped by auto-return-storage
                    // must swap storage and position for slots 1 and 2
                    let (left, right) = res.split_at_mut(2);
                    left[1].swap_markup(&mut right[0]);
                } else {
                    this_index = 2;
                }
            }
            res[this_index].is_this_pointer = true;
        }
    }

    /// Compute the variable storage for `data_types`: element 0 is the return type, the rest
    /// are the input parameter types in order. With `add_auto_params`, "this" and hidden return
    /// pointers are inserted as needed. With `is_var_args`, varargs begin right after the
    /// supplied parameters. The result is ordered by ordinal, return storage first.
    ///
    /// Port of `PrototypeModel.getStorageLocations(Program, DataType[], boolean, boolean)`.
    pub fn get_storage_locations(
        &self,
        program: &dyn Program,
        data_types: &[Arc<dyn DataType>],
        add_auto_params: bool,
        is_var_args: bool,
    ) -> Vec<Box<dyn VariableStorage>> {
        let Some(dt_manager) = program.get_data_type_manager() else {
            return Vec::new();
        };
        let mut injected_this: Option<Arc<dyn DataType>> = None;
        if add_auto_params && self.has_this {
            // explicit support for auto 'this' parameter: must inject pointer arg to obtain
            // storage assignment (Java: `new PointerDataType(program.getDataTypeManager())`, a
            // default-size pointer to the undefined type)
            let pointer: Box<dyn DataType> = dt_manager.get_pointer_with_size(&UndefinedPointee, -1);
            injected_this = Some(Arc::from(pointer));
        }
        // Java also records `this` as `PrototypePieces.model`; nothing on the assignment path
        // reads it, and a `&self` receiver has no shared handle to hand out.
        let mut proto = PrototypePieces::from_old_list(None, data_types, injected_this);
        if is_var_args {
            // All supplied parameters are non-optional; varargs begin immediately after them.
            proto.first_var_arg_slot = proto.intypes.len() as i32;
        }
        let mut res = Vec::new();
        self.assign_parameter_storage(&proto, dt_manager.as_ref(), &mut res, add_auto_params);
        res.iter_mut().map(|piece| piece.get_variable_storage(program)).collect()
    }

    /// If this is an alias of another model, return that model.
    ///
    /// Port of `PrototypeModel.getAliasParent()`.
    pub fn get_alias_parent(&self) -> Option<Arc<PrototypeModel>> {
        self.compat_model.clone()
    }

    /// True if this model is a substitute for one that failed to parse.
    ///
    /// Port of `PrototypeModel.isErrorPlaceholder()` (overridden by `PrototypeModelError`).
    pub fn is_error_placeholder(&self) -> bool {
        matches!(self.kind, ModelKind::ErrorPlaceholder)
    }

    /// Set up the parameter lists for the given allocation strategy.
    ///
    /// Port of the private `PrototypeModel.buildParamList`.
    fn build_param_list(&mut self, strategy: Option<&str>) -> Result<(ParamList, ParamList), XmlParseException> {
        match strategy {
            None | Some("standard") => {
                self.input_list_type = InputListType::Standard;
                Ok((ParamList::Standard(ParamListStandard::new()), ParamList::StandardOut(ParamListStandardOut::new())))
            }
            Some("register") => {
                self.input_list_type = InputListType::Register;
                Ok((ParamList::Standard(ParamListStandard::new()), ParamList::RegisterOut(ParamListRegisterOut::new())))
            }
            Some(other) => Err(XmlParseException::new(format!("Unknown assign strategy: {other}"))),
        }
    }

    /// Encode this model to a stream: a `<modelalias>` for an alias (or error placeholder), a
    /// `<resolveprototype>` for a merged model, otherwise a full `<prototype>`.
    ///
    /// Port of `PrototypeModel.encode(Encoder, PcodeInjectLibrary)` and its
    /// `PrototypeModelMerged` override. `inject_library` supplies the "uponentry"/"uponreturn"
    /// payload when this model has one.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream, or if an injection payload this model
    /// declares is missing from `inject_library`.
    pub fn encode(&self, encoder: &mut dyn Encoder, inject_library: Option<&PcodeInjectLibrary>) -> std::io::Result<()> {
        if let ModelKind::Merged(modellist) = &self.kind {
            return crate::program::model::lang::prototype_model_merged::encode_merged(self, modellist, encoder);
        }
        if let Some(compat) = &self.compat_model {
            encoder.open_element(ELEM_MODELALIAS)?;
            encoder.write_string(ATTRIB_NAME, self.name.as_deref().unwrap_or(""))?;
            encoder.write_string(ATTRIB_PARENT, compat.name.as_deref().unwrap_or(""))?;
            encoder.close_element(ELEM_MODELALIAS)?;
            return Ok(());
        }
        encoder.open_element(ELEM_PROTOTYPE)?;
        encoder.write_string(ATTRIB_NAME, self.name.as_deref().unwrap_or(""))?;
        if self.extrapop != UNKNOWN_EXTRAPOP {
            encoder.write_signed_integer(ATTRIB_EXTRAPOP, self.extrapop as i64)?;
        } else {
            encoder.write_string(ATTRIB_EXTRAPOP, "unknown")?;
        }
        encoder.write_signed_integer(ATTRIB_STACKSHIFT, self.stackshift as i64)?;
        if self.has_this {
            encoder.write_bool(ATTRIB_HASTHIS, true)?;
        }
        if self.is_construct {
            encoder.write_bool(ATTRIB_CONSTRUCTOR, true)?;
        }
        if self.input_list_type != InputListType::Standard {
            encoder.write_string(ATTRIB_STRATEGY, "register")?;
        }
        if let Some(input) = &self.input_params {
            input.encode(encoder, true)?;
        }
        if let Some(output) = &self.output_params {
            output.encode(encoder, false)?;
        }
        if self.has_upon_entry || self.has_upon_return {
            let inject_name = self.get_inject_name();
            let payload = inject_library.and_then(|lib| lib.get_payload(CALLMECHANISM_TYPE, Some(&inject_name)));
            let Some(payload) = payload else {
                return Err(std::io::Error::other(format!("Missing p-code injection payload: {inject_name}")));
            };
            payload.encode(encoder)?;
        }
        if let Some(list) = &self.unaffected {
            encoder.open_element(ELEM_UNAFFECTED)?;
            encode_varnodes(encoder, list)?;
            encoder.close_element(ELEM_UNAFFECTED)?;
        }
        if let Some(list) = &self.killedbycall {
            encoder.open_element(ELEM_KILLEDBYCALL)?;
            encode_varnodes(encoder, list)?;
            encoder.close_element(ELEM_KILLEDBYCALL)?;
        }
        if let Some(list) = &self.likelytrash {
            encoder.open_element(ELEM_LIKELYTRASH)?;
            encode_varnodes(encoder, list)?;
            encoder.close_element(ELEM_LIKELYTRASH)?;
        }
        if let Some(list) = &self.internalstorage {
            encoder.open_element(ELEM_INTERNAL_STORAGE)?;
            encode_varnodes(encoder, list)?;
            encoder.close_element(ELEM_INTERNAL_STORAGE)?;
        }
        if let Some(list) = &self.returnaddress {
            encoder.open_element(ELEM_RETURNADDRESS)?;
            encode_varnodes(encoder, list)?;
            encoder.close_element(ELEM_RETURNADDRESS)?;
        }
        if let Some(range) = self.local_range.as_ref().filter(|r| !r.is_empty()) {
            encoder.open_element(ELEM_LOCALRANGE)?;
            encode_address_set(encoder, range)?;
            encoder.close_element(ELEM_LOCALRANGE)?;
        }
        if let Some(range) = self.param_range.as_ref().filter(|r| !r.is_empty()) {
            encoder.open_element(ELEM_PARAMRANGE)?;
            encode_address_set(encoder, range)?;
            encoder.close_element(ELEM_PARAMRANGE)?;
        }
        encoder.close_element(ELEM_PROTOTYPE)?;
        Ok(())
    }

    /// The name under which this model's call-mechanism injection is registered.
    ///
    /// Port of the protected `PrototypeModel.getInjectName`.
    pub(crate) fn get_inject_name(&self) -> String {
        let name = self.name.as_deref().unwrap_or("null");
        if self.has_upon_entry {
            format!("{name}@@inject_uponentry")
        } else {
            format!("{name}@@inject_uponreturn")
        }
    }

    /// Restore this model from a `<prototype>` element.
    ///
    /// `inject_library` is the compiler spec's p-code injection library (Java reaches it through
    /// `cspec.getPcodeInjectLibrary()`); a `<pcode>` child registers its payload there. Without a
    /// library, a `<pcode>` child is an error.
    ///
    /// Port of `PrototypeModel.restoreXml(XmlPullParser, CompilerSpec)`.
    ///
    /// # Errors
    /// Returns an error for badly formed or inconsistent XML, or a payload that fails to
    /// register.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
        mut inject_library: Option<&mut PcodeInjectLibrary>,
    ) -> Result<(), XmlParseException> {
        self.input_params = None;
        self.output_params = None;
        let proto_element = parser.start(&[])?;
        let name = proto_element.get_attribute(ATTRIB_NAME.name).unwrap_or_default();
        if !SpecExtension::is_valid_formal_name(&name) {
            return Err(XmlParseException::new("Prototype name uses illegal characters"));
        }
        self.extrapop = UNKNOWN_EXTRAPOP;
        let extpop_str = proto_element.get_attribute(ATTRIB_EXTRAPOP.name);
        if extpop_str.as_deref() != Some("unknown") {
            self.extrapop = decode_int(extpop_str.as_deref());
        }
        self.stackshift = decode_int(proto_element.get_attribute(ATTRIB_STACKSHIFT.name).as_deref());
        self.is_construct = false;
        self.has_this = match proto_element.get_attribute(ATTRIB_HASTHIS.name) {
            Some(this_string) => decode_boolean(&this_string),
            None => name == CALLING_CONVENTION_THISCALL,
        };
        if let Some(construct_string) = proto_element.get_attribute(ATTRIB_CONSTRUCTOR.name) {
            self.is_construct = decode_boolean(&construct_string);
        }
        self.name = Some(name);
        let (mut input, mut output) = self.build_param_list(proto_element.get_attribute(ATTRIB_STRATEGY.name).as_deref())?;
        while parser.peek().is_start() {
            let subel = parser.peek();
            let el_name = subel.get_name().to_string();
            if el_name == ELEM_INPUT.name {
                input.restore_xml(parser, cspec)?;
            } else if el_name == ELEM_OUTPUT.name {
                output.restore_xml(parser, cspec)?;
            } else if el_name == ELEM_PCODE.name {
                let source = format!(
                    "Compiler spec={}",
                    cspec.get_compiler_spec_id().get_id_as_string()
                );
                if subel.get_attribute(ATTRIB_INJECT.name).as_deref() == Some("uponentry") {
                    self.has_upon_entry = true;
                } else {
                    self.has_upon_return = true;
                }
                let inject_name = self.get_inject_name();
                let Some(library) = inject_library.as_deref_mut() else {
                    return Err(XmlParseException::new(format!(
                        "No p-code injection library to register {inject_name}"
                    )));
                };
                match library.restore_xml_inject(&source, &inject_name, CALLMECHANISM_TYPE, parser) {
                    Ok(_) => {}
                    // The payload's p-code text needs the unported PcodeParser: it is parsed but
                    // left unregistered (see PcodeInjectLibrary's module docs).
                    Err(PcodeInjectLibraryError::Sleigh(e)) if PcodeInjectLibrary::is_unported_parser_error(&e) => {
                        Msg::warn("PrototypeModel", &format!("{inject_name} not registered: {e}"));
                    }
                    Err(e) => return Err(XmlParseException::new(e.to_string())),
                }
            } else if el_name == ELEM_UNAFFECTED.name {
                self.unaffected = Some(read_varnodes(parser, cspec)?);
            } else if el_name == ELEM_KILLEDBYCALL.name {
                self.killedbycall = Some(read_varnodes(parser, cspec)?);
            } else if el_name == ELEM_RETURNADDRESS.name {
                self.returnaddress = Some(read_varnodes(parser, cspec)?);
            } else if el_name == ELEM_LIKELYTRASH.name {
                self.likelytrash = Some(read_varnodes(parser, cspec)?);
            } else if el_name == ELEM_INTERNAL_STORAGE.name {
                self.internalstorage = Some(read_varnodes(parser, cspec)?);
            } else if el_name == ELEM_LOCALRANGE.name {
                self.local_range = Some(read_address_set(parser, cspec)?);
            } else if el_name == ELEM_PARAMRANGE.name {
                self.param_range = Some(read_address_set(parser, cspec)?);
            } else {
                let subel = parser.start(&[])?;
                parser.discard_sub_tree_element(&subel);
            }
        }
        parser.end_matching(&proto_element)?;
        self.input_params = Some(Arc::new(input));
        self.output_params = Some(Arc::new(output));
        Ok(())
    }

    /// Determine if the given address range is possible input parameter storage for this model;
    /// if so, its slot position is passed back in `res`.
    ///
    /// Port of `PrototypeModel.possibleInputParamWithSlot`.
    pub fn possible_input_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        self.input_params.as_ref().is_some_and(|p| p.possible_param_with_slot(loc, size, res))
    }

    /// Determine if the given address range is possible return value storage for this model; if
    /// so, its slot position is passed back in `res`.
    ///
    /// Port of `PrototypeModel.possibleOutputParamWithSlot`.
    pub fn possible_output_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        self.output_params.as_ref().is_some_and(|p| p.possible_param_with_slot(loc, size, res))
    }

    /// The byte alignment of stack parameters, or -1 if there are none.
    ///
    /// Port of `PrototypeModel.getStackParameterAlignment`.
    pub fn get_stack_parameter_alignment(&self) -> i32 {
        self.input_params.as_ref().map_or(-1, |p| p.get_stack_parameter_alignment())
    }

    /// The offset, relative to the incoming stack pointer, of the first stack parameter, or
    /// `None` if there are no stack parameters.
    ///
    /// Port of `PrototypeModel.getStackParameterOffset`.
    pub fn get_stack_parameter_offset(&self) -> Option<i64> {
        self.input_params.as_ref().and_then(|p| p.get_stack_parameter_offset())
    }

    /// All input storage locations consisting of a single register.
    ///
    /// Port of `PrototypeModel.getPotentialInputRegisterStorage(Program)`; takes the program as
    /// the `ProgramArchitecture` it is in Java.
    pub fn get_potential_input_register_storage(
        &self,
        prog: Arc<dyn ProgramArchitecture>,
    ) -> Vec<Box<dyn VariableStorage>> {
        self.input_params.as_ref().map_or_else(Vec::new, |p| p.get_potential_register_storage(prog))
    }

    /// Determine if this model is equivalent to another: same Java class and identical
    /// configuration.
    ///
    /// Port of `PrototypeModel.isEquivalent` and its `PrototypeModelMerged` override.
    pub fn is_equivalent(&self, obj: &PrototypeModel) -> bool {
        match (&self.kind, &obj.kind) {
            (ModelKind::Merged(a), ModelKind::Merged(b)) => {
                return crate::program::model::lang::prototype_model_merged::merged_lists_equivalent(a, b);
            }
            (ModelKind::Standard, ModelKind::Standard) | (ModelKind::ErrorPlaceholder, ModelKind::ErrorPlaceholder) => {}
            _ => return false,
        }
        if self.name != obj.name {
            return false;
        }
        if self.extrapop != obj.extrapop || self.stackshift != obj.stackshift {
            return false;
        }
        if self.has_this != obj.has_this || self.is_construct != obj.is_construct {
            return false;
        }
        if self.has_upon_entry != obj.has_upon_entry || self.has_upon_return != obj.has_upon_return {
            return false;
        }
        if self.input_list_type != obj.input_list_type {
            return false;
        }
        if !param_lists_equivalent(&self.input_params, &obj.input_params)
            || !param_lists_equivalent(&self.output_params, &obj.output_params)
        {
            return false;
        }
        if self.unaffected != obj.unaffected
            || self.killedbycall != obj.killedbycall
            || self.likelytrash != obj.likelytrash
            || self.internalstorage != obj.internalstorage
        {
            return false;
        }
        let compat_name = self.compat_model.as_ref().and_then(|m| m.name.clone()).unwrap_or_default();
        let compat_name_op2 = obj.compat_model.as_ref().and_then(|m| m.name.clone()).unwrap_or_default();
        if compat_name != compat_name_op2 {
            return false;
        }
        if self.local_range != obj.local_range || self.param_range != obj.param_range {
            return false;
        }
        self.returnaddress == obj.returnaddress
    }
}

/// `SystemUtilities.isEqual` over two (possibly absent) shared parameter lists; Java compares
/// them with `isEquivalent` and would throw on a `null` list.
fn param_lists_equivalent(a: &Option<Arc<ParamList>>, b: &Option<Arc<ParamList>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.is_equivalent(b),
        _ => false,
    }
}

/// Stand-in for the `null` referenced type of Java's `new PointerDataType(dtm)`: the pointer's
/// class and size are all parameter assignment looks at.
struct UndefinedPointee;
impl DataType for UndefinedPointee {}

/// Stand-in for the unported `VoidDataType.dataType` singleton: the void return type the
/// deprecated argument-location queries assume.
struct VoidStandIn;
impl DataType for VoidStandIn {
    fn get_name(&self) -> String {
        "void".to_string()
    }
    fn is_void_type(&self) -> bool {
        true
    }
}

/// Stand-in for the unported `Undefined1DataType.dataType` singleton: a one-byte integer.
struct Undefined1StandIn;
impl DataType for Undefined1StandIn {
    fn get_name(&self) -> String {
        "undefined1".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
}

/// Port of the private `PrototypeModel.encodeVarnodes`.
fn encode_varnodes(encoder: &mut dyn Encoder, varnodes: &[Varnode]) -> std::io::Result<()> {
    for vn in varnodes {
        encoder.open_element(ELEM_VARNODE)?;
        address_xml::encode_attributes_with_size(encoder, vn.get_address(), vn.get_size())?;
        encoder.close_element(ELEM_VARNODE)?;
    }
    Ok(())
}

/// Read a list of `<addr>`/`<register>` children as varnodes.
///
/// Port of the private `PrototypeModel.readVarnodes`.
fn read_varnodes<P: XmlPullParser>(parser: &mut P, cspec: &dyn CompilerSpec) -> Result<Vec<Varnode>, XmlParseException> {
    parser.start(&[])?;
    let mut varnode_list = Vec::new();
    while parser.peek().is_start() {
        let el = parser.start(&[])?;
        let our_address = address_xml::restore_xml(&el, cspec)?;
        if our_address.get_join_record().is_some() {
            return Err(XmlParseException::new(
                "No \"join\" in <unaffected>, <killedbycall>, or <likelytrash>",
            ));
        }
        varnode_list.push(our_address.get_varnode());
        parser.end_matching(&el)?;
    }
    parser.end()?;
    Ok(varnode_list)
}

/// Encode each range of `address_set` as a `<range>` element, splitting a range that crosses 0
/// in a signed space.
///
/// Port of the private `PrototypeModel.encodeAddressSet`.
fn encode_address_set(encoder: &mut dyn Encoder, address_set: &AddressSet) -> std::io::Result<()> {
    for addr_range in address_set.to_list() {
        let space = addr_range.min_address().space().clone();
        let mut first = addr_range.min_address().offset();
        let mut last = addr_range.max_address().offset();
        if space.is_signed() {
            let mut mask: i64 = if space.size() < 64 { 1i64 << space.size() } else { 0 };
            mask = mask.wrapping_sub(1);
            if first < 0 && last >= 0 {
                // Range crosses 0: split out the piece coming before 0
                first &= mask;
                encoder.open_element(ELEM_RANGE)?;
                encoder.write_space(ATTRIB_SPACE, &space)?;
                encoder.write_unsigned_integer(ATTRIB_FIRST, first as u64)?;
                encoder.write_unsigned_integer(ATTRIB_LAST, mask as u64)?;
                encoder.close_element(ELEM_RANGE)?;
                // Reset first,last to be the piece coming after 0
                first = 0;
            }
            first &= mask;
            last &= mask;
        }
        encoder.open_element(ELEM_RANGE)?;
        encoder.write_space(ATTRIB_SPACE, &space)?;
        encoder.write_unsigned_integer(ATTRIB_FIRST, first as u64)?;
        encoder.write_unsigned_integer(ATTRIB_LAST, last as u64)?;
        encoder.close_element(ELEM_RANGE)?;
    }
    Ok(())
}

/// Read a list of `<range>` children as an address set.
///
/// Port of the private `PrototypeModel.readAddressSet`.
fn read_address_set<P: XmlPullParser>(parser: &mut P, cspec: &dyn CompilerSpec) -> Result<AddressSet, XmlParseException> {
    let mut address_set = AddressSet::new();
    parser.start(&[])?;
    while parser.peek().is_start() {
        let el = parser.start(&[])?;
        let range = address_xml::restore_range_xml(&el, cspec)?;
        parser.end_matching(&el)?;
        address_set.add_range(&range.get_first_address(), &range.get_last_address());
    }
    parser.end()?;
    Ok(address_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpaceType, AddressSetView};
    use crate::program::model::lang::cspec_test_support::{
        float_type, int_type, parser, register_space, restore_model, stack_space, TestCompilerSpec,
        TestDataTypeManager, SYSV_INPUT, SYSV_OUTPUT,
    };
    use crate::program::model::pcode::{AttributeId, ElementId};

    /// The x86-64 System V `__stdcall` prototype of `x86-64-gcc.cspec` (float registers reduced
    /// to two), with its killed-by-call and unaffected lists.
    fn sysv() -> PrototypeModel {
        restore_model(&format!(
            r#"<prototype name="__stdcall" extrapop="8" stackshift="8">
                 {SYSV_INPUT}
                 {SYSV_OUTPUT}
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
                 </unaffected>
                 <likelytrash><register name="RCX"/></likelytrash>
                 <returnaddress><varnode space="stack" offset="0" size="8"/></returnaddress>
                 <localrange><range space="stack" first="0xfffffffffff0bdc1" last="0xffffffffffffffff"/></localrange>
                 <paramrange><range space="stack" first="8" last="0x7f"/></paramrange>
               </prototype>"#
        ))
    }

    #[test]
    fn unconfigured_model_matches_java_defaults() {
        let model = PrototypeModel::new();
        assert_eq!(model.get_name(), None);
        assert_eq!(model.get_extrapop(), UNKNOWN_EXTRAPOP);
        assert_eq!(model.get_stackshift(), -1);
        assert!(model.get_unaffected_list().is_empty());
        assert!(model.get_return_address().is_none());
        assert!(!model.has_this_pointer());
        assert!(!model.is_constructor());
        assert!(!model.has_injection());
        assert!(!model.is_merged());
        assert!(!model.is_error_placeholder());
        assert_eq!(model.get_input_list_type(), InputListType::Standard);
        assert_eq!(model.get_stack_parameter_alignment(), -1);
        assert_eq!(model.get_stack_parameter_offset(), None);
        assert!(model.get_alias_parent().is_none());
    }

    #[test]
    fn restore_sysv_prototype() {
        let model = sysv();
        assert_eq!(model.get_name().as_deref(), Some("__stdcall"));
        assert_eq!(model.to_string(), "__stdcall");
        assert_eq!(model.get_extrapop(), 8);
        assert_eq!(model.get_stackshift(), 8);
        assert!(!model.has_this_pointer());
        let killed: Vec<(i64, i32)> = model.get_killed_by_call_list().iter().map(|v| (v.get_offset(), v.get_size())).collect();
        assert_eq!(killed, vec![(0x0, 8), (0x10, 8), (0x1200, 16)]);
        let unaffected: Vec<i64> = model.get_unaffected_list().iter().map(|v| v.get_offset()).collect();
        assert_eq!(unaffected, vec![0x18, 0x20, 0x28, 0xa0]);
        assert_eq!(model.get_likely_trash().len(), 1);
        let ret = model.get_return_address().unwrap();
        assert_eq!(ret[0].get_address().space().space_type(), AddressSpaceType::Stack);
        assert_eq!(ret[0].get_size(), 8);
        assert_eq!(model.get_stack_parameter_alignment(), 8);
        assert_eq!(model.get_stack_parameter_offset(), Some(8));
        let param_range = model.param_range.as_ref().unwrap();
        assert_eq!(param_range.min_address().unwrap().offset(), 8);
        assert_eq!(param_range.max_address().unwrap().offset(), 0x7f);
        assert!(model.local_range.as_ref().unwrap().min_address().unwrap().offset() < 0);
    }

    #[test]
    fn assign_parameter_storage_sysv() {
        let model = sysv();
        // long f(int, double, long, long)
        let proto = PrototypePieces {
            outtype: Some(int_type(8)),
            intypes: vec![int_type(4), float_type(8), int_type(8), int_type(8)],
            ..Default::default()
        };
        let mut res = Vec::new();
        model.assign_parameter_storage(&proto, &TestDataTypeManager, &mut res, true);
        let offs: Vec<i64> = res.iter().map(|p| p.address.as_ref().unwrap().offset()).collect();
        // return RAX; int RDI; double XMM0; long RSI; long RDX
        assert_eq!(offs, vec![0x0, 0x38, 0x1200, 0x30, 0x10]);
        assert!(res.iter().all(|p| !p.is_this_pointer));
    }

    #[test]
    fn assign_parameter_storage_hidden_return_and_this() {
        // A __thiscall alias: hasThis comes from the name.
        let this_model = PrototypeModel::new_alias(CALLING_CONVENTION_THISCALL, &Arc::new(sysv()));
        assert!(this_model.has_this_pointer());
        assert_eq!(this_model.get_alias_parent().unwrap().get_name().as_deref(), Some("__stdcall"));
        // A 32-byte struct return is passed back through a hidden pointer in RDI; `this` follows.
        let proto = PrototypePieces {
            outtype: Some(int_type(32)),
            intypes: vec![int_type(8), int_type(8)],
            ..Default::default()
        };
        let mut res = Vec::new();
        this_model.assign_parameter_storage(&proto, &TestDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 4);
        assert!(res[0].is_indirect);
        assert_eq!(res[0].address.as_ref().unwrap().offset(), 0x0); // pointer returned in RAX
        assert!(res[1].hidden_return_ptr);
        assert_eq!(res[1].address.as_ref().unwrap().offset(), 0x38); // RDI
        assert!(res[2].is_this_pointer); // thisbeforeretpointer is false: `this` after the pointer
        assert_eq!(res[2].address.as_ref().unwrap().offset(), 0x30); // RSI
        assert_eq!(res[3].address.as_ref().unwrap().offset(), 0x10); // RDX
    }

    #[test]
    fn slot_queries_use_input_and_output_lists() {
        let model = sysv();
        let mut rec = WithSlotRec::default();
        assert!(model.possible_input_param_with_slot(&Address::new(register_space(), 0x30), 8, &mut rec));
        assert_eq!(rec.slot, 3);
        assert!(!model.possible_input_param_with_slot(&Address::new(register_space(), 0x0), 8, &mut rec));
        assert!(model.possible_output_param_with_slot(&Address::new(register_space(), 0x0), 8, &mut rec));
        assert!(model.possible_input_param_with_slot(&Address::new(stack_space(), 0x10), 8, &mut rec));
    }

    #[test]
    fn restore_attributes_strategy_and_errors() {
        let model = restore_model(
            r#"<prototype name="__thiscall" extrapop="unknown" stackshift="4" constructor="true" strategy="register">
                 <input><pentry minsize="1" maxsize="4"><register name="RCX"/></pentry></input>
                 <output><pentry minsize="1" maxsize="4"><register name="EAX"/></pentry></output>
                 <somethingelse><x/></somethingelse>
               </prototype>"#,
        );
        assert!(model.has_this_pointer()); // implied by the name
        assert!(model.is_constructor());
        assert_eq!(model.get_extrapop(), UNKNOWN_EXTRAPOP);
        assert_eq!(model.get_input_list_type(), InputListType::Register);
        assert!(matches!(model.get_output_params(), Some(ParamList::RegisterOut(_))));
        let explicit = restore_model(r#"<prototype name="__thiscall" extrapop="4" stackshift="4" hasthis="false"><input/><output/></prototype>"#);
        assert!(!explicit.has_this_pointer());

        let cspec = TestCompilerSpec::x86_64();
        let mut m = PrototypeModel::new();
        let err = m
            .restore_xml(&mut parser(r#"<prototype name="bad name" extrapop="4" stackshift="4"/>"#), &cspec, None)
            .unwrap_err();
        assert_eq!(err.message(), "Prototype name uses illegal characters");
        let err = m
            .restore_xml(&mut parser(r#"<prototype name="x" extrapop="4" stackshift="4" strategy="odd"/>"#), &cspec, None)
            .unwrap_err();
        assert_eq!(err.message(), "Unknown assign strategy: odd");
        let err = m
            .restore_xml(
                &mut parser(r#"<prototype name="x" extrapop="4" stackshift="4"><pcode inject="uponentry"><body/></pcode></prototype>"#),
                &cspec,
                None,
            )
            .unwrap_err();
        assert!(err.message().contains("x@@inject_uponentry"));
        let err = m
            .restore_xml(
                &mut parser(r#"<prototype name="x" extrapop="4" stackshift="4"><unaffected><addr space="join" piece1="RAX" piece2="RDX"/></unaffected></prototype>"#),
                &cspec,
                None,
            )
            .unwrap_err();
        assert!(err.message().contains("No \"join\""));
    }

    #[test]
    fn is_equivalent_compares_configuration() {
        assert!(sysv().is_equivalent(&sysv()));
        let other = restore_model(r#"<prototype name="__stdcall" extrapop="4" stackshift="8"><input/><output/></prototype>"#);
        assert!(!sysv().is_equivalent(&other));
        let parent = Arc::new(sysv());
        let alias = PrototypeModel::new_alias("__cdecl", &parent);
        assert!(alias.is_equivalent(&PrototypeModel::new_alias("__cdecl", &parent)));
        assert!(!alias.is_equivalent(&sysv()));
    }

    #[test]
    #[allow(deprecated)]
    fn storage_locations_and_deprecated_queries() {
        use crate::program::model::lang::cspec_test_support::TestProgram;
        let model = sysv();
        let storage = model.get_storage_locations(&TestProgram, &[int_type(8), int_type(4), float_type(8)], false, false);
        let offs: Vec<i64> = storage.iter().map(|s| s.get_varnodes()[0].get_offset()).collect();
        assert_eq!(offs, vec![0x0, 0x38, 0x1200]);
        assert_eq!(storage[1].get_varnodes()[0].get_size(), 4);

        let ret = model.get_return_location(int_type(8).as_ref(), &TestProgram).unwrap();
        assert_eq!(ret.get_varnodes()[0].get_offset(), 0x0);
        // Third argument, preceding ones unknown (assumed 1-byte integers): RDX.
        let arg = model.get_arg_location(2, None, Some(int_type(8).as_ref()), &TestProgram).unwrap();
        assert_eq!(arg.get_varnodes()[0].get_offset(), 0x10);
        let next = model.get_next_arg_location(None, Some(float_type(8).as_ref()), &TestProgram).unwrap();
        assert_eq!(next.get_varnodes()[0].get_offset(), 0x1200);
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
        fn write_space(&mut self, attrib_id: AttributeId, spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
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
    fn encode_prototype_and_alias() {
        let model = sysv();
        let mut enc = RecordingEncoder::default();
        model.encode(&mut enc, None).unwrap();
        let ev = enc.events;
        assert_eq!(&ev[..4], &["<prototype", "name=__stdcall", "extrapop=8", "stackshift=8"]);
        for tag in ["<input", "/input", "<output", "/output", "<unaffected", "<killedbycall", "<likelytrash", "<returnaddress", "<localrange", "<paramrange"] {
            assert!(ev.iter().any(|e| e == tag), "missing {tag}");
        }
        assert_eq!(ev.last().map(String::as_str), Some("/prototype"));
        // The local range crosses no zero, so it is written as a single range.
        assert!(ev.iter().any(|e| e == "first=0x8"));

        let alias = PrototypeModel::new_alias("__cdecl", &Arc::new(sysv()));
        let mut enc = RecordingEncoder::default();
        alias.encode(&mut enc, None).unwrap();
        assert_eq!(enc.events, vec!["<modelalias", "name=__cdecl", "parent=__stdcall", "/modelalias"]);
    }

    #[test]
    fn encode_splits_a_stack_range_crossing_zero() {
        let mut set = AddressSet::new();
        set.add_range(&stack_space().address(-8), &stack_space().address(7));
        let mut enc = RecordingEncoder::default();
        encode_address_set(&mut enc, &set).unwrap();
        assert_eq!(
            enc.events,
            vec![
                "<range", "space=stack", "first=0xfffffffffffffff8", "last=0xffffffffffffffff", "/range",
                "<range", "space=stack", "first=0x0", "last=0x7", "/range",
            ]
        );
    }
}
