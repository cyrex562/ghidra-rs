//! Port of `sarif.managers.MarkupSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::address::{Address, AddressFormatException, AddressSet, AddressSetView};
use crate::program::model::listing::code_unit::MNEMONIC;
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::listing::Program;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    Equate, ExternalLocation, Namespace, RefType, RefTypeFactory, SourceType,
};
use crate::util::exception::{CancelledException, InvalidInputException};
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifEquateRefWriter, SarifMgr, SarifProgramOptions, SarifReferenceWriter, SarifWriterTask,
    TaskLauncher,
};

/// Everything one `process*Reference` call can fail with.
///
/// Java wraps each of those methods in a single `catch (Exception e) { log.appendException(e); }`,
/// so the distinctions below only matter for the message that reaches the log. [`Runtime`] stands
/// in for the unchecked exceptions Java raises without a dedicated type: its own bare `new
/// RuntimeException(...)`, the `NumberFormatException` from `Integer.parseInt`, the
/// `ArrayIndexOutOfBoundsException` from indexing an empty register array, and the
/// `NullPointerException` a deferred (`FUN_`-prefixed) namespace produces in `addExternal`.
///
/// [`Runtime`]: MarkupError::Runtime
#[derive(Error, Debug)]
enum MarkupError {
    #[error(transparent)]
    AddressFormat(#[from] AddressFormatException),
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error("{0}")]
    Runtime(String),
}

/// Reads and writes `REFERENCES` entries -- every kind of reference plus the equate references
/// that drive operand substitution ("markup") -- between a [`Program`]'s
/// [`ReferenceManager`](crate::program::model::symbol::ReferenceManager) /
/// [`EquateTable`](crate::program::model::symbol::EquateTable) and SARIF.
///
/// Port of `sarif.managers.MarkupSarifMgr`, which extends the abstract `SarifMgr`; that base class
/// is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust does not
/// have. Unlike Java, which caches the `ReferenceManager` and `EquateTable` once in the
/// constructor, this keeps the whole `Program` handle and re-fetches each collaborator on use:
/// `Program::get_reference_manager`/`get_equate_table` hand back borrows, not owned values, so
/// they cannot be stored alongside the `Program` they borrow from. That matches the convention set
/// by [`EquatesSarifMgr`](crate::sarif::managers::EquatesSarifMgr) and
/// [`ExternalLibSarifMgr`](crate::sarif::managers::ExternalLibSarifMgr).
///
/// Java's base class declares `externalMap` as a `static` field shared by every `*SarifMgr`; here,
/// as in `ExternalLibSarifMgr`, it is a plain instance field, since nothing in the crate reads
/// another manager's copy yet.
pub struct MarkupSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    /// `SarifMgr.externalMap`, keyed by the SARIF `libExtAddr` of the external location.
    external_map: HashMap<String, Arc<dyn ExternalLocation>>,
}

impl MarkupSarifMgr {
    /// `MarkupSarifMgr.KEY`.
    pub const KEY: &'static str = "REFERENCES";

    /// `MarkupSarifMgr(Program program, MessageLog log)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            external_map: HashMap::new(),
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `MarkupSarifMgr.read`: dispatches one SARIF result to the `process*Reference` method its
    /// `Message` tag names. Always reports success, exactly as Java's unconditional `return true`
    /// does -- a failure inside one of those methods is logged, not propagated.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        let tag_name = result.get("Message").and_then(Value::as_str).unwrap_or_default();
        let overwrite = options.map_or(true, |o| o.is_overwrite_reference_conflicts());

        let outcome = match tag_name {
            "Ref.Memory" => Some(self.process_memory_reference(result, overwrite)),
            "Ref.Shifted" => Some(self.process_shifted_reference(result, overwrite)),
            "Ref.Register" => Some(self.process_register_reference(result, overwrite)),
            // TODO (from the Java): `&& !ignoreStackReferences`.
            "Ref.Stack" if options.map_or(true, |o| o.is_functions()) => {
                Some(self.process_stack_reference(result, overwrite))
            }
            "Ref.External" if options.map_or(true, |o| o.is_external_libraries()) => {
                Some(self.process_ext_library_reference(result, overwrite))
            }
            "Ref.Equate" => Some(self.process_equate_reference(result, overwrite)),
            _ => None,
        };

        if let Some(Err(e)) = outcome {
            self.log.append_exception(&e);
        }
        true
    }

    /// `MarkupSarifMgr.getRefType(int)`.
    fn get_ref_type(ref_type: i32) -> Result<RefType, MarkupError> {
        RefTypeFactory::get(ref_type as i8).map_err(MarkupError::Runtime)
    }

    /// The `RefType` named by a result's `index` attribute, which Java reads as a string and runs
    /// through `Integer.parseInt` (a `NumberFormatException` -- here a [`MarkupError::Runtime`] --
    /// for anything else, including a missing attribute).
    fn ref_type_of(result: &HashMap<String, Value>) -> Result<RefType, MarkupError> {
        let index = result
            .get("index")
            .and_then(Value::as_str)
            .and_then(|index| index.parse::<i32>().ok())
            .ok_or_else(|| MarkupError::Runtime("Error parsing reference index attribute".to_string()))?;
        Self::get_ref_type(index)
    }

    /// `SarifMgr.getSourceType(String)`, inherited from the base class, applied to a result's
    /// `sourceType` attribute.
    fn source_type_of(&self, result: &HashMap<String, Value>) -> SourceType {
        SarifMgr::get_source_type(&self.log, result.get("sourceType").and_then(Value::as_str))
    }

    /// One of the JSON numbers Java reads as `(int)(double)`/`(long)(double)`, i.e. through gson's
    /// `Double` boxing.
    fn number(result: &HashMap<String, Value>, key: &str) -> Option<f64> {
        result.get(key).and_then(Value::as_f64)
    }

    /// A result's operand index, defaulting to [`MNEMONIC`] when the attribute is absent.
    fn op_index(result: &HashMap<String, Value>) -> i32 {
        Self::number(result, "opIndex").map_or(MNEMONIC, |index| index as i32)
    }

    /// `SarifMgr.parseAddress(AddressFactory, String)`, inherited from the base class. Not hoisted
    /// onto the shared [`SarifMgr`] stub since it needs the base class's `factory` field, which
    /// that field-less stub deliberately does not hold; the factory is taken from this manager's
    /// own `Program` instead, which is where Java's constructor gets it too.
    ///
    /// Java's `null` return (for a `null` address string) has no counterpart here: every caller
    /// checks the attribute is present first, and the "incompatible address" branch each one
    /// guards that return with is therefore unreachable.
    fn parse_address(&self, addr_string: &str) -> Result<Address, MarkupError> {
        self.program
            .get_address_factory()
            .and_then(|factory| factory.get_address(addr_string))
            .ok_or_else(|| MarkupError::Runtime(format!("Error converting {addr_string} to address")))
    }

    /// `MarkupSarifMgr.processMemoryReference`.
    fn process_memory_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let from_addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible Memory Reference FROM Address"))?;

        let to_addr_str = result.get("to").and_then(Value::as_str).ok_or_else(|| {
            MarkupError::Runtime("TO_ADDRESS attribute missing for MEMORY_REFERENCE element".to_string())
        })?;
        let to_addr = self.parse_address(to_addr_str)?;

        let op_index = Self::op_index(result);
        let primary = result.get("primary").and_then(Value::as_bool).unwrap_or(false);
        let base_addr = match result.get("base").and_then(Value::as_str) {
            Some(base) => Some(self.parse_address(base)?),
            None => None,
        };

        if !overwrite {
            let blocked = Arc::get_mut(&mut self.program)
                .and_then(|p| p.get_reference_manager())
                .map(|ref_mgr| ref_mgr.get_references_from_operand(from_addr.clone(), op_index))
                .is_some_and(|existing| existing.first().is_some_and(|r| !r.is_memory_reference()));
            if blocked {
                self.log.append_msg(format!(
                    "Reference already exists from [{from_addr}] to [{to_addr}] on operand [{op_index}]"
                ));
                return Ok(());
            }
        }

        let ref_type = Self::ref_type_of(result)?;
        let source_type = self.source_type_of(result);

        let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) else {
            return Ok(());
        };
        let reference = match &base_addr {
            Some(base_addr) => {
                let offset = Self::number(result, "offset").unwrap_or(0.0) as i64;
                ref_mgr.add_offset_mem_reference(
                    from_addr,
                    to_addr.clone(),
                    to_addr == *base_addr,
                    offset,
                    ref_type,
                    source_type,
                    op_index,
                )
            }
            None => ref_mgr.add_memory_reference(from_addr, to_addr, ref_type, source_type, op_index),
        };
        ref_mgr.set_primary(reference, primary);
        Ok(())
    }

    /// `MarkupSarifMgr.processRegisterReference`.
    fn process_register_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let from_addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible Memory Reference FROM Address"))?;

        let to_addr_str = result.get("to").and_then(Value::as_str).ok_or_else(|| {
            MarkupError::Runtime("TO_ADDRESS attribute missing for REGISTER_REFERENCE element".to_string())
        })?;
        let to_addr = self.parse_address(to_addr_str)?;

        // `program.getLanguage().getRegisters(toAddr)[0]`: Java indexes the array unguarded, so an
        // address that names no register raises `ArrayIndexOutOfBoundsException` and is logged.
        let register = self
            .program
            .get_language()
            .map(|language| language.get_registers_at(&to_addr))
            .and_then(|registers| registers.first().cloned())
            .ok_or_else(|| MarkupError::Runtime(format!("No register at [{to_addr}]")))?;

        let op_index = Self::op_index(result);
        let primary = result.get("primary").and_then(Value::as_bool).unwrap_or(false);

        if !overwrite {
            let blocked = Arc::get_mut(&mut self.program)
                .and_then(|p| p.get_reference_manager())
                .map(|ref_mgr| ref_mgr.get_references_from_operand(from_addr.clone(), op_index))
                .is_some_and(|existing| !existing.is_empty());
            if blocked {
                self.log.append_msg(format!(
                    "Memory reference already existed from [{from_addr}] to [{to_addr}] on operand [{op_index}]"
                ));
                return Ok(());
            }
        }

        let ref_type = Self::ref_type_of(result)?;
        let source_type = self.source_type_of(result);

        let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) else {
            return Ok(());
        };
        let reference =
            ref_mgr.add_register_reference(from_addr, op_index, &register.borrow(), ref_type, source_type);
        ref_mgr.set_primary(reference, primary);
        Ok(())
    }

    /// `MarkupSarifMgr.processStackReference`.
    fn process_stack_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible Stack Reference Address"))?;
        let op_index = Self::op_index(result);

        let code_unit = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_code_unit_containing(&addr));
        let Some(code_unit) = code_unit else {
            self.log.append_msg(format!("No codeunit at {addr}"));
            return Ok(());
        };

        if !overwrite {
            let blocked = Arc::get_mut(&mut self.program)
                .and_then(|p| p.get_reference_manager())
                .map(|ref_mgr| ref_mgr.get_references_from_operand(addr.clone(), op_index))
                .is_some_and(|existing| !existing.is_empty());
            if blocked {
                self.log
                    .append_msg(format!("Reference already exists from [{addr}] on operand [{op_index}]"));
                return Ok(());
            }
            // Java re-checks `!overwrite` after `cu.getPrimaryReference(opIndex)`; that check can
            // only be reached with `overwrite` true, so the existing primary reference is simply
            // replaced below.
            if code_unit.get_primary_reference(op_index).is_some() {
                return Ok(());
            }
        }

        let offset = Self::number(result, "offset").unwrap_or(0.0) as i32;
        let ref_type = Self::ref_type_of(result)?;
        let source_type = self.source_type_of(result);

        if let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) {
            ref_mgr.add_stack_reference(addr, op_index, offset, ref_type, source_type);
        }
        Ok(())
    }

    /// `MarkupSarifMgr.processShiftedReference`.
    fn process_shifted_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible Shifted Reference Address"))?;
        let op_index = Self::op_index(result);

        let code_unit = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_code_unit_containing(&addr));
        let Some(code_unit) = code_unit else {
            self.log.append_msg(format!("No codeunit at {addr}"));
            return Ok(());
        };

        if !overwrite {
            let blocked = Arc::get_mut(&mut self.program)
                .and_then(|p| p.get_reference_manager())
                .map(|ref_mgr| ref_mgr.get_references_from_operand(addr.clone(), op_index))
                .is_some_and(|existing| !existing.is_empty());
            if blocked {
                self.log
                    .append_msg(format!("Reference already exists from [{addr}] on operand [{op_index}]"));
                return Ok(());
            }
            if code_unit.get_primary_reference(op_index).is_some() {
                return Ok(());
            }
        }

        let shift = Self::number(result, "shift").unwrap_or(0.0) as i32;
        let value = Self::number(result, "value").unwrap_or(0.0) as i64;
        // `addr.getNewAddress(value)`: same address space, new offset.
        let to_addr = addr.space().address(value);
        let ref_type = Self::ref_type_of(result)?;
        let source_type = self.source_type_of(result);

        if let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) {
            ref_mgr.add_shifted_mem_reference(addr, to_addr, shift, ref_type, source_type, op_index);
        }
        Ok(())
    }

    /// `MarkupSarifMgr.processExtLibraryReference`.
    fn process_ext_library_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible External Reference Address"))?;
        let op_index = Self::op_index(result);

        let namespace_path = result.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let label = result.get("libLabel").and_then(Value::as_str).map(str::to_string);
        // Unlike the other addresses here this one goes straight through the factory, so an
        // unparseable string is a missing address rather than an error.
        let lib_addr = result
            .get("libAddr")
            .and_then(Value::as_str)
            .and_then(|lib_address| {
                self.program
                    .get_address_factory()
                    .and_then(|factory| factory.get_address(lib_address))
            });
        let lib_ext_address = result
            .get("libExtAddr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let orig_import = result.get("origImport").and_then(Value::as_str).map(str::to_string);
        let is_function = result.get("isFunction").and_then(Value::as_bool).unwrap_or(false);

        if label.is_none() && lib_addr.is_none() {
            self.log.append_msg(format!(
                "External library reference for address {addr} does not have a label or an external \
                 address specified. External reference will not be created"
            ));
            return Ok(());
        }

        let code_unit = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_code_unit_containing(&addr));
        let Some(code_unit) = code_unit else {
            self.log.append_msg(format!("No codeunit at {addr}"));
            return Ok(());
        };

        if let Some(existing) = code_unit.get_external_reference(op_index) {
            if !overwrite {
                return Ok(());
            }
            if let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) {
                ref_mgr.delete(existing);
            }
        }

        let ref_type = match result.get("kind").and_then(Value::as_str) {
            Some(_) => Self::ref_type_of(result)?,
            None => RefType::ExternalRef,
        };
        let source_type = self.source_type_of(result);

        let ext_loc = match self.external_map.get(&lib_ext_address) {
            Some(ext_loc) => ext_loc.clone(),
            None => {
                let ext_loc = self.add_external(
                    label.as_deref(),
                    &namespace_path,
                    lib_addr,
                    source_type,
                    orig_import.as_deref(),
                    is_function,
                )?;
                self.external_map.insert(lib_ext_address, ext_loc.clone());
                ext_loc
            }
        };
        if let Some(orig_import) = &orig_import {
            if ext_loc.get_original_imported_name().as_deref() != Some(orig_import.as_str()) {
                self.log.append_msg("Retrieving incorrect external location - known bug");
            }
        }

        if let Some(ref_mgr) = Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager()) {
            ref_mgr.add_external_reference_for_location(addr, op_index, ext_loc, source_type, ref_type)?;
        }
        Ok(())
    }

    /// `MarkupSarifMgr.addExternal`.
    ///
    /// > This seems like this should be unnecessary but external classes are not listed under
    /// > `ExternalLocation`s.
    fn add_external(
        &mut self,
        name: Option<&str>,
        namespace_path: &str,
        address: Option<Address>,
        source_type: SourceType,
        name0: Option<&str>,
        is_function: bool,
    ) -> Result<Arc<dyn ExternalLocation>, MarkupError> {
        let global = self
            .program
            .get_global_namespace()
            .ok_or_else(|| MarkupError::Runtime("Program has no global namespace".to_string()))?;
        let path = format!("{namespace_path}::");
        let namespace = SarifMgr::walk_namespace(
            &mut self.program,
            global,
            &path,
            address.as_ref(),
            source_type,
            true,
        )
        .map_err(MarkupError::Runtime)?
        // A deferred (`FUN_`-prefixed) namespace is Java's `null`, which the very next line --
        // `getLibrary(p)` -- dereferences; the resulting `NullPointerException` is what reaches
        // `processExtLibraryReference`'s catch-all, so this reports the same end state.
        .ok_or_else(|| MarkupError::Runtime(format!("Namespace {namespace_path} is not resolvable yet")))?;

        let library = Self::get_library(&namespace).unwrap_or_else(|| namespace.clone());

        let Some(ext_manager) = Arc::get_mut(&mut self.program).and_then(|p| p.get_external_manager()) else {
            return Err(InvalidInputException::new().into());
        };
        let mut loc = match (is_function, name0) {
            (true, Some(name0)) => {
                ext_manager.add_ext_function_in_namespace_reuse(library, Some(name0), address, source_type, false)?
            }
            (true, None) => ext_manager.add_ext_function_in_namespace_reuse(
                namespace.clone(),
                name,
                address,
                source_type,
                true,
            )?,
            (false, Some(name0)) => {
                ext_manager.add_ext_location_in_namespace_reuse(library, Some(name0), address, source_type, false)?
            }
            (false, None) => ext_manager.add_ext_location_in_namespace_reuse(
                namespace.clone(),
                name,
                address,
                source_type,
                true,
            )?,
        };

        if name0.is_some() {
            // `loc.setName(p, name, sourceType)`. Best-effort, as in `ExternalLibSarifMgr`: the
            // ported `ExternalManager` hands back an `Arc`, not the freely mutable object identity
            // Java's `ExternalLocation` gives for free, so a location the manager also kept a
            // handle to cannot be renamed from here.
            if let Some(loc) = Arc::get_mut(&mut loc) {
                loc.set_name(namespace, name.unwrap_or_default(), source_type)?;
            }
        }
        Ok(loc)
    }

    /// `MarkupSarifMgr.getLibrary(Namespace)`: walks up the namespace chain (starting at
    /// `namespace` itself) until a `Library` is found. Java duplicates this helper in
    /// `ExternalLibSarifMgr`, which is why the ported sibling has its own copy too.
    fn get_library(namespace: &Arc<dyn Namespace>) -> Option<Arc<dyn Namespace>> {
        let mut current = Some(namespace.clone());
        while let Some(namespace) = current {
            if namespace.is_library() {
                return Some(namespace);
            }
            current = namespace.get_parent_namespace();
        }
        None
    }

    /// `MarkupSarifMgr.processEquateReference`.
    fn process_equate_reference(
        &mut self,
        result: &HashMap<String, Value>,
        overwrite: bool,
    ) -> Result<(), MarkupError> {
        let addr = self
            .base
            .get_location(result)?
            .ok_or_else(|| AddressFormatException::new("Incompatible Equate Reference Address"))?;

        let undefined = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_listing())
            .is_some_and(|listing| listing.is_undefined(&addr, &addr));
        if undefined {
            self.log
                .append_msg(format!("BAD EQUATE REFERENCE: defined code unit not found at {addr}"));
            return Ok(());
        }

        let code_unit = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_code_unit_containing(&addr));
        let Some(code_unit) = code_unit else {
            self.log.append_msg(format!("No codeunit at {addr}"));
            return Ok(());
        };

        let equate_name = result.get("name").and_then(Value::as_str).unwrap_or_default().to_string();

        let mut op_index = MNEMONIC;
        let mut instr_scalars: Vec<Scalar> = Vec::new();
        // The capitalized key is Java's: `processEquateReference` gates on "OpIndex" but reads
        // "opIndex", so a result carrying only the lower-case key keeps the mnemonic operand.
        if result.get("OpIndex").is_some() {
            op_index = Self::op_index(result);
            if op_index != MNEMONIC {
                match code_unit.get_scalar(op_index) {
                    Some(scalar) => instr_scalars.push(scalar),
                    None => {
                        if let Some(instruction) = code_unit.as_instruction() {
                            for op_object in instruction.get_op_objects(op_index) {
                                if let OperandValue::Scalar(scalar) = op_object {
                                    instr_scalars.push(scalar);
                                }
                            }
                            if instr_scalars.is_empty() {
                                self.log.append_msg(format!(
                                    "BAD EQUATE REFERENCE: operand [{op_index}] at address [{addr}] is not a scalar."
                                ));
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        let value = match result.get("value").and_then(Value::as_i64) {
            Some(value) => {
                if !instr_scalars.iter().any(|scalar| scalar.get_signed_value() == value) {
                    self.log.append_msg(format!(
                        "BAD EQUATE REFERENCE: equate [{equate_name}] value [0x{value:x}] does not match \
                         scalar on operand [{op_index}] at address [{addr}]"
                    ));
                    return Ok(());
                }
                value
            }
            None => match instr_scalars.first() {
                Some(scalar) => {
                    // use scalar value as default - seems like a bad idea
                    Msg::warn("MarkupSarifMgr", &"NO VALUE SPECIFIED");
                    scalar.get_signed_value()
                }
                None => {
                    self.log.append_msg(
                        "BAD EQUATE REFERENCE: either the VALUE or OPERAND_INDEX must be specified",
                    );
                    return Ok(());
                }
            },
        };

        let existing_value = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_equate_table())
            .and_then(|table| table.equate(&equate_name))
            .map(|equate| equate.value());
        match existing_value {
            Some(existing_value) => {
                if existing_value != value {
                    self.log.append_msg(format!(
                        "BAD EQUATE REFERENCE: equate [{equate_name}] value [0x{value:x}] conflicts with \
                         existing equate value [0x{existing_value:x}]."
                    ));
                    return Ok(());
                }
            }
            None => {
                let created = Arc::get_mut(&mut self.program)
                    .and_then(|p| p.get_equate_table())
                    .map(|table| table.create_equate(&equate_name, value).map(|_| ()));
                match created {
                    // Java's `DuplicateNameException` arm (an `AssertException`) is unreachable:
                    // the lookup above already established there is no equate by this name, so a
                    // failure here is the `InvalidInputException` arm.
                    Some(Err(_)) => {
                        self.log.append_msg(format!("Invalid name for equate {equate_name}"));
                        return Ok(());
                    }
                    Some(Ok(())) => {}
                    None => return Ok(()),
                }
            }
        }

        let displaced = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_equate_table())
            .and_then(|table| table.equate_at_value(&addr, op_index as i16, value))
            .map(|equate| equate.name().to_string());
        if let (Some(displaced), true) = (displaced, overwrite) {
            if let Some(equate) = Arc::get_mut(&mut self.program)
                .and_then(|p| p.get_equate_table())
                .and_then(|table| table.equate_mut(&displaced))
            {
                equate.remove_reference(&addr, op_index as i16);
            }
        }
        if let Some(equate) = Arc::get_mut(&mut self.program)
            .and_then(|p| p.get_equate_table())
            .and_then(|table| table.equate_mut(&equate_name))
        {
            equate.add_reference(addr, op_index as i16);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `MarkupSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let owned_set;
        let effective_set: &dyn AddressSetView = match set {
            Some(set) => set,
            None => {
                owned_set = self.memory_address_set();
                owned_set.as_ref()
            }
        };

        monitor.set_message("Exporting References...");
        let request: Vec<Address> = match Arc::get_mut(&mut self.program).and_then(|p| p.get_reference_manager())
        {
            Some(ref_mgr) => ref_mgr
                .get_reference_source_iterator_in_set(Some(effective_set), true)
                .collect(),
            None => Vec::new(),
        };

        Self::write_refs_as_sarif(&request, results, monitor);
        Self::write_equate_refs_as_sarif(effective_set, results, monitor);
        Ok(())
    }

    /// `program.getMemory()`, viewed as the `AddressSetView` Java's `Memory` interface also is.
    /// Falls back to an empty set when there is no memory.
    fn memory_address_set(&self) -> Box<dyn AddressSetView> {
        self.program
            .get_memory()
            .map(|memory| memory.get_all_initialized_address_set())
            .unwrap_or_else(|| Box::new(AddressSet::new()) as Box<dyn AddressSetView>)
    }

    /// `MarkupSarifMgr.writeAsSARIF(Program, List<Address>, JsonArray)`.
    pub fn write_refs_as_sarif(request: &[Address], results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifReferenceWriter::new(request.to_vec());
        let task = SarifWriterTask::new("References", writer);
        TaskLauncher::launch(&task, monitor, results);
    }

    /// `MarkupSarifMgr.writeAsSARIF(Program, AddressSetView, JsonArray)`, the equate-reference
    /// overload.
    pub fn write_equate_refs_as_sarif(
        set: &dyn AddressSetView,
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifEquateRefWriter::new(AddressSet::from_set(set));
        let task = SarifWriterTask::new("References", writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Symbol, SymbolType};
    use crate::util::task::DummyMonitor;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    fn manager() -> MarkupSarifMgr {
        MarkupSarifMgr::new(mock_program(), MessageLog::new())
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn tagged(tag: &str) -> HashMap<String, Value> {
        result_map(&[("Message", Value::String(tag.to_string()))])
    }

    struct MockSymbol;

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0), 0)
        }
        fn get_name(&self) -> &str {
            "Global"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::Imported
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockNamespace {
        library: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
        fn is_library(&self) -> bool {
            self.library
        }
    }

    #[test]
    fn key_matches_java() {
        assert_eq!(MarkupSarifMgr::KEY, "REFERENCES");
        assert_eq!(manager().get_key(), "REFERENCES");
    }

    #[test]
    fn get_ref_type_maps_the_java_ref_type_values() {
        // `RefTypeFactory.get((byte) 113)` is `RefType.EXTERNAL_REF`, the type
        // `processExtLibraryReference` falls back to when a result carries no "kind".
        assert_eq!(MarkupSarifMgr::get_ref_type(113).unwrap(), RefType::ExternalRef);
        assert!(MarkupSarifMgr::get_ref_type(-42).is_err());
    }

    #[test]
    fn ref_type_of_reads_the_index_attribute_as_a_string() {
        let result = result_map(&[("index", Value::String("113".to_string()))]);
        assert_eq!(MarkupSarifMgr::ref_type_of(&result).unwrap(), RefType::ExternalRef);

        // Java casts the attribute to `String` before `Integer.parseInt`, so a JSON number is a
        // failure, not a shortcut.
        let numeric = result_map(&[("index", Value::from(113.0))]);
        assert!(MarkupSarifMgr::ref_type_of(&numeric).is_err());
    }

    #[test]
    fn op_index_defaults_to_the_mnemonic_operand() {
        assert_eq!(MarkupSarifMgr::op_index(&HashMap::new()), MNEMONIC);
        assert_eq!(
            MarkupSarifMgr::op_index(&result_map(&[("opIndex", Value::from(2.0))])),
            2
        );
    }

    #[test]
    fn read_dispatches_each_message_tag_to_its_own_processor() {
        // With `SarifUtils` (and therefore `SarifMgr.getLocation`) still stubbed out, every
        // processor stops at its own "no FROM address" guard -- whose message is what identifies
        // which one ran.
        for (tag, expected) in [
            ("Ref.Memory", "Incompatible Memory Reference FROM Address"),
            ("Ref.Register", "Incompatible Memory Reference FROM Address"),
            ("Ref.Shifted", "Incompatible Shifted Reference Address"),
            ("Ref.Stack", "Incompatible Stack Reference Address"),
            ("Ref.External", "Incompatible External Reference Address"),
            ("Ref.Equate", "Incompatible Equate Reference Address"),
        ] {
            let mut mgr = manager();
            assert!(mgr.read(&tagged(tag), None, &DummyMonitor));
            assert_eq!(mgr.log.messages(), vec![expected.to_string()], "tag {tag}");
        }
    }

    #[test]
    fn read_ignores_an_unknown_message_tag() {
        let mut mgr = manager();
        assert!(mgr.read(&tagged("Ref.Unheard.Of"), None, &DummyMonitor));
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn read_skips_stack_references_when_functions_are_not_imported() {
        let options = SarifProgramOptions {
            functions: false,
            ..SarifProgramOptions::default()
        };
        let mut mgr = manager();
        assert!(mgr.read(&tagged("Ref.Stack"), Some(&options), &DummyMonitor));
        assert!(mgr.log.messages().is_empty());

        // ... and processes them when the option is on.
        let mut mgr = manager();
        mgr.read(&tagged("Ref.Stack"), Some(&SarifProgramOptions::default()), &DummyMonitor);
        assert_eq!(mgr.log.messages().len(), 1);
    }

    #[test]
    fn read_skips_external_references_when_external_libraries_are_not_imported() {
        let options = SarifProgramOptions {
            external_libraries: false,
            ..SarifProgramOptions::default()
        };
        let mut mgr = manager();
        assert!(mgr.read(&tagged("Ref.External"), Some(&options), &DummyMonitor));
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn memory_reference_without_a_to_address_is_reported() {
        // Reaching this message means `getLocation` produced a FROM address; it does not yet, so
        // the check that fires first is the FROM one. The TO check is exercised directly instead.
        let mut mgr = manager();
        let result = result_map(&[("Message", Value::String("Ref.Memory".to_string()))]);
        let err = mgr.process_memory_reference(&result, true).unwrap_err();
        assert_eq!(err.to_string(), "Incompatible Memory Reference FROM Address");
    }

    #[test]
    fn parse_address_without_an_address_factory_reports_the_offending_string() {
        let mgr = manager();
        let err = mgr.parse_address("ram:1000").unwrap_err();
        assert_eq!(err.to_string(), "Error converting ram:1000 to address");
    }

    #[test]
    fn get_library_walks_up_to_the_enclosing_library() {
        let library: Arc<dyn Namespace> = Arc::new(MockNamespace {
            library: true,
            parent: None,
        });
        let child: Arc<dyn Namespace> = Arc::new(MockNamespace {
            library: false,
            parent: Some(library.clone()),
        });

        assert!(MarkupSarifMgr::get_library(&child).is_some_and(|ns| ns.is_library()));

        let orphan: Arc<dyn Namespace> = Arc::new(MockNamespace {
            library: false,
            parent: None,
        });
        assert!(MarkupSarifMgr::get_library(&orphan).is_none());
    }

    #[test]
    fn write_over_a_program_with_no_references_produces_no_results() {
        let mut mgr = manager();
        let mut results = Vec::new();
        assert!(mgr.write(&mut results, None, &DummyMonitor).is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn write_as_sarif_with_empty_requests_leaves_results_empty() {
        let mut results = Vec::new();
        MarkupSarifMgr::write_refs_as_sarif(&[], &mut results, &DummyMonitor);
        MarkupSarifMgr::write_equate_refs_as_sarif(&AddressSet::new(), &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }
}
