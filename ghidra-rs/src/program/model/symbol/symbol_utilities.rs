//! Port of `ghidra.program.model.symbol.SymbolUtilities`.
//!
//! The Java class is a `private`-constructor static-method utility (it cannot be instantiated).
//! It was selected as a dependency-cycle cut-point, so -- mirroring
//! [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities),
//! [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities), and
//! [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility) -- it is ported here as a Rust
//! trait ([`SymbolUtilities`]) with default-implemented methods instead of free functions:
//! callers depend on `&dyn SymbolUtilities`/`Box<dyn SymbolUtilities>` (a trait-object seam)
//! rather than importing this module's concrete machinery directly, which is what breaks the
//! cycle. [`DefaultSymbolUtilities`] is a zero-sized marker implementing every method with its
//! default body, mirroring `DefaultSimpleDiffUtility`.
//!
//! Like `SimpleDiffUtility`, every method that needs a `Program` takes it as an explicit leading
//! parameter rather than deriving it via `Symbol.getProgram()`/`Instruction.getProgram()` (this
//! port's `Symbol`/`CodeUnit` have no such accessor, to avoid re-introducing the cycle this class
//! was cut to break). Methods that only need read-only `Program` accessors (`get_register_at`,
//! `get_compiler_spec`, `get_global_namespace`) take `&dyn Program`; methods that need a mutable
//! manager (`Listing`, `SymbolTable`, `ReferenceManager`) take `&mut dyn Program`.
//!
//! A handful of private Java static helpers (`getDynamicDataName`, `generateOffcutDataName`,
//! `getDynamicInstructionName`, `getDyanmicOffcutInstructionName`, `findDynamicPrefix`,
//! `findAddressSpace`, `buildSpaceName`, `getVariableAddressString`, `removeFirstUseOffset`) back
//! the public API. The ones that call back into other `SymbolUtilities` methods (and so need
//! dynamic dispatch) are kept as additional default-provided trait methods, exactly as
//! `SimpleDiffUtility` already does for its own private helpers; the rest, which are pure
//! functions of their arguments, are ported as ordinary module-private free functions.
//!
//! `Symbol.getObject() instanceof Instruction` has no port (this crate's `Symbol` has no
//! `getObject()` accessor); [`SymbolUtilities::get_dynamic_name_for_program`] instead branches on
//! [`CodeUnit::as_data`](crate::program::model::listing::CodeUnit::as_data) being `Some`/`None`,
//! which is equivalent since a code unit is always either `Data` or an instruction-like unit.
//! Java's private `getDynamicInstructionName`/`getDyanmicOffcutInstructionName` only ever call
//! `CodeUnit`-level accessors (`getMinAddress`/`getPrimarySymbol`) on their nominally-`Instruction`
//! parameter, so this port's equivalents take `&dyn CodeUnit` directly and need no `Instruction`
//! downcast at all.
//!
//! Several further adaptations, each noted at its call site below:
//! - [`generate_offcut_data_name`](SymbolUtilities::generate_offcut_data_name) uses
//!   `data_type.get_default_label_prefix()` in place of Java's `MemBuffer`-based
//!   `DataType.getDefaultOffcutLabelPrefix(data, data, ...)` overload, since wiring `&dyn Data` as
//!   both the `MemBuffer` and `Settings` arguments that overload needs is not worth the extra
//!   machinery for an offcut-prefix approximation.
//! - `normalizeSegmentedAddress` (a `SegmentedAddress`-only concern) is not ported;
//!   [`get_dynamic_data_name`](SymbolUtilities::get_dynamic_data_name) uses the address as given.
//! - `getDynamicDataTypePrefixes` (reflection-discovered `BuiltInDataType` prefixes via
//!   `ClassSearcher`) has no port; [`starts_with_default_dynamic_prefix`] only checks the fixed
//!   `DYNAMIC_PREFIX_ARRAY`, matching this module's pre-existing free-function port.
//! - The two Java `getCleanSymbolName` overloads (`Symbol` and `String, Address`) are ported as
//!   [`SymbolUtilities::get_clean_symbol_name`] (string + address) and
//!   [`SymbolUtilities::get_clean_symbol_name_of`] (symbol), since Rust cannot overload trait
//!   methods by parameter type.
//! - [`SymbolUtilities::get_symbol_name_comparator`]'s case-insensitive ordering is ported as
//!   [`SymbolUtilities::compare_symbol_names`] (an explicit two-symbol comparison) rather than a
//!   `Comparator`-returning method, since Rust has no direct analogue of a reusable `Comparator`
//!   object for trait-object symbols.
//! - [`SymbolUtilities::create_preferred_label_or_function_symbol`] ignores `namespace` when
//!   creating a brand new symbol (this port's [`SymbolTable::create_label`] has no namespace
//!   parameter), and best-effort applies a namespace change to an existing global symbol only when
//!   the returned `Arc<dyn Symbol>` is uniquely owned (`Arc::get_mut`); errors from `create_label`
//!   are reported as [`InvalidInputException`] rather than reproducing Java's
//!   catch-and-rewrap-as-`AssertException` behavior.
//! - [`SymbolUtilities::get_default_local_name`] resolves each storage varnode's register via
//!   [`Program::get_register_at`](crate::program::model::listing::Program::get_register_at)
//!   (this port's `Varnode`-to-register lookup), rather than Java's `Program.getRegister(Varnode)`.
//!
//! Grown (all with defaults, so pre-existing implementors keep compiling) to support this port:
//! - [`Symbol::is_dynamic`](crate::program::model::symbol::Symbol::is_dynamic) -- stands in for
//!   `Symbol.isDynamic()`.
//! - [`Symbol::set_namespace`](crate::program::model::symbol::Symbol::set_namespace) -- stands in
//!   for `Symbol.setNamespace(Namespace)`.
//! - [`SymbolTable::get_label_or_function_symbols`](crate::program::model::symbol::SymbolTable::get_label_or_function_symbols)
//!   -- stands in for `SymbolTable.getLabelOrFunctionSymbols(String, Namespace)` (Java's only
//!   caller, this class, always passes a `null` namespace).
//! - [`VariableStorage::is_stack_storage`](crate::program::seam_stubs::VariableStorage::is_stack_storage)
//!   and
//!   [`VariableStorage::get_stack_offset`](crate::program::seam_stubs::VariableStorage::get_stack_offset)
//!   -- stand in for `VariableStorage.isStackStorage()`/`getStackOffset()`.
//!
//! Also fixed in passing: the pre-existing free-function port of
//! `getAddressAppendedName(String, Address)` used `_` as its separator; Java's public single-address
//! overload actually uses `@` (the private 3-arg overload defaults to `@`, only ever called with
//! `_` from `getCleanSymbolName`'s internal fallback check). [`SymbolUtilities::get_address_appended_name`]
//! and its test now match Java.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory, AddressSpace};
use crate::program::model::data::data_type_display_options::DEFAULT as DEFAULT_DISPLAY_OPTIONS;
use crate::program::model::listing::function::{
    DEFAULT_LOCAL_PREFIX, DEFAULT_LOCAL_RESERVED_PREFIX, DEFAULT_LOCAL_TEMP_PREFIX,
    DEFAULT_PARAM_PREFIX,
};
use crate::program::model::listing::{CodeUnit, Data, Program};
use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
use crate::program::seam_stubs::VariableStorage;
use crate::util::exception::InvalidInputException;

/// Maximum allowed symbol name length, matching Ghidra's Java SymbolUtilities.
pub const MAX_SYMBOL_NAME_LENGTH: usize = 2000;

/// Prefix used for ordinal symbol names.
pub const ORDINAL_PREFIX: &str = "Ordinal_";

/// Default prefix for subroutine labels.
pub const DEFAULT_SUBROUTINE_PREFIX: &str = "SUB_";
/// Default prefix for flow labels that are not calls.
pub const DEFAULT_SYMBOL_PREFIX: &str = "LAB_";
/// Default prefix for data labels.
pub const DEFAULT_DATA_PREFIX: &str = "DAT_";
/// Default prefix for unknown labels.
pub const DEFAULT_UNKNOWN_PREFIX: &str = "UNK_";
/// Default prefix for external entry labels.
pub const DEFAULT_EXTERNAL_ENTRY_PREFIX: &str = "EXT_";
/// Default prefix for function labels.
pub const DEFAULT_FUNCTION_PREFIX: &str = "FUN_";
/// Default prefix for offcut reference labels.
pub const DEFAULT_INTERNAL_REF_PREFIX: &str = "OFF_";

/// Reference level for unknown dynamic labels.
pub const UNK_LEVEL: usize = 0;
/// Reference level for data dynamic labels.
pub const DAT_LEVEL: usize = 1;
/// Reference level for label dynamic labels.
pub const LAB_LEVEL: usize = 2;
/// Reference level for subroutine dynamic labels.
pub const SUB_LEVEL: usize = 3;
/// Reference level for external dynamic labels.
pub const EXT_LEVEL: usize = 5;
/// Reference level for function dynamic labels.
pub const FUN_LEVEL: usize = 6;

const UNDERSCORE: &str = "_";
const PLUS: &str = "+";
const MIN_LABEL_ADDRESS_DIGITS: usize = 4;
const DYNAMIC_PREFIX_ARRAY: [&str; 7] = [
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_DATA_PREFIX,
    DEFAULT_SYMBOL_PREFIX,
    DEFAULT_SUBROUTINE_PREFIX,
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_EXTERNAL_ENTRY_PREFIX,
    DEFAULT_FUNCTION_PREFIX,
];

/// Static helper methods for dealing with symbol strings.
///
/// Port of `ghidra.program.model.symbol.SymbolUtilities`.
pub trait SymbolUtilities {
    /// Returns the ordinal value encoded in a symbol name or -1 if it is not an ordinal name.
    fn get_ordinal_value(&self, symbol_name: Option<&str>) -> i32 {
        let Some(symbol_name) = symbol_name else {
            return -1;
        };
        let Some(ordinal_text) = symbol_name.strip_prefix(ORDINAL_PREFIX) else {
            return -1;
        };
        ordinal_text.parse::<i32>().unwrap_or(-1)
    }

    /// Returns true if the string contains an invalid symbol-name character.
    fn contains_invalid_chars(&self, str: &str) -> bool {
        str.chars().any(|c| self.is_invalid_char(c))
    }

    /// Generates Ghidra's default function name for an address.
    fn get_default_function_name(&self, addr: &Address) -> String {
        format!("{}{}", DEFAULT_FUNCTION_PREFIX, self.get_address_string(addr))
    }

    /// Returns true if the name is a reserved default external symbol name.
    fn is_reserved_external_default_name(&self, name: &str, factory: &dyn AddressFactory) -> bool {
        name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX) && self.parse_dynamic_name(factory, name).is_some()
    }

    /// Generates Ghidra's default external function name for an address.
    fn get_default_external_function_name(&self, addr: &Address) -> String {
        format!(
            "{}{}{}",
            DEFAULT_EXTERNAL_ENTRY_PREFIX,
            DEFAULT_FUNCTION_PREFIX,
            self.get_address_string(addr)
        )
    }

    /// Generates Ghidra's default external name for an address and optional data-type prefix.
    fn get_default_external_name(&self, addr: &Address, data_type_prefix: Option<&str>) -> String {
        match data_type_prefix {
            Some(prefix) if !prefix.is_empty() => format!(
                "{}{}{}{}",
                DEFAULT_EXTERNAL_ENTRY_PREFIX,
                prefix,
                UNDERSCORE,
                self.get_address_string(addr)
            ),
            _ => format!("{}{}", DEFAULT_EXTERNAL_ENTRY_PREFIX, self.get_address_string(addr)),
        }
    }

    /// Returns true if the name parses as a reserved dynamic label name for this address factory.
    fn is_reserved_dynamic_label_name(&self, name: &str, factory: &dyn AddressFactory) -> bool {
        let Some(prefix) = find_dynamic_prefix(name) else {
            return false;
        };
        name.len() >= prefix.len() + 1 && self.parse_dynamic_name(factory, name).is_some()
    }

    /// Validates a symbol name against Ghidra's basic Java SymbolUtilities checks.
    fn validate_name(&self, name: Option<&str>) -> Result<(), InvalidInputException> {
        let Some(name) = name else {
            return Err(InvalidInputException::with_message("Symbol name can't be null"));
        };
        if name.is_empty() {
            return Err(InvalidInputException::with_message("Symbol name can't be empty string"));
        }
        if name.len() > MAX_SYMBOL_NAME_LENGTH {
            return Err(InvalidInputException::with_message(format!(
                "Symbol name exceeds maximum length of {}, length={}",
                MAX_SYMBOL_NAME_LENGTH,
                name.len()
            )));
        }
        if self.contains_invalid_chars(name) {
            return Err(InvalidInputException::with_message(format!(
                "Symbol name contains invalid characters: {}",
                name
            )));
        }
        Ok(())
    }

    /// Returns true if the name starts with one of Ghidra's default dynamic prefixes.
    fn starts_with_default_dynamic_prefix(&self, name: &str) -> bool {
        find_dynamic_prefix(name).is_some()
    }

    /// Returns true if the name has a plausible dynamic symbol shape.
    fn is_dynamic_symbol_pattern(&self, name: &str, case_sensitive: bool) -> bool {
        let normalized;
        let name = if case_sensitive {
            name
        } else {
            normalized = name.to_uppercase();
            normalized.as_str()
        };

        if self.starts_with_default_dynamic_prefix(name) {
            return true;
        }

        let Some(last_index) = name.rfind('_') else {
            return false;
        };
        if last_index == 0 {
            return false;
        }
        let suffix = &name[last_index + 1..];
        (3..=16).contains(&suffix.len()) && suffix.chars().all(is_hex_digit)
    }

    /// Returns true if the character is invalid inside a symbol name.
    fn is_invalid_char(&self, c: char) -> bool {
        c < ' ' || c == ' '
    }

    /// Removes invalid characters or replaces them with underscores.
    fn replace_invalid_chars(&self, str: Option<&str>, replace_with_underscore: bool) -> Option<String> {
        str.map(|str| {
            let mut result = String::with_capacity(str.len());
            for c in str.chars() {
                if self.is_invalid_char(c) {
                    if replace_with_underscore {
                        result.push('_');
                    }
                } else {
                    result.push(c);
                }
            }
            result
        })
    }

    /// Creates a dynamic label name for an offcut reference.
    fn get_dynamic_offcut_name(&self, addr: Option<&Address>) -> Option<String> {
        addr.map(|addr| format!("{}{}", DEFAULT_INTERNAL_REF_PREFIX, self.get_address_string(addr)))
    }

    /// Creates a dynamic symbol name for a reference level and address.
    fn get_dynamic_name(&self, reference_level: usize, addr: Option<&Address>) -> Option<String> {
        let addr = addr?;
        DYNAMIC_PREFIX_ARRAY
            .get(reference_level)
            .map(|prefix| format!("{}{}", prefix, self.get_address_string(addr)))
    }

    /// Creates a name for a dynamic symbol at `addr` within `program`, consulting the code unit
    /// (if any) containing that address the way Java's `Program`-taking overload does.
    fn get_dynamic_name_for_program(&self, program: &mut dyn Program, addr: &Address) -> Option<String> {
        if !addr.is_memory_address() {
            return None;
        }

        let code_unit = program.get_listing().and_then(|listing| listing.get_code_unit_containing(addr));
        let ref_level = program.get_reference_manager()?.get_reference_level(addr.clone());

        let Some(code_unit) = code_unit else {
            return self.get_dynamic_name(ref_level.max(0) as usize, Some(addr));
        };

        if let Some(data) = code_unit.as_data() {
            return self.get_dynamic_data_name(data, addr, ref_level);
        }

        self.get_dynamic_instruction_name(program, code_unit.as_ref(), addr, ref_level)
    }

    /// Port of the private `SymbolUtilities.getDynamicDataName(Data, Address, int)`.
    fn get_dynamic_data_name(&self, data: &dyn Data, address: &Address, ref_level: i8) -> Option<String> {
        let code_unit_address = data.get_min_address();
        let diff = address.subtract(&code_unit_address);
        let is_string = data.has_string_value();

        if !is_string {
            let n = data.get_num_components();
            if n > 0 && diff > 0 {
                let data2 = data.get_primitive_at(diff as i32);
                let data2_ref: &dyn Data = data2.as_deref().unwrap_or(data);
                let dat_offset = address.subtract(&data2_ref.get_min_address());
                return Some(if dat_offset == 0 {
                    data2_ref.get_path_name()
                } else {
                    format!(
                        "{}{}{}",
                        data2_ref.get_path_name(),
                        PLUS,
                        self.get_diff_string(dat_offset)
                    )
                });
            }
        }

        // Segmented-address normalization is not ported (see module docs); use the address as given.
        if diff != 0 {
            return self.generate_offcut_data_name(data, address, diff as i32, ref_level, is_string);
        }

        if let Some(prefix) = data.get_default_label_prefix(&DEFAULT_DISPLAY_OPTIONS) {
            return Some(format!("{}{}{}", prefix, UNDERSCORE, self.get_address_string(address)));
        }

        self.get_dynamic_name(ref_level.max(0) as usize, Some(address))
    }

    /// Port of the private `SymbolUtilities.generateOffcutDataName(Data, Address, int, int,
    /// boolean)`. See module docs for the `getDefaultOffcutLabelPrefix` simplification.
    fn generate_offcut_data_name(
        &self,
        data: &dyn Data,
        address: &Address,
        offcut_offset: i32,
        ref_level: i8,
        _is_string: bool,
    ) -> Option<String> {
        let prefix = data.get_data_type().get_default_label_prefix();

        let offcut_text = format!("{}{}", PLUS, self.get_diff_string(offcut_offset as i64));
        if let Some(symbol) = data.get_primary_symbol() {
            if !symbol.is_dynamic() {
                return Some(format!("{}{}", symbol.get_name(), offcut_text));
            }
        }

        let min_address = address.add(-(offcut_offset as i64)).ok()?;
        if let Some(prefix) = prefix {
            return Some(format!(
                "{}{}{}{}",
                prefix,
                UNDERSCORE,
                self.get_address_string(&min_address),
                offcut_text
            ));
        }

        Some(format!(
            "{}{}",
            self.get_dynamic_name(ref_level.max(0) as usize, Some(&min_address))?,
            offcut_text
        ))
    }

    /// Port of the private `SymbolUtilities.getDynamicInstructionName(Program, Instruction,
    /// Address, int)`. Takes `code_unit` directly rather than an `Instruction`; see module docs.
    fn get_dynamic_instruction_name(
        &self,
        program: &mut dyn Program,
        code_unit: &dyn CodeUnit,
        address: &Address,
        ref_level: i8,
    ) -> Option<String> {
        let code_unit_address = code_unit.get_min_address();
        let diff = address.subtract(&code_unit_address);
        if diff != 0 {
            return self.get_dynamic_offcut_instruction_name(code_unit, &code_unit_address, diff);
        }

        let function = program
            .get_listing()
            .and_then(|listing| listing.get_function_at(&code_unit_address));
        if function.is_some() {
            return Some(format!(
                "{}{}",
                DEFAULT_FUNCTION_PREFIX,
                self.get_address_string(&code_unit_address)
            ));
        }

        if ref_level as usize == SUB_LEVEL {
            return Some(format!(
                "{}{}",
                DEFAULT_SUBROUTINE_PREFIX,
                self.get_address_string(&code_unit_address)
            ));
        }
        if ref_level as usize == EXT_LEVEL {
            return Some(format!(
                "{}{}",
                DEFAULT_EXTERNAL_ENTRY_PREFIX,
                self.get_address_string(&code_unit_address)
            ));
        }

        Some(format!(
            "{}{}",
            DEFAULT_SYMBOL_PREFIX,
            self.get_address_string(&code_unit_address)
        ))
    }

    /// Port of the private `SymbolUtilities.getDyanmicOffcutInstructionName(Instruction, Address,
    /// long)`. Takes `code_unit` directly rather than an `Instruction`; see module docs.
    fn get_dynamic_offcut_instruction_name(
        &self,
        code_unit: &dyn CodeUnit,
        code_unit_address: &Address,
        diff: i64,
    ) -> Option<String> {
        let offcut_text = format!("{}{}", PLUS, self.get_diff_string(diff));
        if let Some(symbol) = code_unit.get_primary_symbol() {
            if !symbol.is_dynamic() {
                return Some(format!("{}{}", symbol.get_name(), offcut_text));
            }
        }
        Some(format!(
            "{}{}{}",
            DEFAULT_SYMBOL_PREFIX,
            self.get_address_string(code_unit_address),
            offcut_text
        ))
    }

    /// Formats an offcut difference the same way as Java SymbolUtilities.
    fn get_diff_string(&self, diff: i64) -> String {
        if diff < 10 {
            diff.to_string()
        } else {
            format!("0x{:x}", diff)
        }
    }

    /// Parses a dynamic name into an address using the supplied address factory.
    fn parse_dynamic_name(&self, factory: &dyn AddressFactory, name: &str) -> Option<Address> {
        if name.starts_with(UNDERSCORE) {
            return None;
        }

        let pieces: Vec<&str> = name.split(UNDERSCORE).collect();
        if pieces.len() < 2 {
            return None;
        }

        let address_offset_string = pieces[pieces.len() - 1];
        if address_offset_string.len() < MIN_LABEL_ADDRESS_DIGITS {
            return None;
        }

        let space = find_address_space(factory, &pieces)?;
        space.parse_address(address_offset_string, true).ok().flatten()
    }

    /// Returns the Ghidra dynamic-label address string for an address.
    fn get_address_string(&self, addr: &Address) -> String {
        addr.to_string().replace(':', "_")
    }

    /// Generates a default parameter name for an ordinal. Stands in for
    /// `SymbolUtilities.getDefaultParamName(int)`.
    fn get_default_param_name(&self, ordinal: i32) -> String {
        format!("{}{}", DEFAULT_PARAM_PREFIX, ordinal + 1)
    }

    /// Returns true if the name is a possible default parameter name. Stands in for
    /// `SymbolUtilities.isDefaultParameterName(String)`.
    fn is_default_parameter_name(&self, name: Option<&str>) -> bool {
        let Some(name) = name else {
            return true;
        };
        if name.is_empty() {
            return true;
        }
        match name.strip_prefix(DEFAULT_PARAM_PREFIX) {
            Some(tail) => tail.parse::<i32>().is_ok(),
            None => false,
        }
    }

    /// Generates a default local variable name for a stack-relative offset. Stands in for
    /// `SymbolUtilities.getDefaultLocalName(Program, int, int)`.
    fn get_default_local_name_for_stack(&self, program: &dyn Program, stack_offset: i32, first_use_offset: i32) -> String {
        let stack_grows_negative = program
            .get_compiler_spec()
            .map(|spec| spec.stack_grows_negative())
            .unwrap_or(false);
        let reserved_area = if stack_grows_negative { stack_offset >= 0 } else { stack_offset < 0 };
        let stack_offset = stack_offset.wrapping_abs();

        let mut name = if reserved_area { DEFAULT_LOCAL_RESERVED_PREFIX } else { DEFAULT_LOCAL_PREFIX }.to_string();
        name.push_str(&format!("{:x}", stack_offset));
        if first_use_offset != 0 {
            name.push('_');
            name.push_str(&first_use_offset.to_string());
        }
        name
    }

    /// Generates a default local variable name for the given storage. Stands in for
    /// `SymbolUtilities.getDefaultLocalName(Program, VariableStorage, int)`.
    fn get_default_local_name(&self, program: &dyn Program, storage: &dyn VariableStorage, first_use_offset: i32) -> String {
        if storage.is_hash_storage() {
            let mut name = DEFAULT_LOCAL_TEMP_PREFIX.to_string();
            let hash = storage.get_first_varnode().map(|vn| vn.get_offset()).unwrap_or(0);
            if hash != 0 {
                name.push_str(&format!("{:x}", hash));
            } else {
                name.push('_');
                name.push_str(&first_use_offset.to_string());
            }
            return name;
        }

        if storage.is_stack_storage() {
            return self.get_default_local_name_for_stack(program, storage.get_stack_offset(), first_use_offset);
        }

        let mut buffy = DEFAULT_LOCAL_PREFIX.to_string();
        for (i, v) in storage.get_varnodes().iter().enumerate() {
            if i > 0 {
                buffy.push('_');
            }
            let addr = v.get_address();
            if addr.is_stack_address() {
                let abs_stack_offset = (v.get_offset() as i32).wrapping_abs();
                buffy.push_str(&format!("{:x}", abs_stack_offset));
            } else if let Some(reg) = program.get_register_at(addr) {
                buffy.push_str(reg.borrow().name());
            } else {
                buffy.push_str(&get_variable_address_string(addr));
            }
        }
        if first_use_offset != 0 {
            buffy.push('_');
            buffy.push_str(&first_use_offset.to_string());
        }
        buffy
    }

    /// Returns true if the given name is the default local name for the given storage. Stands in
    /// for `SymbolUtilities.isDefaultLocalName(Program, String, VariableStorage)`.
    ///
    /// `storage == VariableStorage.BAD_STORAGE` has no port (no such singleton exists); an
    /// invalid ([`VariableStorage::is_valid`] false) storage is treated as "not default" instead.
    fn is_default_local_name(&self, program: &dyn Program, name: Option<&str>, storage: &dyn VariableStorage) -> bool {
        let Some(name) = name else {
            return true;
        };
        if name.is_empty() {
            return true;
        }
        if !storage.is_valid() {
            return false;
        }
        if storage.is_stack_storage() {
            return self.is_default_local_stack_name(Some(name));
        }
        let default_name = self.get_default_local_name(program, storage, 0);
        name.starts_with(&default_name)
    }

    /// Returns true if the name is a possible default parameter or local variable name. Stands in
    /// for `SymbolUtilities.isPossibleDefaultLocalOrParamName(String)`.
    fn is_possible_default_local_or_param_name(&self, name: &str) -> bool {
        if self.is_default_parameter_name(Some(name)) {
            return true;
        }
        name.starts_with(DEFAULT_LOCAL_PREFIX)
    }

    /// Returns true if the name could be a default external location name. Stands in for
    /// `SymbolUtilities.isPossibleDefaultExternalName(String)`.
    fn is_possible_default_external_name(&self, name: &str) -> bool {
        name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX)
    }

    /// Returns true if the name is a default local stack variable name. Stands in for
    /// `SymbolUtilities.isDefaultLocalStackName(String)`.
    fn is_default_local_stack_name(&self, name: Option<&str>) -> bool {
        let Some(name) = name else {
            return true;
        };
        if name.is_empty() {
            return true;
        }
        if let Some(tail) = name.strip_prefix(DEFAULT_LOCAL_PREFIX) {
            let tail = remove_first_use_offset(tail);
            return i32::from_str_radix(tail, 16).is_ok();
        }
        if let Some(tail) = name.strip_prefix(DEFAULT_LOCAL_RESERVED_PREFIX) {
            let tail = remove_first_use_offset(tail);
            return i32::from_str_radix(tail, 16).is_ok();
        }
        false
    }

    /// Appends an address to a base name using Ghidra's standard `@`-separated naming convention.
    /// Stands in for `SymbolUtilities.getAddressAppendedName(String, Address)`.
    fn get_address_appended_name(&self, name: &str, addr: &Address) -> String {
        address_appended_name_with_sep(name, addr, "@", self)
    }

    /// Gets the base symbol name regardless of whether an address has been appended, using either
    /// the standard `@` separator or the less-preferred `_` separator. Stands in for
    /// `SymbolUtilities.getCleanSymbolName(String, Address)`.
    fn get_clean_symbol_name(&self, symbol_name: &str, address: &Address) -> String {
        let index_of_at = symbol_name.rfind('@');
        let index_of_underscore = symbol_name.rfind('_');

        let at_found = index_of_at.map(|i| i >= 1).unwrap_or(false);
        let underscore_found = index_of_underscore.map(|i| i >= 1).unwrap_or(false);
        if !at_found && !underscore_found {
            return symbol_name.to_string();
        }

        let use_at = match (index_of_at, index_of_underscore) {
            (Some(a), Some(u)) => a > u,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => false,
        };

        if use_at {
            let i = index_of_at.expect("use_at implies index_of_at is Some");
            let potential_base_name = &symbol_name[..i];
            if symbol_name == address_appended_name_with_sep(potential_base_name, address, "@", self) {
                return potential_base_name.to_string();
            }
            return symbol_name.to_string();
        }

        let i = index_of_underscore.expect("!use_at implies index_of_underscore is Some");
        let potential_base_name = &symbol_name[..i];
        if symbol_name == address_appended_name_with_sep(potential_base_name, address, "_", self) {
            return potential_base_name.to_string();
        }
        symbol_name.to_string()
    }

    /// Gets the base symbol name regardless of whether an address has been appended. Stands in
    /// for `SymbolUtilities.getCleanSymbolName(Symbol)`.
    fn get_clean_symbol_name_of(&self, symbol: &dyn Symbol) -> String {
        self.get_clean_symbol_name(symbol.get_name(), &symbol.get_address())
    }

    /// Returns display text suitable for describing in the GUI the [`SymbolType`] of the given
    /// symbol. Stands in for `SymbolUtilities.getSymbolTypeDisplayName(Symbol)`; `program` is
    /// taken explicitly (see module docs) in place of `symbol.getProgram()`.
    fn get_symbol_type_display_name(&self, program: &mut dyn Program, symbol: &dyn Symbol) -> Option<String> {
        let sym_type = symbol.get_symbol_type();
        if sym_type == SymbolType::Label {
            if symbol.is_external() {
                return Some("External Data".to_string());
            }
            if !symbol.is_primary() {
                let primary = program
                    .get_symbol_table()
                    .and_then(|table| table.get_primary_symbol(&symbol.get_address()).ok().flatten());
                if let Some(primary) = primary {
                    if primary.get_symbol_type() == SymbolType::Function {
                        return Some("Function".to_string());
                    }
                }
            }
            let code_unit = program
                .get_listing()
                .and_then(|listing| listing.get_code_unit_at(&symbol.get_address()));
            if let Some(code_unit) = code_unit {
                return Some(if code_unit.as_data().is_some() {
                    "Data Label".to_string()
                } else {
                    "Instruction Label".to_string()
                });
            }
        } else if sym_type == SymbolType::Function {
            if symbol.is_external() {
                return Some("External Function".to_string());
            }
            let function = symbol.as_function()?;
            return Some(if function.is_thunk() { "Thunk Function".to_string() } else { "Function".to_string() });
        }
        if symbol.is_external() {
            return Some(format!("External {}", sym_type.display_name()));
        }
        Some(sym_type.display_name().to_string())
    }

    /// Returns the global symbol with the given name if and only if it is the only global symbol
    /// with that name. Stands in for `SymbolUtilities.getUniqueSymbol(Program, String)`.
    fn get_unique_symbol(&self, program: &mut dyn Program, name: &str) -> Option<Arc<dyn Symbol>> {
        self.get_unique_symbol_in_namespace(program, name, None)
    }

    /// Returns the symbol in the given namespace with the given name if and only if it is the
    /// only symbol in that namespace with that name. Stands in for
    /// `SymbolUtilities.getUniqueSymbol(Program, String, Namespace)`.
    fn get_unique_symbol_in_namespace(
        &self,
        program: &mut dyn Program,
        name: &str,
        namespace: Option<&dyn Namespace>,
    ) -> Option<Arc<dyn Symbol>> {
        let global_namespace = program.get_global_namespace();
        let symbol_table = program.get_symbol_table()?;
        let namespace = match namespace {
            Some(namespace) => namespace,
            None => global_namespace.as_deref()?,
        };
        let symbols = symbol_table.get_symbols_by_name_namespace(name, namespace).ok()?;
        if symbols.len() == 1 {
            symbols.into_iter().next()
        } else {
            None
        }
    }

    /// Returns the unique global label or function symbol with the given name, reporting via
    /// `error_consumer` when zero or more than one symbol is found. Stands in for
    /// `SymbolUtilities.getExpectedLabelOrFunctionSymbol(Program, String, Consumer<String>)`.
    fn get_expected_label_or_function_symbol(
        &self,
        program: &mut dyn Program,
        symbol_name: &str,
        error_consumer: &mut dyn FnMut(String),
    ) -> Option<Arc<dyn Symbol>> {
        let symbols = program
            .get_symbol_table()
            .and_then(|table| table.get_label_or_function_symbols(symbol_name).ok())
            .unwrap_or_default();
        if symbols.len() == 1 {
            return symbols.into_iter().next();
        }
        if symbols.is_empty() {
            error_consumer(format!("{} symbol not found!", symbol_name));
        } else {
            error_consumer(format!("Multiple {} symbols found!", symbol_name));
        }
        None
    }

    /// Returns the unique global label or function symbol with the given name, reporting via
    /// `error_consumer` only when more than one symbol is found. Stands in for
    /// `SymbolUtilities.getLabelOrFunctionSymbol(Program, String, Consumer<String>)`.
    fn get_label_or_function_symbol(
        &self,
        program: &mut dyn Program,
        symbol_name: &str,
        error_consumer: &mut dyn FnMut(String),
    ) -> Option<Arc<dyn Symbol>> {
        let symbols = program
            .get_symbol_table()
            .and_then(|table| table.get_label_or_function_symbols(symbol_name).ok())
            .unwrap_or_default();
        if symbols.len() == 1 {
            return symbols.into_iter().next();
        }
        if symbols.len() > 1 {
            error_consumer(format!("Multiple {} symbols found!", symbol_name));
        }
        None
    }

    /// Create a label symbol giving preference to non-global symbols. Stands in for
    /// `SymbolUtilities.createPreferredLabelOrFunctionSymbol`. See module docs for the
    /// namespace-handling simplifications this port makes.
    fn create_preferred_label_or_function_symbol(
        &self,
        program: &mut dyn Program,
        address: &Address,
        namespace: Option<Arc<dyn Namespace>>,
        name: &str,
        source: SourceType,
    ) -> Result<Option<Arc<dyn Symbol>>, InvalidInputException> {
        if !address.is_memory_address() {
            return Err(InvalidInputException::with_message("expected memory address"));
        }

        let global_namespace = program.get_global_namespace();
        let namespace = namespace.or(global_namespace);
        let Some(namespace) = namespace else {
            return Err(InvalidInputException::with_message("no global namespace available"));
        };

        let symbol_table = program
            .get_symbol_table()
            .ok_or_else(|| InvalidInputException::with_message("no symbol table available"))?;

        if let Ok(Some(symbol)) = symbol_table.find_symbol_by_name_address_namespace(name, address, namespace.as_ref()) {
            return Ok(Some(symbol));
        }

        if namespace.is_global() {
            let existing = symbol_table.get_symbols(address).unwrap_or_default();
            if existing.iter().any(|s| s.get_name() == name) {
                return Ok(None);
            }
        } else if let Ok(Some(mut symbol)) = symbol_table.get_global_symbol(name, address) {
            if let Some(symbol_mut) = Arc::get_mut(&mut symbol) {
                let _ = symbol_mut.set_namespace(namespace.clone());
            }
            return Ok(Some(symbol));
        }

        symbol_table
            .create_label(address, name, source)
            .map(Some)
            .map_err(|_| InvalidInputException::with_message(format!("unable to create symbol '{}'", name)))
    }

    /// Compares two symbols by name, case-insensitively. Stands in for the `Comparator<Symbol>`
    /// returned by `SymbolUtilities.getSymbolNameComparator()`.
    fn compare_symbol_names(&self, a: &dyn Symbol, b: &dyn Symbol) -> Ordering {
        a.get_name().to_lowercase().cmp(&b.get_name().to_lowercase())
    }
}

/// Zero-sized default implementor of [`SymbolUtilities`], using every method's default body.
/// Mirrors `DefaultSimpleDiffUtility`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultSymbolUtilities;

impl SymbolUtilities for DefaultSymbolUtilities {}

fn find_dynamic_prefix(name: &str) -> Option<&'static str> {
    DYNAMIC_PREFIX_ARRAY.iter().copied().find(|prefix| name.starts_with(prefix))
}

fn find_address_space(factory: &dyn AddressFactory, pieces: &[&str]) -> Option<Arc<AddressSpace>> {
    if pieces.len() > 2 {
        let mut start = 1;
        let mut end = pieces.len() - 2;
        if pieces[end].is_empty() {
            if end == 0 {
                return factory.get_default_address_space();
            }
            end -= 1;
        }

        while start <= end {
            let space_name = pieces[start..=end].join(UNDERSCORE);
            if let Some(space) = factory.get_address_space_by_name(&space_name) {
                return Some(space);
            }
            start += 1;
        }
    }
    factory.get_default_address_space()
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn get_variable_address_string(addr: &Address) -> String {
    format!("{}{:x}", addr.space().name(), addr.offset())
}

fn remove_first_use_offset(str: &str) -> &str {
    let Some(index) = str.rfind('_') else {
        return str;
    };
    if str[index + 1..].parse::<i32>().is_ok() {
        &str[..index]
    } else {
        str
    }
}

fn address_appended_name_with_sep(name: &str, addr: &Address, sep: &str, utils: &(impl SymbolUtilities + ?Sized)) -> String {
    format!("{}{}{}", name, sep, utils.get_address_string(addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::listing::function::DEFAULT_LOCAL_PREFIX;
    use crate::program::model::symbol::SourceType;
    use crate::program::seam_stubs::VarnodeListStorage;
    use std::io;

    const SU: DefaultSymbolUtilities = DefaultSymbolUtilities;

    fn fixture() -> (Arc<AddressSpace>, DefaultAddressFactory) {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let code = AddressSpace::new("program_mem", 32, 1, AddressSpaceType::Code, 2);
        let factory = DefaultAddressFactory::with_default_space(vec![ram.clone(), code], Some(ram.clone()));
        (ram, factory)
    }

    #[test]
    fn ordinal_names_parse_like_java() {
        assert_eq!(SU.get_ordinal_value(Some("Ordinal_7")), 7);
        assert_eq!(SU.get_ordinal_value(Some("Ordinal_-1")), -1);
        assert_eq!(SU.get_ordinal_value(Some("Ordinal_bad")), -1);
        assert_eq!(SU.get_ordinal_value(Some("Name_7")), -1);
        assert_eq!(SU.get_ordinal_value(None), -1);
    }

    #[test]
    fn invalid_character_checks_match_java_rules() {
        assert!(SU.is_invalid_char(' '));
        assert!(SU.is_invalid_char('\n'));
        assert!(!SU.is_invalid_char(':'));
        assert!(SU.contains_invalid_chars("bad name"));
        assert_eq!(SU.replace_invalid_chars(Some("bad name\n"), true), Some("bad_name_".to_string()));
        assert_eq!(SU.replace_invalid_chars(Some("bad name\n"), false), Some("badname".to_string()));
        assert_eq!(SU.replace_invalid_chars(None, true), None);
    }

    #[test]
    fn name_validation_rejects_java_invalid_inputs() {
        assert!(SU.validate_name(Some("valid_name")).is_ok());
        assert!(SU.validate_name(None).unwrap_err().to_string().contains("can't be null"));
        assert!(SU.validate_name(Some("")).unwrap_err().to_string().contains("empty"));
        assert!(SU.validate_name(Some("bad name")).unwrap_err().to_string().contains("invalid"));

        let long_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH + 1);
        assert!(SU.validate_name(Some(&long_name)).unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn default_names_use_address_strings() {
        let (ram, _) = fixture();
        let addr = ram.address(0x1234);

        assert_eq!(SU.get_address_string(&addr), "ram_0x1234");
        assert_eq!(SU.get_default_function_name(&addr), "FUN_ram_0x1234");
        assert_eq!(SU.get_default_external_function_name(&addr), "EXT_FUN_ram_0x1234");
        assert_eq!(SU.get_default_external_name(&addr, None), "EXT_ram_0x1234");
        assert_eq!(SU.get_default_external_name(&addr, Some("char")), "EXT_char_ram_0x1234");
        assert_eq!(SU.get_dynamic_offcut_name(Some(&addr)), Some("OFF_ram_0x1234".to_string()));
        assert_eq!(SU.get_dynamic_offcut_name(None), None);
        assert_eq!(SU.get_dynamic_name(FUN_LEVEL, Some(&addr)), Some("FUN_ram_0x1234".to_string()));
        assert_eq!(SU.get_dynamic_name(99, Some(&addr)), None);
        assert_eq!(SU.get_address_appended_name("base", &addr), "base@ram_0x1234");
    }

    #[test]
    fn dynamic_pattern_detection_matches_default_prefix_and_suffix_rules() {
        assert!(SU.starts_with_default_dynamic_prefix("FUN_ram_0x1234"));
        assert!(!SU.starts_with_default_dynamic_prefix("custom_1234"));
        assert!(SU.is_dynamic_symbol_pattern("FUN_ram_0x1234", true));
        assert!(!SU.is_dynamic_symbol_pattern("fun_ram_0x1234", true));
        assert!(SU.is_dynamic_symbol_pattern("fun_ram_0x1234", false));
        assert!(SU.is_dynamic_symbol_pattern("custom_abc", true));
        assert!(!SU.is_dynamic_symbol_pattern("custom_ab", true));
        assert!(!SU.is_dynamic_symbol_pattern("custom_nothex", true));
    }

    #[test]
    fn dynamic_names_parse_addresses_with_space_names() {
        let (ram, factory) = fixture();
        assert_eq!(SU.parse_dynamic_name(&factory, "FUN_ram_0x1234"), Some(ram.address(0x1234)));
        assert_eq!(
            SU.parse_dynamic_name(&factory, "LAB_program_mem_0x20"),
            Some(factory.get_address_space_by_name("program_mem").unwrap().address(0x20))
        );
        assert_eq!(SU.parse_dynamic_name(&factory, "_FUN_ram_0x1234"), None);
        assert_eq!(SU.parse_dynamic_name(&factory, "FUN_ram_123"), None);
        assert_eq!(SU.parse_dynamic_name(&factory, "plain"), None);
    }

    #[test]
    fn reserved_dynamic_name_checks_require_parseable_addresses() {
        let (_, factory) = fixture();
        assert!(SU.is_reserved_dynamic_label_name("FUN_ram_0x1234", &factory));
        assert!(SU.is_reserved_external_default_name("EXT_ram_0x1234", &factory));
        assert!(!SU.is_reserved_external_default_name("FUN_ram_0x1234", &factory));
        assert!(!SU.is_reserved_dynamic_label_name("custom_0x1234", &factory));
    }

    #[test]
    fn diff_and_clean_name_helpers_match_java_behavior() {
        let (ram, _) = fixture();
        let addr = ram.address(0x1234);

        assert_eq!(SU.get_diff_string(9), "9");
        assert_eq!(SU.get_diff_string(10), "0xa");
        assert_eq!(SU.get_diff_string(-2), "-2");

        // `addr`'s string form ("ram_0x1234") embeds its own `_`, so an appended name built from
        // it is *not* recognized as clean here -- this matches Java's own algorithm, which also
        // relies on the address string containing no separator characters of its own (true for
        // Ghidra's usual default-space addresses, whose `toString()` omits the space prefix).
        assert_eq!(SU.get_clean_symbol_name("base@ram_0x1234", &addr), "base@ram_0x1234");
        assert_eq!(SU.get_clean_symbol_name("base_ram_0x1234", &addr), "base_ram_0x1234");
        assert_eq!(SU.get_clean_symbol_name("base", &addr), "base");
        assert_eq!(SU.get_clean_symbol_name("unrelated@other", &addr), "unrelated@other");

        // A "special" address (this port's stand-in for Ghidra addresses whose `toString()` is
        // just the space name, with no offset/colon) round-trips cleanly through both separators.
        let no_offset_space = AddressSpace::new("X", 0, 1, AddressSpaceType::None, 9);
        let plain_addr = no_offset_space.address(0);
        assert!(plain_addr.is_special_address());
        assert_eq!(SU.get_address_string(&plain_addr), "X");
        assert_eq!(SU.get_clean_symbol_name("myFunc@X", &plain_addr), "myFunc");
        assert_eq!(SU.get_clean_symbol_name("myVar_X", &plain_addr), "myVar");
    }

    #[test]
    fn param_and_local_name_helpers_match_java_conventions() {
        assert_eq!(SU.get_default_param_name(0), "param_1");
        assert_eq!(SU.get_default_param_name(3), "param_4");
        assert!(SU.is_default_parameter_name(Some("param_1")));
        assert!(!SU.is_default_parameter_name(Some("param_x")));
        assert!(SU.is_default_parameter_name(None));

        assert!(SU.is_possible_default_local_or_param_name("param_1"));
        assert!(SU.is_possible_default_local_or_param_name(&format!("{}10", DEFAULT_LOCAL_PREFIX)));
        assert!(!SU.is_possible_default_local_or_param_name("myVar"));

        assert!(SU.is_possible_default_external_name("EXT_ram_0x1234"));
        assert!(!SU.is_possible_default_external_name("FUN_ram_0x1234"));

        assert!(SU.is_default_local_stack_name(Some(&format!("{}1c", DEFAULT_LOCAL_PREFIX))));
        assert!(SU.is_default_local_stack_name(Some(&format!("{}1c_4", DEFAULT_LOCAL_PREFIX))));
        assert!(!SU.is_default_local_stack_name(Some("myVar")));
        assert!(SU.is_default_local_stack_name(None));
    }

    struct MockProgram {
        factory: Option<Arc<dyn AddressFactory>>,
        global_namespace: Option<Arc<dyn Namespace>>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.factory.clone()
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.global_namespace.clone()
        }
    }

    #[test]
    fn get_default_local_name_covers_hash_stack_and_register_storage() {
        let (ram, _) = fixture();
        let program = MockProgram { factory: None, global_namespace: None };

        // [`crate::program::seam_stubs::HashVariableStorage`] does not expose its hash via
        // `get_first_varnode` (it has no varnode representation), so a local storage backed by a
        // real varnode is used here to exercise the hash-offset formatting path.
        struct HashStorageWithVarnode(crate::program::model::pcode::Varnode);
        impl VariableStorage for HashStorageWithVarnode {
            fn is_hash_storage(&self) -> bool {
                true
            }
            fn get_first_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
                Some(self.0.clone())
            }
        }
        let unique_space = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 4);
        let hash_storage = HashStorageWithVarnode(crate::program::model::pcode::Varnode::new(unique_space.address(0x2a), 4));
        assert_eq!(SU.get_default_local_name(&program, &hash_storage, 0), "temp_2a");

        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 3);
        let stack_varnode = crate::program::model::pcode::Varnode::new(stack_space.address(-8i64), 4);
        let stack_storage = VarnodeListStorage(vec![stack_varnode]);
        // No compiler spec available (stack_grows_negative defaults to false) and stack_offset<0
        // => reserved area => "local_res" prefix.
        assert_eq!(SU.get_default_local_name(&program, &stack_storage, 0), "local_res8");

        let non_stack_varnode = crate::program::model::pcode::Varnode::new(ram.address(0x40), 4);
        let non_stack_storage = VarnodeListStorage(vec![non_stack_varnode]);
        assert_eq!(SU.get_default_local_name(&program, &non_stack_storage, 5), "local_ram40_5");
    }

    struct MockSymbol {
        address: Address,
        name: String,
        symbol_type: SymbolType,
        id: i64,
        primary: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockSymbolTable {
        symbols_by_name: Vec<Arc<dyn Symbol>>,
    }

    impl crate::program::model::symbol::SymbolTable for MockSymbolTable {
        fn create_label(&mut self, addr: &Address, name: &str, source: SourceType) -> io::Result<Arc<dyn Symbol>> {
            let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
                address: addr.clone(),
                name: name.to_string(),
                symbol_type: SymbolType::Label,
                id: 42,
                primary: true,
            });
            let _ = source;
            self.symbols_by_name.push(symbol.clone());
            Ok(symbol)
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols_by_name.iter().filter(|s| s.get_address() == *addr).cloned().collect())
        }
        fn get_symbols_by_name_namespace(
            &self,
            name: &str,
            _namespace: &dyn Namespace,
        ) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols_by_name.iter().filter(|s| s.get_name() == name).cloned().collect())
        }
    }

    struct MockGlobalNamespace(Arc<dyn Symbol>);
    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.0.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            crate::program::model::symbol::GLOBAL_NAMESPACE_ID
        }
    }

    struct MockProgramWithSymbolTable {
        global_namespace: Arc<dyn Namespace>,
        symbol_table: MockSymbolTable,
    }

    impl DomainObject for MockProgramWithSymbolTable {}

    impl Program for MockProgramWithSymbolTable {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            Some(self.global_namespace.clone())
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn crate::program::model::symbol::SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    fn mock_program_with_symbol_table() -> MockProgramWithSymbolTable {
        let global_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0),
            name: "Global".to_string(),
            symbol_type: SymbolType::Global,
            id: 0,
            primary: true,
        });
        MockProgramWithSymbolTable {
            global_namespace: Arc::new(MockGlobalNamespace(global_symbol)),
            symbol_table: MockSymbolTable { symbols_by_name: Vec::new() },
        }
    }

    #[test]
    fn get_unique_symbol_requires_exactly_one_match() {
        let mut program = mock_program_with_symbol_table();
        let addr = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0x100);

        assert!(SU.get_unique_symbol(&mut program, "foo").is_none());

        program.symbol_table.symbols_by_name.push(Arc::new(MockSymbol {
            address: addr.clone(),
            name: "foo".to_string(),
            symbol_type: SymbolType::Label,
            id: 1,
            primary: true,
        }));
        assert_eq!(SU.get_unique_symbol(&mut program, "foo").unwrap().get_id(), 1);

        program.symbol_table.symbols_by_name.push(Arc::new(MockSymbol {
            address: addr,
            name: "foo".to_string(),
            symbol_type: SymbolType::Label,
            id: 2,
            primary: true,
        }));
        assert!(SU.get_unique_symbol(&mut program, "foo").is_none());
    }

    #[test]
    fn create_preferred_label_or_function_symbol_reuses_existing_or_creates_new() {
        let mut program = mock_program_with_symbol_table();
        let addr = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0x200);

        let created = SU
            .create_preferred_label_or_function_symbol(&mut program, &addr, None, "LAB_new", SourceType::UserDefined)
            .expect("creation should not error")
            .expect("a symbol should be created");
        assert_eq!(created.get_name(), "LAB_new");

        // A second attempt to create a global symbol with the *same* name at the same address is
        // rejected (mirrors Java returning `null` rather than shadowing the existing symbol).
        let rejected = SU
            .create_preferred_label_or_function_symbol(&mut program, &addr, None, "LAB_new", SourceType::UserDefined)
            .expect("should not error");
        assert!(rejected.is_none());
    }

    #[test]
    fn compare_symbol_names_is_case_insensitive() {
        let a: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0),
            name: "Alpha".to_string(),
            symbol_type: SymbolType::Label,
            id: 1,
            primary: true,
        });
        let b: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0),
            name: "alpha".to_string(),
            symbol_type: SymbolType::Label,
            id: 2,
            primary: true,
        });
        assert_eq!(SU.compare_symbol_names(a.as_ref(), b.as_ref()), Ordering::Equal);

        let c: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(0),
            name: "Beta".to_string(),
            symbol_type: SymbolType::Label,
            id: 3,
            primary: true,
        });
        assert_eq!(SU.compare_symbol_names(a.as_ref(), c.as_ref()), Ordering::Less);
    }
}
