//! Dynamic symbols: the default labels (`LAB_`, `SUB_`, `DAT_`, ...) Java's `SymbolManager`
//! answers for a referenced memory address that has no stored symbol.
//!
//! Java builds a `CodeSymbol` with no record (`SymbolManager.getDynamicSymbol`) whose name is
//! computed on demand by `SymbolUtilities.getDynamicName(Program, Address)` from the program's
//! listing, reference manager and function manager. The symbol manager here does not own the
//! program, so what it needs to know about the rest of the program comes through
//! [`DynamicSymbolSource`], which the program installs
//! ([`SymbolManagerDB::set_dynamic_symbol_source`](super::SymbolManagerDB::set_dynamic_symbol_source)).

use crate::program::model::address::{Address, AddressSpaceType};
use crate::program::model::symbol::symbol_utilities::{
    DefaultSymbolUtilities, SymbolUtilities, DEFAULT_DATA_PREFIX, DEFAULT_EXTERNAL_ENTRY_PREFIX,
    DEFAULT_FUNCTION_PREFIX, DEFAULT_SUBROUTINE_PREFIX, DEFAULT_SYMBOL_PREFIX, DEFAULT_UNKNOWN_PREFIX, EXT_LEVEL,
    SUB_LEVEL, UNK_LEVEL,
};
use crate::program::model::symbol::{SourceType, Symbol, SymbolType, GLOBAL_NAMESPACE_ID};

/// What the symbol manager asks the rest of the program to name and decide dynamic symbols.
pub trait DynamicSymbolSource: Send + Sync {
    /// The highest dynamic-label level of the references to `addr` (Java's
    /// `ReferenceManager.getReferenceLevel`), or `None` when nothing references it (Java's
    /// `hasReferencesTo` is false: no dynamic symbol).
    fn reference_level(&self, addr: &Address) -> Option<i8>;

    /// The start of the instruction containing `addr`, if one does (Java's
    /// `listing.getCodeUnitContaining(addr)` being an `Instruction`). Any other address is
    /// undefined data: the program has no defined data yet.
    fn instruction_containing(&self, addr: &Address) -> Option<Address>;

    /// Whether a function starts at `addr` (`FunctionManager.getFunctionAt(addr) != null`).
    fn is_function_at(&self, addr: &Address) -> bool {
        let _ = addr;
        false
    }

    /// The defined data containing `addr`, described for naming (Java's
    /// `listing.getCodeUnitContaining(addr)` being a defined `Data`); `None` for undefined
    /// data and instructions. The default: the program has no defined data.
    fn defined_data_containing(&self, addr: &Address) -> Option<DynamicDataLabel> {
        let _ = addr;
        None
    }
}

/// What dynamic naming needs to know about a defined data unit: see
/// [`DynamicSymbolSource::defined_data_containing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicDataLabel {
    /// The data's (minimum) address.
    pub start: Address,
    /// How its data type prefixes its label (`Data.getDefaultLabelPrefix`).
    pub prefix: DataLabelPrefix,
    /// The destination of the data's primary memory reference on operand 0, if any.
    pub reference_target: Option<Address>,
}

/// A data type's label prefix, as `getDefaultLabelPrefix(MemBuffer, Settings, int,
/// DataTypeDisplayOptions)` answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataLabelPrefix {
    /// A pointer's prefix depends on what it points to (`PointerDataType.getLabelString`:
    /// `PTR_<target>`), which the symbol manager names.
    Pointer,
    /// Any other type's fixed prefix (`DWORD`, `QWORD`, ...), or `None` for a type without one
    /// (the reference level's prefix is used instead).
    Fixed(Option<String>),
}

/// `PointerDataType.POINTER_LABEL_PREFIX`.
pub const POINTER_LABEL_PREFIX: &str = "PTR";
/// `PointerDataType.POINTER_LOOP_LABEL`.
pub const POINTER_LOOP_LABEL: &str = "PTR_LOOP";

/// Java's `SymbolUtilities.getAddressString(Address)`: `addr.toString()` -- at least 8 hex
/// digits, no `0x`, the space name only for a space that shows it (not RAM) -- with `:` made
/// `_`. ([`SymbolUtilities::get_address_string`] formats with the Rust `Display` form,
/// `ram:0x1234`, which its own parsing relies on; dynamic labels need Java's.)
pub fn label_address_string(addr: &Address) -> String {
    let show_space_name = addr.space().space_type() != AddressSpaceType::Ram;
    addr.format(show_space_name, 8).replace(':', "_")
}

/// Port of `SymbolUtilities.getDynamicName(Program, Address)` over what a
/// [`DynamicSymbolSource`] can answer: `instruction_start` is the start of the instruction
/// containing `addr` (with `start_label` the name of a stored primary symbol there, for an
/// offcut address), anything else is undefined data whose `DEFAULT` data type has no label
/// prefix, so it takes the reference level's prefix.
pub fn dynamic_name(
    addr: &Address,
    ref_level: i8,
    instruction_start: Option<&Address>,
    start_label: Option<&str>,
    is_function: bool,
) -> String {
    let utils = DefaultSymbolUtilities;
    let Some(start) = instruction_start else {
        let level = if ref_level < 0 { UNK_LEVEL } else { ref_level as usize };
        return format!("{}{}", DYNAMIC_PREFIXES.get(level).copied().unwrap_or(DEFAULT_UNKNOWN_PREFIX), label_address_string(addr));
    };
    let diff = addr.subtract(start);
    if diff != 0 {
        // getDyanmicOffcutInstructionName
        let offcut = format!("+{}", utils.get_diff_string(diff));
        return match start_label {
            Some(label) => format!("{label}{offcut}"),
            None => format!("{DEFAULT_SYMBOL_PREFIX}{}{offcut}", label_address_string(start)),
        };
    }
    let prefix = if is_function {
        DEFAULT_FUNCTION_PREFIX
    } else if ref_level as usize == SUB_LEVEL {
        DEFAULT_SUBROUTINE_PREFIX
    } else if ref_level as usize == EXT_LEVEL {
        DEFAULT_EXTERNAL_ENTRY_PREFIX
    } else {
        DEFAULT_SYMBOL_PREFIX
    };
    format!("{prefix}{}", label_address_string(start))
}

/// `SymbolUtilities.DYNAMIC_PREFIX_ARRAY`, indexed by reference level.
const DYNAMIC_PREFIXES: [&str; 7] = [
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_DATA_PREFIX,
    DEFAULT_SYMBOL_PREFIX,
    DEFAULT_SUBROUTINE_PREFIX,
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_EXTERNAL_ENTRY_PREFIX,
    DEFAULT_FUNCTION_PREFIX,
];

/// A dynamic symbol: Java's record-less `CodeSymbol`. A primary, default-sourced label in the
/// global namespace whose [`is_dynamic`](Symbol::is_dynamic) is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicSymbol {
    id: i64,
    name: String,
    address: Address,
}

impl DynamicSymbol {
    /// The dynamic symbol `name` at `address`; `id` is its dynamic symbol ID (Java's
    /// `getDynamicSymbolID`, high bit set so it cannot collide with a stored symbol's).
    pub fn new(id: i64, name: String, address: Address) -> Self {
        DynamicSymbol { id, name, address }
    }
}

impl Symbol for DynamicSymbol {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Label
    }

    fn get_source(&self) -> SourceType {
        SourceType::Default
    }

    fn is_primary(&self) -> bool {
        true
    }

    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_parent_id(&self) -> i64 {
        GLOBAL_NAMESPACE_ID
    }

    fn is_dynamic(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::symbol_utilities::{DAT_LEVEL, LAB_LEVEL};

    fn addr(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1), offset)
    }

    #[test]
    fn undefined_data_takes_the_reference_levels_prefix() {
        assert_eq!(dynamic_name(&addr(0x103fd8), DAT_LEVEL as i8, None, None, false), "DAT_00103fd8");
        assert_eq!(dynamic_name(&addr(0x103fd8), UNK_LEVEL as i8, None, None, false), "UNK_00103fd8");
        assert_eq!(dynamic_name(&addr(0x103fd8), SUB_LEVEL as i8, None, None, false), "SUB_00103fd8");
    }

    #[test]
    fn an_instruction_start_is_a_label_subroutine_or_function() {
        let a = addr(0x101234);
        assert_eq!(dynamic_name(&a, LAB_LEVEL as i8, Some(&a), None, false), "LAB_00101234");
        assert_eq!(dynamic_name(&a, DAT_LEVEL as i8, Some(&a), None, false), "LAB_00101234");
        assert_eq!(dynamic_name(&a, SUB_LEVEL as i8, Some(&a), None, false), "SUB_00101234");
        assert_eq!(dynamic_name(&a, EXT_LEVEL as i8, Some(&a), None, false), "EXT_00101234");
        assert_eq!(dynamic_name(&a, SUB_LEVEL as i8, Some(&a), None, true), "FUN_00101234");
    }

    #[test]
    fn an_offcut_instruction_address_is_relative_to_the_instructions_label() {
        let start = addr(0x101230);
        assert_eq!(dynamic_name(&addr(0x101232), LAB_LEVEL as i8, Some(&start), None, false), "LAB_00101230+2");
        assert_eq!(dynamic_name(&addr(0x101240), LAB_LEVEL as i8, Some(&start), Some("main"), false), "main+0x10");
    }

    #[test]
    fn a_dynamic_symbol_is_a_dynamic_global_primary_label() {
        let symbol = DynamicSymbol::new(i64::MIN | 7, "LAB_00101234".into(), addr(0x101234));
        assert!(symbol.is_dynamic() && symbol.is_primary() && symbol.is_global());
        assert_eq!((symbol.get_symbol_type(), symbol.get_source()), (SymbolType::Label, SourceType::Default));
    }
}
