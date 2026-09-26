//! Port of `ghidra.program.model.lang.AddressLabelInfo`.
//!
//! A utility value type pairing an [`Address`] with a corresponding language-defined label or
//! alias, within the global namespace established with a `SourceType` of `IMPORTED` within a
//! program.
//!
//! A same-named placeholder already exists at
//! [`crate::program::seam_stubs::AddressLabelInfo`] -- a bare marker trait (`pub trait
//! AddressLabelInfo {}`) used opaquely as `Vec<Box<dyn AddressLabelInfo>>` by
//! [`Language::get_default_symbols`](crate::program::model::lang::language::Language::get_default_symbols),
//! before this real class was ported. That trait and this concrete struct are independent types;
//! rewiring `Language::get_default_symbols`'s return type to `Vec<AddressLabelInfo>` (this real
//! struct) is out of scope for this port (it would ripple through every `Language`
//! implementor/mock in the crate).

use std::fmt;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
use crate::program::util::processor_symbol_type::ProcessorSymbolType;
use crate::util::exception::InvalidInputException;

/// Error produced by [`AddressLabelInfo::new`], which can fail either while validating the label
/// name or while computing the end address.
///
/// Java declares `throws AddressOverflowException, InvalidInputException` on the constructor;
/// this crate models both as ordinary `Result` errors, so construction needs a type that can
/// represent both (mirroring the precedent set by `PcodeInjectLibraryError` in
/// `pcode_inject_library.rs`).
#[derive(Debug)]
pub enum AddressLabelInfoError {
    /// `addr + (size_in_bytes - 1)` overflowed the address space.
    AddressOverflow(AddressOverflowException),
    /// `label` is not a valid symbol name.
    InvalidInput(InvalidInputException),
}

impl fmt::Display for AddressLabelInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressOverflow(e) => write!(f, "{e}"),
            Self::InvalidInput(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AddressLabelInfoError {}

impl From<AddressOverflowException> for AddressLabelInfoError {
    fn from(e: AddressOverflowException) -> Self {
        Self::AddressOverflow(e)
    }
}

impl From<InvalidInputException> for AddressLabelInfoError {
    fn from(e: InvalidInputException) -> Self {
        Self::InvalidInput(e)
    }
}

/// A utility value type storing an [`Address`] together with a corresponding language-defined
/// label or alias that is within the global namespace which is established with a `SourceType`
/// of `IMPORTED` within a program.
///
/// Port of `ghidra.program.model.lang.AddressLabelInfo`.
#[derive(Debug, Clone)]
pub struct AddressLabelInfo {
    addr: Address,
    end_addr: Address,
    label: String,
    description: Option<String>,
    is_primary: bool,
    is_entry: bool,
    processor_symbol_type: Option<ProcessorSymbolType>,
    size_in_bytes: i32,
    is_volatile: Option<bool>,
}

impl AddressLabelInfo {
    /// Constructs an `AddressLabelInfo`.
    ///
    /// `size_in_bytes` of `None` or `<= 0` defaults to the addressable unit size of `addr`'s
    /// address space (Java: "Default size in addressable units").
    ///
    /// Port of `AddressLabelInfo(Address, Integer, String, String, boolean, boolean,
    /// ProcessorSymbolType, Boolean)`.
    ///
    /// # Errors
    /// Returns [`AddressLabelInfoError::AddressOverflow`] if `size_in_bytes` causes an overflow
    /// relative to `addr`, or [`AddressLabelInfoError::InvalidInput`] if `label` is not a valid
    /// symbol name.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: Address,
        size_in_bytes: Option<i32>,
        label: impl Into<String>,
        description: Option<String>,
        is_primary: bool,
        is_entry: bool,
        processor_symbol_type: Option<ProcessorSymbolType>,
        is_volatile: Option<bool>,
    ) -> Result<Self, AddressLabelInfoError> {
        let label = label.into();
        DefaultSymbolUtilities.validate_name(Some(&label))?;

        let size_in_bytes = match size_in_bytes {
            Some(size) if size > 0 => size,
            _ => addr.space().unit_size(),
        };
        let end_addr = addr.add_no_wrap((size_in_bytes - 1) as i64)?;

        Ok(Self {
            addr,
            end_addr,
            label,
            description,
            is_primary,
            is_entry,
            processor_symbol_type,
            size_in_bytes,
            is_volatile,
        })
    }

    /// Returns this object's address.
    pub fn get_address(&self) -> &Address {
        &self.addr
    }

    /// Returns this object's end address.
    pub fn get_end_address(&self) -> &Address {
        &self.end_addr
    }

    /// Returns this object's label or alias.
    pub fn get_label(&self) -> &str {
        &self.label
    }

    /// Returns this object's description, if it has one.
    pub fn get_description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns this object's size in bytes. Always a non-zero positive value; defaults to the
    /// addressable unit size of the associated address space.
    pub fn get_byte_size(&self) -> i32 {
        self.size_in_bytes
    }

    /// Returns whether this object is the primary label at the address.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Returns whether this object is volatile: `Some(false)` when the address is explicitly not
    /// volatile, `Some(true)` when the address is volatile, `None` when volatility is not
    /// defined at this address.
    pub fn is_volatile(&self) -> Option<bool> {
        self.is_volatile
    }

    /// Returns the type of processor symbol (if this was defined by a pspec) or `None` if this
    /// is not a processor symbol or it was not specified in the pspec file.
    pub fn get_processor_symbol_type(&self) -> Option<ProcessorSymbolType> {
        self.processor_symbol_type
    }

    /// Returns whether this object is an entry label for its address.
    pub fn is_entry(&self) -> bool {
        self.is_entry
    }
}

impl fmt::Display for AddressLabelInfo {
    /// Port of `AddressLabelInfo.toString()`.
    ///
    /// Faithfully reproduces a real Java quirk: when `description` is present, it is appended
    /// with **no** preceding separator (the `", "` that separates every other field is missing
    /// before `description`), so the rendered string reads e.g.
    /// `"...type = CODEdescription = a comment"` with `CODE` and `description` glued together.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Java's string concatenation renders a null enum reference as the literal "null".
        let type_str = match self.processor_symbol_type {
            Some(ProcessorSymbolType::Code) => "CODE",
            Some(ProcessorSymbolType::CodePtr) => "CODE_PTR",
            None => "null",
        };
        write!(
            f,
            "LABEL INFO NAME={}, ADDR={}, isEntry = {}, type = {}",
            self.label, self.addr, self.is_entry, type_str
        )?;
        if let Some(description) = &self.description {
            // NOTE: no separator here -- see the doc comment above.
            write!(f, "description = {}", description)?;
        }
        Ok(())
    }
}

impl PartialOrd for AddressLabelInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressLabelInfo {
    /// Port of `AddressLabelInfo.compareTo`.
    ///
    /// Faithfully reproduces a real Java quirk: addresses are compared by their **string**
    /// representation (`Address.toString()`), not by numeric/space-aware address ordering. This
    /// means, for example, that within the same address space, an address at offset `0x10` sorts
    /// *before* one at offset `0x9`, because the string `"...0x10"` is lexicographically less
    /// than `"...0x9"` (`'1' < '9'`), even though `0x10 > 0x9` numerically. See the test below.
    ///
    /// Java also special-cases a `null` argument (returning `1`) and a `null` label on either
    /// side; neither has a port here: `Ord::cmp` cannot be called with a null `Self`, and this
    /// struct's `label` field can never be empty-checked-away-to-null since [`AddressLabelInfo::new`]
    /// already rejects it via [`SymbolUtilities::validate_name`].
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let string_compare = self.addr.to_string().cmp(&other.addr.to_string());
        if string_compare != std::cmp::Ordering::Equal {
            return string_compare;
        }
        self.label.cmp(&other.label)
    }
}

/// Java's `AddressLabelInfo` does not override `equals()`/`hashCode()` at all, so `.equals()`
/// there is plain `Object` identity (reference) equality -- not a portable, meaningful value
/// comparison. Rather than leave `Eq`/`PartialEq` unimplemented (which would make [`Ord`] above
/// impossible to express, since `Ord: Eq` in Rust), this port defines them to agree with
/// [`Ord::cmp`], matching normal Rust `Ord`/`Eq` consistency expectations instead of Java's
/// (documented-elsewhere-in-this-port-as-inconsistent) `compareTo`/`equals` split.
impl PartialEq for AddressLabelInfo {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for AddressLabelInfo {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        ram_space().address(offset)
    }

    #[test]
    fn new_defaults_size_to_addressable_unit_size() {
        let info = AddressLabelInfo::new(addr(0x1000), None, "entry", None, true, true, None, None).unwrap();
        assert_eq!(info.get_byte_size(), 1);
        assert_eq!(info.get_end_address(), &addr(0x1000));
    }

    #[test]
    fn new_uses_explicit_size_and_computes_end_address() {
        let info = AddressLabelInfo::new(addr(0x1000), Some(4), "entry", None, true, true, None, None).unwrap();
        assert_eq!(info.get_byte_size(), 4);
        assert_eq!(info.get_end_address(), &addr(0x1003));
    }

    #[test]
    fn new_treats_non_positive_size_as_default() {
        let info = AddressLabelInfo::new(addr(0x1000), Some(0), "entry", None, true, true, None, None).unwrap();
        assert_eq!(info.get_byte_size(), 1);

        let info2 = AddressLabelInfo::new(addr(0x1000), Some(-5), "entry", None, true, true, None, None).unwrap();
        assert_eq!(info2.get_byte_size(), 1);
    }

    #[test]
    fn new_rejects_invalid_label() {
        let err = AddressLabelInfo::new(addr(0x1000), None, "", None, true, true, None, None).unwrap_err();
        assert!(matches!(err, AddressLabelInfoError::InvalidInput(_)));
    }

    #[test]
    fn accessors_report_constructed_values() {
        let info = AddressLabelInfo::new(
            addr(0x2000),
            Some(2),
            "myLabel",
            Some("a comment".to_string()),
            true,
            false,
            Some(ProcessorSymbolType::Code),
            Some(true),
        )
        .unwrap();
        assert_eq!(info.get_address(), &addr(0x2000));
        assert_eq!(info.get_label(), "myLabel");
        assert_eq!(info.get_description(), Some("a comment"));
        assert!(info.is_primary());
        assert!(!info.is_entry());
        assert_eq!(info.get_processor_symbol_type(), Some(ProcessorSymbolType::Code));
        assert_eq!(info.is_volatile(), Some(true));
    }

    #[test]
    fn display_without_description_has_no_trailing_field() {
        let info =
            AddressLabelInfo::new(addr(0x1000), None, "entry", None, true, true, Some(ProcessorSymbolType::Code), None)
                .unwrap();
        assert_eq!(
            info.to_string(),
            format!("LABEL INFO NAME=entry, ADDR={}, isEntry = true, type = CODE", addr(0x1000))
        );
    }

    #[test]
    fn display_with_description_has_no_separator_before_it() {
        // Real Java quirk: `description` is glued directly onto the preceding field with no
        // separating punctuation.
        let info = AddressLabelInfo::new(
            addr(0x1000),
            None,
            "entry",
            Some("a comment".to_string()),
            true,
            true,
            Some(ProcessorSymbolType::Code),
            None,
        )
        .unwrap();
        assert_eq!(
            info.to_string(),
            format!("LABEL INFO NAME=entry, ADDR={}, isEntry = true, type = CODEdescription = a comment", addr(0x1000))
        );
    }

    #[test]
    fn display_with_no_processor_symbol_type_shows_java_null_literal() {
        let info = AddressLabelInfo::new(addr(0x1000), None, "entry", None, true, true, None, None).unwrap();
        assert!(info.to_string().contains("type = null"));
    }

    #[test]
    fn compare_to_orders_by_address_string_not_numeric_value() {
        // Real Java quirk: `compareTo` compares `Address.toString()` lexicographically, not the
        // address's numeric offset. Offset 0x10 (16) sorts *before* offset 0x9 (9) because the
        // string "...0x10" < "...0x9" character-by-character ('1' < '9'), even though 16 > 9.
        let low_offset = AddressLabelInfo::new(addr(0x9), None, "a", None, true, true, None, None).unwrap();
        let high_offset = AddressLabelInfo::new(addr(0x10), None, "a", None, true, true, None, None).unwrap();

        assert!(addr(0x10).offset() > addr(0x9).offset(), "sanity: 0x10 really is numerically larger");
        assert!(
            high_offset < low_offset,
            "the numerically larger address should sort first under the string-based comparator"
        );
    }

    #[test]
    fn compare_to_falls_back_to_label_when_addresses_match() {
        let a = AddressLabelInfo::new(addr(0x1000), None, "aaa", None, true, true, None, None).unwrap();
        let b = AddressLabelInfo::new(addr(0x1000), None, "bbb", None, true, true, None, None).unwrap();
        assert!(a < b);
    }

    #[test]
    fn compare_to_equal_for_identical_address_and_label() {
        let a = AddressLabelInfo::new(addr(0x1000), None, "same", None, true, true, None, None).unwrap();
        let b = AddressLabelInfo::new(addr(0x1000), None, "same", None, false, false, None, None).unwrap();
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }
}
