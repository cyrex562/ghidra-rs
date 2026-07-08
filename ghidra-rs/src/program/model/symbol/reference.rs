use std::any::Any;
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, SourceType};

/// Operand index corresponding to the instruction/data mnemonic.
pub const MNEMONIC: i32 = RefType::MNEMONIC;
/// Special-purpose operand index used when no operand applies.
pub const OTHER: i32 = RefType::OTHER;

/// Base interface for a Ghidra reference from one address to another.
///
/// This mirrors Ghidra's `Reference` contract while using Rust naming
/// conventions.
pub trait Reference: Send + Sync + Any {
    /// Gets the address of the code unit making the reference.
    fn from_address(&self) -> Address;

    /// Gets the destination address for this reference.
    fn to_address(&self) -> Address;

    /// Returns whether this reference is marked as primary.
    fn is_primary(&self) -> bool;

    /// Gets the associated symbol ID, or `-1` when none applies.
    fn symbol_id(&self) -> i64;

    /// Gets the type of reference being made.
    fn reference_type(&self) -> RefType;

    /// Gets the operand index where this reference was placed.
    fn operand_index(&self) -> i32;

    /// Returns true when this reference is on the mnemonic, not an operand.
    fn is_mnemonic_reference(&self) -> bool;

    /// Returns true when this reference is on an operand, not the mnemonic.
    fn is_operand_reference(&self) -> bool;

    /// Returns true when this reference points to a stack location.
    fn is_stack_reference(&self) -> bool;

    /// Returns true when this is an external reference.
    fn is_external_reference(&self) -> bool;

    /// Returns true when this is an entry point reference.
    fn is_entry_point_reference(&self) -> bool;

    /// Returns true when this points to program memory.
    fn is_memory_reference(&self) -> bool;

    /// Returns true when this points to a register address.
    fn is_register_reference(&self) -> bool;

    /// Returns true when this is an offset reference.
    fn is_offset_reference(&self) -> bool;

    /// Returns true when this is a shifted reference.
    fn is_shifted_reference(&self) -> bool;

    /// Gets the source of this reference.
    fn source(&self) -> SourceType;

    /// Returns a reference to self as Any for downcasting.
    fn as_any(&self) -> &dyn Any;
}

/// Marker trait for dynamically determined references that may not be
/// explicitly added, deleted, or modified.
pub trait DynamicReference: Reference {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_constants_match_java_reference() {
        assert_eq!(MNEMONIC, -1);
        assert_eq!(OTHER, -2);
    }
}
