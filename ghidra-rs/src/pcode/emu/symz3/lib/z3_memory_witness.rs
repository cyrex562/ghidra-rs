//! Port of `ghidra.pcode.emu.symz3.lib.Z3MemoryWitness`.

use std::fmt;

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;

/// Whether a [`Z3MemoryWitness`] records a memory load or a store.
///
/// Port of the nested enum `Z3MemoryWitness.WitnessType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WitnessType {
    Load,
    Store,
}

/// A record of a single symbolic memory access: the address touched, how many bytes moved, and
/// whether it was a load or a store.
///
/// Port of the Java `record Z3MemoryWitness(SymValueZ3 address, int bytesMoved, WitnessType t)`.
/// Java records generate public accessors named after each component (`address()`,
/// `bytesMoved()`, `t()`) plus `equals`/`hashCode`/`toString` over all three fields; this port
/// exposes the fields directly (matching this crate's established treatment of other Java records,
/// e.g. [`RegisterPlusConstant`](crate::pcode::emu::symz3::lib::z3_infix_printer::RegisterPlusConstant))
/// and derives the equivalent traits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Z3MemoryWitness {
    /// The (symbolic) address touched by the access. Java record component `address`.
    pub address: SymValueZ3,
    /// The number of bytes moved by the access. Java record component `bytesMoved`.
    pub bytes_moved: i32,
    /// Whether this was a load or a store. Java record component `t`.
    pub t: WitnessType,
}

impl Z3MemoryWitness {
    /// Java: the canonical record constructor `Z3MemoryWitness(SymValueZ3, int, WitnessType)`.
    pub fn new(address: SymValueZ3, bytes_moved: i32, t: WitnessType) -> Self {
        Self { address, bytes_moved, t }
    }
}

impl fmt::Display for Z3MemoryWitness {
    /// Java: `Record.toString()`, e.g. `Z3MemoryWitness[address=..., bytesMoved=..., t=LOAD]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Z3MemoryWitness[address={}, bytesMoved={}, t={:?}]",
            self.address, self.bytes_moved, self.t
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_stores_all_three_components() {
        let addr = SymValueZ3::parse("B:bool;p:::::V:bv;8;;x").expect("well-formed serialization");
        let witness = Z3MemoryWitness::new(addr.clone(), 4, WitnessType::Load);
        assert_eq!(witness.address, addr);
        assert_eq!(witness.bytes_moved, 4);
        assert_eq!(witness.t, WitnessType::Load);
    }

    #[test]
    fn equality_and_hash_compare_all_fields_like_a_java_record() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = Z3MemoryWitness::new(SymValueZ3::default(), 8, WitnessType::Store);
        let b = Z3MemoryWitness::new(SymValueZ3::default(), 8, WitnessType::Store);
        let different_size = Z3MemoryWitness::new(SymValueZ3::default(), 4, WitnessType::Store);
        let different_type = Z3MemoryWitness::new(SymValueZ3::default(), 8, WitnessType::Load);

        assert_eq!(a, b);
        assert_ne!(a, different_size);
        assert_ne!(a, different_type);

        let hash_of = |w: &Z3MemoryWitness| {
            let mut h = DefaultHasher::new();
            w.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn display_matches_java_record_to_string_shape() {
        let witness = Z3MemoryWitness::new(SymValueZ3::default(), 2, WitnessType::Store);
        assert_eq!(witness.to_string(), "Z3MemoryWitness[address=<SymValueZ3: >, bytesMoved=2, t=Store]");
    }

    #[test]
    fn load_and_store_are_distinct() {
        assert_ne!(WitnessType::Load, WitnessType::Store);
    }
}
