//! Port of `ghidra.app.decompiler.parallel.DecompilerReducer`.
//!
//! # Shape
//!
//! Java is an `interface` with one abstract method and no in-repo implementors -- an open
//! extension point clients implement to fold the per-function results of a parallel decompile
//! into one value -- so this becomes a generic `trait` (per `scripts/shape_rules.py`), the
//! reducing counterpart of [`DecompilerMapFunction`](super::DecompilerMapFunction).
//!
//! # Seams
//!
//! * **`DominantPair`.** `generic.DominantPair` is not yet ported; a minimal placeholder lives in
//!   [`seam_stubs`](super::seam_stubs).

use super::seam_stubs::DominantPair;
use crate::program::model::address::Address;

/// Reduces a list of `(function entry address, mapped value)` pairs into a single result.
///
/// Port of the Java interface `ghidra.app.decompiler.parallel.DecompilerReducer<R, D>`, where
/// `D` is the per-function value produced by a
/// [`DecompilerMapFunction`](super::DecompilerMapFunction) and `R` is the reduced result.
pub trait DecompilerReducer<R, D> {
    /// Mirrors `R reduce(List<DominantPair<Address, D>> list)`. The list is taken by value, as
    /// Java hands the reducer a freshly collected list it owns.
    fn reduce(&self, list: Vec<DominantPair<Address, D>>) -> R;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Sums per-function instruction counts, like a typical client reducer would.
    struct SumReducer;

    impl DecompilerReducer<i64, i64> for SumReducer {
        fn reduce(&self, list: Vec<DominantPair<Address, i64>>) -> i64 {
            list.into_iter().map(|p| p.second).sum()
        }
    }

    /// Picks the entry address with the largest value.
    struct MaxEntryReducer;

    impl DecompilerReducer<Option<Address>, u32> for MaxEntryReducer {
        fn reduce(&self, list: Vec<DominantPair<Address, u32>>) -> Option<Address> {
            list.into_iter().max_by_key(|p| p.second).map(|p| p.first)
        }
    }

    #[test]
    fn reduce_folds_all_pairs() {
        let list = vec![
            DominantPair::new(addr(0x1000), 3),
            DominantPair::new(addr(0x2000), 5),
            DominantPair::new(addr(0x3000), 7),
        ];
        assert_eq!(SumReducer.reduce(list), 15);
        assert_eq!(SumReducer.reduce(Vec::new()), 0);
    }

    #[test]
    fn reduce_can_return_an_address() {
        let r: &dyn DecompilerReducer<Option<Address>, u32> = &MaxEntryReducer;
        let list = vec![DominantPair::new(addr(0x10), 1), DominantPair::new(addr(0x20), 9)];
        assert_eq!(r.reduce(list).map(|a| a.offset()), Some(0x20));
        assert_eq!(r.reduce(Vec::new()), None);
    }
}
