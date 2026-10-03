//! Port of `ghidra.program.database.references.RefListFlagsV0`.
//!
//! `RefListFlagsV0` packs a `RefListV0` record's per-reference metadata (primary flag, offset/shift
//! flags, "has symbol ID" flag, and [`SourceType`]) into a single byte, using bit layout:
//! `SOURCE_LOBIT (0x01) | IS_PRIMARY (0x02) | IS_OFFSET (0x04) | HAS_SYMBOL_ID (0x08) | IS_SHIFT
//! (0x10) | SOURCE_HIBITS (0x60)`. The three-bit `SourceType` storage ID is split across the low
//! bit (`0x01`) and the two high bits (`0x60`) rather than stored contiguously, and — per the
//! Java source's own note — uses a *local* storage-ID mapping for `DEFAULT`/`ANALYSIS` that
//! differs from [`SourceType::storage_id`]: `DEFAULT` encodes as `0` and `ANALYSIS` as `2` (the
//! reverse of their real storage IDs), while `AI`/`IMPORTED`/`USER_DEFINED` use their real storage
//! ID unchanged. [`encode_flags`] and [`decode_source`] implement that same swap.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait rather
//! than a concrete struct. Its public/package instance API — `getValue`/`getSource`/
//! `hasSymbolID`/`isShiftRef`/`isOffsetRef`/`isPrimary`/`setPrimary`/`setHasSymbolID` — maps
//! directly to trait methods.
//!
//! Not ported here: the package-private `RefListFlagsV0(byte)` and public
//! `RefListFlagsV0(boolean, boolean, boolean, boolean, SourceType)` constructors, since a
//! constructor returns `Self` by value and so cannot be a trait method without losing
//! object-safety (the same convention `RefListV0` and `ToAdapter` already use for their static
//! factories). The encoding logic the second constructor performs is preserved as the free
//! function [`encode_flags`] so implementers can still reuse it; the matching decode half of
//! `getSource()` is exposed the same way as [`decode_source`].
//!
//! `SourceType` is already ported (`crate::program::model::symbol::SourceType`), so no placeholder
//! stub is needed for this type.

use crate::program::model::symbol::SourceType;

const SOURCE_LOBIT: u8 = 0x01;
const IS_PRIMARY: u8 = 0x02;
const IS_OFFSET: u8 = 0x04;
const HAS_SYMBOL_ID: u8 = 0x08;
const IS_SHIFT: u8 = 0x10;
const SOURCE_HIBITS: u8 = 0x60;

const SOURCE_HIBITS_SHIFT: u8 = 5;

const MAX_SOURCE_VALUE: i32 = 7; // value limit based upon 3-bit storage capacity

/// Maps a [`SourceType`] to the local storage ID `RefListFlagsV0` encodes it with, which for
/// `Default`/`Analysis` differs from [`SourceType::storage_id`]. Stands in for the `sourceId`
/// `switch` inside `RefListFlagsV0(boolean, boolean, boolean, boolean, SourceType)`.
fn local_source_id(source: SourceType) -> i32 {
    match source {
        SourceType::Default => 0,
        SourceType::Analysis => 2,
        other => other.storage_id(),
    }
}

/// Encodes a `RefListV0` record's flags into the packed byte `RefListFlagsV0` stores. Stands in
/// for `RefListFlagsV0(boolean isPrimary, boolean isOffsetRef, boolean hasSymbolID, boolean
/// isShiftRef, SourceType source)`.
///
/// # Errors
///
/// Returns an error if `source`'s local storage ID exceeds the 3-bit storage capacity (mirrors
/// the Java constructor's `RuntimeException`; unreachable for the current `SourceType` variants).
pub fn encode_flags(
    is_primary: bool,
    is_offset_ref: bool,
    has_symbol_id: bool,
    is_shift_ref: bool,
    source: SourceType,
) -> Result<u8, String> {
    let source_id = local_source_id(source);
    if source_id > MAX_SOURCE_VALUE {
        return Err(format!("Unsupported SourceType storage ID: {source_id}"));
    }

    let source_type_lo_bit = (source_id & 1) as u8; // 1-bit, shift 0
    let source_type_hi_bits = ((source_id >> 1) as u8) << SOURCE_HIBITS_SHIFT; // remaining hi-bits
    let mut flags = source_type_hi_bits | source_type_lo_bit;

    if is_primary {
        flags |= IS_PRIMARY;
    }
    if is_offset_ref {
        flags |= IS_OFFSET;
    }
    if has_symbol_id {
        flags |= HAS_SYMBOL_ID;
    }
    if is_shift_ref {
        flags |= IS_SHIFT;
    }
    Ok(flags)
}

/// Decodes the [`SourceType`] packed into a `RefListFlagsV0` byte. Stands in for
/// `RefListFlagsV0.getSource()`.
pub fn decode_source(flags: u8) -> SourceType {
    let source_type_lo_bit = (flags & SOURCE_LOBIT) as i32; // 1-bit, shift 0
    let source_type_hi_bits = ((flags & SOURCE_HIBITS) >> (SOURCE_HIBITS_SHIFT - 1)) as i32; // remaining hi-bits
    let source_type_id = source_type_hi_bits | source_type_lo_bit;

    match source_type_id {
        0 => SourceType::Default,
        2 => SourceType::Analysis,
        other => SourceType::get_source_type(other)
            .unwrap_or_else(|_| panic!("Unsupported SourceType storage ID: {other}")),
    }
}

/// A single `RefListV0` record's packed flag byte: primary/offset/shift/has-symbol-ID flags plus
/// its [`SourceType`], all stored in one byte.
///
/// Port of `ghidra.program.database.references.RefListFlagsV0`. See the module docs for what was
/// intentionally left out (the two constructors, replaced by the free functions [`encode_flags`]
/// and [`decode_source`]).
pub trait RefListFlagsV0 {
    /// Returns the packed flag byte, as stored on disk. Stands in for `RefListFlagsV0.getValue()`.
    fn get_value(&self) -> u8;

    /// Returns the decoded [`SourceType`]. Stands in for `RefListFlagsV0.getSource()`.
    fn get_source(&self) -> SourceType {
        decode_source(self.get_value())
    }

    /// Returns true if a symbol ID is associated with this reference. Stands in for
    /// `RefListFlagsV0.hasSymbolID()`.
    fn has_symbol_id(&self) -> bool {
        self.get_value() & HAS_SYMBOL_ID != 0
    }

    /// Returns true if this is a shifted reference. Stands in for `RefListFlagsV0.isShiftRef()`.
    fn is_shift_ref(&self) -> bool {
        self.get_value() & IS_SHIFT != 0
    }

    /// Returns true if this is an offset reference. Stands in for `RefListFlagsV0.isOffsetRef()`.
    fn is_offset_ref(&self) -> bool {
        self.get_value() & IS_OFFSET != 0
    }

    /// Returns true if this reference is marked primary. Stands in for
    /// `RefListFlagsV0.isPrimary()`.
    fn is_primary(&self) -> bool {
        self.get_value() & IS_PRIMARY != 0
    }

    /// Sets or clears the primary flag. Stands in for `RefListFlagsV0.setPrimary(boolean)`.
    fn set_primary(&mut self, is_primary: bool);

    /// Sets or clears the "has symbol ID" flag. Stands in for
    /// `RefListFlagsV0.setHasSymbolID(boolean)`.
    fn set_has_symbol_id(&mut self, has_symbol_id: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal byte-backed implementation, just enough to prove the trait is object-safe and
    /// round-trips the same bit layout as the Java class.
    struct MockRefListFlagsV0 {
        flags: u8,
    }

    impl RefListFlagsV0 for MockRefListFlagsV0 {
        fn get_value(&self) -> u8 {
            self.flags
        }

        fn set_primary(&mut self, is_primary: bool) {
            self.flags &= !IS_PRIMARY;
            if is_primary {
                self.flags |= IS_PRIMARY;
            }
        }

        fn set_has_symbol_id(&mut self, has_symbol_id: bool) {
            self.flags &= !HAS_SYMBOL_ID;
            if has_symbol_id {
                self.flags |= HAS_SYMBOL_ID;
            }
        }
    }

    #[test]
    fn encode_decode_round_trips_every_source_type() {
        for source in [
            SourceType::Default,
            SourceType::Analysis,
            SourceType::AI,
            SourceType::Imported,
            SourceType::UserDefined,
        ] {
            let flags = encode_flags(true, false, true, false, source).unwrap();
            assert_eq!(decode_source(flags), source);
        }
    }

    #[test]
    fn flag_accessors_reflect_encoded_bits() {
        let flags = encode_flags(true, true, false, true, SourceType::Imported).unwrap();
        let list_flags = MockRefListFlagsV0 { flags };

        assert!(list_flags.is_primary());
        assert!(list_flags.is_offset_ref());
        assert!(!list_flags.has_symbol_id());
        assert!(list_flags.is_shift_ref());
        assert_eq!(list_flags.get_source(), SourceType::Imported);
    }

    #[test]
    fn setters_mutate_only_their_own_bit() {
        let flags = encode_flags(false, true, false, true, SourceType::UserDefined).unwrap();
        let mut list_flags = MockRefListFlagsV0 { flags };

        list_flags.set_primary(true);
        assert!(list_flags.is_primary());
        assert!(list_flags.is_offset_ref());
        assert!(list_flags.is_shift_ref());

        list_flags.set_has_symbol_id(true);
        assert!(list_flags.has_symbol_id());
        assert!(list_flags.is_primary());

        list_flags.set_primary(false);
        assert!(!list_flags.is_primary());
        assert!(list_flags.has_symbol_id());
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut list_flags: Box<dyn RefListFlagsV0> = Box::new(MockRefListFlagsV0 { flags: 0 });
        list_flags.set_primary(true);
        list_flags.set_has_symbol_id(true);
        assert!(list_flags.is_primary());
        assert!(list_flags.has_symbol_id());
        assert_eq!(list_flags.get_source(), SourceType::Default);
    }
}
