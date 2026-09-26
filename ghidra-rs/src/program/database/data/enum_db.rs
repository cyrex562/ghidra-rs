//! Port of `ghidra.program.database.data.EnumDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private `extends DataTypeDB implements Enum` providing the
//! database-backed implementation for the enumerated data type. `DataTypeDB` and
//! `DataTypeManagerDB` are not yet ported, and neither is the private `EnumValues` cache class
//! `EnumDB` delegates most of its `Enum` accessors to -- so, mirroring the sibling DB-backed
//! cycle-cut port [`CompositeDb`](super::composite_db::CompositeDb)'s convention of extending
//! only the already-ported interface its unported superclass implements, this trait extends
//! [`Enum`] directly (which already pulls in [`DataType`]).
//!
//! `EnumDB`'s Java accessors that just forward straight through to `EnumValues`/the inherited
//! `DataTypeDB` plumbing (`getValue`, `getName`, `getNames`, `getComment`, `getValues`,
//! `getCount`, `add`, `remove`, `contains`, `isSigned`, `getSignedState`,
//! `getMinimumPossibleLength`, plus the lock/refresh/record bookkeeping in `replaceWith`,
//! `setDescription`, `setUniversalID`, etc.) are not re-modeled here: they need real per-instance
//! record/adapter/cache storage this trait does not yet prescribe, exactly as
//! [`CompositeDb`](super::composite_db::CompositeDb) deferred the equivalent DB-record plumbing.
//! [`Enum`] (and, transitively, [`DataType`]) already declares the object-safe surface for all of
//! them.
//!
//! What *is* ported here, as real default-bodied trait methods operating purely on the
//! [`Enum`]/[`DataType`] surface a conforming implementation already exposes:
//!   - [`EnumDb::check_value`] -- port of the private `EnumDB.checkValue(long)`.
//!   - [`EnumDb::get_bit_groups`] -- port of the private `EnumDB.getBitGroups()`. The Java method
//!     lazily caches its result in a `bitGroups` field; this port recomputes it from
//!     [`Enum::get_values`]/[`DataType::get_length`] on each call instead, since caching is a
//!     per-instance storage concern out of scope for a trait default (a concrete implementation
//!     is free to add its own cache and skip calling this default).
//!   - [`EnumDb::get_compound_value`] -- port of the private `EnumDB.getCompoundValue(long)`.
//!   - [`EnumDb::enum_db_representation`] -- port of the private `EnumDB.getRepresentation(long)`.
//!     Named `enum_db_representation` rather than `get_representation` to avoid colliding with
//!     [`DataType::get_representation`]'s unrelated `MemBuffer`-based overload.
//!   - [`EnumDb::is_each_value_equivalent`] -- port of the private
//!     `EnumDB.isEachValueEquivalent(Enum)`.
//!   - [`EnumDb::enum_db_is_equivalent`] -- port of the protected
//!     `EnumDB.isEquivalent(DataType, DataTypeConflictHandler)`. Named `enum_db_is_equivalent`
//!     rather than `is_equivalent` since [`DataType::is_equivalent`] already claims that name for
//!     an unrelated (`bool`-defaulted) supertrait method, and Rust does not allow a subtrait to
//!     override a supertrait's same-named default without an ambiguous call site (see
//!     [`CompositeDb`](super::composite_db::CompositeDb)'s equivalent `composite_db_*` naming
//!     note). Takes `dt: &dyn Enum` directly rather than `&dyn DataType` plus an `instanceof Enum`
//!     check, since Rust trait objects have no generic downcast hook; the Java method's identity
//!     fast path (`dt == this`) and its use of the not-yet-ported
//!     `DataTypeUtilities.equalsIgnoreConflict` for the name comparison (here just `==`) are
//!     likewise simplified away.
//!   - [`max_possible_value`]/[`min_possible_value`] -- free-function ports of the package-private
//!     static `EnumDB.getMaxPossibleValue(int, boolean)`/`getMinPossibleValue(int, boolean)`,
//!     available for a concrete implementation's own [`Enum::get_max_possible_value`]/
//!     [`Enum::get_min_possible_value`] to call (those remain required, non-defaulted methods on
//!     [`Enum`] itself, so cannot be defaulted here -- same reasoning as the naming note above).

use crate::program::model::data::bit_group::BitGroup;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::{ConflictResult, DataTypeConflictHandler};
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_value_partitioner::EnumValuePartitioner;

/// Database implementation for the enumerated data type.
///
/// Port of `ghidra.program.database.data.EnumDB`.
pub trait EnumDb: Enum {
    /// Get the bit groups (non-intersecting sets of bits used by this enum's current values),
    /// used to build a compound (OR'd) representation for a value with no exact name match.
    /// Stands in for the private `EnumDB.getBitGroups()`.
    fn get_bit_groups(&self) -> Vec<BitGroup> {
        EnumValuePartitioner::partition(&self.get_values(), self.get_length())
    }

    /// Builds a `|`-separated compound representation of `value` from the names of its
    /// non-intersecting bit groups, falling back to an uppercase hex literal (`"h"`-suffixed) for
    /// any bits with no matching name. Stands in for the private
    /// `EnumDB.getCompoundValue(long)`.
    fn get_compound_value(&self, value: i64) -> String {
        if value == 0 {
            return "0".to_string();
        }
        let mut buf = String::new();
        for bit_group in self.get_bit_groups() {
            let sub_value = bit_group.get_mask() & value;
            if sub_value != 0 {
                let part = self
                    .get_name_for_value(sub_value)
                    .unwrap_or_else(|| format!("{:X}h", sub_value as u64));
                if !buf.is_empty() {
                    buf.push_str(" | ");
                }
                buf.push_str(&part);
            }
        }
        buf
    }

    /// Get the display representation of `value`: its entry name if one exists, otherwise a
    /// compound representation of its bits. Named `enum_db_representation` rather than
    /// `get_representation` per the module-level documentation. Stands in for the private
    /// `EnumDB.getRepresentation(long)`.
    fn enum_db_representation(&self, value: i64) -> String {
        self.get_name_for_value(value)
            .unwrap_or_else(|| self.get_compound_value(value))
    }

    /// Checks that `value` fits within this enum's current length, unless the length is 8 bytes
    /// (in which case all `i64` values are permitted). Returns `Err` with a message mirroring the
    /// Java `IllegalArgumentException` if `value` is out of range. Stands in for the private
    /// `EnumDB.checkValue(long)`.
    fn check_value(&self, value: i64) -> Result<(), String> {
        if self.get_length() == 8 {
            return Ok(());
        }
        let min = self.get_min_possible_value();
        let max = self.get_max_possible_value();
        if value < min || value > max {
            return Err(format!(
                "IllegalArgumentException: Attempted to add a value outside the range for this enum: ({min}, {max}): {value}"
            ));
        }
        Ok(())
    }

    /// Returns `true` if every name in this enum maps to the same value and comment in `other`.
    /// Stands in for the private `EnumDB.isEachValueEquivalent(Enum)`.
    fn is_each_value_equivalent(&self, other: &dyn Enum) -> bool {
        for name in self.get_names() {
            let Some(other_value) = other.get_value_for_name(&name) else {
                return false;
            };
            let Some(value) = self.get_value_for_name(&name) else {
                return false;
            };
            if value != other_value {
                return false;
            }
            if self.get_comment(&name) != other.get_comment(&name) {
                return false;
            }
        }
        true
    }

    /// Checks whether `dt` is equivalent to this enum: same name, same length and entry count,
    /// and every entry equivalent (per [`EnumDb::is_each_value_equivalent`]) -- unless `handler`
    /// resolves the conflict by keeping the existing datatype, in which case they are treated as
    /// equivalent regardless. Named `enum_db_is_equivalent` and takes `dt: &dyn Enum` directly per
    /// the module-level documentation. Stands in for the protected
    /// `EnumDB.isEquivalent(DataType, DataTypeConflictHandler)`.
    ///
    /// Requires `Self: Sized` (so is not callable through `dyn EnumDb`, though the trait as a
    /// whole remains object-safe): the `handler.resolve_conflict` call needs `self` upcast to
    /// `&dyn DataType`, and coercing a by-value-generic `&Self` into a trait object requires
    /// `Self: Sized` in the same way [`crate::program::seam_stubs::share_data_type`]'s
    /// `SharedDataType` wrapper needs a concrete, already-boxed value to do the same thing.
    fn enum_db_is_equivalent(&self, dt: &dyn Enum, handler: Option<&dyn DataTypeConflictHandler>) -> bool
    where
        Self: Sized,
    {
        if self.get_name() != dt.get_name() {
            return false;
        }
        if let Some(handler) = handler {
            let added: &dyn DataType = dt;
            let existing: &dyn DataType = self;
            if handler.resolve_conflict(added, existing) == ConflictResult::UseExisting {
                // treat this type as equivalent if existing type will be used
                return true;
            }
        }
        if self.get_length() != dt.get_length() || self.get_count() != dt.get_count() {
            return false;
        }
        self.is_each_value_equivalent(dt)
    }
}

/// Largest value representable in `bytes` bytes, optionally reserving the sign bit when
/// `allow_negative_values` is `true`. Stands in for the package-private static
/// `EnumDB.getMaxPossibleValue(int, boolean)`.
pub fn max_possible_value(bytes: i32, allow_negative_values: bool) -> i64 {
    if bytes == 8 {
        return i64::MAX;
    }
    let mut bits = bytes * 8;
    if allow_negative_values {
        bits -= 1; // take away 1 bit for the sign
    }
    // the largest value that can be held in n bits in 2^n - 1
    (1i64 << bits) - 1
}

/// Smallest (most negative) value representable in `bytes` bytes when `allow_negative_values` is
/// `true`, otherwise `0`. Stands in for the package-private static
/// `EnumDB.getMinPossibleValue(int, boolean)`.
pub fn min_possible_value(bytes: i32, allow_negative_values: bool) -> i64 {
    if !allow_negative_values {
        return 0;
    }
    let bits = bytes * 8;
    // smallest value (largest negative) that can be stored in n bits is when the sign bit
    // is on (and sign extended), and all less significant bits are 0
    -1i64 << (bits - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::data::EnumSignedState;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::docking::settings::settings::Settings;

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockSettings;
    impl Settings for MockSettings {}

    /// Minimal DB-backed [`EnumDb`], proving object-safety and exercising real
    /// `checkValue`/`getBitGroups`/`getCompoundValue`/`isEquivalent` behavior.
    #[derive(Clone)]
    struct MockEnumDb {
        name: String,
        length: i32,
        entries: Vec<(String, i64, String)>,
    }

    impl MockEnumDb {
        fn new(name: &str, length: i32) -> Self {
            MockEnumDb { name: name.to_string(), length, entries: Vec::new() }
        }
    }

    impl DataType for MockEnumDb {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    impl Enum for MockEnumDb {
        fn get_value_for_name(&self, name: &str) -> Option<i64> {
            self.entries.iter().find(|(n, _, _)| n == name).map(|(_, v, _)| *v)
        }

        fn get_name_for_value(&self, value: i64) -> Option<String> {
            self.entries.iter().find(|(_, v, _)| *v == value).map(|(n, _, _)| n.clone())
        }

        fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
            let names: Vec<String> = self
                .entries
                .iter()
                .filter(|(_, v, _)| *v == value)
                .map(|(n, _, _)| n.clone())
                .collect();
            if names.is_empty() {
                None
            } else {
                Some(names)
            }
        }

        fn get_comment(&self, name: &str) -> String {
            self.entries
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, _, c)| c.clone())
                .unwrap_or_default()
        }

        fn get_values(&self) -> Vec<i64> {
            let mut values: Vec<i64> = self.entries.iter().map(|(_, v, _)| *v).collect();
            values.sort_unstable();
            values
        }

        fn get_names(&self) -> Vec<String> {
            let mut names: Vec<(i64, String)> =
                self.entries.iter().map(|(n, v, _)| (*v, n.clone())).collect();
            names.sort();
            names.into_iter().map(|(_, n)| n).collect()
        }

        fn get_count(&self) -> i32 {
            self.entries.len() as i32
        }

        fn add(&mut self, name: &str, value: i64) {
            self.add_with_comment(name, value, "");
        }

        fn add_with_comment(&mut self, name: &str, value: i64, comment: &str) {
            self.entries.push((name.to_string(), value, comment.to_string()));
        }

        fn remove(&mut self, name: &str) {
            self.entries.retain(|(n, _, _)| n != name);
        }

        fn set_description(&mut self, _description: &str) {}

        fn get_enum_representation(&self, big_int: i128, _settings: &dyn Settings, _bit_length: i32) -> String {
            self.enum_db_representation(big_int as i64)
        }

        fn contains_name(&self, name: &str) -> bool {
            self.entries.iter().any(|(n, _, _)| n == name)
        }

        fn contains_value(&self, value: i64) -> bool {
            self.entries.iter().any(|(_, v, _)| *v == value)
        }

        fn is_signed(&self) -> bool {
            self.entries.iter().any(|(_, v, _)| *v < 0)
        }

        fn get_signed_state(&self) -> EnumSignedState {
            if self.is_signed() {
                EnumSignedState::Signed
            } else {
                EnumSignedState::None
            }
        }

        fn get_max_possible_value(&self) -> i64 {
            max_possible_value(self.length, self.is_signed())
        }

        fn get_min_possible_value(&self) -> i64 {
            min_possible_value(self.length, self.is_signed())
        }

        fn get_minimum_possible_length(&self) -> i32 {
            1
        }

        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
            Box::new(self.clone())
        }
    }

    impl EnumDb for MockEnumDb {}

    fn sample() -> MockEnumDb {
        let mut e = MockEnumDb::new("Colors", 1);
        e.add("RED", 1);
        e.add_with_comment("GREEN", 2, "the green one");
        e.add("BLUE", 4);
        e
    }

    #[test]
    fn usable_as_trait_object() {
        let e = sample();
        let dyn_enum_db: &dyn EnumDb = &e;
        assert_eq!(dyn_enum_db.get_count(), 3);
    }

    #[test]
    fn check_value_rejects_out_of_range_for_unsigned_byte() {
        let e = sample();
        assert!(e.check_value(255).is_ok());
        let err = e.check_value(256).unwrap_err();
        assert!(err.contains("IllegalArgumentException"));
        assert!(err.contains("256"));
    }

    #[test]
    fn check_value_allows_any_i64_at_length_eight() {
        let e = MockEnumDb::new("Big", 8);
        assert!(e.check_value(i64::MIN).is_ok());
        assert!(e.check_value(i64::MAX).is_ok());
    }

    #[test]
    fn enum_db_representation_uses_exact_name_when_present() {
        let e = sample();
        assert_eq!(e.enum_db_representation(2), "GREEN");
    }

    #[test]
    fn enum_db_representation_falls_back_to_compound_value() {
        let e = sample();
        // 1 (RED) | 4 (BLUE) has no exact-name match, so it should combine both bit groups.
        assert_eq!(e.enum_db_representation(5), "RED | BLUE");
    }

    #[test]
    fn compound_value_of_zero_is_literal_zero() {
        let e = sample();
        assert_eq!(e.get_compound_value(0), "0");
    }

    #[test]
    fn compound_value_uses_hex_for_unnamed_bits() {
        let e = sample();
        // bit 0x08 has no matching name of its own.
        assert_eq!(e.get_compound_value(0b1100), "BLUE | 8h");
    }

    #[test]
    fn is_each_value_equivalent_detects_value_mismatch() {
        let a = sample();
        let mut b = sample();
        b.remove("BLUE");
        b.add("BLUE", 5);
        assert!(!a.is_each_value_equivalent(&b));
    }

    #[test]
    fn is_each_value_equivalent_detects_comment_mismatch() {
        let a = sample();
        let mut b = sample();
        b.remove("GREEN");
        b.add_with_comment("GREEN", 2, "different comment");
        assert!(!a.is_each_value_equivalent(&b));
    }

    #[test]
    fn is_each_value_equivalent_true_for_identical_entries() {
        let a = sample();
        let b = sample();
        assert!(a.is_each_value_equivalent(&b));
    }

    #[test]
    fn enum_db_is_equivalent_rejects_name_mismatch() {
        let a = sample();
        let mut b = sample();
        b.name = "Shades".to_string();
        assert!(!a.enum_db_is_equivalent(&b, None));
    }

    #[test]
    fn enum_db_is_equivalent_rejects_length_mismatch() {
        let a = sample();
        let mut b = sample();
        b.length = 2;
        assert!(!a.enum_db_is_equivalent(&b, None));
    }

    #[test]
    fn enum_db_is_equivalent_true_for_matching_enum() {
        let a = sample();
        let b = sample();
        assert!(a.enum_db_is_equivalent(&b, None));
    }

    #[test]
    fn enum_db_is_equivalent_honors_use_existing_handler() {
        struct KeepExistingHandler;
        impl DataTypeConflictHandler for KeepExistingHandler {
            fn resolve_conflict(&self, _added: &dyn DataType, _existing: &dyn DataType) -> ConflictResult {
                ConflictResult::UseExisting
            }
        }

        let a = sample();
        let mut b = sample();
        b.length = 2; // would otherwise fail the length check
        assert!(a.enum_db_is_equivalent(&b, Some(&KeepExistingHandler)));
    }

    #[test]
    fn max_and_min_possible_value_helpers() {
        assert_eq!(max_possible_value(1, false), 255);
        assert_eq!(max_possible_value(1, true), 127);
        assert_eq!(max_possible_value(8, true), i64::MAX);
        assert_eq!(min_possible_value(1, false), 0);
        assert_eq!(min_possible_value(1, true), -128);
    }
}
