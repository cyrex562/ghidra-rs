//! Port of `ghidra.program.model.data.FileTimeDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point, and structurally the Windows-`FILETIME` sibling of
//! [`MacintoshTimeStampDataType`](super::macintosh_time_stamp_data_type::MacintoshTimeStampDataType)
//! (see that module's docs for why no `chrono`/`time` crate dependency was needed and how the
//! shared [`civil_from_days`](crate::util::date_utils::civil_from_days)/
//! [`days_from_civil`](crate::util::date_utils::days_from_civil) calendar helpers are reused).
//!
//! The Java class `extends BuiltIn`, already ported as a trait ([`BuiltIn`]), so this trait
//! extends it directly.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getDescription`, `getLength`, `getMnemonic(Settings)`, `getRepresentation(...)`,
//! `getValue(...)`, `getValueClass(Settings)`). Rust does not allow a subtrait to override a
//! supertrait's same-named default without creating an ambiguous call site, so those overrides
//! are exposed here under distinct `file_time_*` names, mirroring
//! [`MacintoshTimeStampDataType`]'s `mac_time_stamp_*` convention. A concrete `impl DataType +
//! BuiltIn for ...` should delegate to these.
//!
//! `FILETIME` counts 100-nanosecond ticks since `1601-01-01 00:00:00 GMT`; the Java body divides
//! by `10000` to get milliseconds (discarding the sub-millisecond remainder for the `Date`
//! itself) and separately recovers a *sub-second* fractional-seconds string straight from the raw
//! tick count via `numTicks % 10000000 + 100000000` then `Long.toString(...).substring(1)`. That
//! arithmetic is ported bit-for-bit as [`fractional_seconds_string`], including its apparent
//! off-by-one digit width (`10000000` ticks/second is 7 digits, but the literal padding base is
//! `100000000`, one power of ten too many, which -- because the padded range `[100000000,
//! 109999999]` always starts with `"10"` -- produces an 8-character string with a redundant
//! leading `'0'` rather than the presumably-intended 7; preserved verbatim rather than "corrected"
//! since this is a faithful translation, not a rewrite).
//!
//! `getValue(MemBuffer, Settings, int)` returns the *raw* tick count (boxed `i64`, standing in for
//! `Long`), unlike `MacintoshTimeStampDataType.getValue` which returns the formatted string --
//! this is a genuine difference in the two Java classes, not a porting inconsistency.
//!
//! The Java `if (epochData == null) { return "unparsed date"; }` guard is not ported for the same
//! reason given in [`MacintoshTimeStampDataType`]'s module docs: this port's epoch computation is
//! pure integer arithmetic and cannot fail.
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `ClassTranslator.put(...)` legacy-name registration (needs `ClassTranslator`, not yet ported).

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::mem::MemBuffer;
use crate::util::date_utils::civil_from_days;

/// Number of seconds from `1601-01-01 00:00:00 GMT` (the Windows `FILETIME` epoch) to
/// `1970-01-01 00:00:00 GMT` (the Unix epoch). Standing in for `0 - epochData.getTime()`
/// converted from milliseconds to seconds.
fn file_time_epoch_offset_seconds() -> i64 {
    -crate::util::date_utils::days_from_civil(1601, 1, 1) * 86_400
}

/// Port of the `Long.toString(numTicks % 10000000 + 100000000).substring(1)` fractional-seconds
/// computation. See the module docs for why this is 8 characters, not 7, preserved verbatim from
/// the Java source.
fn fractional_seconds_string(num_ticks: i64) -> String {
    let fractional_part_plus_1e8 = (num_ticks % 10_000_000) + 100_000_000;
    let digits = fractional_part_plus_1e8.to_string();
    digits[1..].to_string()
}

/// Formats a raw `FILETIME` tick count -- 100-nanosecond ticks since `1601-01-01 00:00:00 GMT` --
/// as `"yyyy-MM-dd HH:mm:ss.ffffffff UTC"` in GMT.
///
/// Port of the body of `FileTimeDataType.getRepresentation(MemBuffer, Settings, int)` after the
/// successful `buf.getLong(0)` read.
fn format_file_timestamp(num_ticks: i64) -> String {
    let num_milliseconds = num_ticks / 10_000;
    let num_seconds = num_milliseconds.div_euclid(1000);
    let unix_seconds = num_seconds - file_time_epoch_offset_seconds();
    let (year, month, day) = civil_from_days(unix_seconds.div_euclid(86_400));
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{} UTC",
        fractional_seconds_string(num_ticks)
    )
}

/// A datatype to interpret the FILETIME timestamp convention, which is based on the number of
/// 100-nanosecond ticks since January 1, 1601.
///
/// Port of `ghidra.program.model.data.FileTimeDataType`. See the module docs for what was
/// ported, added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator.put(...)` legacy-name registration (needs `ClassTranslator`, not yet ported).
pub trait FileTimeDataType: BuiltIn {
    /// Port of `FileTimeDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn file_time_description(&self) -> String {
        "The stamp follows the Filetime-measurement scheme (that is, the number of 100 \
         nanosecond ticks measured from midnight January 1, 1601)."
            .to_string()
    }

    /// Port of `FileTimeDataType.getLength()`, which overrides the default `DataType.getLength()`.
    fn file_time_length(&self) -> i32 {
        8
    }

    /// Port of `FileTimeDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"FileTime"`.
    fn file_time_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "FileTime".to_string()
    }

    /// Port of `FileTimeDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`. `""` on a failed read, matching the Java
    /// `catch (Exception e) {}` falling through to `return "";`. See the module docs for why the
    /// `"unparsed date"` branch is unreachable here.
    fn file_time_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (settings, length);
        match buf.get_long(0) {
            Ok(num_ticks) => format_file_timestamp(num_ticks),
            Err(_) => String::new(),
        }
    }

    /// Port of `FileTimeDataType.getValue(MemBuffer, Settings, int)`, which overrides the default
    /// `DataType.getValue(...)`. Boxes the raw tick count (`i64`, standing in for `Long`), or
    /// `None` on a failed read, matching the Java `catch (MemoryAccessException e) { return
    /// null; }`.
    fn file_time_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        let num_ticks = buf.get_long(0).ok()?;
        Some(Box::new(num_ticks) as Box<dyn Any>)
    }

    /// Port of `FileTimeDataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of `i64`, standing in for
    /// `Long.class`.
    fn file_time_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<i64>())
    }

    /// Port of `FileTimeDataType.clone(DataTypeManager)`. Left as a required method (no default);
    /// see [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn file_time_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn FileTimeDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.0.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    #[derive(Clone)]
    struct MockFileTime;

    impl DataType for MockFileTime {
        fn get_name(&self) -> String {
            "FileTime".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.file_time_length()
        }
        fn get_description(&self) -> String {
            self.file_time_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.file_time_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.file_time_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.file_time_value(buf, settings, length)
        }
    }

    impl DataTypeImpl for MockFileTime {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl BuiltInDataType for MockFileTime {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockFileTime {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl FileTimeDataType for MockFileTime {
        fn file_time_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn FileTimeDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockFileTime;
        let dyn_dt: &dyn FileTimeDataType = &dt;
        assert_eq!(dyn_dt.file_time_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert_eq!(dyn_dt.file_time_mnemonic(&MockSettings), "FileTime");
        assert_eq!(dyn_dt.file_time_value_class(&MockSettings), Some(TypeId::of::<i64>()));
        assert!(dyn_dt.file_time_description().contains("January 1, 1601"));
    }

    #[test]
    fn epoch_zero_formats_to_the_filetime_epoch_date() {
        let dt = MockFileTime;
        let buf = FixedMemBuffer(0i64.to_be_bytes().to_vec());
        assert_eq!(
            dt.file_time_representation(&buf, &MockSettings, 8),
            "1601-01-01 00:00:00.00000000 UTC"
        );
    }

    #[test]
    fn known_filetime_matches_expected_unix_epoch() {
        // 1601-01-01 to 1970-01-01 is 11644473600 seconds; at 10^7 ticks/sec that is the
        // well-known FILETIME-for-Unix-epoch tick count.
        let dt = MockFileTime;
        let ticks: i64 = 11_644_473_600 * 10_000_000;
        let buf = FixedMemBuffer(ticks.to_be_bytes().to_vec());
        assert_eq!(
            dt.file_time_representation(&buf, &MockSettings, 8),
            "1970-01-01 00:00:00.00000000 UTC"
        );
    }

    #[test]
    fn fractional_seconds_reflect_sub_second_ticks() {
        let dt = MockFileTime;
        // 1234567 ticks (out of 10,000,000 per second) into the epoch second.
        let ticks: i64 = 1_234_567;
        let buf = FixedMemBuffer(ticks.to_be_bytes().to_vec());
        assert_eq!(
            dt.file_time_representation(&buf, &MockSettings, 8),
            "1601-01-01 00:00:00.01234567 UTC"
        );
    }

    #[test]
    fn representation_is_empty_string_when_the_read_fails() {
        let dt = MockFileTime;
        let buf = FixedMemBuffer(vec![0x00, 0x00]);
        assert_eq!(dt.file_time_representation(&buf, &MockSettings, 8), "");
    }

    #[test]
    fn value_boxes_the_raw_tick_count() {
        let dt = MockFileTime;
        let ticks: i64 = 123_456_789;
        let buf = FixedMemBuffer(ticks.to_be_bytes().to_vec());
        let value = dt.file_time_value(&buf, &MockSettings, 8).unwrap();
        assert_eq!(*value.downcast_ref::<i64>().unwrap(), ticks);
    }

    #[test]
    fn value_is_none_when_the_read_fails() {
        let dt = MockFileTime;
        let buf = FixedMemBuffer(vec![0x00]);
        assert!(dt.file_time_value(&buf, &MockSettings, 8).is_none());
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockFileTime;
        let cloned = dt.file_time_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}
