//! Port of `ghidra.program.model.data.MacintoshTimeStampDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`, already ported as a trait ([`BuiltIn`]), so this trait
//! extends it directly, mirroring
//! [`ShiftedAddressDataType`](super::shifted_address_data_type::ShiftedAddressDataType).
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getDescription`, `getLength`, `getMnemonic(Settings)`, `getRepresentation(...)`,
//! `getValue(...)`). Rust does not allow a subtrait to override a supertrait's same-named default
//! without creating an ambiguous call site, so -- mirroring
//! [`ShiftedAddressDataType`]'s `shifted_address_*` convention -- those overrides are exposed here
//! under distinct `mac_time_stamp_*` names. A concrete `impl DataType + BuiltIn for ...` should
//! delegate to these.
//!
//! There is no crate dependency on `chrono` or the `time` crate (neither is in `Cargo.toml`), so
//! the calendar math is done directly with the same Howard-Hinnant-based
//! [`civil_from_days`](crate::util::date_utils::civil_from_days)/
//! [`days_from_civil`](crate::util::date_utils::days_from_civil) conversion this crate's own
//! [`DateUtils`](crate::util::date_utils::DateUtils) already uses (those two functions were
//! promoted from module-private to `pub(crate)` for this reuse). The Java `getRepresentation`
//! body computes `dateInSeconds = buf.getInt(0) & 0xffffffffL` (the stored 32-bit field
//! reinterpreted as unsigned), converts to milliseconds, and offsets by
//! `-macStartDate.getTime()` (the Unix-epoch-millisecond value of `1904-01-01 00:00:00 GMT`,
//! itself negative since 1904 predates 1970). This port instead computes the equivalent
//! [`MAC_EPOCH_OFFSET_SECONDS`] directly via `days_from_civil(1904, 1, 1) * -86400` (a positive
//! number of seconds *from* 1904 *to* 1970) and subtracts it from the unsigned 32-bit second
//! count to get Unix-epoch seconds, then formats with [`civil_from_days`] plus manual
//! hour/minute/second-of-day arithmetic -- reproducing `SimpleDateFormat("dd-MMM-yyyy
//! HH:mm:ss")` in GMT exactly (a fixed English 3-letter month abbreviation table, since Java's
//! `Locale.US` "MMM" pattern is locale-fixed here rather than actually locale-sensitive).
//!
//! The Java `if (macStartDate == null) { return "unparsed date"; }` guard (protecting against the
//! static initializer's `SimpleDateFormat.parse` throwing) is not ported: this port's equivalent
//! epoch computation is pure integer arithmetic that cannot fail, so that branch is unreachable
//! here by construction. The `catch (Exception e) {}` around the actual formatting (falling
//! through to `return "";`) *is* ported, collapsing a failed `buf.getInt(0)` read to `""`.
//!
//! `getValue(MemBuffer, Settings, int)` returns the same formatted `String` as
//! `getRepresentation` (matching the Java body, which literally calls `getRepresentation` and
//! returns it as the `Object` value); there is no `getValueClass` override in the Java source, so
//! none is added here either (the default `DataType.getValueClass`/`get_value_class` -- `None` --
//! already matches).
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `ClassTranslator.put(...)` legacy-name registration (needs `ClassTranslator`, not yet ported).

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::mem::MemBuffer;
use crate::util::date_utils::civil_from_days;

const MONTH_ABBREVIATIONS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Number of seconds from `1904-01-01 00:00:00 GMT` (the Mac OS timestamp epoch) to
/// `1970-01-01 00:00:00 GMT` (the Unix epoch). Standing in for `0 - macStartDate.getTime()`
/// converted from milliseconds to seconds; see the module docs for the derivation.
fn mac_epoch_offset_seconds() -> i64 {
    -crate::util::date_utils::days_from_civil(1904, 1, 1) * 86_400
}

/// Formats a raw 32-bit (already zero-extended to `i64`) Mac OS timestamp -- seconds since
/// `1904-01-01 00:00:00 GMT` -- as `"dd-MMM-yyyy HH:mm:ss"` in GMT.
///
/// Port of the body of `MacintoshTimeStampDataType.getRepresentation(MemBuffer, Settings, int)`
/// after the successful `buf.getInt(0)` read. See the module docs for what this replaces
/// (`SimpleDateFormat`/`Date`) and why it cannot fail the way the Java `catch (Exception e)`
/// anticipates.
fn format_mac_timestamp(date_in_seconds: i64) -> String {
    let unix_seconds = date_in_seconds - mac_epoch_offset_seconds();
    let (year, month, day) = civil_from_days(unix_seconds.div_euclid(86_400));
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!(
        "{day:02}-{}-{year:04} {hour:02}:{minute:02}:{second:02}",
        MONTH_ABBREVIATIONS[(month - 1) as usize]
    )
}

/// A datatype to interpret the Mac OS timestamp convention, which is based on the number of
/// seconds measured from January 1, 1904.
///
/// Port of `ghidra.program.model.data.MacintoshTimeStampDataType`. See the module docs for what
/// was ported, added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator.put(...)` legacy-name registration (needs `ClassTranslator`, not yet ported).
pub trait MacintoshTimeStampDataType: BuiltIn {
    /// Port of `MacintoshTimeStampDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn mac_time_stamp_description(&self) -> String {
        "The stamp follows the Macintosh time-measurement scheme (that is, the number of seconds \
         measured from January 1, 1904)."
            .to_string()
    }

    /// Port of `MacintoshTimeStampDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn mac_time_stamp_length(&self) -> i32 {
        4
    }

    /// Port of `MacintoshTimeStampDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"MacTime"`.
    fn mac_time_stamp_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "MacTime".to_string()
    }

    /// Port of `MacintoshTimeStampDataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`. `""` on a failed read, matching
    /// the Java `catch (Exception e) {}` falling through to `return "";`. See the module docs for
    /// why the `"unparsed date"` branch is unreachable here.
    fn mac_time_stamp_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (settings, length);
        match buf.get_int(0) {
            Ok(raw) => format_mac_timestamp(raw as u32 as i64),
            Err(_) => String::new(),
        }
    }

    /// Port of `MacintoshTimeStampDataType.getValue(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getValue(...)`. Boxes the same formatted string
    /// [`mac_time_stamp_representation`](Self::mac_time_stamp_representation) computes, matching
    /// the Java body (`return getRepresentation(buf, settings, length);`).
    fn mac_time_stamp_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        Some(Box::new(self.mac_time_stamp_representation(buf, settings, length)) as Box<dyn Any>)
    }

    /// Port of `MacintoshTimeStampDataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn mac_time_stamp_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn MacintoshTimeStampDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
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
    struct MockMacTimeStamp;

    impl DataType for MockMacTimeStamp {
        fn get_name(&self) -> String {
            "MacTime".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.mac_time_stamp_length()
        }
        fn get_description(&self) -> String {
            self.mac_time_stamp_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.mac_time_stamp_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.mac_time_stamp_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.mac_time_stamp_value(buf, settings, length)
        }
    }

    impl DataTypeImpl for MockMacTimeStamp {
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

    impl BuiltInDataType for MockMacTimeStamp {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockMacTimeStamp {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl MacintoshTimeStampDataType for MockMacTimeStamp {
        fn mac_time_stamp_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn MacintoshTimeStampDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockMacTimeStamp;
        let dyn_dt: &dyn MacintoshTimeStampDataType = &dt;
        assert_eq!(dyn_dt.mac_time_stamp_length(), 4);
        assert_eq!(DataType::get_length(dyn_dt), 4);
        assert_eq!(dyn_dt.mac_time_stamp_mnemonic(&MockSettings), "MacTime");
        assert!(dyn_dt.mac_time_stamp_description().contains("January 1, 1904"));
    }

    #[test]
    fn epoch_zero_formats_to_the_mac_epoch_date() {
        let dt = MockMacTimeStamp;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            dt.mac_time_stamp_representation(&buf, &MockSettings, 4),
            "01-Jan-1904 00:00:00"
        );
    }

    #[test]
    fn known_mac_timestamp_matches_expected_unix_date() {
        // 2082844800 mac-seconds after 1904-01-01 lands exactly on the Unix epoch,
        // 1970-01-01 00:00:00.
        let dt = MockMacTimeStamp;
        let seconds: u32 = 2_082_844_800;
        let buf = FixedMemBuffer(seconds.to_be_bytes().to_vec());
        assert_eq!(
            dt.mac_time_stamp_representation(&buf, &MockSettings, 4),
            "01-Jan-1970 00:00:00"
        );
    }

    #[test]
    fn representation_advances_seconds_correctly() {
        let dt = MockMacTimeStamp;
        // One day and one second past the mac epoch.
        let seconds: u32 = 86_401;
        let buf = FixedMemBuffer(seconds.to_be_bytes().to_vec());
        assert_eq!(
            dt.mac_time_stamp_representation(&buf, &MockSettings, 4),
            "02-Jan-1904 00:00:01"
        );
    }

    #[test]
    fn representation_is_empty_string_when_the_read_fails() {
        let dt = MockMacTimeStamp;
        let buf = FixedMemBuffer(vec![0x00, 0x00]);
        assert_eq!(dt.mac_time_stamp_representation(&buf, &MockSettings, 4), "");
    }

    #[test]
    fn value_boxes_the_same_string_as_the_representation() {
        let dt = MockMacTimeStamp;
        let buf = FixedMemBuffer(vec![0x00, 0x00, 0x00, 0x00]);
        let value = dt.mac_time_stamp_value(&buf, &MockSettings, 4).unwrap();
        assert_eq!(
            *value.downcast_ref::<String>().unwrap(),
            "01-Jan-1904 00:00:00".to_string()
        );
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockMacTimeStamp;
        let cloned = dt.mac_time_stamp_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}
