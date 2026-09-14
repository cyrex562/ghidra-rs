//! Port of `ghidra.app.util.bin.format.pe.rich.RichHeaderRecord`.

use crate::format::pe::rich::comp_id::CompId;
use crate::format::seam_stubs::RichHeaderUtils;

/// An element of a `RichTable`.
///
/// Port of `ghidra.app.util.bin.format.pe.rich.RichHeaderRecord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RichHeaderRecord {
    record_index: i32,
    comp_id: CompId,
    count: i32,
}

impl RichHeaderRecord {
    /// Port of `RichHeaderRecord(int recordIndex, int compid, int count)`.
    pub fn new(record_index: i32, compid: i32, count: i32) -> Self {
        RichHeaderRecord { record_index, comp_id: CompId::new(compid), count }
    }

    /// Port of `getIndex()`.
    pub fn get_index(&self) -> i32 {
        self.record_index
    }

    /// Port of `getCompId()`.
    pub fn get_comp_id(&self) -> CompId {
        self.comp_id
    }

    /// Port of `getObjectCount()`.
    pub fn get_object_count(&self) -> i32 {
        self.count
    }

    /// Port of `toString()`: `compid + " Count: " + count`, where Java's implicit string
    /// concatenation invokes `CompId.toString()`, i.e.
    /// `getProductDescription() + ", build " + getBuildNumber()`.
    ///
    /// Java reaches `RichHeaderUtils.getProduct(int)` (inside `getProductDescription()`) via a
    /// *static* method call, so `RichHeaderRecord.toString()` needs no extra parameter there.
    /// This crate's already-ported [`CompId::product_description`] instead takes an injected
    /// `&dyn RichHeaderUtils` (see that method's own doc comment for why), so producing the
    /// equivalent full display string here requires the same injected dependency -- there is no
    /// parameterless `impl Display` that could reach it without one. `CompId` itself has no
    /// ported `to_string`/`Display` (only raw accessors plus `product_description`), so this
    /// reproduces `CompId.toString()`'s exact concatenation inline rather than delegating to a
    /// `CompId` display impl that doesn't exist.
    pub fn to_display_string(&self, rich_header_utils: &dyn RichHeaderUtils) -> String {
        format!(
            "{}, build {} Count: {}",
            self.comp_id.product_description(rich_header_utils),
            self.comp_id.build_number(),
            self.count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::RichProduct;

    struct MockRichHeaderUtils;

    impl RichHeaderUtils for MockRichHeaderUtils {
        fn get_product(&self, _id: i32) -> Option<Box<dyn RichProduct>> {
            None
        }
    }

    #[test]
    fn new_derives_comp_id_from_the_raw_value() {
        let record = RichHeaderRecord::new(0, 0x0009_0042, 3);
        assert_eq!(record.get_index(), 0);
        assert_eq!(record.get_comp_id().value(), 0x0009_0042);
        assert_eq!(record.get_object_count(), 3);
    }

    #[test]
    fn get_index_and_get_object_count_are_independent_of_comp_id() {
        let record = RichHeaderRecord::new(5, 0x1234_5678, 42);
        assert_eq!(record.get_index(), 5);
        assert_eq!(record.get_object_count(), 42);
    }

    #[test]
    fn to_display_string_matches_java_to_string_format() {
        // compid.toString() = getProductDescription() + ", build " + getBuildNumber(); the
        // record appends " Count: " + count on top.
        let record = RichHeaderRecord::new(0, 0x0009_0042, 3);
        let utils = MockRichHeaderUtils;

        let display = record.to_display_string(&utils);

        // build_number() of 0x00090042 is 0x0042 == 66, formatted in decimal (matching Java's
        // plain int-to-string concatenation, not hex).
        assert!(display.contains("Unknown Product"));
        assert!(display.contains(", build 66"));
        assert!(display.ends_with("Count: 3"));
    }

    #[test]
    fn to_display_string_includes_object_count() {
        let record = RichHeaderRecord::new(0, 0x0001_0000, 99);
        let utils = MockRichHeaderUtils;

        assert!(record.to_display_string(&utils).ends_with("Count: 99"));
    }
}
