use crate::program::util::ProgramEvent;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_ADDED: ProgramEvent = ProgramEvent::DataTypeCategoryAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_REMOVED: ProgramEvent = ProgramEvent::DataTypeCategoryRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_RENAMED: ProgramEvent = ProgramEvent::DataTypeCategoryRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_MOVED: ProgramEvent = ProgramEvent::DataTypeCategoryMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_ADDED: ProgramEvent = ProgramEvent::DataTypeAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_REMOVED: ProgramEvent = ProgramEvent::DataTypeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_RENAMED: ProgramEvent = ProgramEvent::DataTypeRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_MOVED: ProgramEvent = ProgramEvent::DataTypeMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_CHANGED: ProgramEvent = ProgramEvent::DataTypeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_SETTING_CHANGED: ProgramEvent = ProgramEvent::DataTypeSettingChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_REPLACED: ProgramEvent = ProgramEvent::DataTypeReplaced;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deprecated_constants_reference_correct_events() {
        assert_eq!(DOCR_CATEGORY_ADDED, ProgramEvent::DataTypeCategoryAdded);
        assert_eq!(DOCR_CATEGORY_REMOVED, ProgramEvent::DataTypeCategoryRemoved);
        assert_eq!(DOCR_CATEGORY_RENAMED, ProgramEvent::DataTypeCategoryRenamed);
        assert_eq!(DOCR_CATEGORY_MOVED, ProgramEvent::DataTypeCategoryMoved);
        assert_eq!(DOCR_DATA_TYPE_ADDED, ProgramEvent::DataTypeAdded);
        assert_eq!(DOCR_DATA_TYPE_REMOVED, ProgramEvent::DataTypeRemoved);
        assert_eq!(DOCR_DATA_TYPE_RENAMED, ProgramEvent::DataTypeRenamed);
        assert_eq!(DOCR_DATA_TYPE_MOVED, ProgramEvent::DataTypeMoved);
        assert_eq!(DOCR_DATA_TYPE_CHANGED, ProgramEvent::DataTypeChanged);
        assert_eq!(DOCR_DATA_TYPE_SETTING_CHANGED, ProgramEvent::DataTypeSettingChanged);
        assert_eq!(DOCR_DATA_TYPE_REPLACED, ProgramEvent::DataTypeReplaced);
    }
}
