/// Map item type code constants for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.MapItemTypeCodes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItemTypeCodes;

impl MapItemTypeCodes {
    pub const TYPE_HEADER_ITEM: i16 = 0x0000;
    pub const TYPE_STRING_ID_ITEM: i16 = 0x0001;
    pub const TYPE_TYPE_ID_ITEM: i16 = 0x0002;
    pub const TYPE_PROTO_ID_ITEM: i16 = 0x0003;
    pub const TYPE_FIELD_ID_ITEM: i16 = 0x0004;
    pub const TYPE_METHOD_ID_ITEM: i16 = 0x0005;
    pub const TYPE_CLASS_DEF_ITEM: i16 = 0x0006;
    pub const TYPE_MAP_LIST: i16 = 0x1000;
    pub const TYPE_TYPE_LIST: i16 = 0x1001;
    pub const TYPE_ANNOTATION_SET_REF_LIST: i16 = 0x1002;
    pub const TYPE_ANNOTATION_SET_ITEM: i16 = 0x1003;
    pub const TYPE_CLASS_DATA_ITEM: i16 = 0x2000;
    pub const TYPE_CODE_ITEM: i16 = 0x2001;
    pub const TYPE_STRING_DATA_ITEM: i16 = 0x2002;
    pub const TYPE_DEBUG_INFO_ITEM: i16 = 0x2003;
    pub const TYPE_ANNOTATION_ITEM: i16 = 0x2004;
    pub const TYPE_ENCODED_ARRAY_ITEM: i16 = 0x2005;
    pub const TYPE_ANNOTATIONS_DIRECTORY_ITEM: i16 = 0x2006;

    /// Returns the field name for the given type code, or `"Type:<type>"` if unknown.
    ///
    /// Replicates the reflection-based `toString(short)` from the Java source, preserving
    /// declaration order.
    pub fn to_string(type_: i16) -> String {
        const TYPES: &[(&str, i16)] = &[
            ("TYPE_HEADER_ITEM", MapItemTypeCodes::TYPE_HEADER_ITEM),
            ("TYPE_STRING_ID_ITEM", MapItemTypeCodes::TYPE_STRING_ID_ITEM),
            ("TYPE_TYPE_ID_ITEM", MapItemTypeCodes::TYPE_TYPE_ID_ITEM),
            ("TYPE_PROTO_ID_ITEM", MapItemTypeCodes::TYPE_PROTO_ID_ITEM),
            ("TYPE_FIELD_ID_ITEM", MapItemTypeCodes::TYPE_FIELD_ID_ITEM),
            ("TYPE_METHOD_ID_ITEM", MapItemTypeCodes::TYPE_METHOD_ID_ITEM),
            ("TYPE_CLASS_DEF_ITEM", MapItemTypeCodes::TYPE_CLASS_DEF_ITEM),
            ("TYPE_MAP_LIST", MapItemTypeCodes::TYPE_MAP_LIST),
            ("TYPE_TYPE_LIST", MapItemTypeCodes::TYPE_TYPE_LIST),
            ("TYPE_ANNOTATION_SET_REF_LIST", MapItemTypeCodes::TYPE_ANNOTATION_SET_REF_LIST),
            ("TYPE_ANNOTATION_SET_ITEM", MapItemTypeCodes::TYPE_ANNOTATION_SET_ITEM),
            ("TYPE_CLASS_DATA_ITEM", MapItemTypeCodes::TYPE_CLASS_DATA_ITEM),
            ("TYPE_CODE_ITEM", MapItemTypeCodes::TYPE_CODE_ITEM),
            ("TYPE_STRING_DATA_ITEM", MapItemTypeCodes::TYPE_STRING_DATA_ITEM),
            ("TYPE_DEBUG_INFO_ITEM", MapItemTypeCodes::TYPE_DEBUG_INFO_ITEM),
            ("TYPE_ANNOTATION_ITEM", MapItemTypeCodes::TYPE_ANNOTATION_ITEM),
            ("TYPE_ENCODED_ARRAY_ITEM", MapItemTypeCodes::TYPE_ENCODED_ARRAY_ITEM),
            ("TYPE_ANNOTATIONS_DIRECTORY_ITEM", MapItemTypeCodes::TYPE_ANNOTATIONS_DIRECTORY_ITEM),
        ];
        for &(name, value) in TYPES {
            if value == type_ {
                return name.to_string();
            }
        }
        format!("Type:{}", type_)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(MapItemTypeCodes::TYPE_HEADER_ITEM, 0x0000);
        assert_eq!(MapItemTypeCodes::TYPE_STRING_ID_ITEM, 0x0001);
        assert_eq!(MapItemTypeCodes::TYPE_TYPE_ID_ITEM, 0x0002);
        assert_eq!(MapItemTypeCodes::TYPE_PROTO_ID_ITEM, 0x0003);
        assert_eq!(MapItemTypeCodes::TYPE_FIELD_ID_ITEM, 0x0004);
        assert_eq!(MapItemTypeCodes::TYPE_METHOD_ID_ITEM, 0x0005);
        assert_eq!(MapItemTypeCodes::TYPE_CLASS_DEF_ITEM, 0x0006);
        assert_eq!(MapItemTypeCodes::TYPE_MAP_LIST, 0x1000);
        assert_eq!(MapItemTypeCodes::TYPE_TYPE_LIST, 0x1001);
        assert_eq!(MapItemTypeCodes::TYPE_ANNOTATION_SET_REF_LIST, 0x1002);
        assert_eq!(MapItemTypeCodes::TYPE_ANNOTATION_SET_ITEM, 0x1003);
        assert_eq!(MapItemTypeCodes::TYPE_CLASS_DATA_ITEM, 0x2000);
        assert_eq!(MapItemTypeCodes::TYPE_CODE_ITEM, 0x2001);
        assert_eq!(MapItemTypeCodes::TYPE_STRING_DATA_ITEM, 0x2002);
        assert_eq!(MapItemTypeCodes::TYPE_DEBUG_INFO_ITEM, 0x2003);
        assert_eq!(MapItemTypeCodes::TYPE_ANNOTATION_ITEM, 0x2004);
        assert_eq!(MapItemTypeCodes::TYPE_ENCODED_ARRAY_ITEM, 0x2005);
        assert_eq!(MapItemTypeCodes::TYPE_ANNOTATIONS_DIRECTORY_ITEM, 0x2006);
    }

    #[test]
    fn to_string_known_types() {
        assert_eq!(MapItemTypeCodes::to_string(0x0000), "TYPE_HEADER_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0001), "TYPE_STRING_ID_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0002), "TYPE_TYPE_ID_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0003), "TYPE_PROTO_ID_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0004), "TYPE_FIELD_ID_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0005), "TYPE_METHOD_ID_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x0006), "TYPE_CLASS_DEF_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x1000), "TYPE_MAP_LIST");
        assert_eq!(MapItemTypeCodes::to_string(0x1001), "TYPE_TYPE_LIST");
        assert_eq!(MapItemTypeCodes::to_string(0x1002), "TYPE_ANNOTATION_SET_REF_LIST");
        assert_eq!(MapItemTypeCodes::to_string(0x1003), "TYPE_ANNOTATION_SET_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2000), "TYPE_CLASS_DATA_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2001), "TYPE_CODE_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2002), "TYPE_STRING_DATA_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2003), "TYPE_DEBUG_INFO_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2004), "TYPE_ANNOTATION_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2005), "TYPE_ENCODED_ARRAY_ITEM");
        assert_eq!(MapItemTypeCodes::to_string(0x2006), "TYPE_ANNOTATIONS_DIRECTORY_ITEM");
    }

    #[test]
    fn to_string_unknown_type() {
        assert_eq!(MapItemTypeCodes::to_string(0x0007), "Type:7");
        assert_eq!(MapItemTypeCodes::to_string(0x0100), "Type:256");
        assert_eq!(MapItemTypeCodes::to_string(-1), "Type:-1");
    }
}
