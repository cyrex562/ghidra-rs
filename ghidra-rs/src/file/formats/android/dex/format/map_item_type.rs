/// Map item type codes for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.MapItemType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItemType;

impl MapItemType {
    pub const K_DEX_TYPE_HEADER_ITEM: i16 = 0x0000;
    pub const K_DEX_TYPE_STRING_ID_ITEM: i16 = 0x0001;
    pub const K_DEX_TYPE_TYPE_ID_ITEM: i16 = 0x0002;
    pub const K_DEX_TYPE_PROTO_ID_ITEM: i16 = 0x0003;
    pub const K_DEX_TYPE_FIELD_ID_ITEM: i16 = 0x0004;
    pub const K_DEX_TYPE_METHOD_ID_ITEM: i16 = 0x0005;
    pub const K_DEX_TYPE_CLASS_DEF_ITEM: i16 = 0x0006;
    pub const K_DEX_TYPE_CALL_SITE_ID_ITEM: i16 = 0x0007;
    pub const K_DEX_TYPE_METHOD_HANDLE_ITEM: i16 = 0x0008;
    pub const K_DEX_TYPE_MAP_LIST: i16 = 0x1000;
    pub const K_DEX_TYPE_TYPE_LIST: i16 = 0x1001;
    pub const K_DEX_TYPE_ANNOTATION_SET_REF_LIST: i16 = 0x1002;
    pub const K_DEX_TYPE_ANNOTATION_SET_ITEM: i16 = 0x1003;
    pub const K_DEX_TYPE_CLASS_DATA_ITEM: i16 = 0x2000;
    pub const K_DEX_TYPE_CODE_ITEM: i16 = 0x2001;
    pub const K_DEX_TYPE_STRING_DATA_ITEM: i16 = 0x2002;
    pub const K_DEX_TYPE_DEBUG_INFO_ITEM: i16 = 0x2003;
    pub const K_DEX_TYPE_ANNOTATION_ITEM: i16 = 0x2004;
    pub const K_DEX_TYPE_ENCODED_ARRAY_ITEM: i16 = 0x2005;
    pub const K_DEX_TYPE_ANNOTATIONS_DIRECTORY_ITEM: i16 = 0x2006;
    /// 0xF000 cast to signed i16 = -4096, matching Java `(short) 0xF000`.
    pub const K_DEX_TYPE_HIDDENAPI_CLASS_DATA: i16 = -4096;

    /// Returns the field name for the given type code, or `"MapItemType:<type>"` if unknown.
    ///
    /// Replicates the reflection-based `toString(short)` from the Java source, preserving
    /// declaration order.
    pub fn to_string(type_: i16) -> String {
        const TYPES: &[(&str, i16)] = &[
            ("kDexTypeHeaderItem", MapItemType::K_DEX_TYPE_HEADER_ITEM),
            ("kDexTypeStringIdItem", MapItemType::K_DEX_TYPE_STRING_ID_ITEM),
            ("kDexTypeTypeIdItem", MapItemType::K_DEX_TYPE_TYPE_ID_ITEM),
            ("kDexTypeProtoIdItem", MapItemType::K_DEX_TYPE_PROTO_ID_ITEM),
            ("kDexTypeFieldIdItem", MapItemType::K_DEX_TYPE_FIELD_ID_ITEM),
            ("kDexTypeMethodIdItem", MapItemType::K_DEX_TYPE_METHOD_ID_ITEM),
            ("kDexTypeClassDefItem", MapItemType::K_DEX_TYPE_CLASS_DEF_ITEM),
            ("kDexTypeCallSiteIdItem", MapItemType::K_DEX_TYPE_CALL_SITE_ID_ITEM),
            ("kDexTypeMethodHandleItem", MapItemType::K_DEX_TYPE_METHOD_HANDLE_ITEM),
            ("kDexTypeMapList", MapItemType::K_DEX_TYPE_MAP_LIST),
            ("kDexTypeTypeList", MapItemType::K_DEX_TYPE_TYPE_LIST),
            ("kDexTypeAnnotationSetRefList", MapItemType::K_DEX_TYPE_ANNOTATION_SET_REF_LIST),
            ("kDexTypeAnnotationSetItem", MapItemType::K_DEX_TYPE_ANNOTATION_SET_ITEM),
            ("kDexTypeClassDataItem", MapItemType::K_DEX_TYPE_CLASS_DATA_ITEM),
            ("kDexTypeCodeItem", MapItemType::K_DEX_TYPE_CODE_ITEM),
            ("kDexTypeStringDataItem", MapItemType::K_DEX_TYPE_STRING_DATA_ITEM),
            ("kDexTypeDebugInfoItem", MapItemType::K_DEX_TYPE_DEBUG_INFO_ITEM),
            ("kDexTypeAnnotationItem", MapItemType::K_DEX_TYPE_ANNOTATION_ITEM),
            ("kDexTypeEncodedArrayItem", MapItemType::K_DEX_TYPE_ENCODED_ARRAY_ITEM),
            ("kDexTypeAnnotationsDirectoryItem", MapItemType::K_DEX_TYPE_ANNOTATIONS_DIRECTORY_ITEM),
            ("kDexTypeHiddenapiClassData", MapItemType::K_DEX_TYPE_HIDDENAPI_CLASS_DATA),
        ];
        for &(name, value) in TYPES {
            if value == type_ {
                return name.to_string();
            }
        }
        format!("MapItemType:{}", type_)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(MapItemType::K_DEX_TYPE_HEADER_ITEM, 0x0000);
        assert_eq!(MapItemType::K_DEX_TYPE_STRING_ID_ITEM, 0x0001);
        assert_eq!(MapItemType::K_DEX_TYPE_TYPE_ID_ITEM, 0x0002);
        assert_eq!(MapItemType::K_DEX_TYPE_PROTO_ID_ITEM, 0x0003);
        assert_eq!(MapItemType::K_DEX_TYPE_FIELD_ID_ITEM, 0x0004);
        assert_eq!(MapItemType::K_DEX_TYPE_METHOD_ID_ITEM, 0x0005);
        assert_eq!(MapItemType::K_DEX_TYPE_CLASS_DEF_ITEM, 0x0006);
        assert_eq!(MapItemType::K_DEX_TYPE_CALL_SITE_ID_ITEM, 0x0007);
        assert_eq!(MapItemType::K_DEX_TYPE_METHOD_HANDLE_ITEM, 0x0008);
        assert_eq!(MapItemType::K_DEX_TYPE_MAP_LIST, 0x1000);
        assert_eq!(MapItemType::K_DEX_TYPE_TYPE_LIST, 0x1001);
        assert_eq!(MapItemType::K_DEX_TYPE_ANNOTATION_SET_REF_LIST, 0x1002);
        assert_eq!(MapItemType::K_DEX_TYPE_ANNOTATION_SET_ITEM, 0x1003);
        assert_eq!(MapItemType::K_DEX_TYPE_CLASS_DATA_ITEM, 0x2000);
        assert_eq!(MapItemType::K_DEX_TYPE_CODE_ITEM, 0x2001);
        assert_eq!(MapItemType::K_DEX_TYPE_STRING_DATA_ITEM, 0x2002);
        assert_eq!(MapItemType::K_DEX_TYPE_DEBUG_INFO_ITEM, 0x2003);
        assert_eq!(MapItemType::K_DEX_TYPE_ANNOTATION_ITEM, 0x2004);
        assert_eq!(MapItemType::K_DEX_TYPE_ENCODED_ARRAY_ITEM, 0x2005);
        assert_eq!(MapItemType::K_DEX_TYPE_ANNOTATIONS_DIRECTORY_ITEM, 0x2006);
        assert_eq!(MapItemType::K_DEX_TYPE_HIDDENAPI_CLASS_DATA, -4096i16);
    }

    #[test]
    fn hiddenapi_matches_java_cast() {
        // Java: (short) 0xF000 == -4096
        assert_eq!(MapItemType::K_DEX_TYPE_HIDDENAPI_CLASS_DATA, 0xF000u16 as i16);
    }

    #[test]
    fn to_string_known_types() {
        assert_eq!(MapItemType::to_string(0x0000), "kDexTypeHeaderItem");
        assert_eq!(MapItemType::to_string(0x0001), "kDexTypeStringIdItem");
        assert_eq!(MapItemType::to_string(0x0008), "kDexTypeMethodHandleItem");
        assert_eq!(MapItemType::to_string(0x1000), "kDexTypeMapList");
        assert_eq!(MapItemType::to_string(0x2000), "kDexTypeClassDataItem");
        assert_eq!(MapItemType::to_string(0x2006), "kDexTypeAnnotationsDirectoryItem");
        assert_eq!(MapItemType::to_string(-4096), "kDexTypeHiddenapiClassData");
    }

    #[test]
    fn to_string_unknown_type() {
        assert_eq!(MapItemType::to_string(0x0009), "MapItemType:9");
        assert_eq!(MapItemType::to_string(0x0100), "MapItemType:256");
    }

    #[test]
    fn to_string_hiddenapi_via_cast() {
        let v = 0xF000u16 as i16;
        assert_eq!(MapItemType::to_string(v), "kDexTypeHiddenapiClassData");
    }
}
