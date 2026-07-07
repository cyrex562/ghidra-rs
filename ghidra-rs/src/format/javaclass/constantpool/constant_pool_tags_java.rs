//! Java constant pool tag types.
//!
//! Ported from `ghidra.javaclass.format.constantpool.ConstantPoolTagsJava`.

/// Constant pool tag for Class references (value 7).
pub const CONSTANT_CLASS: u8 = 7;

/// Constant pool tag for Field references (value 9).
pub const CONSTANT_FIELDREF: u8 = 9;

/// Constant pool tag for Method references (value 10).
pub const CONSTANT_METHODREF: u8 = 10;

/// Constant pool tag for Interface Method references (value 11).
pub const CONSTANT_INTERFACE_METHODREF: u8 = 11;

/// Constant pool tag for String literals (value 8).
pub const CONSTANT_STRING: u8 = 8;

/// Constant pool tag for Integer constants (value 3).
pub const CONSTANT_INTEGER: u8 = 3;

/// Constant pool tag for Float constants (value 4).
pub const CONSTANT_FLOAT: u8 = 4;

/// Constant pool tag for Long constants (value 5).
pub const CONSTANT_LONG: u8 = 5;

/// Constant pool tag for Double constants (value 6).
pub const CONSTANT_DOUBLE: u8 = 6;

/// Constant pool tag for Name and Type descriptions (value 12).
pub const CONSTANT_NAME_AND_TYPE: u8 = 12;

/// Constant pool tag for UTF-8 strings (value 1).
pub const CONSTANT_UTF8: u8 = 1;

/// Constant pool tag for Method Handles (value 15).
pub const CONSTANT_METHOD_HANDLE: u8 = 15;

/// Constant pool tag for Method Types (value 16).
pub const CONSTANT_METHOD_TYPE: u8 = 16;

/// Constant pool tag for Dynamic constants (value 17).
pub const CONSTANT_DYNAMIC: u8 = 17;

/// Constant pool tag for InvokeDynamic call sites (value 18).
pub const CONSTANT_INVOKE_DYNAMIC: u8 = 18;

/// Constant pool tag for Module references (value 19).
pub const CONSTANT_MODULE: u8 = 19;

/// Constant pool tag for Package references (value 20).
pub const CONSTANT_PACKAGE: u8 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_pool_tag_values_are_correct() {
        assert_eq!(CONSTANT_UTF8, 1);
        assert_eq!(CONSTANT_INTEGER, 3);
        assert_eq!(CONSTANT_FLOAT, 4);
        assert_eq!(CONSTANT_LONG, 5);
        assert_eq!(CONSTANT_DOUBLE, 6);
        assert_eq!(CONSTANT_CLASS, 7);
        assert_eq!(CONSTANT_STRING, 8);
        assert_eq!(CONSTANT_FIELDREF, 9);
        assert_eq!(CONSTANT_METHODREF, 10);
        assert_eq!(CONSTANT_INTERFACE_METHODREF, 11);
        assert_eq!(CONSTANT_NAME_AND_TYPE, 12);
        assert_eq!(CONSTANT_METHOD_HANDLE, 15);
        assert_eq!(CONSTANT_METHOD_TYPE, 16);
        assert_eq!(CONSTANT_DYNAMIC, 17);
        assert_eq!(CONSTANT_INVOKE_DYNAMIC, 18);
        assert_eq!(CONSTANT_MODULE, 19);
        assert_eq!(CONSTANT_PACKAGE, 20);
    }

    #[test]
    fn all_tags_are_distinct() {
        let tags = [
            CONSTANT_UTF8,
            CONSTANT_INTEGER,
            CONSTANT_FLOAT,
            CONSTANT_LONG,
            CONSTANT_DOUBLE,
            CONSTANT_CLASS,
            CONSTANT_STRING,
            CONSTANT_FIELDREF,
            CONSTANT_METHODREF,
            CONSTANT_INTERFACE_METHODREF,
            CONSTANT_NAME_AND_TYPE,
            CONSTANT_METHOD_HANDLE,
            CONSTANT_METHOD_TYPE,
            CONSTANT_DYNAMIC,
            CONSTANT_INVOKE_DYNAMIC,
            CONSTANT_MODULE,
            CONSTANT_PACKAGE,
        ];
        let mut sorted = tags.to_vec();
        let original_len = sorted.len();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "constant pool tags should all be distinct"
        );
    }

    #[test]
    fn tags_match_java_class_file_specification() {
        assert_eq!(CONSTANT_UTF8, 1);
        assert_eq!(CONSTANT_INTEGER, 3);
        assert_eq!(CONSTANT_FLOAT, 4);
        assert_eq!(CONSTANT_LONG, 5);
        assert_eq!(CONSTANT_DOUBLE, 6);
        assert_eq!(CONSTANT_CLASS, 7);
        assert_eq!(CONSTANT_STRING, 8);
        assert_eq!(CONSTANT_FIELDREF, 9);
        assert_eq!(CONSTANT_METHODREF, 10);
        assert_eq!(CONSTANT_INTERFACE_METHODREF, 11);
        assert_eq!(CONSTANT_NAME_AND_TYPE, 12);
        assert_eq!(CONSTANT_METHOD_HANDLE, 15);
        assert_eq!(CONSTANT_METHOD_TYPE, 16);
        assert_eq!(CONSTANT_DYNAMIC, 17);
        assert_eq!(CONSTANT_INVOKE_DYNAMIC, 18);
        assert_eq!(CONSTANT_MODULE, 19);
        assert_eq!(CONSTANT_PACKAGE, 20);
    }

    #[test]
    fn numeric_reference_tags() {
        assert!(CONSTANT_FIELDREF > CONSTANT_STRING);
        assert!(CONSTANT_METHODREF > CONSTANT_FIELDREF);
        assert!(CONSTANT_INTERFACE_METHODREF > CONSTANT_METHODREF);
    }
}
