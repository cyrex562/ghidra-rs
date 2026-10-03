use crate::program::seam_stubs::DataTypeInfoLike;
use std::fmt;
use std::sync::Arc;

/// Port of `ghidra.program.model.util.DataTypeInfo`.
///
/// Associates a length and alignment with some opaque data type identity handle. The Java
/// `dataTypeHandle` field is `Object` and may be `null`; this port follows the precedent
/// already established by [`DataTypeInfoLike`] (used by the sibling
/// [`CompositeDataTypeElementInfo`](super::composite_data_type_element_info::CompositeDataTypeElementInfo)
/// trait, which was ported first as a cycle cut-point) of requiring a non-optional
/// `Arc<dyn Display + Send + Sync>` handle, so the Java null-handle branches of `equals`/
/// `hashCode` are unreachable here by construction.
///
/// `Object.equals`/`Object.hashCode` on the handle (used when no override is present) are
/// stood in for by comparing/hashing the handle's `Display` rendering, matching the
/// convention already used by `CompositeDataTypeElementInfo::data_equals`.
#[derive(Clone)]
pub struct DataTypeInfo {
    pub(crate) data_type_handle: Arc<dyn fmt::Display + Send + Sync>,
    pub(crate) data_type_length: i32,
    pub(crate) data_type_alignment: i32,
}

impl DataTypeInfo {
    /// Port of the public constructor
    /// `DataTypeInfo(Object dataTypeHandle, int dataTypeLength, int dataTypeAlignment)`.
    pub fn new(
        data_type_handle: Arc<dyn fmt::Display + Send + Sync>,
        data_type_length: i32,
        data_type_alignment: i32,
    ) -> Self {
        Self {
            data_type_handle,
            data_type_length,
            data_type_alignment,
        }
    }

    /// Port of the package-private "copy" constructor `DataTypeInfo(DataTypeInfo
    /// dataTypeInfo)`, documented in Java as "used only by CompositeDataTypeElementInfo".
    pub fn copy_of(other: &DataTypeInfo) -> Self {
        Self {
            data_type_handle: other.data_type_handle.clone(),
            data_type_length: other.data_type_length,
            data_type_alignment: other.data_type_alignment,
        }
    }

    /// Port of `hashCode()`, reproducing Java's exact 31-multiplier accumulation (including
    /// wraparound on overflow, which `int` arithmetic does silently in Java).
    pub fn hash_code(&self) -> i32 {
        let prime: i32 = 31;
        let mut result: i32 = 1;
        result = prime.wrapping_mul(result).wrapping_add(self.data_type_alignment);
        result = prime
            .wrapping_mul(result)
            .wrapping_add(java_string_hash(&self.data_type_handle.to_string()));
        result = prime.wrapping_mul(result).wrapping_add(self.data_type_length);
        result
    }
}

impl DataTypeInfoLike for DataTypeInfo {
    fn get_data_type_handle(&self) -> Arc<dyn fmt::Display + Send + Sync> {
        self.data_type_handle.clone()
    }

    fn get_data_type_length(&self) -> i32 {
        self.data_type_length
    }

    fn get_data_type_alignment(&self) -> i32 {
        self.data_type_alignment
    }
}

impl PartialEq for DataTypeInfo {
    /// Port of `equals(Object obj)`.
    fn eq(&self, other: &Self) -> bool {
        self.data_type_alignment == other.data_type_alignment
            && self.data_type_length == other.data_type_length
            && self.data_type_handle.to_string() == other.data_type_handle.to_string()
    }
}

impl Eq for DataTypeInfo {}

impl fmt::Debug for DataTypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataTypeInfo")
            .field("data_type_handle", &self.data_type_handle.to_string())
            .field("data_type_length", &self.data_type_length)
            .field("data_type_alignment", &self.data_type_alignment)
            .finish()
    }
}

/// Stand-in for `String.hashCode()`, needed since `Object.hashCode()` has no general Rust
/// equivalent; used here only to hash the handle's `Display` rendering (see the type-level
/// docs). Mirrors the same helper already duplicated per-file elsewhere in this crate (e.g.
/// `program::model::gclass::class_id::java_string_hash`).
fn java_string_hash(s: &str) -> i32 {
    let mut hash = 0i32;
    for c in s.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(c as i32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(s: &str) -> Arc<dyn fmt::Display + Send + Sync> {
        Arc::new(s.to_string())
    }

    #[test]
    fn getters_return_constructor_values() {
        let info = DataTypeInfo::new(handle("intHandle"), 4, 4);
        assert_eq!(info.get_data_type_handle().to_string(), "intHandle");
        assert_eq!(info.get_data_type_length(), 4);
        assert_eq!(info.get_data_type_alignment(), 4);
    }

    #[test]
    fn copy_of_reproduces_all_fields() {
        let original = DataTypeInfo::new(handle("myField"), 8, 2);
        let copy = DataTypeInfo::copy_of(&original);
        assert_eq!(copy, original);
        assert_eq!(copy.get_data_type_length(), 8);
        assert_eq!(copy.get_data_type_alignment(), 2);
    }

    #[test]
    fn equals_true_for_same_field_values() {
        let a = DataTypeInfo::new(handle("myField"), 8, 2);
        let b = DataTypeInfo::new(handle("myField"), 8, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn equals_false_for_differing_alignment() {
        let a = DataTypeInfo::new(handle("myField"), 8, 2);
        let b = DataTypeInfo::new(handle("myField"), 8, 4);
        assert_ne!(a, b);
    }

    #[test]
    fn equals_false_for_differing_length() {
        let a = DataTypeInfo::new(handle("myField"), 8, 2);
        let b = DataTypeInfo::new(handle("myField"), 16, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn equals_false_for_differing_handle() {
        let a = DataTypeInfo::new(handle("myField"), 8, 2);
        let b = DataTypeInfo::new(handle("otherField"), 8, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_code_matches_for_equal_instances() {
        let a = DataTypeInfo::new(handle("myField"), 8, 2);
        let b = DataTypeInfo::new(handle("myField"), 8, 2);
        assert_eq!(a.hash_code(), b.hash_code());
    }

    /// Java's `hashCode()` computes `31 * (31 * (31 * 1 + alignment) + handle.hashCode()) +
    /// length`. Verify the exact arithmetic against a hand-computed value for a known input,
    /// so a future refactor can't silently change the accumulation order or multiplier.
    #[test]
    fn hash_code_matches_java_formula_for_known_input() {
        let info = DataTypeInfo::new(handle("ab"), 8, 2);
        // "ab".hashCode() in Java == 97 * 31 + 98 = 3105.
        let handle_hash = java_string_hash("ab");
        assert_eq!(handle_hash, 3105);

        let mut expected: i32 = 1;
        expected = 31i32.wrapping_mul(expected).wrapping_add(2); // alignment
        expected = 31i32.wrapping_mul(expected).wrapping_add(handle_hash); // handle
        expected = 31i32.wrapping_mul(expected).wrapping_add(8); // length

        assert_eq!(info.hash_code(), expected);
    }
}
