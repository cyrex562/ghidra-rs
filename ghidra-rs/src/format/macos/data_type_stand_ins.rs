//! Crate-private stand-ins for the string `DataType` singletons the macOS resource-fork and CFM
//! `toDataType()` implementations reference.
//!
//! Java's `StructConverter.STRING` (`new StringDataType()`) and `new PascalString255DataType()`
//! are string data types, which are not ported yet: they sit on `AbstractStringDataType` and a
//! faithful `StringDataInstance`, neither of which exists as a concrete type in this crate. Until
//! they land, the structures built here use a name-and-length stand-in for those two types only;
//! only the name and length are observable through the resulting structure. (The numeric
//! primitives these files use -- byte, word, dword, qword, uint3 -- are the real built-ins.)

use crate::program::model::data::data_type::DataType;

/// A named, fixed-length string-type stand-in (see the module docs).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrimitiveDt {
    name: &'static str,
    length: i32,
}

impl PrimitiveDt {
    /// Stand-in for `StructConverter.STRING` / `new StringDataType()`. The component length is
    /// supplied at each `add` call, as with Java's `add(DataType, int, String, String)` overload.
    pub(crate) const STRING: PrimitiveDt = PrimitiveDt { name: "string", length: 1 };
    /// Stand-in for `new PascalString255DataType()`. The component length is supplied at the `add`
    /// call.
    pub(crate) const PASCAL_STRING255: PrimitiveDt =
        PrimitiveDt { name: "PascalString255", length: 1 };

    /// Boxes this stand-in for a `Composite::add*` call.
    pub(crate) fn boxed(self) -> Box<dyn DataType> {
        Box::new(self)
    }
}

impl DataType for PrimitiveDt {
    fn get_name(&self) -> String {
        self.name.to_string()
    }

    fn get_length(&self) -> i32 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stand_ins_report_java_names_and_lengths() {
        assert_eq!(PrimitiveDt::STRING.get_name(), "string");
        assert_eq!(PrimitiveDt::STRING.boxed().get_length(), 1);
        assert_eq!(PrimitiveDt::PASCAL_STRING255.get_name(), "PascalString255");
    }
}
