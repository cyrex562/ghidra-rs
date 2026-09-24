//! Crate-private stand-ins for the primitive `DataType` singletons the macOS resource-fork and
//! CFM `toDataType()` implementations reference.
//!
//! Java's `StructConverter` exposes `BYTE`, `WORD`, `DWORD` and `STRING`, and several of these
//! classes also instantiate `UnsignedInteger3DataType`/`PascalString255DataType`. This crate has not
//! ported concrete singletons for those yet (see `app::util::bin::struct_converter`'s docs), so --
//! following the identical per-file stand-ins in `cram_fs_inode.rs`, `coff_archive_member_header.rs`
//! and `omf2or4.rs` -- the structures built here use a name-and-length stand-in. Only the name and
//! length are observable through the resulting structure. They are shared across this module tree
//! instead of being copied into each of the files that need them.

use crate::program::model::data::data_type::DataType;

/// A named, fixed-length primitive stand-in (see the module docs).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrimitiveDt {
    name: &'static str,
    length: i32,
}

impl PrimitiveDt {
    /// Stand-in for `StructConverter.BYTE`.
    pub(crate) const BYTE: PrimitiveDt = PrimitiveDt { name: "byte", length: 1 };
    /// Stand-in for `StructConverter.WORD`.
    pub(crate) const WORD: PrimitiveDt = PrimitiveDt { name: "word", length: 2 };
    /// Stand-in for `StructConverter.DWORD`.
    pub(crate) const DWORD: PrimitiveDt = PrimitiveDt { name: "dword", length: 4 };
    /// Stand-in for `StructConverter.STRING` / `new StringDataType()`. The component length is
    /// supplied at each `add` call, as with Java's `add(DataType, int, String, String)` overload.
    pub(crate) const STRING: PrimitiveDt = PrimitiveDt { name: "string", length: 1 };
    /// Stand-in for `new UnsignedInteger3DataType()`.
    pub(crate) const UINT3: PrimitiveDt = PrimitiveDt { name: "uint3", length: 3 };
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
        assert_eq!(PrimitiveDt::WORD.get_name(), "word");
        assert_eq!(PrimitiveDt::WORD.get_length(), 2);
        assert_eq!(PrimitiveDt::DWORD.boxed().get_length(), 4);
        assert_eq!(PrimitiveDt::UINT3.get_length(), 3);
    }
}
