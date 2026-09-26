//! Port of `ghidra.app.util.bin.format.macos.asd.Entry`.
//!
//! # Shape
//!
//! Java's `Entry` is an abstract class carrying one field (the entry's descriptor) and no abstract
//! methods. Per `scripts/shape_rules.py` (R11) the state lives in [`EntryBase`], which concrete
//! entries (e.g. [`ResourceHeader`](crate::format::macos::rm::resource_header::ResourceHeader))
//! embed by composition, and the [`Entry`] trait gives uniform access to it.

use crate::format::macos::asd::entry_descriptor::EntryDescriptor;

/// Shared state of every AppleSingle/AppleDouble entry: the descriptor it was parsed from.
///
/// Port of the fields of the abstract Java class `Entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryBase {
    entry_descriptor: EntryDescriptor,
}

impl EntryBase {
    /// Port of the protected `Entry(EntryDescriptor)` constructor.
    pub fn new(entry_descriptor: EntryDescriptor) -> Self {
        Self { entry_descriptor }
    }

    /// Port of `getEntryDescriptor()`.
    pub fn get_entry_descriptor(&self) -> &EntryDescriptor {
        &self.entry_descriptor
    }
}

/// An AppleSingle/AppleDouble entry.
///
/// Port of the abstract Java class `ghidra.app.util.bin.format.macos.asd.Entry`.
pub trait Entry {
    /// The shared entry state embedded in the implementor.
    fn entry_base(&self) -> &EntryBase;

    /// Returns the descriptor this entry was parsed from.
    ///
    /// Port of `getEntryDescriptor()`.
    fn get_entry_descriptor(&self) -> &EntryDescriptor {
        self.entry_base().get_entry_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEntry(EntryBase);

    impl Entry for TestEntry {
        fn entry_base(&self) -> &EntryBase {
            &self.0
        }
    }

    #[test]
    fn entry_exposes_its_descriptor() {
        let e = TestEntry(EntryBase::new(EntryDescriptor::new(2, 0x40, 0x100)));
        let d = e.get_entry_descriptor();
        assert_eq!((d.get_entry_id(), d.get_offset(), d.get_length()), (2, 0x40, 0x100));
    }
}
