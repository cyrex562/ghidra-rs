//! Port of `ghidra.app.util.bin.format.elf.AndroidElfRelocationGroup`.
//!
//! Provides a dynamic substructure component for relocation groups within a packed Android ELF
//! Relocation Table. See `AndroidElfRelocationTableDataType` (not yet ported).
//!
//! The Java class is a package-private concrete `class AndroidElfRelocationGroup extends
//! DynamicDataType`. Per this crate's shape rules a concrete, non-extended Java class ports to a
//! `struct` + `impl`, not a trait; [`DynamicDataType`] only requires [`Dynamic`] (which only
//! requires [`BuiltInDataType`]) as its supertrait bound, so -- unlike the `AbstractLeb128DataType`
//! chain (which additionally requires `BuiltIn`/`DataTypeImpl`) -- this struct needs no
//! `universal_id`/`source_archive_id`/change-time/parent-refs bookkeeping fields; it implements
//! [`DataType`] + [`BuiltInDataType`] + [`Dynamic`] + [`DynamicDataType`] directly.
//!
//! # Downcasting simplification (`getLastRelocationOffset`)
//!
//! Java's `getLastRelocationOffset` inspects the *last* built component's `DataType` via
//! `instanceof AndroidElfRelocationOffset` / `instanceof AndroidElfRelocationData`, purely to
//! decide which concrete type to cast to before calling the identically-named
//! `getRelocationOffset()` on either one -- both branches return the exact same kind of value.
//! This crate's [`DataType`] trait documents that arbitrary `Box<dyn DataType>` downcasting has no
//! supported mechanism (trait objects cannot be downcast without extra machinery it does not
//! provide). Since every component this class builds is constructed by its own algorithm, the
//! "which concrete class built this component" fact is tracked directly as a field
//! (`relocation_offset: Option<i64>`) on the private [`GroupComponent`] wrapper instead of being
//! recovered via a downcast after the fact -- `Some(offset)` reproduces the union of both
//! `instanceof` branches (they agree on the return value), `None` reproduces "neither matched".
//! [`get_last_relocation_offset`](AndroidElfRelocationGroup::get_last_relocation_offset) also
//! re-derives `groupSize`/`groupOffsetDelta` from its own decode pass rather than re-reading them
//! back out of a `Scalar` via `DataType.getValue` (mirroring the same values, since it is the same
//! bytes decoded the same way), avoiding the need to implement `getValue`/`Scalar` support on the
//! internal LEB128 stand-in types below (a simplification already accepted for this type family --
//! see [`AndroidElfRelocationData`]'s own module docs -- since nothing here calls `get_value`
//! polymorphically).
//!
//! # Forward references
//!
//! - `AndroidElfRelocationOffset` (constructed directly by this class, for `reloc_offset_N`
//!   components) is not yet ported; a minimal placeholder -- only a [`DataType`] identity plus the
//!   stashed base/relocation offset pair and their accessor -- lives at
//!   [`crate::format::seam_stubs::AndroidElfRelocationOffset`] (see `STUBS.tsv`).
//! - `AndroidElfRelocationTableDataType.getLEB128Component(...)` (the static helper used for
//!   `group_*`/`reloc_info_N`/`reloc_addend_N` components) is not reproduced as a placeholder for
//!   that whole class -- its two overloads' bodies are trivial and built entirely from
//!   already-real types ([`ReadOnlyDataTypeComponent`]-equivalent local component storage,
//!   [`AndroidElfRelocationData`] for the offset-carrying overload), so they are inlined locally
//!   as [`AndroidElfRelocationGroup::leb128_component`] /
//!   [`AndroidElfRelocationGroup::leb128_component_with_offset`]. The plain (non-offset-carrying)
//!   overload constructs `new SignedLeb128DataType(dtm)` -- the Java base class itself, with no
//!   extra payload -- for which this crate has no concrete production implementor yet (only
//!   [`AndroidElfRelocationData`], which carries an Android-specific description/offset), so a
//!   private [`GenericSignedLeb128DataType`] stands in, mirroring `AndroidElfRelocationData`'s own
//!   `DataTypeImpl`+`BuiltIn` chain precedent minus the extra field.
//! - `ReadOnlyDataTypeComponent`'s constructor needs an `Arc<dyn DynamicDataType>` for the
//!   *parent* component; like
//!   [`RepeatCountDataType`](crate::program::model::data::repeat_count_data_type::RepeatCountDataType)'s
//!   own module docs explain for the identical problem, there is no way to conjure that from a
//!   plain `&self` borrow, so a private [`GroupComponent`] implementing [`DataTypeComponent`]
//!   directly stands in instead.

use std::any::TypeId;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::{Arc, Weak};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::app::util::bin::mem_buffer_byte_provider::MemBufferByteProvider;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::format::elf::android_elf_relocation_data::AndroidElfRelocationData;
use crate::format::seam_stubs::AndroidElfRelocationOffset as AndroidElfRelocationOffsetStub;
use crate::program::model::data::abstract_leb128_data_type::AbstractLeb128DataType;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::data::signed_leb128_data_type::SignedLeb128DataType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;
use crate::util::UniversalID;

/// A [`BinaryReader`] backed by a [`MemBufferByteProvider`], mirroring the Java constructor call
/// `new BinaryReader(provider, false)`. Kept private/local: this crate has no canonical
/// `MemBuffer`-backed production `BinaryReader` yet (see
/// [`ElfInfoItem`](crate::format::elf::info::elf_info_item)'s own `ProviderBinaryReader` for the
/// identical, `GByteStore`-backed precedent this mirrors).
struct MemBufferBinaryReader<'a> {
    provider: Rc<RefCell<MemBufferByteProvider<'a>>>,
    is_little_endian: bool,
    current_index: u64,
}

impl<'a> MemBufferBinaryReader<'a> {
    fn new(provider: MemBufferByteProvider<'a>, is_little_endian: bool) -> Self {
        MemBufferBinaryReader {
            provider: Rc::new(RefCell::new(provider)),
            is_little_endian,
            current_index: 0,
        }
    }
}

impl<'a> BinaryReader for MemBufferBinaryReader<'a> {
    fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }

    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    fn set_pointer_index(&mut self, index: u64) -> u64 {
        let previous = self.current_index;
        self.current_index = index;
        previous
    }

    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }

    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n_elements);
        for i in 0..n_elements as u64 {
            out.push(self.provider.borrow_mut().read_byte(index + i)?);
        }
        Ok(out)
    }

    fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
        // Not exercised by anything this type needs; `MemBufferByteProvider` is not `'static`
        // (it borrows the `MemBuffer`), so it cannot be unsized into the trait's `'static`
        // `Rc<RefCell<dyn GByteStore>>` return type.
        unimplemented!("not needed for LEB128 decoding")
    }

    fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
        unimplemented!("not needed for LEB128 decoding")
    }
}

/// Reads the next byte-advancing signed LEB128 value, mirroring Java's
/// `reader.readNext(LEB128Info::signed)`.
fn read_next_sleb128(reader: &mut MemBufferBinaryReader<'_>) -> io::Result<LEB128Info> {
    LEB128Info::signed(reader)
}

/// Minimal concrete stand-in for a plain `new SignedLeb128DataType(dtm)` instance -- the Java
/// base class itself, with no extra payload -- needed for [`GroupComponent`]s built from
/// group-level LEB128 fields (`group_size`, `group_flags`, `group_offsetDelta`, `group_info`,
/// `group_addend`) that carry no stashed relocation offset. Mirrors
/// [`AndroidElfRelocationData`]'s `DataTypeImpl`+`BuiltIn` chain precedent, minus the extra
/// `relocation_offset` field that class needs and this one does not.
struct GenericSignedLeb128DataType {
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
    parents: Vec<Weak<dyn DataType>>,
}

impl GenericSignedLeb128DataType {
    fn new() -> Self {
        GenericSignedLeb128DataType {
            universal_id: UniversalID::new(0),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
            parents: Vec::new(),
        }
    }
}

impl DataType for GenericSignedLeb128DataType {
    fn get_name(&self) -> String {
        "sleb128".to_string()
    }

    fn get_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    fn get_length(&self) -> i32 {
        self.leb128_length()
    }

    fn get_description(&self) -> String {
        self.signed_leb128_description()
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        self.leb128_value_class(settings)
    }
}

impl DataTypeImpl for GenericSignedLeb128DataType {
    fn stored_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(self)
    }

    fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}

    fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        None
    }

    fn set_stored_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>) {
        self.source_archive_id = archive.map(|a| a.source_archive_id());
    }

    fn stored_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn stored_last_change_time(&self) -> i64 {
        self.last_change_time
    }

    fn set_stored_last_change_time(&mut self, last_change_time: i64) {
        self.last_change_time = last_change_time;
    }

    fn stored_last_change_time_in_source_archive(&self) -> i64 {
        self.last_change_time_in_source_archive
    }

    fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
        self.last_change_time_in_source_archive = last_change_time;
    }

    fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
        self.parents.clone()
    }

    fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
        self.parents = parents;
    }
}

impl BuiltInDataType for GenericSignedLeb128DataType {
    fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        None
    }

    fn set_default_settings(&mut self, _settings: &dyn Settings) {}
}

impl BuiltIn for GenericSignedLeb128DataType {
    fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
        dt.get_name() == self.get_name()
    }

    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }
}

impl Dynamic for GenericSignedLeb128DataType {
    fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        self.leb128_dynamic_length(buf, max_length)
    }

    fn can_specify_length(&self) -> bool {
        self.leb128_can_specify_length()
    }

    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        self.leb128_replacement_base_type()
    }
}

impl AbstractLeb128DataType for GenericSignedLeb128DataType {
    fn leb128_is_signed(&self) -> bool {
        true
    }
}

impl SignedLeb128DataType for GenericSignedLeb128DataType {
    fn signed_leb128_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedLeb128DataType> {
        Box::new(GenericSignedLeb128DataType::new())
    }
}

/// Private stand-in for `ghidra.program.model.data.ReadOnlyDataTypeComponent`, used by
/// [`AndroidElfRelocationGroup`]'s component-building methods. See the module docs for why the
/// real class is not used here (its constructor needs an `Arc<dyn DynamicDataType>` pointing at
/// the parent, which a bare `&self` borrow cannot supply).
///
/// `relocation_offset` tracks the fact Java recovers via `instanceof
/// AndroidElfRelocationOffset`/`instanceof AndroidElfRelocationData` on this component's data
/// type: `Some(offset)` for a component built from either of those two classes (both `-- via
/// their identically-named `getRelocationOffset()` -- would return the same `offset`), `None`
/// for a plain `group_*` component.
struct GroupComponent {
    data_type: Arc<dyn DataType>,
    length: i32,
    ordinal: i32,
    offset: i32,
    field_name: String,
    comment: Option<String>,
    relocation_offset: Option<i64>,
}

impl DataTypeComponent for GroupComponent {
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn get_field_name(&self) -> Option<String> {
        Some(self.field_name.clone())
    }

    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }
}

/// Result of decoding an [`AndroidElfRelocationGroup`]'s components from a [`MemBuffer`],
/// carrying the handful of decoded group-header values
/// [`get_last_relocation_offset`](AndroidElfRelocationGroup::get_last_relocation_offset) needs
/// alongside the components themselves (see the module docs for why these are tracked directly
/// rather than re-derived from a `Scalar` downcast).
struct DecodedGroup {
    components: Vec<GroupComponent>,
    group_size: i64,
    group_offset_delta: i64,
    grouped_by_delta: bool,
}

/// Provides a dynamic substructure component for relocation groups within a packed Android ELF
/// Relocation Table.
///
/// Port of `ghidra.app.util.bin.format.elf.AndroidElfRelocationGroup`. See the module docs for
/// what was ported, added, and omitted.
pub struct AndroidElfRelocationGroup {
    base_reloc_offset: i64,
}

impl AndroidElfRelocationGroup {
    /// Port of `RELOCATION_GROUPED_BY_INFO_FLAG`.
    pub const RELOCATION_GROUPED_BY_INFO_FLAG: i64 = 1;
    /// Port of `RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG`.
    pub const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: i64 = 2;
    /// Port of `RELOCATION_GROUPED_BY_ADDEND_FLAG`.
    pub const RELOCATION_GROUPED_BY_ADDEND_FLAG: i64 = 4;
    /// Port of `RELOCATION_GROUP_HAS_ADDEND_FLAG`.
    pub const RELOCATION_GROUP_HAS_ADDEND_FLAG: i64 = 8;

    /// Port of `AndroidElfRelocationGroup(DataTypeManager, long)`. `_dtm` is accepted (matching
    /// the Java constructor's parameter list) but not retained, mirroring
    /// [`AndroidElfRelocationData::new`]'s precedent for the same constructor shape.
    pub fn new(_dtm: Option<&dyn DataTypeManager>, base_reloc_offset: i64) -> Self {
        AndroidElfRelocationGroup { base_reloc_offset }
    }

    /// Port of the package-private `getDescription()` (actually declared `public` here, an
    /// override of the default `DataType.getDescription()`).
    fn description(&self) -> String {
        "Android Packed Relocation Entry Group for ELF".to_string()
    }

    fn leb128_component(&self, leb128: &LEB128Info, ordinal: i32, name: &str, comment: Option<String>) -> GroupComponent {
        GroupComponent {
            data_type: Arc::new(GenericSignedLeb128DataType::new()),
            length: leb128.get_length(),
            ordinal,
            offset: leb128.get_offset() as i32,
            field_name: name.to_string(),
            comment,
            relocation_offset: None,
        }
    }

    fn leb128_component_with_offset(
        &self,
        leb128: &LEB128Info,
        ordinal: i32,
        name: &str,
        comment: Option<String>,
        reloc_offset: i64,
    ) -> GroupComponent {
        GroupComponent {
            data_type: Arc::new(AndroidElfRelocationData::new(None, reloc_offset)),
            length: leb128.get_length(),
            ordinal,
            offset: leb128.get_offset() as i32,
            field_name: name.to_string(),
            comment,
            relocation_offset: Some(reloc_offset),
        }
    }

    /// Port of `getAllComponents(MemBuffer)`. See the module docs for the forward-reference and
    /// downcast-avoidance notes.
    fn decode(&self, buf: &dyn MemBuffer) -> Option<DecodedGroup> {
        let provider = MemBufferByteProvider::new(buf);
        let mut reader = MemBufferBinaryReader::new(provider, false);

        let mut list: Vec<GroupComponent> = Vec::new();

        let sleb128 = read_next_sleb128(&mut reader).ok()?;
        let group_size = sleb128.as_long();
        list.push(self.leb128_component(&sleb128, list.len() as i32, "group_size", None));

        let sleb128 = read_next_sleb128(&mut reader).ok()?;
        let group_flags = sleb128.as_long();
        list.push(self.leb128_component(&sleb128, list.len() as i32, "group_flags", None));

        let grouped_by_info = (group_flags & Self::RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
        let grouped_by_delta = (group_flags & Self::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
        let grouped_by_addend = (group_flags & Self::RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
        let group_has_addend = (group_flags & Self::RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;

        let mut group_offset_delta: i64 = 0;
        if grouped_by_delta {
            let sleb128 = read_next_sleb128(&mut reader).ok()?;
            group_offset_delta = sleb128.as_long();

            let min_offset = self.base_reloc_offset + group_offset_delta;
            let range_str = format!("First relocation offset: 0x{:x}", min_offset);

            list.push(self.leb128_component(&sleb128, list.len() as i32, "group_offsetDelta", Some(range_str)));
        }

        if grouped_by_info {
            let sleb128 = read_next_sleb128(&mut reader).ok()?;
            list.push(self.leb128_component(&sleb128, list.len() as i32, "group_info", None));
        }

        if grouped_by_addend && group_has_addend {
            let sleb128 = read_next_sleb128(&mut reader).ok()?;
            list.push(self.leb128_component(&sleb128, list.len() as i32, "group_addend", None));
        }

        let mut reloc_offset = self.base_reloc_offset;

        if grouped_by_delta && grouped_by_info && (!group_has_addend || grouped_by_addend) {
            // no individual relocation entry data
            reloc_offset += (group_size - 1) * group_offset_delta;
        } else {
            for i in 0..group_size {
                if grouped_by_delta {
                    reloc_offset += group_offset_delta;
                } else {
                    let sleb128 = read_next_sleb128(&mut reader).ok()?;
                    reloc_offset += sleb128.as_long();
                    list.push(GroupComponent {
                        data_type: Arc::new(AndroidElfRelocationOffsetStub::new(
                            None,
                            self.base_reloc_offset,
                            reloc_offset,
                        )),
                        length: sleb128.get_length(),
                        ordinal: list.len() as i32,
                        offset: sleb128.get_offset() as i32,
                        field_name: format!("reloc_offset_{i}"),
                        comment: None,
                        relocation_offset: Some(reloc_offset),
                    });
                }

                if !grouped_by_info {
                    let sleb128 = read_next_sleb128(&mut reader).ok()?;
                    list.push(self.leb128_component_with_offset(
                        &sleb128,
                        list.len() as i32,
                        &format!("reloc_info_{i}"),
                        None,
                        reloc_offset,
                    ));
                }

                if group_has_addend && !grouped_by_addend {
                    let sleb128 = read_next_sleb128(&mut reader).ok()?;
                    list.push(self.leb128_component_with_offset(
                        &sleb128,
                        list.len() as i32,
                        &format!("reloc_addend_{i}"),
                        None,
                        reloc_offset,
                    ));
                }
            }
        }

        Some(DecodedGroup { components: list, group_size, group_offset_delta, grouped_by_delta })
    }

    /// Port of the package-private `getLastRelocationOffset(WrappedMemBuffer)`. See the module
    /// docs for the downcast-avoidance/re-derivation notes.
    pub fn get_last_relocation_offset(&self, buf: &dyn MemBuffer) -> i64 {
        let decoded = match self.decode(buf) {
            Some(d) if d.components.len() >= 3 => d,
            _ => return -1,
        };

        // Java: `"group_offsetDelta".equals(comps[2].getFieldName())`. Component index 2 is
        // exactly `group_offsetDelta` if and only if `grouped_by_delta` was set (see `decode`).
        if decoded.grouped_by_delta {
            return self.base_reloc_offset + (decoded.group_size * decoded.group_offset_delta);
        }

        let last = decoded.components.last().unwrap();
        if last.field_name.starts_with("group_") {
            return -1; // unexpected
        }

        last.relocation_offset.unwrap_or(-1)
    }
}

impl DataType for AndroidElfRelocationGroup {
    fn get_name(&self) -> String {
        "AndroidElfRelocationGroup".to_string()
    }

    fn get_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    /// Port of `AndroidElfRelocationGroup.clone(DataTypeManager)`.
    ///
    /// # Panics
    /// Always panics, mirroring Java's `throw new UnsupportedOperationException("may not be
    /// cloned")`: specific instances are used by `AndroidElfRelocationTableDataType` and must not
    /// be duplicated.
    fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        panic!("may not be cloned")
    }

    fn get_description(&self) -> String {
        self.description()
    }

    fn get_value(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Option<Box<dyn std::any::Any>> {
        None
    }

    fn get_representation(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
        String::new()
    }
}

impl BuiltInDataType for AndroidElfRelocationGroup {
    fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        None
    }

    fn set_default_settings(&mut self, _settings: &dyn Settings) {}
}

impl Dynamic for AndroidElfRelocationGroup {
    fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        self.dynamic_length_from_components(buf, max_length)
    }

    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        self.default_replacement_base_type()
    }
}

impl DynamicDataType for AndroidElfRelocationGroup {
    fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let decoded = self.decode(buf)?;
        Some(
            decoded
                .components
                .into_iter()
                .map(|c| Some(Box::new(c) as Box<dyn DataTypeComponent>))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, SpecialAddress};
    use crate::program::model::mem::MemoryAccessException;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer {
        bytes: Vec<u8>,
        space: Arc<AddressSpace>,
    }

    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
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
            false
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            self.space.address(0)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// Unsigned LEB128 byte encoding helper for building test buffers, mirroring how
    /// `Leb128`/`LEB128Info` decode signed values (zig-zag not needed here since every encoded
    /// value in these tests is small and non-negative, so the raw unsigned encoding round-trips
    /// through the signed decoder identically).
    fn sleb128_bytes(mut value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
            if !done {
                byte |= 0x80;
            }
            out.push(byte);
            if done {
                break;
            }
        }
        out
    }

    #[test]
    fn description_matches_java() {
        let dt = AndroidElfRelocationGroup::new(None, 0);
        assert_eq!(dt.get_description(), "Android Packed Relocation Entry Group for ELF");
    }

    #[test]
    fn name_and_category_match_java() {
        let dt = AndroidElfRelocationGroup::new(None, 0x1000);
        assert_eq!(dt.get_name(), "AndroidElfRelocationGroup");
        assert_eq!(dt.get_category_path(), ROOT.clone());
    }

    #[test]
    #[should_panic(expected = "may not be cloned")]
    fn clone_is_unsupported() {
        struct DummyDtm;
        impl DataTypeManager for DummyDtm {}
        let dt = AndroidElfRelocationGroup::new(None, 0);
        let _ = dt.clone_data_type(&DummyDtm);
    }

    #[test]
    fn value_and_representation_are_always_empty() {
        let dt = AndroidElfRelocationGroup::new(None, 0);
        let buf = BytesMemBuffer { bytes: vec![], space: ram_space() };
        assert!(dt.get_value(&buf, &MockSettings, 0).is_none());
        assert_eq!(dt.get_representation(&buf, &MockSettings, 0), "");
    }

    /// A minimal group: `group_size = 1`, `group_flags = RELOCATION_GROUPED_BY_INFO_FLAG` (1) --
    /// so `groupedByInfo` is true (always contributes one shared `group_info` field, read
    /// unconditionally whenever the flag is set) and neither delta nor addend flags are set --
    /// followed by one `reloc_offset_0` entry (since `!groupedByDelta`). No per-relocation
    /// `reloc_info`/`reloc_addend` entries are produced because `groupedByInfo` is true and
    /// `groupHasAddend` is false.
    fn minimal_group_bytes() -> Vec<u8> {
        let mut bytes = sleb128_bytes(1); // group_size = 1
        bytes.extend(sleb128_bytes(AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_INFO_FLAG)); // group_flags
        bytes.extend(sleb128_bytes(7)); // group_info (shared, read once since groupedByInfo)
        bytes.extend(sleb128_bytes(5)); // reloc_offset_0 delta
        bytes
    }

    #[test]
    fn all_components_decode_minimal_group() {
        let dt = AndroidElfRelocationGroup::new(None, 100);
        let buf = BytesMemBuffer { bytes: minimal_group_bytes(), space: ram_space() };
        let comps = dt.get_all_components(&buf).unwrap();
        // group_size, group_flags, group_info, reloc_offset_0
        assert_eq!(comps.len(), 4);
        assert_eq!(comps[0].as_ref().unwrap().get_field_name(), Some("group_size".to_string()));
        assert_eq!(comps[1].as_ref().unwrap().get_field_name(), Some("group_flags".to_string()));
        assert_eq!(comps[2].as_ref().unwrap().get_field_name(), Some("group_info".to_string()));
        assert_eq!(comps[3].as_ref().unwrap().get_field_name(), Some("reloc_offset_0".to_string()));
    }

    #[test]
    fn last_relocation_offset_from_reloc_offset_entry() {
        let dt = AndroidElfRelocationGroup::new(None, 100);
        let buf = BytesMemBuffer { bytes: minimal_group_bytes(), space: ram_space() };
        // base_reloc_offset (100) + decoded delta (5) == 105
        assert_eq!(dt.get_last_relocation_offset(&buf), 105);
    }

    #[test]
    fn last_relocation_offset_short_reads_are_unexpected() {
        let dt = AndroidElfRelocationGroup::new(None, 0);
        let buf = BytesMemBuffer { bytes: vec![0x00, 0x00], space: ram_space() };
        // Only 2 components can ever be produced from that input (group_size, group_flags -- no
        // flags set, so no further fields, and groupSize == 0 means the individual-entry loop
        // never runs) -- fewer than the 3 Java requires.
        assert_eq!(dt.get_last_relocation_offset(&buf), -1);
    }

    #[test]
    fn last_relocation_offset_grouped_by_delta_uses_group_size_times_delta() {
        // group_size = 3, group_flags = GROUPED_BY_OFFSET_DELTA_FLAG (2) | GROUPED_BY_INFO_FLAG
        // (1) = 3, group_offsetDelta = 4, group_info = 9 (groupedByInfo always contributes this
        // shared field). `groupedByDelta && groupedByInfo && (!groupHasAddend ||
        // groupedByAddend)` is true (no addend flags set), so no individual relocation entries
        // are produced -- component index 2 (`group_offsetDelta`) is what
        // `get_last_relocation_offset` keys off of, matching Java's `comps[2].getFieldName()`
        // check regardless of what (if anything) follows it.
        let mut bytes = sleb128_bytes(3);
        bytes.extend(sleb128_bytes(
            AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
                | AndroidElfRelocationGroup::RELOCATION_GROUPED_BY_INFO_FLAG,
        ));
        bytes.extend(sleb128_bytes(4)); // group_offsetDelta
        bytes.extend(sleb128_bytes(9)); // group_info

        let dt = AndroidElfRelocationGroup::new(None, 100);
        let buf = BytesMemBuffer { bytes, space: ram_space() };

        let comps = dt.get_all_components(&buf).unwrap();
        assert_eq!(comps.len(), 4);
        assert_eq!(comps[2].as_ref().unwrap().get_field_name(), Some("group_offsetDelta".to_string()));
        assert_eq!(comps[3].as_ref().unwrap().get_field_name(), Some("group_info".to_string()));

        // base_reloc_offset (100) + group_size (3) * group_offset_delta (4) == 112
        assert_eq!(dt.get_last_relocation_offset(&buf), 112);
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = AndroidElfRelocationGroup::new(None, 0);
        let dyn_dt: &dyn DynamicDataType = &dt;
        assert_eq!(dyn_dt.get_name(), "AndroidElfRelocationGroup");
    }
}
