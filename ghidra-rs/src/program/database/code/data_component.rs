//! Port of `ghidra.program.database.code.DataComponent`.
//!
//! `DataComponent` provides [`Data`] and [`CodeUnit`] access to struct and array components.
//!
//! NOTE (from the Java source): `DataComponent`s only have a unique key within their parent
//! struct/array. This places a constraint on the use of the key field and `getKey()` method on the
//! underlying `CodeUnitDB`/`DataDB` classes -- the key should only be used for managing an object
//! cache.
//!
//!
//! # Known gaps
//!
//! A real implementation, not a stub, but some methods are blocked on crate infrastructure that
//! does not exist yet. Each is marked `TODO(port):` at its site; collected here for visibility:
//!
//! - The `Settings` setters (`set_long`/`set_string`/`set_value`/`clear_setting`/
//!   `clear_all_settings`) are inherited from [`DataDB`](super::data_db)'s own gap: they route
//!   through `program.getDataTypeManager()`, and the ported `Program` trait has no such accessor.
//!   They are no-ops; the getters fall back to the data type's default settings.
//!   `get_default_settings` is fully ported.
//! - `DynamicDataType` component instantiation: `DataType` exposes `as_dynamic()` for the
//!   `Dynamic` interface but offers no downcast to `DynamicDataType`, where
//!   `getComponent(int, MemBuffer)` and `getNumComponents(MemBuffer)` actually live. This is the
//!   same blocker already documented on `abstract_db_trace_data_component.rs`.
//! # `extends DataDB`, without inheritance
//!
//! Java's `class DataComponent extends DataDB`. Mirroring what
//! [`DataDB`](super::data_db::DataDB) itself does one level up with
//! [`CodeUnitDbBase`](super::code_unit_db::CodeUnitDbBase), this type *composes* a concrete
//! `DataDB` in its [`data`](DataComponent) field and forwards to it for everything Java inherits.
//! The methods Java overrides -- `getByte`, `getBytes`, `getComment`, `getComponentIndex`,
//! `getComponentPath`, `getComponentPathName`, `getDefaultSettings`, `getFieldName`, `getParent`,
//! `getParentOffset`, `getPathName`, `getRoot`, `getRootOffset`, `equals`,
//! `getPreferredCacheLength` and, critically, `hasBeenDeleted` -- get real bodies here.
//!
//! Both concrete types implement [`DataDb`], each with its own `has_been_deleted`; that trait is
//! precisely the seam that lets this type hold its `parent` as an `Arc<dyn DataDb>` without naming
//! `DataDB` (or, for a nested component, itself) as a concrete type.
//!
//! # The embedded `DataDB` is replaced, not mutated
//!
//! Java's `hasBeenDeleted` re-derives this component from its parent's *current* layout and writes
//! the results straight into the inherited `dataType`/`baseDataType`/`address`/`addr`/`length`
//! fields. [`CodeUnitDbBase`](super::code_unit_db::CodeUnitDbBase) deliberately exposes no setter
//! for its cached `address`/`addr`, so this port instead swaps in a freshly constructed `DataDB`
//! at the new address -- which reproduces every one of those assignments (including Java's
//! `bytes = null`) in one step. The component's own [`DbObject`] bookkeeping lives in a separate
//! field so that the swap does not disturb the cache key or the deleted/valid flags.

use std::any::{Any, TypeId};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, RwLock};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::framework::db::DBRecord;
use crate::program::database::code::code_unit_db::{CodeUnitDb, CodeUnitDbBase};
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::data_db::{DataDb, DataDB};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::Address;
use crate::program::model::data::array::Array;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::seam_stubs::RegisterValue;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::symbol::{
    ExternalReference, Reference as SymReference, ReferenceIterator, RefType as SymRefType,
    SourceType, Symbol,
};
use crate::program::model::util::PropertySet;
use crate::util::string_utilities::StringUtilities;
use crate::program::seam_stubs::{RefType, Reference};
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// Provides [`Data`] and [`CodeUnit`] access to struct and array components.
///
/// Port of `ghidra.program.database.code.DataComponent`.
pub struct DataComponent {
    /// The `DataDB` half Java inherits. Held behind a lock because `has_been_deleted` replaces it
    /// wholesale -- see the module docs.
    data: RwLock<Arc<DataDB>>,
    /// This component's own `DbObject` bookkeeping, keyed (as Java's is) on the ordinal.
    state: DbObjectState,
    /// The creating code manager, kept so components of *this* component can be built.
    owner: Arc<dyn CodeUnitOwner>,
    /// Stands in for `DataComponent.parent`, the data item that contains this component.
    parent: Arc<dyn DataDb>,
    /// Stands in for `DataComponent.component`; `None` for an array element, exactly as Java
    /// leaves the field null there.
    component: RwLock<Option<Arc<dyn DataTypeComponent>>>,
    /// Stands in for `DataComponent.indexInParent`.
    index_in_parent: i32,
    /// Stands in for `DataComponent.offset`, the byte offset within the parent.
    offset: AtomicI32,
    /// Stands in for the lazily built `DataComponent.path`.
    path: RwLock<Option<Vec<i32>>>,
}

impl DataComponent {
    /// Constructs a new `DataComponent` for a [`DataTypeComponent`].
    ///
    /// NOTE: a zero-length component will be forced to have a length of 1 byte. This can result in
    /// what would appear to be overlapping components with the same offset.
    ///
    /// Stands in for
    /// `DataComponent(CodeManager, Address, long, DataDB, DataTypeComponent)`.
    ///
    /// # Arguments
    /// * `owner` - the code manager
    /// * `address` - the address of the data component
    /// * `addr` - the converted address long value
    /// * `parent` - the data item that contains this component
    /// * `component` - the `DataTypeComponent` for this `DataComponent`
    pub fn new(
        owner: Arc<dyn CodeUnitOwner>,
        address: Address,
        addr: i64,
        parent: Arc<dyn DataDb>,
        component: Arc<dyn DataTypeComponent>,
    ) -> Self {
        let index_in_parent = component.get_ordinal();
        let offset = component.get_offset();
        let mut length = component.get_length();
        if length == 0 {
            length = 1; // zero-length components must be forced to have a length of 1
        }
        let data = Self::build_data(
            &owner,
            index_in_parent,
            address,
            addr,
            Arc::from(component.get_data_type()),
            parent.get_component_level() + 1,
            length,
        );
        DataComponent {
            data: RwLock::new(data),
            state: DbObjectState::new(i64::from(index_in_parent)),
            owner,
            parent,
            component: RwLock::new(Some(component)),
            index_in_parent,
            offset: AtomicI32::new(offset),
            path: RwLock::new(None),
        }
    }

    /// Constructs a new `DataComponent` for an [`Array`] element.
    ///
    /// Stands in for `DataComponent(CodeManager, Address, long, DataDB, Array, int)`.
    ///
    /// # Arguments
    /// * `owner` - the code manager
    /// * `address` - the address of the data component
    /// * `addr` - the converted address long value
    /// * `parent` - the data item that contains this component
    /// * `array` - the array containing this component
    /// * `ordinal` - the array index for this component
    pub fn new_array_element(
        owner: Arc<dyn CodeUnitOwner>,
        address: Address,
        addr: i64,
        parent: Arc<dyn DataDb>,
        array: &dyn Array,
        ordinal: i32,
    ) -> Self {
        let element_length = array.get_element_length();
        let data = Self::build_data(
            &owner,
            ordinal,
            address,
            addr,
            Arc::from(array.get_data_type()),
            parent.get_component_level() + 1,
            element_length,
        );
        DataComponent {
            data: RwLock::new(data),
            state: DbObjectState::new(i64::from(ordinal)),
            owner,
            parent,
            component: RwLock::new(None),
            index_in_parent: ordinal,
            offset: AtomicI32::new(ordinal * element_length),
            path: RwLock::new(None),
        }
    }

    /// Port of the inner `DataDB.ComponentFactory.instantiate(long ordinal)`, which is how every
    /// `DataComponent` is actually created: `DataDB.getComponent(int)` asks its component cache
    /// for the ordinal, and the cache calls this factory on a miss.
    ///
    /// # TODO(port)
    /// The factory's `baseDataType instanceof DynamicDataType` branch is not ported: the ported
    /// [`DataType`] trait offers `as_dynamic()` (the `Dynamic` *interface*) but no downcast to
    /// [`DynamicDataType`](crate::program::model::data::dynamic_data_type::DynamicDataType),
    /// where `getComponent(int, MemBuffer)` lives. A dynamic parent therefore yields `None`, the
    /// same result the factory's final `Msg.error(..); return null;` arm produces for an
    /// unsupported composite type.
    pub(crate) fn for_ordinal(
        owner: Arc<dyn CodeUnitOwner>,
        parent: Arc<dyn DataDb>,
        index: i32,
    ) -> Option<DataComponent> {
        let address_map = owner.get_address_map();
        let parent_address = parent.get_min_address();
        let base_data_type = parent.get_base_data_type();

        if let Some(array) = base_data_type.as_array() {
            let component_addr = parent_address
                .add(i64::from(index) * i64::from(array.get_element_length()))
                .ok()?;
            let db_key = address_map.get_key(&component_addr, false);
            return Some(DataComponent::new_array_element(
                owner,
                component_addr,
                db_key,
                parent.clone(),
                array,
                index,
            ));
        }

        if let Some(composite) = base_data_type.as_composite() {
            let dtc = composite.get_component(index).ok()?;
            let component_addr = parent_address.add(i64::from(dtc.get_offset())).ok()?;
            let db_key = address_map.get_key(&component_addr, false);
            return Some(DataComponent::new(
                owner,
                component_addr,
                db_key,
                parent.clone(),
                Arc::from(dtc),
            ));
        }

        None
    }

    /// Builds the embedded `DataDB` for a component at `address`, with the component's own
    /// (non-lazy) length and one level deeper than its parent.
    ///
    /// Stands in for the `super(codeMgr, ordinal, address, addr, dataType)` call plus the
    /// `this.level = parent.level + 1` / `length = ...` assignments both Java constructors make.
    fn build_data(
        owner: &Arc<dyn CodeUnitOwner>,
        ordinal: i32,
        address: Address,
        addr: i64,
        data_type: Arc<dyn DataType>,
        level: i32,
        length: i32,
    ) -> Arc<DataDB> {
        let data = DataDB::new(
            owner.clone(),
            i64::from(ordinal),
            address,
            addr,
            Some(data_type),
        );
        data.set_level(level);
        // Java assigns the inherited `length` field directly, so `DataDB.getLength()` never runs
        // its lazy `computeLength()` for a component.
        data.base().set_length(length);
        Arc::new(data)
    }

    /// The embedded `DataDB`, i.e. everything `DataComponent` inherits.
    fn data(&self) -> Arc<DataDB> {
        self.data.read().unwrap().clone()
    }

    /// The shared `CodeUnitDB` state, reached through the embedded `DataDB`.
    fn base(&self) -> Arc<DataDB> {
        self.data()
    }

    /// Stands in for reading the `DataComponent.offset` field.
    fn offset(&self) -> i32 {
        self.offset.load(Ordering::SeqCst)
    }

    /// Stands in for reading the `DataComponent.component` field.
    fn component(&self) -> Option<Arc<dyn DataTypeComponent>> {
        self.component.read().unwrap().clone()
    }

    /// An independent instance describing the same component, sharing the embedded `DataDB`.
    ///
    /// Backs both [`DataDb::to_boxed_data`] and [`Self::this`]; see [`DataDb::to_boxed_data`] for
    /// why the ported `Data` trait needs it.
    fn shallow_clone(&self) -> DataComponent {
        DataComponent {
            data: RwLock::new(self.data()),
            state: DbObjectState::new(self.state.get_key()),
            owner: self.owner.clone(),
            parent: self.parent.clone(),
            component: RwLock::new(self.component()),
            index_in_parent: self.index_in_parent,
            offset: AtomicI32::new(self.offset()),
            path: RwLock::new(self.path.read().unwrap().clone()),
        }
    }

    /// This object as the polymorphic `DataDB.this` the inherited method bodies dispatch on --
    /// which, for a component, must be the *component*, so that components of components are
    /// parented correctly. See [`DataDB`]'s module docs on explicit virtual-call parameters.
    fn this(&self) -> Arc<dyn DataDb> {
        Arc::new(self.shallow_clone())
    }

    /// Port of the private `DataComponent.getComponentName(String)`.
    fn component_name(&self, parent_path: &str) -> String {
        let mut buffer = String::new();
        if !parent_path.is_empty() {
            buffer.push_str(parent_path);
            if self.component().is_some() {
                // not an array?
                buffer.push('.');
            }
        }
        buffer.push_str(&self.get_field_name().unwrap_or_default());
        buffer
    }
}

// ===========================================================================================
// MemBuffer -- `DataComponent` overrides the byte accessors to read through its parent.
// ===========================================================================================

impl MemBuffer for DataComponent {
    fn get_address(&self) -> Address {
        self.base().base().address()
    }

    /// Port of `DataComponent.getByte(int)`.
    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        let data = self.base();
        let _guard = data.base().lock().read();
        self.refresh_if_needed();
        MemBuffer::get_byte(&*self.parent, self.offset() + offset)
    }

    /// Port of `DataComponent.getBytes(byte[], int)`.
    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        let data = self.base();
        let _guard = data.base().lock().read();
        self.refresh_if_needed();
        MemBuffer::get_bytes(&*self.parent, buf, self.offset() + offset)
    }

    fn is_big_endian(&self) -> bool {
        self.base().base().is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.base().base().get_memory()
    }
}

// ===========================================================================================
// PropertySet -- inherited.
// ===========================================================================================

impl PropertySet for DataComponent {
    fn set_object_property(&mut self, name: &str, value: Box<dyn Saveable>) {
        // TODO(port): same blocker as `DataDB`/`InstructionDB` -- `CodeUnitDbBase` has no
        // object-property setter because the ported `ObjectPropertyMap` carries no `add_object`.
        let _ = (name, value);
    }

    fn set_string_property(&mut self, name: &str, value: &str) {
        self.base().base().set_string_property(name, value);
    }

    fn set_int_property(&mut self, name: &str, value: i32) {
        self.base().base().set_int_property(name, value);
    }

    fn set_void_property(&mut self, name: &str) {
        self.base().base().set_void_property(name);
    }

    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        self.base().base().get_object_property(name)
    }

    fn get_string_property(&self, name: &str) -> Option<String> {
        self.base().base().get_string_property(name)
    }

    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        self.base().base().get_int_property(name)
    }

    fn has_property(&self, name: &str) -> bool {
        self.base().base().has_property(name)
    }

    fn get_void_property(&self, name: &str) -> bool {
        self.base().base().get_void_property(name)
    }

    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.base().base().property_names().into_iter())
    }

    fn remove_property(&mut self, name: &str) {
        self.base().base().remove_property(name);
    }
}

// ===========================================================================================
// Settings -- inherited except for `getDefaultSettings`.
// ===========================================================================================

impl Settings for DataComponent {
    /// Port of `DataComponent.getDefaultSettings()`.
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        if let Some(component) = self.component() {
            return Some(component.get_default_settings());
        }
        if self.parent.get_component_index() >= 0 {
            // Ensure we pick up default component settings for an array. Java tests
            // `parent instanceof DataComponent`; a non-negative component index is exactly what
            // distinguishes a `DataComponent` from a top-level `DataDB`.
            return self.parent.get_default_settings();
        }
        Settings::get_default_settings(&*self.base())
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        Settings::get_long(&*self.base(), name)
    }

    fn get_string(&self, name: &str) -> Option<String> {
        Settings::get_string(&*self.base(), name)
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        Settings::get_value(&*self.base(), name)
    }

    fn get_names(&self) -> Vec<String> {
        Settings::get_names(&*self.base())
    }

    fn is_empty(&self) -> bool {
        Settings::is_empty(&*self.base())
    }

    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        Settings::is_change_allowed(&*self.base(), settings_definition)
    }

    fn set_long(&mut self, name: &str, value: i64) {
        // TODO(port): `DataDB`'s setters are already no-ops (no reachable
        // `ProgramDataTypeManager`); forwarding would require `&mut DataDB`, which the shared
        // `Arc` cannot provide.
        let _ = (name, value);
    }

    fn set_string(&mut self, name: &str, value: &str) {
        // TODO(port): see `set_long`.
        let _ = (name, value);
    }

    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        // TODO(port): see `set_long`.
        let _ = (name, value);
    }

    fn clear_setting(&mut self, name: &str) {
        // TODO(port): see `set_long`.
        let _ = name;
    }

    fn clear_all_settings(&mut self) {
        // TODO(port): see `set_long`.
    }
}

// ===========================================================================================
// CodeUnit -- inherited except for the byte accessors and `getComment`.
// ===========================================================================================

impl CodeUnit for DataComponent {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        self.base().base().get_address_string(show_block_name, pad)
    }

    fn get_label(&self) -> Option<String> {
        self.base().base().get_label()
    }

    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        self.base().base().get_symbols()
    }

    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.base().base().get_primary_symbol()
    }

    fn get_min_address(&self) -> Address {
        self.base().base().address()
    }

    fn get_max_address(&self) -> Address {
        let length = self.get_length();
        self.base().base().get_max_address(length)
    }

    fn get_mnemonic_string(&self) -> String {
        self.refresh_if_needed();
        self.base().mnemonic_string(self)
    }

    /// Port of `DataComponent.getComment(CommentType)`, which falls back to the
    /// `DataTypeComponent`'s own comment for an end-of-line comment.
    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        let data = self.base();
        let length = self.get_length();
        let comment = data.comment_at(comment_type, &self.this(), self, length);
        if comment.is_none() && comment_type == CommentType::Eol {
            if let Some(component) = self.component() {
                return component.get_comment();
            }
        }
        comment
    }

    /// Inherited `CodeUnitDB.getCommentAsArray(CommentType)`, which splits the *virtual*
    /// `getComment(..)` -- i.e. this type's override.
    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        match CodeUnit::get_comment(self, comment_type) {
            Some(comment) => comment.to_lines_default(),
            None => Vec::new(),
        }
    }

    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        let data = self.base();
        let length = self.get_length();
        data.set_comment_at(comment_type, comment, &self.this(), self, length);
    }

    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        self.set_comment(comment_type, Some(comment.join("\n")));
    }

    /// The component's length, assigned by its constructor (and re-derived by
    /// `hasBeenDeleted`) rather than lazily computed the way `DataDB.getLength()` does.
    fn get_length(&self) -> i32 {
        self.base().base().length()
    }

    /// Port of `DataComponent.getBytes()`.
    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        let data = self.base();
        let _guard = data.base().lock().read();
        self.refresh_if_needed();
        let length = self.get_length().max(0) as usize;
        let mut buffer = vec![0u8; length];
        if MemBuffer::get_bytes(&*self.parent, &mut buffer, self.offset()) != length {
            return Err(MemoryAccessException::new(
                "Couldn't get all bytes for CodeUnit",
            ));
        }
        Ok(buffer)
    }

    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        let code_unit_bytes = CodeUnit::get_bytes(self)?;
        let start = buffer_offset.max(0) as usize;
        let n = buffer
            .len()
            .saturating_sub(start)
            .min(code_unit_bytes.len());
        buffer[start..start + n].copy_from_slice(&code_unit_bytes[..n]);
        Ok(())
    }

    fn contains(&self, test_addr: &Address) -> bool {
        let length = self.get_length();
        self.base().base().contains(test_addr, length)
    }

    fn compare_to(&self, addr: &Address) -> i32 {
        let length = self.get_length();
        self.base().base().compare_to(addr, length)
    }

    fn add_mnemonic_reference(
        &mut self,
        ref_addr: Address,
        ref_type: SymRefType,
        source_type: SourceType,
    ) {
        self.base()
            .base()
            .add_mnemonic_reference(&ref_addr, ref_type, source_type);
    }

    fn remove_mnemonic_reference(&mut self, ref_addr: &Address) {
        self.base().base().remove_mnemonic_reference(ref_addr);
    }

    fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
        self.base().base().get_mnemonic_references()
    }

    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn SymReference>> {
        self.base().base().get_operand_references(index)
    }

    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn SymReference>> {
        self.base().base().get_primary_reference(index)
    }

    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: SymRefType,
        source_type: SourceType,
    ) {
        self.base()
            .base()
            .add_operand_reference(index, &ref_addr, ref_type, source_type);
    }

    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address) {
        self.base().base().remove_operand_reference(index, ref_addr);
    }

    fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
        let length = self.get_length();
        self.base().references_from(length)
    }

    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        self.base().base().get_reference_iterator_to()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.base().base().get_program()
    }

    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        self.base().base().get_external_reference(op_index)
    }

    fn remove_external_reference(&mut self, op_index: i32) {
        self.base().base().remove_external_reference(op_index);
    }

    fn set_primary_memory_reference(&mut self, reference: Arc<dyn SymReference>) {
        self.base().base().set_primary_memory_reference(reference);
    }

    fn set_stack_reference(
        &mut self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: SymRefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base().base().set_stack_reference(
            op_index,
            offset,
            source_type,
            ref_type,
            num_operands,
        );
    }

    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: SymRefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base().base().set_register_reference(
            op_index,
            Register::from_register(reg),
            source_type,
            ref_type,
            num_operands,
        );
    }

    fn get_num_operands(&self) -> i32 {
        1
    }

    fn get_address(&self, op_index: i32) -> Option<Address> {
        let length = self.get_length();
        self.base().address_for_operand(op_index, self, self, length)
    }

    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        let length = self.get_length();
        self.base().scalar_for_operand(op_index, self, self, length)
    }

    fn as_data(&self) -> Option<&dyn Data> {
        Some(self)
    }
}


// ===========================================================================================
// ProcessorContext / ProcessorContextView -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl ProcessorContextView for DataComponent {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        Some(self.base().base().get_base_context_register())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.base().base().get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.base().base().get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.base().base().get_register_bigint_value(register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>> {
        self.base().base().get_register_value(register)
    }

    fn has_value(&self, register: &Register) -> bool {
        self.base().base().has_value(register)
    }
}

impl ProcessorContext for DataComponent {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        self.base().base().set_register_bigint_value(register, value)
    }

    fn set_register_value(
        &mut self,
        value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        self.base().base().set_register_value(value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        self.base().base().clear_register(register)
    }
}

// ===========================================================================================
// Data -- inherited except for the component/parent-relative accessors.
// ===========================================================================================

impl Data for DataComponent {
    fn get_value(&self) -> Option<Box<dyn Any>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base().value(self, self, length)
    }

    fn get_value_class(&self) -> Option<TypeId> {
        self.base().value_class(self)
    }

    fn has_string_value(&self) -> bool {
        self.get_value_class() == Some(TypeId::of::<String>())
    }

    fn is_constant(&self) -> bool {
        self.refresh_if_needed();
        self.base().has_mutability(
            crate::program::model::data::mutability_settings_definition::CONSTANT,
            self,
        )
    }

    fn is_writable(&self) -> bool {
        self.refresh_if_needed();
        self.base().has_mutability(
            crate::program::model::data::mutability_settings_definition::WRITABLE,
            self,
        )
    }

    fn is_volatile(&self) -> bool {
        self.refresh_if_needed();
        self.base().has_mutability(
            crate::program::model::data::mutability_settings_definition::VOLATILE,
            self,
        )
    }

    fn is_defined(&self) -> bool {
        Data::is_defined(&*self.base())
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        Data::get_data_type(&*self.base())
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        Data::get_base_data_type(&*self.base())
    }

    fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
        Data::get_value_references(&*self.base())
    }

    fn add_value_reference(&mut self, ref_addr: Address, ref_type: Box<dyn RefType>) {
        // TODO(port): inherited from `DataDB`, whose own body is blocked on the placeholder
        // `seam_stubs::RefType` carrying no mappable reference type.
        let _ = (ref_addr, ref_type);
    }

    fn remove_value_reference(&mut self, ref_addr: Address) {
        self.base().base().remove_operand_reference(
            crate::program::database::code::data_db::DATA_OP_INDEX,
            &ref_addr,
        );
    }

    /// Port of `DataComponent.getFieldName()`.
    fn get_field_name(&self) -> Option<String> {
        let Some(component) = self.component() else {
            // is array?
            return Some(format!("[{}]", self.index_in_parent));
        };
        let name = component.get_field_name().filter(|name| !name.is_empty());
        match name {
            Some(name) => Some(name),
            None => component.get_default_field_name(),
        }
    }

    /// Port of `DataComponent.getPathName()`.
    fn get_path_name(&self) -> String {
        let parent_path = self.parent.get_path_name();
        self.component_name(&parent_path)
    }

    /// Port of `DataComponent.getComponentPathName()`.
    fn get_component_path_name(&self) -> String {
        let parent_path = self.parent.get_component_path_name();
        self.component_name(&parent_path)
    }

    fn is_pointer(&self) -> bool {
        Data::is_pointer(&*self.base())
    }

    fn is_union(&self) -> bool {
        Data::is_union(&*self.base())
    }

    fn is_structure(&self) -> bool {
        Data::is_structure(&*self.base())
    }

    fn is_array(&self) -> bool {
        Data::is_array(&*self.base())
    }

    fn is_dynamic(&self) -> bool {
        Data::is_dynamic(&*self.base())
    }

    /// Port of `DataComponent.getParent()`.
    fn get_parent(&self) -> Option<Box<dyn Data>> {
        Some(self.parent.to_boxed_data())
    }

    /// Port of `DataComponent.getRoot()`.
    fn get_root(&self) -> Box<dyn Data> {
        self.parent.get_root()
    }

    /// Port of `DataComponent.getRootOffset()`.
    fn get_root_offset(&self) -> i32 {
        self.parent.get_root_offset() + self.get_parent_offset()
    }

    /// Port of `DataComponent.getParentOffset()`.
    fn get_parent_offset(&self) -> i32 {
        self.offset()
    }

    fn get_component(&self, index: i32) -> Option<Box<dyn Data>> {
        let length = self.get_length();
        self.base()
            .component(index, &self.this(), self, length)
            .map(|component| Box::new(component) as Box<dyn Data>)
    }

    fn get_component_by_path(&self, component_path: &[i32]) -> Option<Box<dyn Data>> {
        let length = self.get_length();
        self.base()
            .component_by_path(component_path, &self.this(), self, length)
    }

    /// Port of `DataComponent.getComponentPath()`, including its lazy `path` memoization.
    fn get_component_path(&self) -> Vec<i32> {
        if let Some(path) = self.path.read().unwrap().as_ref() {
            return path.clone();
        }
        let level = self.get_component_level().max(0) as usize;
        let mut path = vec![0i32; level];
        if level == 0 {
            return path;
        }
        let mut parent_level = level - 1;
        path[parent_level] = self.index_in_parent;

        // Java walks `while (parentData instanceof DataComponent)`; a non-negative component
        // index is exactly what makes a `Data` a `DataComponent`.
        let mut parent_data: Option<Box<dyn Data>> = Some(self.parent.to_boxed_data());
        while let Some(data) = parent_data {
            let index = data.get_component_index();
            if index < 0 || parent_level == 0 {
                break;
            }
            parent_level -= 1;
            path[parent_level] = index;
            parent_data = data.get_parent();
        }

        *self.path.write().unwrap() = Some(path.clone());
        path
    }

    fn get_num_components(&self) -> i32 {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base().num_components(self, length)
    }

    fn get_component_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.get_component_containing(offset)
    }

    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base()
            .component_containing(offset, &self.this(), self, length)
            .map(|component| Box::new(component) as Box<dyn Data>)
    }

    fn get_components_containing(&self, offset: i32) -> Option<Vec<Box<dyn Data>>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base()
            .components_containing(offset, &self.this(), self, length)
    }

    fn get_primitive_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base().primitive_at(offset, &self.this(), self, length)
    }

    /// Port of `DataComponent.getComponentIndex()`.
    fn get_component_index(&self) -> i32 {
        self.index_in_parent
    }

    fn get_component_level(&self) -> i32 {
        self.base().level()
    }

    fn get_default_value_representation(&self) -> String {
        self.refresh_if_needed();
        let length = self.get_length();
        self.base().default_value_representation(self, self, length)
    }

    fn get_default_label_prefix(&self, options: &dyn DataTypeDisplayOptions) -> Option<String> {
        let length = self.get_length();
        self.base()
            .default_label_prefix(self, self, length, options)
    }
}

// ===========================================================================================
// DbObject / CodeUnitDb / DataDb.
// ===========================================================================================

impl DbObject for DataComponent {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Inherited `DataDB.refresh(DBRecord)`, but chaining into *this* type's `hasBeenDeleted`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        self.base().refresh_shared();
        !DataDb::has_been_deleted(self, record)
    }
}

impl CodeUnitDb for DataComponent {
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
        DataDb::has_been_deleted(self, record)
    }

    /// Port of `DataComponent.getPreferredCacheLength()`: rely on the parent for cached bytes.
    fn get_preferred_cache_length(&self) -> i32 {
        0
    }

    fn code_unit_string(&self) -> String {
        let length = self.get_length();
        self.base().data_string(self, self, length)
    }
}

impl DataDb for DataComponent {
    /// Port of `DataComponent.hasBeenDeleted(DBRecord)`.
    ///
    /// Records do not apply to data components, which are derived from their parent's data type;
    /// the `record` argument is accepted (and ignored) to match the inherited signature, exactly
    /// as the Java override does.
    fn has_been_deleted(&self, _record: Option<&DBRecord>) -> bool {
        if self.parent.has_been_deleted(None) {
            return true;
        }

        let parent_data_type = self.parent.get_base_data_type();
        let (new_component, new_data_type, new_offset, new_length) =
            if let Some(composite) = parent_data_type.as_composite() {
                // if we are deleted, the parent may not have as many components as it used to, so
                // if our index is bigger than the number of components, then we are deleted.
                if self.index_in_parent >= composite.get_num_components() {
                    return true;
                }
                let Ok(dtc) = composite.get_component(self.index_in_parent) else {
                    return true;
                };
                let data_type = dtc.get_data_type();
                let offset = dtc.get_offset();
                let mut length = dtc.get_length();
                if length == 0 {
                    length = 1; // zero-length components must be forced to have a length of 1
                }
                (Some(Arc::from(dtc)), data_type, offset, length)
            } else if let Some(array) = parent_data_type.as_array() {
                if self.index_in_parent >= array.get_num_elements() {
                    return true;
                }
                let length = array.get_element_length();
                (
                    None,
                    array.get_data_type(),
                    length * self.index_in_parent,
                    length,
                )
            } else {
                return true;
            };

        let Ok(address) = self
            .parent
            .get_min_address()
            .add(i64::from(new_offset))
        else {
            return true;
        };
        // Java computes `addr = parent.addr + offset`, exploiting the address map's encoding.
        // `CodeUnitDbBase` publishes no `addr` for the parent, so the index is re-derived the
        // same way `ComponentFactory` derives it for a freshly created component.
        let addr = self.owner.get_address_map().get_key(&address, false);

        *self.component.write().unwrap() = new_component;
        self.offset.store(new_offset, Ordering::SeqCst);
        *self.data.write().unwrap() = Self::build_data(
            &self.owner,
            self.index_in_parent,
            address,
            addr,
            Arc::from(new_data_type),
            self.parent.get_component_level() + 1,
            new_length,
        );
        false
    }

    fn to_boxed_data(&self) -> Box<dyn Data> {
        Box::new(self.shallow_clone())
    }
}

impl std::fmt::Display for DataComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", CodeUnitDb::code_unit_string(self))
    }
}

/// Port of `DataComponent.equals(Object)`: same ordinal, same offset, and -- via
/// `super.equals(obj)` -- the same address index and owning manager.
impl PartialEq for DataComponent {
    fn eq(&self, other: &Self) -> bool {
        if self.index_in_parent != other.index_in_parent || self.offset() != other.offset() {
            return false;
        }
        let (mine, theirs) = (self.base(), other.base());
        let (mine, theirs): (&CodeUnitDbBase, &CodeUnitDbBase) = (mine.base(), theirs.base());
        mine.same_code_unit(theirs)
    }
}

impl Eq for DataComponent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::code::test_support::{TestCodeUnitOwner, TestDataType};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn owner_with(bytes: Vec<u8>) -> Arc<TestCodeUnitOwner> {
        Arc::new(TestCodeUnitOwner::new(space(), 0x1000, bytes))
    }

    /// A `DataDB` at 0x1000 over a 3-field struct `{ byte a; word b; byte c; }`.
    fn struct_root(owner: &Arc<TestCodeUnitOwner>) -> Arc<dyn DataDb> {
        let structure: Arc<dyn DataType> = Arc::new(TestDataType::structure(
            "S",
            vec![("a", 1, 0), ("b", 2, 1), ("c", 1, 3)],
        ));
        Arc::new(DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(structure),
        ))
    }

    /// A `DataDB` at 0x1000 over `byte[4]`.
    fn array_root(owner: &Arc<TestCodeUnitOwner>) -> Arc<dyn DataDb> {
        let array: Arc<dyn DataType> = Arc::new(TestDataType::array("byte", 1, 4));
        Arc::new(DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(array),
        ))
    }

    #[test]
    fn structure_component_derives_offset_length_and_address() {
        let owner = owner_with(vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
        let root = struct_root(&owner);
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 1).expect("component 1");

        assert_eq!(component.get_component_index(), 1);
        assert_eq!(component.get_parent_offset(), 1);
        assert_eq!(component.get_length(), 2);
        assert_eq!(component.get_min_address(), owner.address(0x1001));
        assert_eq!(component.get_max_address(), owner.address(0x1002));
        assert_eq!(component.get_component_level(), 1);
        assert_eq!(component.get_field_name().as_deref(), Some("b"));
        assert_eq!(component.get_component_path(), vec![1]);
        assert_eq!(component.get_num_operands(), 1);
        // `getPreferredCacheLength()` is overridden to 0 so bytes come from the parent's cache.
        assert_eq!(CodeUnitDb::get_preferred_cache_length(&component), 0);
    }

    #[test]
    fn array_element_component_has_bracketed_field_name() {
        let owner = owner_with(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let root = array_root(&owner);
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 2).expect("component 2");

        assert_eq!(component.get_field_name().as_deref(), Some("[2]"));
        assert_eq!(component.get_parent_offset(), 2);
        assert_eq!(component.get_length(), 1);
        assert_eq!(component.get_min_address(), owner.address(0x1002));
        assert_eq!(component.get_component_path_name(), "[2]");
    }

    #[test]
    fn component_bytes_are_read_at_its_offset_within_the_parent() {
        let owner = owner_with(vec![0x10, 0x21, 0x22, 0x40, 0x50, 0x60]);
        let root = struct_root(&owner);
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 1).expect("component 1");

        // Field `b` covers parent offsets 1..=2.
        assert_eq!(CodeUnit::get_bytes(&component).unwrap(), vec![0x21, 0x22]);
        assert_eq!(MemBuffer::get_byte(&component, 0).unwrap(), 0x21);
        assert_eq!(MemBuffer::get_byte(&component, 1).unwrap(), 0x22);

        let mut buffer = [0u8; 2];
        assert_eq!(MemBuffer::get_bytes(&component, &mut buffer, 0), 2);
        assert_eq!(buffer, [0x21, 0x22]);

        // Reading one byte further reaches into the following field, exactly as Java's
        // parent-relative `getByte(this.offset + n)` does.
        assert_eq!(MemBuffer::get_byte(&component, 2).unwrap(), 0x40);
    }

    #[test]
    fn parent_root_and_offsets_walk_back_up_the_hierarchy() {
        let owner = owner_with(vec![0x00; 8]);
        let root = struct_root(&owner);
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 2).expect("component 2");

        let parent = component.get_parent().expect("parent");
        assert_eq!(parent.get_min_address(), owner.address(0x1000));
        assert_eq!(parent.get_component_index(), -1);

        let component_root = component.get_root();
        assert_eq!(component_root.get_min_address(), owner.address(0x1000));
        assert_eq!(component_root.get_component_index(), -1);

        assert_eq!(component.get_parent_offset(), 3);
        assert_eq!(component.get_root_offset(), 3);
        // `getPathName()` is the parent's path name (here the dynamic label, since the test
        // symbol table has no primary symbol) plus this field's name.
        assert_eq!(
            component.get_path_name(),
            format!("{}.c", root.get_path_name())
        );
    }

    #[test]
    fn nested_component_path_and_root_offset() {
        let owner = owner_with(vec![0x00; 16]);
        // struct S { byte a; byte[3] arr; } -- `arr` is itself a composite with elements.
        let inner: Arc<dyn DataType> = Arc::new(TestDataType::array("byte", 1, 3));
        let structure: Arc<dyn DataType> = Arc::new(TestDataType::structure_of(
            "S",
            vec![
                ("a", Arc::new(TestDataType::fixed("byte", 1)) as Arc<dyn DataType>, 0),
                ("arr", inner, 1),
            ],
        ));
        let root: Arc<dyn DataDb> = Arc::new(DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(structure),
        ));

        let arr = DataComponent::for_ordinal(owner.clone(), root.clone(), 1).expect("arr");
        assert_eq!(arr.get_num_components(), 3);
        assert_eq!(arr.get_parent_offset(), 1);

        let element = arr.get_component(2).expect("arr[2]");
        assert_eq!(element.get_component_index(), 2);
        assert_eq!(element.get_component_level(), 2);
        assert_eq!(element.get_component_path(), vec![1, 2]);
        assert_eq!(element.get_parent_offset(), 2);
        assert_eq!(element.get_root_offset(), 3);
        assert_eq!(element.get_min_address(), owner.address(0x1003));
        // The root's component path name is empty, so the component path stops at the fields:
        // `arr` contributes its field name, and the array element its bracketed index (with no
        // separating dot, exactly as `getComponentName` does for an array).
        assert_eq!(arr.get_component_path_name(), "arr");
        assert_eq!(element.get_component_path_name(), "arr[2]");
        assert_eq!(element.get_root().get_min_address(), owner.address(0x1000));
    }

    #[test]
    fn has_been_deleted_diverges_from_data_db_through_the_trait_object() {
        let owner = owner_with(vec![0x00; 8]);
        let root = struct_root(&owner);
        let root_as_data_db: &dyn DataDb = &*root;

        // The owner records the same three-field structure at the root's address, so the root is
        // present and its ordinal-2 component exists.
        owner.set_data_type_at(
            0x1000,
            Arc::new(TestDataType::structure(
                "S",
                vec![("a", 1, 0), ("b", 2, 1), ("c", 1, 3)],
            )),
        );
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 2).expect("component 2");
        let component_as_data_db: &dyn DataDb = &component;

        assert!(!root_as_data_db.has_been_deleted(None));
        assert!(!component_as_data_db.has_been_deleted(None));

        // The structure now loses its trailing fields, and the root picks that up on refresh.
        owner.set_data_type_at(
            0x1000,
            Arc::new(TestDataType::structure("S", vec![("a", 1, 0)])),
        );
        assert!(root_as_data_db.refresh(None));
        assert_eq!(root_as_data_db.get_num_components(), 1);

        // Same parent, same call, two different answers: `DataDB.hasBeenDeleted` asks "is a data
        // type still recorded at my address?" (yes), while `DataComponent.hasBeenDeleted` asks "is
        // my ordinal still within my parent's layout?" (no). That divergence is the entire reason
        // `DataDb` declares `has_been_deleted` rather than sharing one body.
        assert!(!root_as_data_db.has_been_deleted(None));
        assert!(component_as_data_db.has_been_deleted(None));

        // Ordinal 0 survives the same shrink.
        let survivor =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 0).expect("component 0");
        assert!(!DataDb::has_been_deleted(&survivor, None));
    }

    #[test]
    fn has_been_deleted_re_derives_offset_and_length_after_the_parent_changes() {
        let owner = owner_with(vec![0x00; 16]);
        let root = struct_root(&owner);
        let component =
            DataComponent::for_ordinal(owner.clone(), root.clone(), 2).expect("component 2");
        assert_eq!(component.get_parent_offset(), 3);
        assert_eq!(component.get_length(), 1);
        assert_eq!(component.get_min_address(), owner.address(0x1003));

        // The parent's layout grows field `b` to four bytes, shifting `c`.
        owner.set_data_type_at(
            0x1000,
            Arc::new(TestDataType::structure(
                "S",
                vec![("a", 1, 0), ("b", 4, 1), ("c", 2, 5)],
            )),
        );
        let root_ref: &dyn DataDb = &*root;
        assert!(root_ref.refresh(None));

        assert!(!DataDb::has_been_deleted(&component, None));
        assert_eq!(component.get_parent_offset(), 5);
        assert_eq!(component.get_length(), 2);
        assert_eq!(component.get_min_address(), owner.address(0x1005));
    }

    #[test]
    fn zero_length_component_is_forced_to_one_byte() {
        let owner = owner_with(vec![0x00; 8]);
        let structure: Arc<dyn DataType> =
            Arc::new(TestDataType::structure("S", vec![("empty", 0, 0), ("a", 1, 0)]));
        let root: Arc<dyn DataDb> = Arc::new(DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(structure),
        ));

        let empty = DataComponent::for_ordinal(owner.clone(), root, 0).expect("component 0");
        assert_eq!(empty.get_length(), 1);
    }

    #[test]
    fn equality_requires_the_same_ordinal_offset_and_address() {
        let owner = owner_with(vec![0x00; 8]);
        let root = struct_root(&owner);
        let a = DataComponent::for_ordinal(owner.clone(), root.clone(), 1).expect("a");
        let b = DataComponent::for_ordinal(owner.clone(), root.clone(), 1).expect("b");
        let c = DataComponent::for_ordinal(owner.clone(), root.clone(), 2).expect("c");

        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn default_settings_come_from_the_data_type_component() {
        let owner = owner_with(vec![0x00; 8]);
        let root = struct_root(&owner);
        let component = DataComponent::for_ordinal(owner.clone(), root, 0).expect("component 0");
        // `DataTypeComponent::get_default_settings` is the source, not `DataDB`'s data type.
        assert!(Settings::get_default_settings(&component).is_some());
    }

    #[test]
    fn component_comment_falls_back_to_the_data_type_component_comment() {
        let owner = owner_with(vec![0x00; 8]);
        let structure: Arc<dyn DataType> = Arc::new(TestDataType::structure_with_comments(
            "S",
            vec![("a", 1, 0, Some("field a"))],
        ));
        let root: Arc<dyn DataDb> = Arc::new(DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(structure),
        ));
        let component = DataComponent::for_ordinal(owner.clone(), root, 0).expect("component 0");

        assert_eq!(
            component.get_comment(CommentType::Eol).as_deref(),
            Some("field a")
        );
        // Only EOL falls back to the DataTypeComponent's comment.
        assert_eq!(component.get_comment(CommentType::Plate), None);
    }
}
