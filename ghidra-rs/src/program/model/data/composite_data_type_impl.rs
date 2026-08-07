//! Port of `ghidra.program.model.data.CompositeDataTypeImpl`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends GenericDataType implements CompositeInternal`. `GenericDataType`
//! (itself extending the unported `DataTypeImpl`) contributes no interface beyond [`DataType`] --
//! it only adds protected field storage (`name`, `categoryPath`) and a `checkValidName` helper
//! inherited from `DataTypeImpl` -- so, mirroring [`AbstractComplexDataType`]'s convention of
//! extending only the already-ported interfaces its unported superclass implements, this trait
//! extends [`CompositeInternal`] directly (which already pulls in [`Composite`] and [`DataType`]).
//!
//! Several Java methods here share a name with an already-provided default method on
//! [`DataType`], [`Composite`], or [`CompositeInternal`] (`getMnemonic`, `setName`,
//! `getStoredPackingValue`, `getStoredMinimumAlignment`, `getPackingType`, `getAlignmentType`,
//! `add`/`insert` and their overloads, `repack`, `getDescription`/`setDescription`). Rust does not
//! allow a subtrait to override a supertrait's same-named default without creating an ambiguous
//! call site, so -- mirroring [`AbstractComplexDataType`]'s `complex_*` convention -- those
//! overrides are exposed here under distinct `composite_impl_*` names. A concrete `impl
//! Composite`/`impl DataType for ...` should delegate to these.
//!
//! Three Java methods override a supertrait default with *identical* behavior to the Rust
//! default already in place, so they are intentionally not re-declared here (matching the
//! precedent set by [`AbstractComplexDataType::complex_length`]'s note about
//! `getAlignedLength()`):
//!   - `getAlignedLength()` just returns `getLength()`, exactly [`DataType::get_aligned_length`]'s
//!     existing default.
//!   - `dataTypeNameChanged(DataType, String)` is a no-op ("ignored"), exactly
//!     [`DataType::data_type_name_changed`]'s existing default.
//!   - `getValue(MemBuffer, Settings, int)` always returns `null`, exactly
//!     [`DataType::get_value`]'s existing default (`None`).
//!   - `toString()` is just `return CompositeInternal.toString(this);`, which requires no
//!     additional logic beyond calling the already-ported
//!     [`composite_internal::to_string`](super::composite_internal::to_string) directly on a
//!     `&dyn Composite` coercion of the concrete implementor -- there is nothing this trait needs
//!     to add.
//!
//! The Java private fields `description`, `minimumAlignment`, and `packing`, and the inherited
//! `name` field (from `DataTypeImpl` via `GenericDataType`), have no home on a trait, so they are
//! exposed via required accessor methods ([`CompositeDataTypeImpl::stored_description`]/
//! [`CompositeDataTypeImpl::set_stored_description`], etc.) that implementors are expected to
//! back with real storage -- mirroring [`AbstractComplexDataType::float_type`]'s accessor
//! convention.
//!
//! A handful of methods are left as required (non-defaulted) trait methods because their Java
//! bodies fundamentally depend on capabilities [`DataType`] does not yet expose generically:
//!   - `hasLanguageDependantLength()` and `repack(boolean)` are themselves `abstract` in Java
//!     (implemented by `Structure`/`Union`), so they stay required here too
//!     ([`CompositeDataTypeImpl::composite_impl_has_language_dependant_length`],
//!     [`CompositeDataTypeImpl::repack_with_notify`]).
//!   - `getAlignment()` is `abstract` in `CompositeDataTypeImpl` itself (overriding
//!     [`DataType::get_alignment`]'s default), so it stays required too
//!     ([`CompositeDataTypeImpl::composite_impl_alignment`]).
//!   - `forEachDefinedComponent(Consumer<DataTypeComponentImpl>)` is package-private abstract, so
//!     it stays required ([`CompositeDataTypeImpl::for_each_defined_component`]), using
//!     `&dyn DataTypeComponent` in place of the unported concrete `DataTypeComponentImpl`.
//!   - The canonical 4-argument `add`/`insert` overloads remain `abstract` in Java (implemented by
//!     `Structure`/`Union`); only the short-form overloads that `CompositeDataTypeImpl` makes
//!     `final` (delegating to the canonical form) get real default bodies here.
//!   - `validateDataType(DataType)` needs `instanceof Dynamic`/`instanceof FactoryDataType` checks
//!     and the `DataType.DEFAULT`/`Undefined1DataType.dataType` singletons, none of which
//!     [`DataType`] exposes generically yet (it provides no `Dynamic`/`FactoryDataType` downcast
//!     hook, unlike its existing `into_composite`/`into_array_stringable`), so it stays required
//!     ([`CompositeDataTypeImpl::composite_impl_validate_data_type`]).
//!   - `updateBitFieldDataType(DataTypeComponentImpl, DataType, DataType)` operates on the
//!     concrete (unported) `DataTypeComponentImpl`'s package-private `setDataType` and constructs
//!     a new (unported) `BitFieldDataType`, so it stays required too
//!     ([`CompositeDataTypeImpl::composite_impl_update_bit_field_data_type`]).
//!   - `getPreferredComponentLength`'s `(dataType instanceof Dynamic dynamic) &&
//!     dynamic.canSpecifyLength()` check has the same downcast problem; rather than leaving the
//!     whole method required, the two default methods here
//!     ([`CompositeDataTypeImpl::composite_impl_preferred_component_length`],
//!     [`preferred_component_length_for_data_type`]) take that check's *result* as an extra
//!     `bool` parameter for the caller to supply (`false` is always a safe, conservative answer).
//!
//! `createComponent` constructs a `new DataTypeComponentImpl(...)`, a concrete type that is not
//! yet ported. Rather than adding a placeholder stub for it, [`CompositeDataTypeImpl::composite_impl_create_component`]
//! returns a `Box<dyn DataTypeComponent>` backed by a private [`BasicDataTypeComponent`] that
//! stores the six constructor arguments directly and implements the already-real
//! [`DataTypeComponent`] trait faithfully for every accessor *except*
//! [`DataTypeComponent::get_data_type`] and [`DataTypeComponent::get_parent`] (both left at their
//! trait defaults): both would need to return a fresh owned `Box<dyn DataType>` from a `&self`
//! method, which is impossible without a `DataType: Clone` bound that does not exist on the
//! trait. [`DataTypeComponent::get_data_type_name`] is overridden instead, which carries the same
//! information (the component's data type's name) without the ownership problem.
//!
//! `isPartOf(DataType)` delegates to the unported `DataTypeUtilities.isSecondPartOfFirst`, a
//! recursive walk through pointer/equals/`Array`/`TypeDef`/`Composite` cases. Rather than adding a
//! placeholder stub for that utility class, [`CompositeDataTypeImpl::composite_impl_is_part_of`]
//! and its helper [`is_part_of_data_type`] reimplement the walk directly using already-ported
//! [`DataType`] methods (`is_pointer`, `typedef_base_data_type`, `into_composite`); the `Array`
//! case is conservatively treated as "not part of" since [`DataType`] has no generic accessor for
//! an array's element type yet (no `into_array`, unlike `into_composite`), and reference identity
//! (Java's `.equals()`) is approximated with [`DataType::get_data_type_path`] equality.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::alignment_type::AlignmentType;
#[cfg(test)]
use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_internal::{
    CompositeInternal, DEFAULT_ALIGNMENT, DEFAULT_PACKING, MACHINE_ALIGNMENT, NO_PACKING,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::{uses_zero_length_component, DataTypeComponent};
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::mem::MemBuffer;
use crate::util::exception::{InvalidNameException, NotYetImplementedException};

/// Common implementation methods for structure and union.
///
/// Port of `ghidra.program.model.data.CompositeDataTypeImpl`. See the module-level documentation
/// for the conventions used to resolve name clashes with [`DataType`]/[`Composite`]/
/// [`CompositeInternal`], for the required accessors standing in for private fields, and for what
/// was left required (rather than defaulted) or intentionally omitted.
pub trait CompositeDataTypeImpl: CompositeInternal {
    /// Backing storage for the private `description` field.
    fn stored_description(&self) -> String;

    /// Mutator for the private `description` field's backing storage.
    fn set_stored_description(&mut self, description: String);

    /// Backing storage for the protected `minimumAlignment` field.
    fn stored_minimum_alignment_value(&self) -> i32;

    /// Mutator for the protected `minimumAlignment` field's backing storage.
    fn set_stored_minimum_alignment_value(&mut self, minimum_alignment: i32);

    /// Backing storage for the protected `packing` field.
    fn stored_packing_value(&self) -> i32;

    /// Mutator for the protected `packing` field's backing storage.
    fn set_stored_packing_value_raw(&mut self, packing: i32);

    /// Mutator for the inherited `name` field's backing storage (from `DataTypeImpl` via
    /// `GenericDataType`, neither of which is ported).
    fn set_stored_name(&mut self, name: String);

    /// Port of the abstract `CompositeDataTypeImpl.hasLanguageDependantLength()`, still abstract
    /// here since it is abstract in Java too (implemented by `Structure`/`Union`). Exposed under
    /// a distinct name since [`DataType::has_language_dependant_length`] already provides a
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn composite_impl_has_language_dependant_length(&self) -> bool;

    /// Port of the abstract `CompositeDataTypeImpl.repack(boolean)`. Returns `true` if a layout
    /// change was detected.
    fn repack_with_notify(&mut self, notify: bool) -> bool;

    /// Port of the abstract `CompositeDataTypeImpl.getAlignment()`. Exposed under a distinct name
    /// since [`DataType::get_alignment`] already provides a default. A concrete `impl DataType
    /// for ...` should delegate to this.
    fn composite_impl_alignment(&self) -> i32;

    /// Port of the package-private abstract `CompositeDataTypeImpl.forEachDefinedComponent(Consumer<DataTypeComponentImpl>)`,
    /// using `&dyn DataTypeComponent` in place of the unported concrete `DataTypeComponentImpl`.
    fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent));

    /// Port of the canonical (still abstract in Java, implemented by `Structure`/`Union`)
    /// `Composite.add(DataType, int, String, String)`. Exposed under a distinct name since
    /// [`Composite::add_with_length_and_name`] already provides a (placeholder) default.
    fn composite_impl_add_with_length_and_name(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String>;

    /// Port of the canonical (still abstract in Java, implemented by `Structure`/`Union`)
    /// `Composite.insert(int, DataType, int, String, String)`. Exposed under a distinct name
    /// since [`Composite::insert_with_length_and_name`] already provides a (placeholder) default.
    fn composite_impl_insert_with_length_and_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String>;

    /// Port of `CompositeDataTypeImpl.validateDataType(DataType)`. See the module-level
    /// documentation for why this is left required rather than defaulted.
    ///
    /// # Errors
    /// Returns `Err` if `data_type` is not allowed to be added to this composite (mirrors
    /// `IllegalArgumentException`).
    fn composite_impl_validate_data_type(
        &self,
        data_type: Box<dyn DataType>,
    ) -> Result<Box<dyn DataType>, String>;

    /// Port of `CompositeDataTypeImpl.updateBitFieldDataType(DataTypeComponentImpl, DataType,
    /// DataType)`. See the module-level documentation for why this is left required rather than
    /// defaulted. Returns `Ok(true)` if the bitfield component was modified.
    ///
    /// # Errors
    /// Returns `Err` if `bitfield_component` is not actually a bitfield component (mirrors the
    /// `AssertException` thrown in that case).
    fn composite_impl_update_bit_field_data_type(
        &mut self,
        bitfield_component: Box<dyn DataTypeComponent>,
        old_dt: &dyn DataType,
        new_dt: Option<&dyn DataType>,
    ) -> Result<bool, String>;

    /// Port of the protected `CompositeDataTypeImpl.createComponent(DataType, int, int, int,
    /// String, String)`. See the module-level documentation for why the returned component's
    /// [`DataTypeComponent::get_data_type`]/[`DataTypeComponent::get_parent`] are left at their
    /// trait defaults.
    fn composite_impl_create_component(
        &self,
        data_type: Box<dyn DataType>,
        length: i32,
        ordinal: i32,
        offset: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Box<dyn DataTypeComponent> {
        Box::new(BasicDataTypeComponent {
            data_type_name: data_type.get_name(),
            length,
            ordinal,
            offset,
            field_name,
            comment,
        })
    }

    /// Port of the final `CompositeDataTypeImpl.getStoredPackingValue()`. Exposed under a
    /// distinct name since [`CompositeInternal::get_stored_packing_value`] already provides a
    /// (placeholder) default. A concrete `impl CompositeInternal for ...` should delegate to
    /// this.
    fn composite_impl_stored_packing_value(&self) -> i32 {
        self.stored_packing_value()
    }

    /// Port of the final `CompositeDataTypeImpl.getStoredMinimumAlignment()`. Exposed under a
    /// distinct name since [`CompositeInternal::get_stored_minimum_alignment`] already provides a
    /// (placeholder) default. A concrete `impl CompositeInternal for ...` should delegate to
    /// this.
    fn composite_impl_stored_minimum_alignment(&self) -> i32 {
        self.stored_minimum_alignment_value()
    }

    /// Port of the final `CompositeDataTypeImpl.isNotYetDefined()`. Exposed under a distinct name
    /// since [`DataType::is_not_yet_defined`] already provides a default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn composite_impl_is_not_yet_defined(&self) -> bool {
        self.get_num_components() == 0 && !self.is_packing_enabled()
    }

    /// Port of `CompositeDataTypeImpl.isPartOf(DataType)`. Exposed under a distinct name since
    /// [`Composite::is_part_of`] already provides a (placeholder) default. A concrete `impl
    /// Composite for ...` should delegate to this. See the module-level documentation for how
    /// this diverges from `DataTypeUtilities.isSecondPartOfFirst`.
    fn composite_impl_is_part_of(&self, data_type_of_interest: &dyn DataType) -> bool {
        if self.get_data_type_path() == data_type_of_interest.get_data_type_path() {
            return true;
        }
        self.get_defined_components()
            .into_iter()
            .any(|dtc| is_part_of_data_type(dtc.get_data_type(), data_type_of_interest))
    }

    /// Port of `CompositeDataTypeImpl.getDescription()`. Exposed under a distinct name since
    /// [`DataType::get_description`] already provides a default. A concrete `impl DataType for
    /// ...` should delegate to this.
    fn composite_impl_description(&self) -> String {
        self.stored_description()
    }

    /// Port of `CompositeDataTypeImpl.setDescription(String)`. Exposed under a distinct name
    /// since [`DataType::set_description`] already provides a default with a different signature
    /// (no `Option`). A concrete `impl DataType for ...` should delegate to this.
    fn composite_impl_set_description(&mut self, description: Option<&str>) {
        self.set_stored_description(description.unwrap_or("").to_string());
    }

    /// Port of `CompositeDataTypeImpl.setValue(MemBuffer, Settings, int, Object)`, which always
    /// throws.
    ///
    /// # Errors
    /// Always returns `Err` (mirrors `NotYetImplementedException`).
    fn composite_impl_set_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
        value: &dyn Any,
    ) -> Result<(), NotYetImplementedException> {
        let _ = (buf, settings, length, value);
        Err(NotYetImplementedException::with_message("setValue() not implemented"))
    }

    /// Port of the final `CompositeDataTypeImpl.add(DataType)`. Exposed under a distinct name
    /// since [`Composite::add`] already provides a (placeholder) default. A concrete `impl
    /// Composite for ...` should delegate to this.
    fn composite_impl_add(&mut self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_length_and_name(data_type, -1, None, None)
    }

    /// Port of the final `CompositeDataTypeImpl.add(DataType, int)`. Exposed under a distinct
    /// name since [`Composite::add_with_length`] already provides a (placeholder) default.
    fn composite_impl_add_with_length(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_length_and_name(data_type, length, None, None)
    }

    /// Port of the final `CompositeDataTypeImpl.add(DataType, String, String)`. Exposed under a
    /// distinct name since [`Composite::add_with_name`] already provides a (placeholder) default.
    fn composite_impl_add_with_name(
        &mut self,
        data_type: Box<dyn DataType>,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_length_and_name(data_type, -1, field_name, comment)
    }

    /// Port of the final `CompositeDataTypeImpl.insert(int, DataType, int)`. Exposed under a
    /// distinct name since [`Composite::insert_with_length`] already provides a (placeholder)
    /// default.
    fn composite_impl_insert_with_length(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_insert_with_length_and_name(ordinal, data_type, length, None, None)
    }

    /// Port of the final `CompositeDataTypeImpl.insert(int, DataType)`. Exposed under a distinct
    /// name since [`Composite::insert`] already provides a (placeholder) default.
    fn composite_impl_insert(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_insert_with_length_and_name(ordinal, data_type, -1, None, None)
    }

    /// Port of `CompositeDataTypeImpl.getMnemonic(Settings)`. Exposed under a distinct name since
    /// [`DataType::get_mnemonic`] already provides a default with different behavior (delegates
    /// to `get_name` rather than `get_display_name`). A concrete `impl DataType for ...` should
    /// delegate to this.
    fn composite_impl_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_display_name()
    }

    /// Port of `CompositeDataTypeImpl.setName(String)`. Exposed under a distinct name since
    /// [`DataType::set_name`] already provides a (no-op) default. A concrete `impl DataType for
    /// ...` should delegate to this.
    ///
    /// # Errors
    /// Returns `Err` if `name` is blank or contains a control character (mirrors
    /// `InvalidNameException`, via the port of `DataUtilities.isValidDataTypeName` in
    /// [`check_valid_name`]).
    fn composite_impl_set_name(&mut self, name: &str) -> Result<(), InvalidNameException> {
        check_valid_name(name)?;
        self.set_stored_name(name.to_string());
        Ok(())
    }

    /// Port of the final `CompositeDataTypeImpl.repack()`. Exposed under a distinct name since
    /// [`Composite::repack`] already provides a (placeholder, no-op) default with a different
    /// signature (no return value). Returns `true` if a layout change was detected.
    fn composite_impl_repack(&mut self) -> bool {
        self.repack_with_notify(true)
    }

    /// Port of `CompositeDataTypeImpl.setPackingEnabled(boolean)`. Exposed under a distinct name
    /// since [`Composite::set_packing_enabled`] already provides a (placeholder, no-op) default.
    fn composite_impl_set_packing_enabled(&mut self, enabled: bool) {
        let currently_enabled = self.composite_impl_packing_type() != PackingType::Disabled;
        if enabled == currently_enabled {
            return;
        }
        self.composite_impl_set_stored_packing_value(if enabled { DEFAULT_PACKING } else { NO_PACKING });
    }

    /// Port of `CompositeDataTypeImpl.getPackingType()`. Exposed under a distinct name since
    /// [`Composite::get_packing_type`] already provides a (placeholder) default. A concrete `impl
    /// Composite for ...` should delegate to this.
    fn composite_impl_packing_type(&self) -> PackingType {
        let packing = self.stored_packing_value();
        if packing < DEFAULT_PACKING {
            PackingType::Disabled
        } else if packing == DEFAULT_PACKING {
            PackingType::Default
        } else {
            PackingType::Explicit
        }
    }

    /// Port of `CompositeDataTypeImpl.setToDefaultPacking()`. Exposed under a distinct name since
    /// [`Composite::set_to_default_packing`] already provides a (placeholder, no-op) default.
    fn composite_impl_set_to_default_packing(&mut self) {
        self.composite_impl_set_stored_packing_value(DEFAULT_PACKING);
    }

    /// Port of `CompositeDataTypeImpl.getExplicitPackingValue()`. Exposed under a distinct name
    /// since [`Composite::get_explicit_packing_value`] already provides a (placeholder) default.
    fn composite_impl_explicit_packing_value(&self) -> i32 {
        self.stored_packing_value()
    }

    /// Port of `CompositeDataTypeImpl.setExplicitPackingValue(int)`. Exposed under a distinct
    /// name since [`Composite::set_explicit_packing_value`] already provides a (placeholder)
    /// default.
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors `IllegalArgumentException`).
    fn composite_impl_set_explicit_packing_value(&mut self, packing_value: i32) -> Result<(), String> {
        if packing_value <= 0 {
            return Err(format!(
                "IllegalArgumentException: explicit packing value must be positive: {packing_value}"
            ));
        }
        self.composite_impl_set_stored_packing_value(packing_value);
        Ok(())
    }

    /// Port of the private `CompositeDataTypeImpl.setStoredPackingValue(int)`. Not exposed in
    /// Java beyond this class, but kept as a normal (non-required) trait method for reuse by the
    /// public setters above; callers already validate `packing_value >= NO_PACKING` before
    /// reaching here, so an out-of-range value is silently ignored rather than panicking.
    fn composite_impl_set_stored_packing_value(&mut self, packing_value: i32) {
        if packing_value < NO_PACKING {
            return;
        }
        if packing_value == self.stored_packing_value() {
            return;
        }
        if self.stored_packing_value() == NO_PACKING || packing_value == NO_PACKING {
            // force default alignment when transitioning to or from disabled packing
            self.set_stored_minimum_alignment_value(DEFAULT_ALIGNMENT);
        }
        self.set_stored_packing_value_raw(packing_value);
        self.repack_with_notify(true);
    }

    /// Port of `CompositeDataTypeImpl.getAlignmentType()`. Exposed under a distinct name since
    /// [`Composite::get_alignment_type`] already provides a (placeholder) default. A concrete
    /// `impl Composite for ...` should delegate to this.
    fn composite_impl_alignment_type(&self) -> AlignmentType {
        let alignment = self.stored_minimum_alignment_value();
        if alignment < DEFAULT_ALIGNMENT {
            AlignmentType::Machine
        } else if alignment == DEFAULT_ALIGNMENT {
            AlignmentType::Default
        } else {
            AlignmentType::Explicit
        }
    }

    /// Port of `CompositeDataTypeImpl.setToDefaultAligned()`. Exposed under a distinct name since
    /// [`Composite::set_to_default_aligned`] already provides a (placeholder, no-op) default.
    fn composite_impl_set_to_default_aligned(&mut self) {
        self.composite_impl_set_stored_minimum_alignment(DEFAULT_ALIGNMENT);
    }

    /// Port of `CompositeDataTypeImpl.setToMachineAligned()`. Exposed under a distinct name since
    /// [`Composite::set_to_machine_aligned`] already provides a (placeholder, no-op) default.
    fn composite_impl_set_to_machine_aligned(&mut self) {
        self.composite_impl_set_stored_minimum_alignment(MACHINE_ALIGNMENT);
    }

    /// Port of `CompositeDataTypeImpl.getExplicitMinimumAlignment()`. Exposed under a distinct
    /// name since [`Composite::get_explicit_minimum_alignment`] already provides a (placeholder)
    /// default.
    fn composite_impl_explicit_minimum_alignment(&self) -> i32 {
        self.stored_minimum_alignment_value()
    }

    /// Port of `CompositeDataTypeImpl.setExplicitMinimumAlignment(int)`. Exposed under a distinct
    /// name since [`Composite::set_explicit_minimum_alignment`] already provides a (placeholder)
    /// default.
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors `IllegalArgumentException`).
    fn composite_impl_set_explicit_minimum_alignment(&mut self, minimum_alignment: i32) -> Result<(), String> {
        if minimum_alignment <= 0 {
            return Err(format!(
                "IllegalArgumentException: explicit minimum alignment must be positive: {minimum_alignment}"
            ));
        }
        self.composite_impl_set_stored_minimum_alignment(minimum_alignment);
        Ok(())
    }

    /// Port of the private `CompositeDataTypeImpl.setStoredMinimumAlignment(int)`. Not exposed in
    /// Java beyond this class, but kept as a normal (non-required) trait method for reuse by the
    /// public setters above; callers already validate `minimum_alignment >= MACHINE_ALIGNMENT`
    /// before reaching here, so an out-of-range value is silently ignored rather than panicking.
    fn composite_impl_set_stored_minimum_alignment(&mut self, minimum_alignment: i32) {
        if minimum_alignment < MACHINE_ALIGNMENT {
            return;
        }
        if self.stored_minimum_alignment_value() == minimum_alignment {
            return;
        }
        self.set_stored_minimum_alignment_value(minimum_alignment);
        self.repack_with_notify(true);
    }

    /// Port of the protected final `CompositeDataTypeImpl.getNonPackedAlignment()`.
    fn composite_impl_non_packed_alignment(&self) -> i32 {
        let alignment = self.stored_minimum_alignment_value();
        if alignment == DEFAULT_ALIGNMENT {
            1
        } else if alignment == MACHINE_ALIGNMENT {
            self.get_data_organization().get_machine_alignment()
        } else {
            alignment
        }
    }

    /// Port of the protected `CompositeDataTypeImpl.getPreferredComponentLength(DataType, int,
    /// int)`. See the module-level documentation for why `is_dynamic_with_specifiable_length`
    /// stands in for `(dataType instanceof Dynamic dynamic) && dynamic.canSpecifyLength()`.
    ///
    /// # Errors
    /// Returns `Err` if a positive length cannot be determined for a non-dynamic `data_type`
    /// (mirrors `IllegalArgumentException`).
    fn composite_impl_preferred_component_length(
        &self,
        data_type: &dyn DataType,
        is_dynamic_with_specifiable_length: bool,
        length: i32,
        max_length: i32,
    ) -> Result<i32, String> {
        if uses_zero_length_component(data_type) {
            return Ok(0);
        }
        if !is_dynamic_with_specifiable_length {
            if self.is_packing_enabled() {
                let aligned = data_type.get_aligned_length();
                if aligned > 0 {
                    return Ok(aligned);
                }
            } else if self.is_union() {
                // enforce Union component size for fixed-length types
                let l = data_type.get_length();
                if l > 0 {
                    return Ok(l);
                }
            } else if max_length >= 0 {
                // length determined by datatype but must not exceed maxLength
                let l = data_type.get_length().min(max_length);
                if l > 0 {
                    return Ok(l);
                }
            }
        }
        preferred_component_length_for_data_type(data_type, is_dynamic_with_specifiable_length, length)
    }

    /// Port of the protected `CompositeDataTypeImpl.getPreferredComponentLength(DataType, int)`.
    ///
    /// # Errors
    /// See [`CompositeDataTypeImpl::composite_impl_preferred_component_length`].
    fn composite_impl_preferred_component_length_default(
        &self,
        data_type: &dyn DataType,
        is_dynamic_with_specifiable_length: bool,
        length: i32,
    ) -> Result<i32, String> {
        self.composite_impl_preferred_component_length(data_type, is_dynamic_with_specifiable_length, length, -1)
    }
}

/// Port of `DataUtilities.isValidDataTypeName(String)`, used by
/// [`CompositeDataTypeImpl::composite_impl_set_name`] in place of the unported
/// `DataTypeImpl.checkValidName`/`DataUtilities.isValidDataTypeName`.
fn check_valid_name(name: &str) -> Result<(), InvalidNameException> {
    if name.trim().is_empty() || name.chars().any(|c| c.is_control()) {
        return Err(InvalidNameException::with_message(format!("Invalid Name: {name}")));
    }
    Ok(())
}

/// Port of the static `DataTypeComponentImpl.getPreferredComponentLength(DataType, int)`, used by
/// [`CompositeDataTypeImpl::composite_impl_preferred_component_length`] and (since the Java
/// `CompositeDB.getPreferredComponentLength` body is identical up to this shared tail call) by
/// [`CompositeDb`](crate::program::database::data::composite_db::CompositeDb)'s own port of that
/// method. See the module-level documentation for why `is_dynamic_with_specifiable_length` stands
/// in for `(dataType instanceof Dynamic dynamic) && dynamic.canSpecifyLength()`.
pub(crate) fn preferred_component_length_for_data_type(
    data_type: &dyn DataType,
    is_dynamic_with_specifiable_length: bool,
    length: i32,
) -> Result<i32, String> {
    if uses_zero_length_component(data_type) {
        return Ok(0);
    }
    if is_dynamic_with_specifiable_length {
        return Ok(length);
    }
    let dt_length = data_type.get_length();
    let mut length = length;
    if length <= 0 {
        length = dt_length;
    } else if dt_length >= 0 && dt_length < length {
        length = dt_length;
    }
    if length <= 0 {
        return Err(format!(
            "IllegalArgumentException: Positive length must be specified for {} component",
            data_type.get_display_name()
        ));
    }
    Ok(length)
}

/// Port of the relevant cases of `DataTypeUtilities.isSecondPartOfFirst(DataType, DataType)`,
/// used by [`CompositeDataTypeImpl::composite_impl_is_part_of`] to recurse into a component's
/// data type. See the module-level documentation for what diverges from the Java original.
fn is_part_of_data_type(data_type: Box<dyn DataType>, target: &dyn DataType) -> bool {
    if data_type.is_pointer() || target.is_pointer() {
        return false;
    }
    if data_type.get_data_type_path() == target.get_data_type_path() {
        return true;
    }
    if data_type.is_typedef() {
        return match data_type.typedef_base_data_type() {
            Some(inner) => is_part_of_data_type(inner, target),
            None => false,
        };
    }
    match data_type.into_composite() {
        Some(composite) => composite
            .get_defined_components()
            .into_iter()
            .any(|dtc| is_part_of_data_type(dtc.get_data_type(), target)),
        None => false,
    }
}

/// Minimal stand-in for the unported `DataTypeComponentImpl`, backing
/// [`CompositeDataTypeImpl::composite_impl_create_component`]'s default implementation. See the
/// module-level documentation for why [`DataTypeComponent::get_data_type`]/
/// [`DataTypeComponent::get_parent`] are left at their trait defaults.
struct BasicDataTypeComponent {
    data_type_name: String,
    length: i32,
    ordinal: i32,
    offset: i32,
    field_name: Option<String>,
    comment: Option<String>,
}

impl DataTypeComponent for BasicDataTypeComponent {
    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_data_type_name(&self) -> String {
        self.data_type_name.clone()
    }

    fn get_field_name(&self) -> Option<String> {
        self.field_name.clone()
    }

    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MockComposite {
        name: RefCell<String>,
        description: RefCell<String>,
        packing: RefCell<i32>,
        minimum_alignment: RefCell<i32>,
        num_components: i32,
        components: Vec<(&'static str, i32)>,
        is_union_flag: RefCell<bool>,
        repack_calls: RefCell<Vec<bool>>,
        add_calls: RefCell<Vec<(i32, Option<String>, Option<String>)>>,
    }

    /// Test-only component whose [`DataTypeComponent::get_data_type`] returns a real (freshly
    /// constructed) [`MockPlainDataType`], unlike [`BasicDataTypeComponent`] -- needed to exercise
    /// [`is_part_of_data_type`]'s recursion into a component's data type.
    struct NamedComponent {
        name: &'static str,
        length: i32,
    }

    impl DataTypeComponent for NamedComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockPlainDataType { name: self.name, length: self.length })
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_data_type_name(&self) -> String {
            self.name.to_string()
        }
    }

    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            self.name.borrow().clone()
        }
        fn get_display_name(&self) -> String {
            format!("display:{}", self.name.borrow())
        }
        fn is_union(&self) -> bool {
            *self.is_union_flag.borrow()
        }
    }

    impl Composite for MockComposite {
        fn get_num_components(&self) -> i32 {
            self.num_components
        }
        fn get_num_defined_components(&self) -> i32 {
            self.components.len() as i32
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|(name, len)| -> Box<dyn DataTypeComponent> {
                    Box::new(NamedComponent { name, length: *len })
                })
                .collect()
        }
        fn get_packing_type(&self) -> PackingType {
            self.composite_impl_packing_type()
        }
    }

    impl CompositeInternal for MockComposite {
        fn get_stored_packing_value(&self) -> i32 {
            self.composite_impl_stored_packing_value()
        }
        fn get_stored_minimum_alignment(&self) -> i32 {
            self.composite_impl_stored_minimum_alignment()
        }
    }

    impl CompositeDataTypeImpl for MockComposite {
        fn stored_description(&self) -> String {
            self.description.borrow().clone()
        }
        fn set_stored_description(&mut self, description: String) {
            *self.description.borrow_mut() = description;
        }
        fn stored_minimum_alignment_value(&self) -> i32 {
            *self.minimum_alignment.borrow()
        }
        fn set_stored_minimum_alignment_value(&mut self, minimum_alignment: i32) {
            *self.minimum_alignment.borrow_mut() = minimum_alignment;
        }
        fn stored_packing_value(&self) -> i32 {
            *self.packing.borrow()
        }
        fn set_stored_packing_value_raw(&mut self, packing: i32) {
            *self.packing.borrow_mut() = packing;
        }
        fn set_stored_name(&mut self, name: String) {
            *self.name.borrow_mut() = name;
        }
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            false
        }
        fn repack_with_notify(&mut self, notify: bool) -> bool {
            self.repack_calls.borrow_mut().push(notify);
            false
        }
        fn composite_impl_alignment(&self) -> i32 {
            1
        }
        fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {
            for dtc in self.get_defined_components() {
                consumer(dtc.as_ref());
            }
        }
        fn composite_impl_add_with_length_and_name(
            &mut self,
            data_type: Box<dyn DataType>,
            length: i32,
            field_name: Option<String>,
            comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            self.add_calls.borrow_mut().push((length, field_name.clone(), comment.clone()));
            Ok(self.composite_impl_create_component(data_type, length, 0, 0, field_name, comment))
        }
        fn composite_impl_insert_with_length_and_name(
            &mut self,
            _ordinal: i32,
            data_type: Box<dyn DataType>,
            length: i32,
            field_name: Option<String>,
            comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Ok(self.composite_impl_create_component(data_type, length, 0, 0, field_name, comment))
        }
        fn composite_impl_validate_data_type(
            &self,
            data_type: Box<dyn DataType>,
        ) -> Result<Box<dyn DataType>, String> {
            Ok(data_type)
        }
        fn composite_impl_update_bit_field_data_type(
            &mut self,
            _bitfield_component: Box<dyn DataTypeComponent>,
            _old_dt: &dyn DataType,
            _new_dt: Option<&dyn DataType>,
        ) -> Result<bool, String> {
            Ok(false)
        }
    }

    struct MockPlainDataType {
        name: &'static str,
        length: i32,
    }

    impl DataType for MockPlainDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn sample() -> MockComposite {
        MockComposite {
            name: RefCell::new("MyStruct".to_string()),
            packing: RefCell::new(NO_PACKING),
            minimum_alignment: RefCell::new(DEFAULT_ALIGNMENT),
            ..Default::default()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let c = sample();
        let dyn_c: &dyn CompositeDataTypeImpl = &c;
        assert_eq!(dyn_c.composite_impl_packing_type(), PackingType::Disabled);
        assert!(dyn_c.composite_impl_is_not_yet_defined());
    }

    #[test]
    fn packing_type_reflects_boundaries() {
        let mut c = sample();
        assert_eq!(c.composite_impl_packing_type(), PackingType::Disabled);
        *c.packing.borrow_mut() = DEFAULT_PACKING;
        assert_eq!(c.composite_impl_packing_type(), PackingType::Default);
        *c.packing.borrow_mut() = 8;
        assert_eq!(c.composite_impl_packing_type(), PackingType::Explicit);
    }

    #[test]
    fn set_packing_enabled_resets_alignment_and_calls_repack() {
        let mut c = sample();
        *c.minimum_alignment.borrow_mut() = 16;
        assert_eq!(c.composite_impl_packing_type(), PackingType::Disabled);

        c.composite_impl_set_packing_enabled(true);
        assert_eq!(c.composite_impl_packing_type(), PackingType::Default);
        assert_eq!(*c.minimum_alignment.borrow(), DEFAULT_ALIGNMENT);
        assert_eq!(*c.repack_calls.borrow(), vec![true]);

        // toggling to the same state again is a no-op
        c.composite_impl_set_packing_enabled(true);
        assert_eq!(c.repack_calls.borrow().len(), 1);
    }

    #[test]
    fn alignment_type_reflects_boundaries() {
        let mut c = sample();
        assert_eq!(c.composite_impl_alignment_type(), AlignmentType::Default);
        *c.minimum_alignment.borrow_mut() = MACHINE_ALIGNMENT;
        assert_eq!(c.composite_impl_alignment_type(), AlignmentType::Machine);
        *c.minimum_alignment.borrow_mut() = 32;
        assert_eq!(c.composite_impl_alignment_type(), AlignmentType::Explicit);
    }

    #[test]
    fn set_explicit_packing_and_alignment_reject_non_positive() {
        let mut c = sample();
        assert!(c.composite_impl_set_explicit_packing_value(0).is_err());
        assert!(c.composite_impl_set_explicit_packing_value(-1).is_err());
        assert!(c.composite_impl_set_explicit_packing_value(4).is_ok());
        assert_eq!(c.composite_impl_explicit_packing_value(), 4);

        assert!(c.composite_impl_set_explicit_minimum_alignment(0).is_err());
        assert!(c.composite_impl_set_explicit_minimum_alignment(16).is_ok());
        assert_eq!(c.composite_impl_explicit_minimum_alignment(), 16);
    }

    #[test]
    fn is_not_yet_defined_requires_no_components_and_disabled_packing() {
        let mut c = sample();
        assert!(c.composite_impl_is_not_yet_defined());

        c.num_components = 1;
        assert!(!c.composite_impl_is_not_yet_defined());

        c.num_components = 0;
        *c.packing.borrow_mut() = DEFAULT_PACKING;
        assert!(!c.composite_impl_is_not_yet_defined());
    }

    #[test]
    fn is_part_of_finds_nested_component() {
        let c = MockComposite {
            components: vec![("int", 4), ("float", 4)],
            ..sample()
        };
        struct TargetType;
        impl DataType for TargetType {
            fn get_name(&self) -> String {
                "int".to_string()
            }
        }
        let target = TargetType;
        // component data type path "/int" matches target's path "/int"
        assert!(c.composite_impl_is_part_of(&target));

        struct Missing;
        impl DataType for Missing {
            fn get_name(&self) -> String {
                "missing".to_string()
            }
        }
        assert!(!c.composite_impl_is_part_of(&Missing));
    }

    #[test]
    fn mnemonic_uses_display_name() {
        let c = sample();
        struct MockSettings;
        impl Settings for MockSettings {}
        assert_eq!(c.composite_impl_mnemonic(&MockSettings), "display:MyStruct");
    }

    #[test]
    fn set_name_validates_and_stores() {
        let mut c = sample();
        assert!(c.composite_impl_set_name("").is_err());
        assert!(c.composite_impl_set_name("bad\u{0007}name").is_err());
        assert!(c.composite_impl_set_name("NewName").is_ok());
        assert_eq!(c.get_name(), "NewName");
    }

    #[test]
    fn add_overloads_delegate_to_canonical_form() {
        let mut c = sample();
        let dt: Box<dyn DataType> = Box::new(MockPlainDataType { name: "byte", length: 1 });
        c.composite_impl_add(dt).unwrap();
        assert_eq!(c.add_calls.borrow()[0], (-1, None, None));

        let dt2: Box<dyn DataType> = Box::new(MockPlainDataType { name: "word", length: 2 });
        c.composite_impl_add_with_length(dt2, 4).unwrap();
        assert_eq!(c.add_calls.borrow()[1], (4, None, None));

        let dt3: Box<dyn DataType> = Box::new(MockPlainDataType { name: "dword", length: 4 });
        c.composite_impl_add_with_name(dt3, Some("field".to_string()), Some("note".to_string()))
            .unwrap();
        assert_eq!(
            c.add_calls.borrow()[2],
            (-1, Some("field".to_string()), Some("note".to_string()))
        );
    }

    #[test]
    fn preferred_component_length_zero_length_component() {
        let c = sample();
        struct ZeroLength;
        impl DataType for ZeroLength {
            fn is_zero_length(&self) -> bool {
                true
            }
        }
        assert_eq!(
            c.composite_impl_preferred_component_length(&ZeroLength, false, -1, -1),
            Ok(0)
        );
    }

    #[test]
    fn preferred_component_length_uses_union_size_when_disabled() {
        let c = sample();
        *c.is_union_flag.borrow_mut() = true;
        let dt = MockPlainDataType { name: "qword", length: 8 };
        assert_eq!(c.composite_impl_preferred_component_length(&dt, false, -1, -1), Ok(8));
    }

    #[test]
    fn preferred_component_length_for_data_type_rejects_non_positive() {
        let dt = MockPlainDataType { name: "empty", length: 0 };
        let err = preferred_component_length_for_data_type(&dt, false, -1).unwrap_err();
        assert!(err.contains("Positive length"));
    }

    #[test]
    fn create_component_carries_fields() {
        let c = sample();
        let dt: Box<dyn DataType> = Box::new(MockPlainDataType { name: "byte", length: 1 });
        let component = c.composite_impl_create_component(
            dt,
            4,
            2,
            8,
            Some("field2".to_string()),
            Some("a comment".to_string()),
        );
        assert_eq!(component.get_length(), 4);
        assert_eq!(component.get_ordinal(), 2);
        assert_eq!(component.get_offset(), 8);
        assert_eq!(component.get_field_name(), Some("field2".to_string()));
        assert_eq!(component.get_comment(), Some("a comment".to_string()));
        assert_eq!(component.get_data_type_name(), "byte");
    }

    #[test]
    fn non_packed_alignment_reflects_boundaries() {
        let mut c = sample();
        assert_eq!(c.composite_impl_non_packed_alignment(), 1);
        *c.minimum_alignment.borrow_mut() = 4;
        assert_eq!(c.composite_impl_non_packed_alignment(), 4);
    }

    #[test]
    fn set_value_is_not_yet_implemented() {
        let c = sample();
        struct MockBuf;
        impl MemBuffer for MockBuf {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
            fn get_address(&self) -> crate::program::model::address::Address {
                crate::program::model::address::SpecialAddress::no_address()
            }
        }
        struct MockSettings;
        impl Settings for MockSettings {}
        let result = c.composite_impl_set_value(&MockBuf, &MockSettings, 4, &0i32);
        assert!(result.is_err());
    }

    #[test]
    fn description_get_and_set() {
        let mut c = sample();
        assert_eq!(c.composite_impl_description(), "");
        c.composite_impl_set_description(Some("a composite"));
        assert_eq!(c.composite_impl_description(), "a composite");
        c.composite_impl_set_description(None);
        assert_eq!(c.composite_impl_description(), "");
    }
}
