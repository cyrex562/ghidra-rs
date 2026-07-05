use std::collections::HashSet;

use crate::program::model::data::alignment_type::AlignmentType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::internal_data_type_component::cleanup_field_name;
use crate::program::model::data::packing_type::PackingType;

/// Interface for common methods in Structure and Union.
///
/// Port of `ghidra.program.model.data.Composite`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that already carried
/// `get_num_components`, which maps directly onto this interface's abstract method of the same
/// shape and is retained here as a superset so existing callers
/// ([`Structure`](super::structure::Structure)'s default `get_component_at`) keep compiling.
///
/// Every method is given a default so that existing bare `impl Composite for Mock {}` blocks in
/// [`Structure`](super::structure::Structure), [`Union`](super::union::Union), and
/// [`AnnotationHandler`](super::annotation_handler::AnnotationHandler)'s tests keep compiling
/// unmodified. Concrete implementations (`CompositeDB`, `StructureDataType`, `UnionDataType`,
/// etc.) will override these with real behavior once they are ported. Methods that throw checked
/// or runtime exceptions in Java (`IllegalArgumentException`, `IndexOutOfBoundsException`,
/// `InvalidDataTypeException`) return `Result<_, String>` here, matching the convention already
/// used by [`Structure`](super::structure::Structure) and [`Union`](super::union::Union).
pub trait Composite: DataType {
    /// Gets the number of component data types in this composite. If this is Structure with
    /// packing disabled, the count will include all undefined filler components which may be
    /// present.
    fn get_num_components(&self) -> i32 {
        0
    }

    /// Returns the number of explicitly defined components in this composite. For Unions and
    /// packed Structures this is equivalent to [`get_num_components`](Self::get_num_components)
    /// since they do not contain undefined components. This count will always exclude all
    /// undefined filler components which may be present within a Structure whose packing is
    /// disabled (see [`is_packing_enabled`](Self::is_packing_enabled)).
    fn get_num_defined_components(&self) -> i32 {
        0
    }

    /// Returns the component of this data type with the indicated ordinal.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Find the first component which has the specified case-sensitive field name. Note that
    /// multiple components may be specified with the same name, if this is a possibility
    /// [`find_components`](Self::find_components) should be used. Only components with an
    /// explicit non-default field name will be considered. The name specified may be sanitized
    /// to be consistent with those permitted by `Composite` data types.
    fn find_component(&self, field_name: &str) -> Option<Box<dyn DataTypeComponent>> {
        if self.get_num_defined_components() == 0 {
            return None;
        }
        let field_name = cleanup_field_name(Some(field_name))?;
        self.get_defined_components()
            .into_iter()
            .find(|dtc| dtc.get_field_name().as_deref() == Some(field_name.as_str()))
    }

    /// Find all components which have the specified case-sensitive field name. Note that
    /// multiple components may be specified with the same name, if this is a possibility
    /// [`find_components`](Self::find_components) should be used. Only components with an
    /// explicit non-default field name will be considered. The name specified may be sanitized
    /// to be consistent with those permitted by `Composite` data types.
    fn find_components(&self, name: &str) -> Vec<Box<dyn DataTypeComponent>> {
        if self.get_num_defined_components() == 0 {
            return Vec::new();
        }
        self.get_defined_components()
            .into_iter()
            .filter(|dtc| dtc.get_field_name().as_deref() == Some(name))
            .collect()
    }

    /// Returns a vec of Data Type Components that make up this composite including undefined
    /// filler components which may be present within a Structure which has packing disabled.
    /// The number of components corresponds to
    /// [`get_num_components`](Self::get_num_components).
    fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        Vec::new()
    }

    /// Returns a vec of Data Type Components that make up this composite excluding undefined
    /// filler components which may be present within Structures where packing is disabled. The
    /// number of components corresponds to
    /// [`get_num_defined_components`](Self::get_num_defined_components). For Unions and packed
    /// Structures this is equivalent to [`get_components`](Self::get_components) since they do
    /// not contain undefined filler components.
    fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        Vec::new()
    }

    /// Adds a new datatype to the end of this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be added to this composite
    /// data type (mirrors `IllegalArgumentException`). For example, suppose dt1 contains dt2.
    /// Therefore it is not valid to add dt1 to dt2 since this would cause a cyclic dependency.
    fn add(&mut self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = data_type;
        Err("IllegalArgumentException: data type not allowed in this composite".to_string())
    }

    /// Adds a new datatype to the end of this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be added to this composite
    /// data type or an invalid length is specified (mirrors `IllegalArgumentException`).
    fn add_with_length(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = length;
        self.add(data_type)
    }

    /// Adds a new datatype to the end of this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be added to this composite
    /// data type (mirrors `IllegalArgumentException`).
    fn add_with_name(
        &mut self,
        data_type: Box<dyn DataType>,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = (component_name, comment);
        self.add(data_type)
    }

    /// Adds a new bitfield to the end of this composite. This method is intended to be used
    /// with packed structures/unions only where the bitfield will be appropriately packed. The
    /// minimum storage byte size will be applied. It will not provide useful results for
    /// composites with packing disabled.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not a valid base type for bitfields (mirrors
    /// `InvalidDataTypeException`).
    fn add_bit_field(
        &mut self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _) = (base_data_type, bit_size, component_name, comment);
        Err("InvalidDataTypeException: not a valid bitfield base type".to_string())
    }

    /// Adds a new datatype to the end of this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be added to this composite
    /// data type or an invalid length is specified (mirrors `IllegalArgumentException`).
    fn add_with_length_and_name(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = length;
        self.add_with_name(data_type, component_name, comment)
    }

    /// Inserts a new datatype at the specified ordinal position in this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be inserted into this
    /// composite data type (mirrors `IllegalArgumentException`), or if `ordinal` is out of
    /// bounds (mirrors `IndexOutOfBoundsException`).
    fn insert(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = data_type;
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Inserts a new datatype at the specified ordinal position in this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be inserted into this
    /// composite data type or an invalid length is specified (mirrors
    /// `IllegalArgumentException`), or if `ordinal` is out of bounds (mirrors
    /// `IndexOutOfBoundsException`).
    fn insert_with_length(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = length;
        self.insert(ordinal, data_type)
    }

    /// Inserts a new datatype at the specified ordinal position in this composite.
    ///
    /// Note: When packing is enabled the component's offset will get determined automatically
    /// to provide the proper alignment.
    ///
    /// # Errors
    /// Returns `Err` if the specified data type is not allowed to be inserted into this
    /// composite data type or an invalid length is specified (mirrors
    /// `IllegalArgumentException`), or if `ordinal` is out of bounds (mirrors
    /// `IndexOutOfBoundsException`).
    fn insert_with_length_and_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let _ = (component_name, comment);
        self.insert_with_length(ordinal, data_type, length)
    }

    /// Deletes the component at the given ordinal position.
    ///
    /// Note: Removal of bitfields from a structure with packing disabled will not shift other
    /// components causing vacated bytes to revert to undefined filler.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn delete(&mut self, ordinal: i32) -> Result<(), String> {
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Deletes the specified set of components at the given ordinal positions.
    ///
    /// Note: Removal of bitfields from a structure with packing disabled will not shift other
    /// components causing vacated bytes to revert to undefined filler.
    ///
    /// # Errors
    /// Returns `Err` if any specified component ordinal is out of bounds (mirrors
    /// `IndexOutOfBoundsException`).
    fn delete_set(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        for ordinal in ordinals {
            self.delete(*ordinal)?;
        }
        Ok(())
    }

    /// Check if a data type is part of this data type. A data type could be part of another by:
    /// being the same data type, containing the data type directly, or containing another data
    /// type that has the data type as a part of it.
    fn is_part_of(&self, data_type: &dyn DataType) -> bool {
        let _ = data_type;
        false
    }

    /// Updates packed composite to any changes in the data organization. If the composite does
    /// not have packing enabled this method does nothing.
    ///
    /// NOTE: Changes to data organization is discouraged. Attempts to use this method in such
    /// cases should be performed on all composites in dependency order (ignoring pointer
    /// components).
    fn repack(&mut self) {}

    /// The packing type set for this composite.
    fn get_packing_type(&self) -> PackingType {
        PackingType::Disabled
    }

    /// Determine if this data type has its internal components currently packed based upon
    /// alignment and packing settings. If disabled, component placement is based upon explicit
    /// placement by offset.
    fn is_packing_enabled(&self) -> bool {
        self.get_packing_type() != PackingType::Disabled
    }

    /// Sets whether this data type's internal components are currently packed. The affect of
    /// disabled packing differs between `Structure` and `Union`. When packing disabled:
    /// Structures utilize explicit component offsets and produce undefined filler components
    /// where defined components do not consume space; Unions always place components at offset
    /// 0 and do not pad for alignment.
    ///
    /// In addition, when packing is disabled the default alignment is always 1 unless a
    /// different minimum alignment has been set. When packing is enabled the overall composite
    /// length influenced by the composite's minimum alignment setting. If a change in
    /// enablement occurs, the default alignment and packing behavior will be used.
    fn set_packing_enabled(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Determine if packing is enabled with an explicit packing value (see
    /// [`get_explicit_packing_value`](Self::get_explicit_packing_value)).
    fn has_explicit_packing_value(&self) -> bool {
        self.get_packing_type() == PackingType::Explicit
    }

    /// Determine if default packing is enabled.
    fn has_default_packing(&self) -> bool {
        self.get_packing_type() == PackingType::Default
    }

    /// Gets the current packing value (typically a power of 2). If this isn't a packed
    /// composite with an explicit packing value (see
    /// [`has_explicit_packing_value`](Self::has_explicit_packing_value)) then the return value
    /// is undefined.
    fn get_explicit_packing_value(&self) -> i32 {
        0
    }

    /// Sets the pack value for this composite (positive value, usually a power of 2). If
    /// packing was previously disabled, packing will be enabled. This value will establish the
    /// maximum effective alignment for this composite and each of the components during the
    /// alignment computation (e.g., a value of 1 will eliminate any padding). The overall
    /// composite length may be influenced by the composite's minimum alignment setting.
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors
    /// `IllegalArgumentException`).
    fn set_explicit_packing_value(&mut self, packing_value: i32) -> Result<(), String> {
        if packing_value <= 0 {
            return Err("IllegalArgumentException: packing value must be positive".to_string());
        }
        Ok(())
    }

    /// Same as [`set_explicit_packing_value`](Self::set_explicit_packing_value).
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors
    /// `IllegalArgumentException`).
    fn pack(&mut self, packing_value: i32) -> Result<(), String> {
        self.set_explicit_packing_value(packing_value)
    }

    /// Enables default packing behavior. If packing was previously disabled, packing will be
    /// enabled. Composite will automatically pack based upon the alignment requirements of its
    /// components with overall composite length possibly influenced by the composite's minimum
    /// alignment setting.
    fn set_to_default_packing(&mut self) {}

    /// The alignment type set for this composite.
    fn get_alignment_type(&self) -> AlignmentType {
        AlignmentType::Default
    }

    /// Whether or not this data type is using the default alignment. When Structure packing is
    /// disabled the default alignment is always 1 (see
    /// [`set_packing_enabled`](Self::set_packing_enabled)).
    fn is_default_aligned(&self) -> bool {
        self.get_alignment_type() == AlignmentType::Default
    }

    /// Whether or not this data type is using the machine alignment value, specified by
    /// `DataOrganization.getMachineAlignment()`, for its alignment.
    fn is_machine_aligned(&self) -> bool {
        self.get_alignment_type() == AlignmentType::Machine
    }

    /// Determine if an explicit minimum alignment has been set (see
    /// [`get_explicit_minimum_alignment`](Self::get_explicit_minimum_alignment)). An undefined
    /// value is returned if default alignment or machine alignment is enabled.
    fn has_explicit_minimum_alignment(&self) -> bool {
        self.get_alignment_type() == AlignmentType::Explicit
    }

    /// Get the explicit minimum alignment setting for this Composite which contributes to the
    /// actual computed alignment value (see `DataType.getAlignment()`).
    fn get_explicit_minimum_alignment(&self) -> i32 {
        0
    }

    /// Sets this data type's explicit minimum alignment (positive value). Together with the
    /// pack setting and component alignments will affect the actual computed alignment of this
    /// composite. When packing is enabled, the alignment setting may also affect padding at the
    /// end of the composite and its length. When packing is disabled, this setting will not
    /// affect the length of this composite.
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors
    /// `IllegalArgumentException`).
    fn set_explicit_minimum_alignment(&mut self, min_alignment: i32) -> Result<(), String> {
        if min_alignment <= 0 {
            return Err("IllegalArgumentException: minimum alignment must be positive".to_string());
        }
        Ok(())
    }

    /// Same as [`set_explicit_minimum_alignment`](Self::set_explicit_minimum_alignment).
    ///
    /// # Errors
    /// Returns `Err` if a non-positive value is specified (mirrors
    /// `IllegalArgumentException`).
    fn align(&mut self, min_alignment: i32) -> Result<(), String> {
        self.set_explicit_minimum_alignment(min_alignment)
    }

    /// Sets this data type's alignment to its default alignment. For packed composites, this
    /// data type's alignment will be based upon the components it contains and its current
    /// pack settings. This is the default state and only needs to be used when changing from a
    /// non-default alignment type.
    fn set_to_default_aligned(&mut self) {}

    /// Sets this data type's minimum alignment to the machine alignment which is specified by
    /// `DataOrganization.getMachineAlignment()`. The machine alignment is defined as the
    /// maximum useful alignment for the target machine.
    fn set_to_machine_aligned(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeComponent {
        field_name: Option<String>,
    }

    impl DataTypeComponent for MockDataTypeComponent {
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
    }

    struct MockComposite {
        packing_type: PackingType,
        components: Vec<(&'static str,)>,
    }

    impl DataType for MockComposite {}

    impl Composite for MockComposite {
        fn get_num_defined_components(&self) -> i32 {
            self.components.len() as i32
        }

        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|(name,)| -> Box<dyn DataTypeComponent> {
                    Box::new(MockDataTypeComponent {
                        field_name: Some(name.to_string()),
                    })
                })
                .collect()
        }

        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
    }

    fn sample() -> MockComposite {
        MockComposite {
            packing_type: PackingType::Disabled,
            components: vec![("alpha",), ("beta",)],
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let c = sample();
        let dyn_composite: &dyn Composite = &c;
        assert_eq!(dyn_composite.get_num_components(), 0);
        assert_eq!(dyn_composite.get_num_defined_components(), 2);
        assert!(dyn_composite.get_component(0).is_err());
        assert!(!dyn_composite.is_part_of(&EmptyDataType));
    }

    struct EmptyDataType;
    impl DataType for EmptyDataType {}

    #[test]
    fn find_component_matches_field_name() {
        let c = sample();
        let found = c.find_component("beta");
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_field_name(), Some("beta".to_string()));
        assert!(c.find_component("missing").is_none());
    }

    #[test]
    fn find_components_returns_all_matches() {
        let c = sample();
        assert_eq!(c.find_components("alpha").len(), 1);
        assert_eq!(c.find_components("missing").len(), 0);
    }

    #[test]
    fn packing_defaults_track_packing_type() {
        let mut c = sample();
        assert!(!c.is_packing_enabled());
        assert!(!c.has_explicit_packing_value());
        assert!(!c.has_default_packing());

        c.packing_type = PackingType::Explicit;
        assert!(c.is_packing_enabled());
        assert!(c.has_explicit_packing_value());

        c.packing_type = PackingType::Default;
        assert!(c.has_default_packing());
    }

    #[test]
    fn set_explicit_packing_value_rejects_non_positive() {
        let mut c = sample();
        assert!(c.set_explicit_packing_value(0).is_err());
        assert!(c.set_explicit_packing_value(-1).is_err());
        assert!(c.set_explicit_packing_value(4).is_ok());
        assert!(c.pack(8).is_ok());
    }

    #[test]
    fn alignment_defaults_track_alignment_type() {
        struct AlignedComposite(AlignmentType);
        impl DataType for AlignedComposite {}
        impl Composite for AlignedComposite {
            fn get_alignment_type(&self) -> AlignmentType {
                self.0
            }
        }

        let default_aligned = AlignedComposite(AlignmentType::Default);
        assert!(default_aligned.is_default_aligned());
        assert!(!default_aligned.is_machine_aligned());
        assert!(!default_aligned.has_explicit_minimum_alignment());

        let machine_aligned = AlignedComposite(AlignmentType::Machine);
        assert!(machine_aligned.is_machine_aligned());

        let explicit_aligned = AlignedComposite(AlignmentType::Explicit);
        assert!(explicit_aligned.has_explicit_minimum_alignment());
    }

    #[test]
    fn set_explicit_minimum_alignment_rejects_non_positive() {
        let mut c = sample();
        assert!(c.set_explicit_minimum_alignment(0).is_err());
        assert!(c.set_explicit_minimum_alignment(-4).is_err());
        assert!(c.set_explicit_minimum_alignment(16).is_ok());
        assert!(c.align(8).is_ok());
    }

    #[test]
    fn delete_set_stops_at_first_error() {
        let mut c = sample();
        let mut ordinals = HashSet::new();
        ordinals.insert(0);
        assert!(c.delete_set(&ordinals).is_err());
    }

    #[test]
    fn bare_impl_stays_object_safe() {
        struct BareComposite;
        impl DataType for BareComposite {}
        impl Composite for BareComposite {}

        let c = BareComposite;
        let dyn_composite: &dyn Composite = &c;
        assert_eq!(dyn_composite.get_num_components(), 0);
        assert!(dyn_composite.get_components().is_empty());
        assert!(dyn_composite.get_defined_components().is_empty());
        assert!(!dyn_composite.is_packing_enabled());
    }
}
