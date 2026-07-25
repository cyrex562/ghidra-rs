use std::fmt;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::label_string::{LabelString, LabelType};
use crate::program::model::listing::variable::Variable;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::Reference;

/// The Scalar or Register sub-operand replaced by a [`VariableOffset`].
///
/// Stands in for the `Object replacedElement` field on the Java class, which is always either a
/// `Scalar` or a `Register` (or unset).
#[derive(Debug, Clone, PartialEq)]
pub enum ReplacedElement {
    /// Stands in for `setReplacedElement(Scalar, boolean)`.
    Scalar(Scalar),
    /// Stands in for `setReplacedElement(Register)`.
    Register(RegisterRef),
}

/// One markup object making up a [`VariableOffset`]'s displayable representation, as produced by
/// `getObjects()`.
#[derive(Debug, Clone)]
pub enum VariableOffsetObject {
    /// The variable (and any field/array-index navigation) name label.
    Label(LabelString),
    /// The `+`/`-` sign separating the label from a trailing offset scalar.
    Sign(char),
    /// The residual offset scalar, when one remains after field/array navigation.
    Scalar(Scalar),
}

impl fmt::Display for VariableOffsetObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableOffsetObject::Label(label) => write!(f, "{label}"),
            VariableOffsetObject::Sign(sign) => write!(f, "{sign}"),
            VariableOffsetObject::Scalar(scalar) => write!(f, "{scalar}"),
        }
    }
}

/// Can be used as an operand or sub-operand representation object. [`VariableOffset::to_display_string`]
/// should be used to obtain the displayable representation string. This is intended to correspond
/// to an explicit or implicit register/stack variable reference. If an offset other than 0 is
/// specified, the original [`Scalar`] should be specified via
/// [`set_replaced_element_scalar`](Self::set_replaced_element_scalar).
///
/// Port of `ghidra.program.model.listing.VariableOffset`. This was selected as a dependency-cycle
/// cut-point and ported to a trait rather than a concrete class; [`VariableOffsetImpl`] is a
/// straightforward concrete implementation carrying the two Java constructors.
pub trait VariableOffset {
    /// Returns the variable this offset is relative to. Stands in for `getVariable()`.
    fn get_variable(&self) -> Arc<dyn Variable>;

    /// Returns the offset into the variable. Stands in for `getOffset()`.
    fn get_offset(&self) -> i64;

    /// If true and the variable data-type is a pointer, the offset is relative to the underlying
    /// data-type of the pointer-type. Stands in for `isIndirect()`.
    fn is_indirect(&self) -> bool;

    /// True if the content of the variable is being read and/or written. Stands in for
    /// `isDataAccess()`.
    fn is_data_access(&self) -> bool;

    /// Returns the Scalar or Register sub-operand replaced by this object, or `None`. Stands in
    /// for `getReplacedElement()`.
    fn get_replaced_element(&self) -> Option<ReplacedElement>;

    /// True if scalar adjustment should be included with the object list or string
    /// representation. Backing state for the `includeScalarAdjustment` field, exposed since it
    /// feeds [`VariableOffset::get_objects`]'s default implementation.
    fn include_scalar_adjustment(&self) -> bool;

    /// Sets the original replaced sub-operand Scalar. `include_scalar_adjustment` controls
    /// whether scalar adjustment will be included with the object list or string representation.
    /// Stands in for `setReplacedElement(Scalar, boolean)`.
    fn set_replaced_element_scalar(&mut self, scalar: Scalar, include_scalar_adjustment: bool);

    /// Sets the original replaced sub-operand Register. Stands in for
    /// `setReplacedElement(Register)`.
    fn set_replaced_element_register(&mut self, register: RegisterRef);

    /// Returns the data type access portion of this variable offset as a string. Stands in for
    /// `getDataTypeDisplayText()`.
    fn get_data_type_display_text(&self) -> String {
        match self.get_objects_with(false).first() {
            Some(VariableOffsetObject::Label(label)) => label.to_string(),
            _ => String::new(),
        }
    }

    /// Get list of markup objects. Stands in for `getObjects()`.
    fn get_objects(&self) -> Vec<VariableOffsetObject> {
        self.get_objects_with(self.include_scalar_adjustment())
    }

    /// Renders [`VariableOffset::get_objects`] as a single string. Stands in for `toString()`.
    fn to_display_string(&self) -> String {
        self.get_objects().iter().map(ToString::to_string).collect()
    }

    /// Determine if another `VariableOffset` is equivalent to this one. Stands in for
    /// `equals(Object)`, comparing every field except the referenced [`Variable`] (compared via
    /// [`Variable::is_equivalent`] rather than Java's `Object.equals`, since `dyn Variable` has
    /// no blanket equality).
    fn variable_offset_equals(&self, other: &dyn VariableOffset) -> bool {
        self.is_data_access() == other.is_data_access()
            && self.include_scalar_adjustment() == other.include_scalar_adjustment()
            && self.is_indirect() == other.is_indirect()
            && self.get_offset() == other.get_offset()
            && self.get_replaced_element() == other.get_replaced_element()
            && self
                .get_variable()
                .is_equivalent(other.get_variable().as_ref())
    }

    /// Private helper backing [`VariableOffset::get_objects`] and
    /// [`VariableOffset::get_data_type_display_text`]. Stands in for the Java class's private
    /// `getObjects(boolean showScalarAdjustment)`.
    fn get_objects_with(&self, show_scalar_adjustment: bool) -> Vec<VariableOffsetObject> {
        let variable = self.get_variable();
        let offset = self.get_offset();
        let mut dt: Option<Box<dyn DataType>> = Some(variable.get_data_type());
        let mut name = variable.get_name().unwrap_or_default();

        let mut scalar_adjustment: i64 = 0;
        if show_scalar_adjustment {
            if let Some(ReplacedElement::Scalar(s)) = self.get_replaced_element() {
                scalar_adjustment = if variable.is_stack_variable() {
                    s.get_signed_value()
                } else {
                    s.get_value()
                };
                scalar_adjustment -= offset;
                if variable.is_stack_variable() || variable.is_memory_variable() {
                    if let Some(storage_addr) = variable.get_min_address() {
                        scalar_adjustment -= storage_addr.offset();
                    }
                }
            }
        }

        let mut abs_offset: i64 = if offset < 0 { -offset } else { offset };

        if abs_offset <= i32::MAX as i64 {
            if matches!(&dt, Some(d) if d.is_typedef()) {
                dt = dt.and_then(|d| d.typedef_base_data_type());
            }

            let mut display_as_ptr = false;
            if self.is_indirect() && matches!(&dt, Some(d) if d.is_pointer()) {
                dt = dt
                    .as_deref()
                    .and_then(|d| d.as_pointer())
                    .and_then(|p| p.get_data_type());
                display_as_ptr = true;
            }

            let mut int_off = abs_offset as i32;
            while int_off > 0 || (self.is_data_access() && int_off == 0) {
                if matches!(&dt, Some(d) if d.is_typedef()) {
                    dt = dt.and_then(|d| d.typedef_base_data_type());
                }

                let advanced = match dt.as_deref() {
                    Some(d) if d.is_structure() => match d.as_structure() {
                        Some(structure) => match structure.get_component_at(int_off) {
                            Some(cdt) if !cdt.is_bit_field_component() => {
                                let field_name = cdt
                                    .get_field_name()
                                    .or_else(|| cdt.get_default_field_name())
                                    .unwrap_or_default();
                                name.push_str(if display_as_ptr { "->" } else { "." });
                                name.push_str(&field_name);
                                int_off -= cdt.get_offset();
                                dt = Some(cdt.get_data_type());
                                true
                            }
                            // NOTE: byte offset is insufficient to identify a specific bitfield
                            _ => false,
                        },
                        None => false,
                    },
                    Some(d) if d.is_array() => match d.as_array() {
                        Some(array) if int_off < d.get_length() => {
                            let element_len = array.get_element_length();
                            let index = if element_len != 0 { int_off / element_len } else { 0 };
                            if display_as_ptr {
                                name.insert(0, '*');
                            }
                            name.push('[');
                            name.push_str(&index.to_string());
                            name.push(']');
                            int_off -= index * element_len;
                            dt = Some(array.get_data_type());
                            true
                        }
                        // unexpected
                        _ => false,
                    },
                    _ => false,
                };

                if !advanced {
                    break;
                }
                display_as_ptr = false;
            }
            abs_offset = int_off as i64;
        }

        let mut list = Vec::new();
        list.push(VariableOffsetObject::Label(LabelString::new(name, LabelType::Variable)));

        if abs_offset != 0 || scalar_adjustment != 0 {
            let mut adjusted_offset = (if offset < 0 { -abs_offset } else { abs_offset }) + scalar_adjustment;
            if adjusted_offset < 0 {
                adjusted_offset = -adjusted_offset;
                list.push(VariableOffsetObject::Sign('-'));
            } else {
                list.push(VariableOffsetObject::Sign('+'));
            }
            list.push(VariableOffsetObject::Scalar(Scalar::new(32, adjusted_offset)));
        }
        list
    }
}

impl fmt::Display for dyn VariableOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

/// Straightforward concrete [`VariableOffset`] implementation carrying the state (and the two
/// public constructors) of the ported Java class.
pub struct VariableOffsetImpl {
    variable: Arc<dyn Variable>,
    offset: i64,
    indirect: bool,
    data_access: bool,
    replaced_element: Option<ReplacedElement>,
    include_scalar_adjustment: bool,
}

impl VariableOffsetImpl {
    /// Constructor for an implied variable reference. Stands in for
    /// `VariableOffset(Variable var, long offset, boolean indirect, boolean dataAccess)`.
    ///
    /// `indirect`: if true and the variable data-type is a pointer, the offset is relative to the
    /// underlying data-type of the pointer-type. This should generally be true for register use
    /// which would contain a structure pointer not a structure instance, whereas it would be
    /// false for stack-references.
    pub fn new(variable: Arc<dyn Variable>, offset: i64, indirect: bool, data_access: bool) -> Self {
        VariableOffsetImpl {
            variable,
            offset,
            indirect,
            data_access,
            replaced_element: None,
            include_scalar_adjustment: false,
        }
    }

    /// Constructor for an explicit variable reference. Stands in for
    /// `VariableOffset(Reference ref, Variable var)`.
    pub fn from_reference(reference: &dyn Reference, variable: Arc<dyn Variable>) -> Self {
        let rt = reference.reference_type();
        let data_access = rt.is_read() || rt.is_write();

        let mut offset = 0i64;
        if variable.is_stack_variable() {
            if let Some(stack_ref) = reference.as_stack_reference() {
                if let Ok(var_stack_offset) = variable.get_stack_offset() {
                    offset = stack_ref.stack_offset() as i64 - var_stack_offset as i64;
                }
            }
        }

        VariableOffsetImpl {
            variable,
            offset,
            indirect: false,
            data_access,
            replaced_element: None,
            include_scalar_adjustment: false,
        }
    }
}

impl VariableOffset for VariableOffsetImpl {
    fn get_variable(&self) -> Arc<dyn Variable> {
        self.variable.clone()
    }

    fn get_offset(&self) -> i64 {
        self.offset
    }

    fn is_indirect(&self) -> bool {
        self.indirect
    }

    fn is_data_access(&self) -> bool {
        self.data_access
    }

    fn get_replaced_element(&self) -> Option<ReplacedElement> {
        self.replaced_element.clone()
    }

    fn include_scalar_adjustment(&self) -> bool {
        self.include_scalar_adjustment
    }

    fn set_replaced_element_scalar(&mut self, scalar: Scalar, include_scalar_adjustment: bool) {
        self.replaced_element = Some(ReplacedElement::Scalar(scalar));
        self.include_scalar_adjustment = include_scalar_adjustment;
    }

    fn set_replaced_element_register(&mut self, register: RegisterRef) {
        self.replaced_element = Some(ReplacedElement::Register(register));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::listing::function::Function;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;
    use std::cmp::Ordering;

    struct MockDataType {
        name: &'static str,
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockComponent {
        offset: i32,
        field_name: &'static str,
        data_type_length: i32,
    }

    impl DataTypeComponent for MockComponent {
        fn get_offset(&self) -> i32 {
            self.offset
        }

        fn get_field_name(&self) -> Option<String> {
            Some(self.field_name.to_string())
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: "int",
                length: self.data_type_length,
            })
        }
    }

    struct MockStructure {
        length: i32,
        component: MockComponent,
    }

    impl DataType for MockStructure {
        fn get_name(&self) -> String {
            "MockStruct".to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_structure(&self) -> bool {
            true
        }

        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }

    impl Composite for MockStructure {}

    impl Structure for MockStructure {
        fn get_component_at(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
            if offset == self.component.offset {
                Some(Box::new(MockComponent {
                    offset: self.component.offset,
                    field_name: self.component.field_name,
                    data_type_length: self.component.data_type_length,
                }))
            } else {
                None
            }
        }
    }

    struct MockVariable {
        name: String,
        data_type_length: i32,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockStructure {
                length: 16,
                component: MockComponent {
                    offset: 4,
                    field_name: "y",
                    data_type_length: self.data_type_length,
                },
            })
        }

        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_name(&self) -> Option<String> {
            Some(self.name.clone())
        }

        fn get_length(&self) -> i32 {
            self.data_type_length
        }

        fn is_valid(&self) -> bool {
            true
        }

        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }

        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }

        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            None
        }

        fn is_stack_variable(&self) -> bool {
            false
        }

        fn has_stack_storage(&self) -> bool {
            false
        }

        fn is_register_variable(&self) -> bool {
            false
        }

        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a simple stack variable".to_string()))
        }

        fn is_memory_variable(&self) -> bool {
            false
        }

        fn is_unique_variable(&self) -> bool {
            false
        }

        fn is_compound_variable(&self) -> bool {
            false
        }

        fn has_assigned_storage(&self) -> bool {
            false
        }

        fn get_first_use_offset(&self) -> i32 {
            0
        }

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    fn mock_variable(name: &str, data_type_length: i32) -> Arc<dyn Variable> {
        Arc::new(MockVariable {
            name: name.to_string(),
            data_type_length,
        })
    }

    #[test]
    fn struct_field_offset_resolves_to_dotted_name() {
        // local_10 is a struct { ...; int y at offset 4; ... }; offset 4 with dataAccess=false
        // should resolve entirely into the field name, leaving no residual scalar.
        let vo = VariableOffsetImpl::new(mock_variable("local_10", 4), 4, false, false);
        let objects = vo.get_objects();
        assert_eq!(objects.len(), 1);
        match &objects[0] {
            VariableOffsetObject::Label(label) => assert_eq!(label.to_string(), "local_10.y"),
            other => panic!("expected a single label object, got {other:?}"),
        }
        assert_eq!(vo.to_display_string(), "local_10.y");
        assert_eq!(vo.get_data_type_display_text(), "local_10.y");
    }

    #[test]
    fn unresolved_offset_appends_sign_and_scalar() {
        // param_1 is a plain (non-composite) 4-byte variable; an offset that doesn't resolve
        // against any field/array navigation is reported as a trailing "+0x8".
        let vo = VariableOffsetImpl::new(mock_variable("param_1", 4), 8, false, true);
        let objects = vo.get_objects();
        assert_eq!(objects.len(), 3);
        match (&objects[0], &objects[1], &objects[2]) {
            (
                VariableOffsetObject::Label(label),
                VariableOffsetObject::Sign(sign),
                VariableOffsetObject::Scalar(scalar),
            ) => {
                assert_eq!(label.to_string(), "param_1");
                assert_eq!(*sign, '+');
                assert_eq!(scalar.get_value(), 8);
            }
            other => panic!("unexpected object shape: {other:?}"),
        }
        assert_eq!(vo.to_display_string(), "param_1+0x8");
    }

    #[test]
    fn set_replaced_element_scalar_round_trips() {
        let mut vo = VariableOffsetImpl::new(mock_variable("local_4", 4), 0, false, false);
        assert_eq!(vo.get_replaced_element(), None);

        let scalar = Scalar::new(32, 10);
        vo.set_replaced_element_scalar(scalar, true);
        assert_eq!(
            vo.get_replaced_element(),
            Some(ReplacedElement::Scalar(scalar))
        );
        assert!(vo.include_scalar_adjustment());
    }

    #[test]
    fn variable_offset_equals_compares_state() {
        let a = VariableOffsetImpl::new(mock_variable("local_4", 4), 4, false, true);
        let b = VariableOffsetImpl::new(mock_variable("local_4", 4), 4, false, true);
        let c = VariableOffsetImpl::new(mock_variable("local_4", 4), 8, false, true);
        assert!(a.variable_offset_equals(&b));
        assert!(!a.variable_offset_equals(&c));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let vo: Box<dyn VariableOffset> = Box::new(VariableOffsetImpl::new(
            mock_variable("param_2", 4),
            0,
            false,
            false,
        ));
        assert_eq!(vo.get_offset(), 0);
        assert!(!vo.is_indirect());
        let displayed: &dyn VariableOffset = vo.as_ref();
        assert_eq!(displayed.to_string(), "param_2");
    }
}
