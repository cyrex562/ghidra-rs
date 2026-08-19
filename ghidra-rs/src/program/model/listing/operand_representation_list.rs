use std::fmt;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::label_string::LabelString;
use crate::program::model::listing::variable_offset::VariableOffset;
use crate::program::model::scalar::Scalar;

/// One element of an [`OperandRepresentationList`]'s object list.
///
/// The Java class is a raw `ArrayList<Object>`; its javadoc enumerates the concrete types that
/// may appear (`Character`, `String`, `VariableOffset`, `Register`, `Address`, `Scalar`,
/// `LabelString`, or a nested `OperandRepresentationList`). This enum closes that open set so the
/// trait below stays object-safe.
#[derive(Clone)]
pub enum OperandRepresentationElement {
    /// Stands in for a bare `Character` element.
    Character(char),
    /// Stands in for a bare `String` element.
    Text(String),
    /// Stands in for a `VariableOffset` element.
    VariableOffset(Arc<dyn VariableOffset>),
    /// Stands in for a `Register` element.
    Register(RegisterRef),
    /// Stands in for an `Address` element.
    Address(Address),
    /// Stands in for a `Scalar` element.
    Scalar(Scalar),
    /// Stands in for a `LabelString` element.
    Label(LabelString),
    /// Stands in for a nested `OperandRepresentationList` element.
    Nested(Arc<dyn OperandRepresentationList>),
}

impl fmt::Display for OperandRepresentationElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandRepresentationElement::Character(c) => write!(f, "{c}"),
            OperandRepresentationElement::Text(s) => write!(f, "{s}"),
            OperandRepresentationElement::VariableOffset(vo) => {
                write!(f, "{}", vo.to_display_string())
            }
            OperandRepresentationElement::Register(r) => write!(f, "{}", r.borrow()),
            OperandRepresentationElement::Address(a) => write!(f, "{a}"),
            OperandRepresentationElement::Scalar(s) => write!(f, "{s}"),
            OperandRepresentationElement::Label(l) => write!(f, "{l}"),
            OperandRepresentationElement::Nested(list) => write!(f, "{}", list.to_display_string()),
        }
    }
}

/// Provides a list for operand sub-elements. The number of elements are expected to remain
/// constant for a given code unit operand regardless of its format.
///
/// The list may contain [`OperandRepresentationElement`]s of various kinds, including nesting of
/// other `OperandRepresentationList`s. All elements support [`fmt::Display`] for producing an
/// appropriate listing representation.
///
/// Port of `ghidra.program.model.listing.OperandRepresentationList`. This was selected as a
/// dependency-cycle cut-point and ported to a trait rather than a concrete `ArrayList<Object>`
/// subclass; [`OperandRepresentationListImpl`] is a straightforward concrete implementation
/// carrying the Java class's constructors.
pub trait OperandRepresentationList {
    /// Returns true if the primary reference is not reflected in the representation. Stands in
    /// for `isPrimaryReferenceHidden()`.
    fn is_primary_reference_hidden(&self) -> bool;

    /// Set flag indicating that representation does not include primary reference
    /// representation. Stands in for `setPrimaryReferenceHidden(boolean)`.
    fn set_primary_reference_hidden(&mut self, primary_reference_is_hidden: bool);

    /// Returns true if the representation encountered an error. The error will be reflected
    /// within the representation as a String. Stands in for `hasError()`.
    fn has_error(&self) -> bool;

    /// Set flag indicating that representation encountered an error. Stands in for
    /// `setHasError(boolean)`.
    fn set_has_error(&mut self, has_error: bool);

    /// Returns the number of elements. Backs the inherited `ArrayList.size()`.
    fn len(&self) -> usize;

    /// Returns true if this list has no elements. Backs the inherited `ArrayList.isEmpty()`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the element at `index`, or `None` if out of bounds. Backs the inherited
    /// `ArrayList.get(int)`.
    fn get(&self, index: usize) -> Option<OperandRepresentationElement>;

    /// Returns a formatted string representation of the specified code unit operand. Stands in
    /// for `toString()`.
    fn to_display_string(&self) -> String {
        (0..self.len())
            .filter_map(|index| self.get(index))
            .map(|element| element.to_string())
            .collect()
    }
}

impl fmt::Display for dyn OperandRepresentationList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

/// Straightforward concrete [`OperandRepresentationList`] implementation carrying the state (and
/// the five Java constructors) of the ported class.
#[derive(Default)]
pub struct OperandRepresentationListImpl {
    elements: Vec<OperandRepresentationElement>,
    primary_reference_is_hidden: bool,
    has_error: bool,
}

impl OperandRepresentationListImpl {
    /// Stands in for `OperandRepresentationList(List<?> opList, boolean
    /// primaryReferenceIsHidden)`.
    pub fn new(elements: Vec<OperandRepresentationElement>, primary_reference_is_hidden: bool) -> Self {
        OperandRepresentationListImpl {
            elements,
            primary_reference_is_hidden,
            has_error: false,
        }
    }

    /// Stands in for `OperandRepresentationList(boolean primaryReferenceIsHidden)`.
    pub fn with_primary_reference_hidden(primary_reference_is_hidden: bool) -> Self {
        OperandRepresentationListImpl {
            elements: Vec::new(),
            primary_reference_is_hidden,
            has_error: false,
        }
    }

    /// Stands in for `OperandRepresentationList(List<?> opList)`.
    pub fn from_elements(elements: Vec<OperandRepresentationElement>) -> Self {
        OperandRepresentationListImpl {
            elements,
            primary_reference_is_hidden: false,
            has_error: false,
        }
    }

    /// Stands in for `OperandRepresentationList(String error)`.
    pub fn from_error(error: impl Into<String>) -> Self {
        OperandRepresentationListImpl {
            elements: vec![OperandRepresentationElement::Text(error.into())],
            primary_reference_is_hidden: false,
            has_error: true,
        }
    }

    /// Appends an element to the list. Backs the inherited `ArrayList.add(Object)`.
    pub fn push(&mut self, element: OperandRepresentationElement) {
        self.elements.push(element);
    }
}

impl OperandRepresentationList for OperandRepresentationListImpl {
    fn is_primary_reference_hidden(&self) -> bool {
        self.primary_reference_is_hidden
    }

    fn set_primary_reference_hidden(&mut self, primary_reference_is_hidden: bool) {
        self.primary_reference_is_hidden = primary_reference_is_hidden;
    }

    fn has_error(&self) -> bool {
        self.has_error
    }

    fn set_has_error(&mut self, has_error: bool) {
        self.has_error = has_error;
    }

    fn len(&self) -> usize {
        self.elements.len()
    }

    fn get(&self, index: usize) -> Option<OperandRepresentationElement> {
        self.elements.get(index).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::label_string::LabelType;

    #[test]
    fn to_display_string_concatenates_mixed_elements() {
        let mut list = OperandRepresentationListImpl::from_elements(vec![
            OperandRepresentationElement::Label(LabelString::new(
                "local_10".to_string(),
                LabelType::Variable,
            )),
        ]);
        list.push(OperandRepresentationElement::Character('+'));
        list.push(OperandRepresentationElement::Scalar(Scalar::new(32, 8)));

        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
        assert_eq!(list.to_display_string(), "local_10+0x8");
    }

    #[test]
    fn nested_list_flattens_into_parent_string() {
        let inner: Arc<dyn OperandRepresentationList> = Arc::new(OperandRepresentationListImpl::from_elements(vec![
            OperandRepresentationElement::Text("EAX".to_string()),
        ]));
        let outer = OperandRepresentationListImpl::from_elements(vec![
            OperandRepresentationElement::Text("[".to_string()),
            OperandRepresentationElement::Nested(inner),
            OperandRepresentationElement::Text("]".to_string()),
        ]);

        assert_eq!(outer.to_display_string(), "[EAX]");
    }

    #[test]
    fn from_error_sets_error_flag_and_message() {
        let list = OperandRepresentationListImpl::from_error("bad operand");
        assert!(list.has_error());
        assert!(!list.is_primary_reference_hidden());
        assert_eq!(list.to_display_string(), "bad operand");
    }

    #[test]
    fn setters_toggle_flags() {
        let mut list = OperandRepresentationListImpl::with_primary_reference_hidden(false);
        assert!(!list.is_primary_reference_hidden());
        list.set_primary_reference_hidden(true);
        assert!(list.is_primary_reference_hidden());

        assert!(!list.has_error());
        list.set_has_error(true);
        assert!(list.has_error());
    }

    /// Mock proving the trait is object-safe and usable through a trait object, exercising real
    /// (non-default) `get`/`len` behavior rather than the provided `to_display_string` default.
    struct MockOperandRepresentationList {
        text: &'static str,
        hidden: bool,
    }

    impl OperandRepresentationList for MockOperandRepresentationList {
        fn is_primary_reference_hidden(&self) -> bool {
            self.hidden
        }

        fn set_primary_reference_hidden(&mut self, primary_reference_is_hidden: bool) {
            self.hidden = primary_reference_is_hidden;
        }

        fn has_error(&self) -> bool {
            false
        }

        fn set_has_error(&mut self, _has_error: bool) {}

        fn len(&self) -> usize {
            1
        }

        fn get(&self, index: usize) -> Option<OperandRepresentationElement> {
            (index == 0).then(|| OperandRepresentationElement::Text(self.text.to_string()))
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let list: Box<dyn OperandRepresentationList> =
            Box::new(MockOperandRepresentationList { text: "RAX", hidden: true });
        assert!(list.is_primary_reference_hidden());
        assert_eq!(list.len(), 1);
        assert_eq!(list.to_string(), "RAX");
    }
}
