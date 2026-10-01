//! Port of `ghidra.framework.options.AttributedSaveState`.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use crate::framework::options::save_state::SaveState;
use crate::util::xml::element::Element;

/// Port of `ghidra.framework.options.AttributedSaveState`: a [`SaveState`] that lets clients
/// attach extra XML attributes to a property's element. The attributes are written onto the
/// property's element by `saveToXml` and read back (all attributes other than `NAME`, `TYPE` and
/// `VALUE`) when restoring.
///
/// Java's subclass is modeled as a [`SaveState`] whose attribute map is present (see
/// [`SaveState::property_attributes`]); this wrapper provides the subclass's constructors and
/// attribute accessors and dereferences to the state.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributedSaveState {
    state: SaveState,
}

impl Default for AttributedSaveState {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for AttributedSaveState {
    type Target = SaveState;
    fn deref(&self) -> &SaveState {
        &self.state
    }
}

impl DerefMut for AttributedSaveState {
    fn deref_mut(&mut self) -> &mut SaveState {
        &mut self.state
    }
}

impl AttributedSaveState {
    /// `new AttributedSaveState()`.
    pub fn new() -> Self {
        Self::wrap(SaveState::new())
    }

    /// `new AttributedSaveState(String)`.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self::wrap(SaveState::with_name(name))
    }

    /// `new AttributedSaveState(Element)`.
    pub fn from_xml(root: &Element) -> Self {
        AttributedSaveState { state: SaveState::restore(Self::new().state, root) }
    }

    fn wrap(mut state: SaveState) -> Self {
        state.property_attributes = Some(BTreeMap::new());
        AttributedSaveState { state }
    }

    /// Views a state created as an `AttributedSaveState` (for instance a nested state restored
    /// inside one, which Java's `createSaveState` makes attributed) as one; `None` for a plain
    /// [`SaveState`] (Java's failing cast).
    pub fn from_save_state(state: SaveState) -> Option<Self> {
        state.property_attributes.is_some().then_some(AttributedSaveState { state })
    }

    /// The underlying state.
    pub fn into_save_state(self) -> SaveState {
        self.state
    }

    fn attributes_mut(&mut self) -> &mut BTreeMap<String, BTreeMap<String, String>> {
        self.state.property_attributes.get_or_insert_with(BTreeMap::new)
    }

    /// `addAttributes(String, Map)`: replaces the extra attributes written for `property_name`.
    pub fn add_attributes(&mut self, property_name: &str, attributes: BTreeMap<String, String>) {
        self.attributes_mut().insert(property_name.to_string(), attributes);
    }

    /// `removeAttributes(String)`.
    pub fn remove_attributes(&mut self, property_name: &str) {
        self.attributes_mut().remove(property_name);
    }

    /// `getAttributes(String)`.
    pub fn get_attributes(&self, property_name: &str) -> Option<&BTreeMap<String, String>> {
        self.state.property_attributes.as_ref().and_then(|a| a.get(property_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn attributes_are_written_onto_the_property_element_and_restored() {
        let mut ss = AttributedSaveState::new();
        ss.put_int("a", 5);
        ss.put_ints("arr", Some(&[1]));
        ss.add_attributes("a", attrs(&[("COLOR", "red")]));
        ss.add_attributes("arr", attrs(&[("X", "1")]));
        let xml = ss.save_to_xml();
        assert_eq!(
            xml.output_string(),
            "<SAVE_STATE>\r\n    <STATE NAME=\"a\" TYPE=\"int\" VALUE=\"5\" COLOR=\"red\" />\r\n    \
             <ARRAY NAME=\"arr\" TYPE=\"int\" X=\"1\">\r\n        <A VALUE=\"1\" />\r\n    \
             </ARRAY>\r\n</SAVE_STATE>"
        );
        let restored = AttributedSaveState::from_xml(&Element::parse_str(&xml.output_string()).unwrap());
        assert_eq!(restored.get_int("a", 0), 5);
        assert_eq!(restored.get_attributes("a"), Some(&attrs(&[("COLOR", "red")])));
        assert_eq!(restored.get_attributes("arr"), Some(&attrs(&[("X", "1")])));
        // A plain SaveState reading the same XML ignores the extra attributes.
        assert_eq!(SaveState::from_xml(&xml).get_int("a", 0), 5);
    }

    #[test]
    fn remove_attributes_and_nested_states_are_attributed() {
        let mut ss = AttributedSaveState::with_name("Outer");
        ss.put_boolean("b", true);
        ss.add_attributes("b", attrs(&[("K", "v")]));
        ss.remove_attributes("b");
        assert_eq!(ss.get_attributes("b"), None);
        assert!(!ss.save_to_xml().output_string().contains("K="));

        let mut nested = AttributedSaveState::with_name("Inner");
        nested.put_int("x", 1);
        nested.add_attributes("x", attrs(&[("HINT", "h")]));
        ss.put_save_state("N", nested.into_save_state());
        let restored = AttributedSaveState::from_xml(&ss.save_to_xml());
        let inner =
            AttributedSaveState::from_save_state(restored.get_save_state("N").unwrap().clone())
                .unwrap();
        assert_eq!(inner.get_name(), "Inner");
        assert_eq!(inner.get_attributes("x"), Some(&attrs(&[("HINT", "h")])));
        // Java quirk kept: the nested <SAVE_STATE> element's own KEY attribute is recorded
        // under its NAME.
        assert_eq!(restored.get_attributes("Inner"), Some(&attrs(&[("KEY", "N")])));
        assert!(AttributedSaveState::from_save_state(SaveState::new()).is_none());
    }
}
