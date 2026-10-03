//! Port of `ghidra.framework.options.SaveState` (and its base `XmlProperties`).
//!
//! A [`GProperties`] that can additionally hold nested `SaveState`s, written as nested
//! `<SAVE_STATE KEY=".." NAME=".." TYPE="SaveState">` elements. Java's `extends` is modeled by
//! composition plus `Deref`/`DerefMut` to the inner [`GProperties`], so every typed `put*`/`get*`
//! accessor is available on a `SaveState` directly.

use std::collections::BTreeMap;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use crate::framework::options::g_properties::{
    GProperties, GPropertyValue, ATTRIBUTE_KEY, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, ATTRIBUTE_VALUE,
    STATE,
};
use crate::framework::options::xml_properties::read_xml_file;
use crate::util::xml::element::Element;

/// Port of `ghidra.framework.options.SaveState`: name/value pairs saved as XML or JSON, used by
/// classes to persist their state. Getters take a default, so a restoring object is fully
/// initialized even when a value is missing.
///
/// A state restored or created as an `AttributedSaveState` (see
/// [`AttributedSaveState`](crate::framework::options::AttributedSaveState)) additionally carries
/// per-property XML attributes; that Java subclass is modeled by
/// [`property_attributes`](Self::property_attributes) being `Some`, so nested states created while
/// restoring one are attributed too, as Java's overridden `createSaveState` makes them.
#[derive(Debug, Clone, PartialEq)]
pub struct SaveState {
    props: GProperties,
    pub(crate) property_attributes: Option<BTreeMap<String, BTreeMap<String, String>>>,
}

impl Default for SaveState {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SaveState {
    type Target = GProperties;
    fn deref(&self) -> &GProperties {
        &self.props
    }
}

impl DerefMut for SaveState {
    fn deref_mut(&mut self) -> &mut GProperties {
        &mut self.props
    }
}

impl SaveState {
    const XML_TYPE: &'static str = "SaveState";
    /// `SaveState.SAVE_STATE_TAG_NAME`: the default name and the nested-state tag.
    pub const SAVE_STATE_TAG_NAME: &'static str = "SAVE_STATE";
    /// `SaveState.DEFAULT_NAME`: the name written for a nested state with the default name.
    pub const DEFAULT_NAME: &'static str = "UNNAMED";

    /// `new SaveState()`: named [`SAVE_STATE_TAG_NAME`](Self::SAVE_STATE_TAG_NAME).
    pub fn new() -> Self {
        Self::with_name(Self::SAVE_STATE_TAG_NAME)
    }

    /// `new SaveState(String)`: the name only hints at what the state represents.
    pub fn with_name(name: impl Into<String>) -> Self {
        SaveState { props: GProperties::new(name), property_attributes: None }
    }

    /// `new SaveState(Element)`: restores a state saved by [`save_to_xml`](Self::save_to_xml).
    pub fn from_xml(element: &Element) -> Self {
        Self::restore(SaveState::new(), element)
    }

    /// The `GProperties(Element)` constructor body run on `state` (named for `root`), with this
    /// class's `processElement` override.
    pub(crate) fn restore(mut state: SaveState, root: &Element) -> SaveState {
        state.props = GProperties::new(root.get_name());
        for e in root.get_children() {
            state.process_element(e);
        }
        state
    }

    /// `SaveState.processElement(Element)` (and `AttributedSaveState`'s override of it).
    fn process_element(&mut self, element: &Element) {
        if element.get_name() == Self::SAVE_STATE_TAG_NAME {
            self.process_save_state_element(element);
        } else {
            self.props.process_element(element);
        }
        if let Some(attributes) = &mut self.property_attributes {
            // AttributedSaveState: keep the non-standard attributes of the element.
            let Some(name) = element.get_attribute_value(ATTRIBUTE_NAME) else {
                return; // sub-element; properties not supported
            };
            let new_attrs: BTreeMap<String, String> = element
                .get_attributes()
                .iter()
                .filter(|(n, _)| ![ATTRIBUTE_NAME, ATTRIBUTE_TYPE, ATTRIBUTE_VALUE].contains(&n.as_str()))
                .cloned()
                .collect();
            if !new_attrs.is_empty() {
                attributes.insert(name.to_string(), new_attrs);
            }
        }
    }

    /// `new SaveState(File)` (via `XmlProperties(File)`): restores a state saved by
    /// [`save_to_file`](Self::save_to_file).
    ///
    /// # Errors
    /// If the file cannot be read or is not well-formed XML.
    pub fn from_file(file: &Path) -> io::Result<Self> {
        Ok(Self::from_xml(&read_xml_file(file)?))
    }

    /// `saveToFile(File)`: writes the state to `file` as an XML document.
    pub fn save_to_file(&self, file: &Path) -> io::Result<()> {
        std::fs::write(file, self.save_to_xml().to_document_bytes())
    }

    /// `saveToXml()`, with nested states written as `<SAVE_STATE>` elements.
    pub fn save_to_xml(&self) -> Element {
        let mut root = Element::new(self.get_name());
        for (key, value) in &self.props.map {
            let element = match value {
                GPropertyValue::SaveState(s) => s.create_nested_element(key),
                _ => {
                    let mut element = GProperties::create_element(key, value);
                    // AttributedSaveState.initializeElement
                    if let Some(attrs) = self.property_attributes.as_ref().and_then(|a| a.get(key)) {
                        for (n, v) in attrs {
                            element.set_attribute(n.as_str(), v.as_str());
                        }
                    }
                    element
                }
            };
            root.add_content(element);
        }
        root
    }

    /// The inherited `GProperties` view of this state.
    pub fn as_g_properties(&self) -> &GProperties {
        &self.props
    }

    /// `putSaveState(String, SaveState)`.
    pub fn put_save_state(&mut self, name: &str, value: SaveState) {
        self.props.map.insert(name.to_string(), GPropertyValue::SaveState(Box::new(value)));
    }

    /// `getSaveState(String)`: the nested state stored under `name`, if any.
    pub fn get_save_state(&self, name: &str) -> Option<&SaveState> {
        match self.props.map.get(name) {
            Some(GPropertyValue::SaveState(s)) => Some(s),
            _ => None,
        }
    }

    /// `createSaveState(String)`: a nested state of this state's class; `None` (old-style XML
    /// without a name) gets the default name.
    fn create_save_state(&self, name: Option<&str>) -> SaveState {
        let mut state = name.map_or_else(SaveState::new, SaveState::with_name);
        if self.property_attributes.is_some() {
            state.property_attributes = Some(BTreeMap::new());
        }
        state
    }

    /// `SaveState.processElement`'s `<SAVE_STATE>` branch: restores a nested state.
    fn process_save_state_element(&mut self, element: &Element) {
        if !element.has_attribute(ATTRIBUTE_KEY) {
            self.restore_save_state_without_key_attribute(element);
            return;
        }
        // <SAVE_STATE KEY="Property Key" NAME="Client Name" TYPE="SaveState">
        //     <STATE NAME="a" TYPE="int" VALUE="5" />
        // </SAVE_STATE>
        let key = element.get_attribute_value(ATTRIBUTE_KEY).unwrap_or_default().to_string();
        let mut save_state = self.create_save_state(element.get_attribute_value(ATTRIBUTE_NAME));
        for e in element.get_children() {
            save_state.process_element(e);
        }
        self.props.map.insert(key, GPropertyValue::SaveState(Box::new(save_state)));
    }

    /// `restoreSaveStateWithoutKeyAttribute(Element)`: the old style, keyed by `NAME`, with or
    /// without an intermediate `<SAVE_STATE>` child.
    fn restore_save_state_without_key_attribute(&mut self, element: &Element) {
        let key = element.get_attribute_value(ATTRIBUTE_NAME).unwrap_or_default().to_string();
        let mut save_state = self.create_save_state(None);
        let mut children = element.get_children();
        if let Some(child) = children.first() {
            if child.get_name() != STATE {
                // an intermediate node; we want that child's children
                children = child.get_children();
            }
        }
        for e in children {
            save_state.process_element(e);
        }
        self.props.map.insert(key, GPropertyValue::SaveState(Box::new(save_state)));
    }

    /// `SaveState.createElement(String, Object)` for a nested state: the state's own children
    /// under one `<SAVE_STATE KEY NAME TYPE>` element (no extra intermediate node).
    pub(crate) fn create_nested_element(&self, key: &str) -> Element {
        let saved = self.save_to_xml();
        let mut element = Element::new(Self::SAVE_STATE_TAG_NAME);
        let mut name = self.get_name();
        if name == Self::SAVE_STATE_TAG_NAME {
            name = Self::DEFAULT_NAME;
        }
        element.set_attribute(ATTRIBUTE_NAME, name);
        element.set_attribute(ATTRIBUTE_KEY, key);
        element.set_attribute(ATTRIBUTE_TYPE, Self::XML_TYPE);
        for e in saved.get_children() {
            element.add_content(e.clone());
        }
        element
    }
}

impl std::fmt::Display for SaveState {
    /// `toString()`: `XmlUtilities.toString(saveToXml())`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.save_to_xml().output_string())
    }
}

#[cfg(test)]
mod tests {
    //! Ported from `SaveStateTest` (Features/Base test tree).
    use super::*;

    fn round_trip(ss: &SaveState) -> SaveState {
        let bytes = ss.save_to_xml().to_document_bytes();
        SaveState::from_xml(&Element::parse_bytes(&bytes).unwrap())
    }

    fn restore(xml: &str) -> SaveState {
        SaveState::from_xml(&Element::parse_str(xml).unwrap())
    }

    #[test]
    fn test_empty_save_state() {
        let restored = round_trip(&SaveState::with_name("Client_Name"));
        assert_eq!(restored.get_name(), "Client_Name");
        assert!(restored.is_empty());
    }

    #[test]
    fn test_empty_nested_save_state() {
        let mut ss = SaveState::with_name("Client_Name");
        ss.put_save_state("Nested", SaveState::with_name("Client_Name2"));
        let restored = round_trip(&ss);
        assert_eq!(restored.get_save_state("Nested").unwrap().get_name(), "Client_Name2");
    }

    #[test]
    fn oldest_style_with_intermediate_node() {
        let r = restore(
            "<SAVE_STATE><SAVE_STATE NAME=\"Bar\" TYPE=\"SaveState\"><SAVE_STATE>\
             <STATE NAME=\"DATED_OPTION\" TYPE=\"int\" VALUE=\"3\" /></SAVE_STATE></SAVE_STATE>\
             </SAVE_STATE>",
        );
        let ss = r.get_save_state("Bar").unwrap();
        assert_eq!(ss.get_name(), SaveState::SAVE_STATE_TAG_NAME);
        assert_eq!(ss.get_int("DATED_OPTION", -1), 3);
    }

    #[test]
    fn oldest_style_with_custom_intermediate_tag() {
        let r = restore(
            "<SAVE_STATE><SAVE_STATE NAME=\"TEST\" TYPE=\"SaveState\"><BAR>\
             <STATE NAME=\"DATED_OPTION\" TYPE=\"int\" VALUE=\"3\" /></BAR></SAVE_STATE>\
             </SAVE_STATE>",
        );
        let ss = r.get_save_state("TEST").unwrap();
        assert_eq!(ss.get_name(), SaveState::SAVE_STATE_TAG_NAME);
        assert_eq!(ss.get_int("DATED_OPTION", -1), 3);
    }

    #[test]
    fn oldest_style_empty_nested_state() {
        let r = restore("<SAVE_STATE><SAVE_STATE NAME=\"Bar\" TYPE=\"SaveState\" /></SAVE_STATE>");
        let ss = r.get_save_state("Bar").unwrap();
        assert_eq!(ss.get_name(), SaveState::SAVE_STATE_TAG_NAME);
        assert!(ss.is_empty());
    }

    #[test]
    fn recent_style_without_intermediate_node() {
        let r = restore(
            "<SAVE_STATE><SAVE_STATE NAME=\"Bar\" TYPE=\"SaveState\">\
             <STATE NAME=\"DATED_OPTION\" TYPE=\"int\" VALUE=\"3\" /></SAVE_STATE></SAVE_STATE>",
        );
        let ss = r.get_save_state("Bar").unwrap();
        assert_eq!(ss.get_name(), SaveState::SAVE_STATE_TAG_NAME);
        assert_eq!(ss.get_int("DATED_OPTION", -1), 3);
    }

    #[test]
    fn single_layer_round_trips() {
        let mut ss = SaveState::new();
        ss.put_int("Foo", 21);
        let r = round_trip(&ss);
        assert_eq!(r.get_int("Foo", -1), 21);
        assert_eq!(r.get_name(), SaveState::SAVE_STATE_TAG_NAME);
        let mut named = SaveState::with_name("Client_Name");
        named.put_int("Foo", 21);
        assert_eq!(round_trip(&named).get_name(), "Client_Name");
    }

    #[test]
    fn unnamed_double_layer_xml_shape_and_round_trip() {
        let mut two = SaveState::new();
        two.put_int("layer_two.aa", 5);
        two.put_string("layer_two.bb", Some("bar"));
        let mut ss = SaveState::new();
        ss.put_save_state("LAYER_TWO", two);
        ss.put_string("layer_one.a", Some("zzzz"));
        assert_eq!(
            ss.save_to_xml().output_string(),
            "<SAVE_STATE>\r\n    <SAVE_STATE NAME=\"UNNAMED\" KEY=\"LAYER_TWO\" TYPE=\"SaveState\">\
             \r\n        <STATE NAME=\"layer_two.aa\" TYPE=\"int\" VALUE=\"5\" />\
             \r\n        <STATE NAME=\"layer_two.bb\" TYPE=\"string\" VALUE=\"bar\" />\
             \r\n    </SAVE_STATE>\
             \r\n    <STATE NAME=\"layer_one.a\" TYPE=\"string\" VALUE=\"zzzz\" />\r\n</SAVE_STATE>"
        );
        let r = round_trip(&ss);
        assert_eq!(r.get_string("layer_one.a", None).as_deref(), Some("zzzz"));
        let sub = r.get_save_state("LAYER_TWO").unwrap();
        assert_eq!(sub.get_name(), SaveState::DEFAULT_NAME);
        assert_eq!(sub.get_names(), vec!["layer_two.aa", "layer_two.bb"]);
        assert_eq!(sub.get_int("layer_two.aa", 0), 5);
        assert_eq!(sub.get_string("layer_two.bb", Some("")).as_deref(), Some("bar"));
    }

    #[test]
    fn named_triple_layer_round_trip() {
        let mut three = SaveState::with_name("Client_Name_3");
        three.put_boolean("layer_three.power_on", false);
        let mut two = SaveState::with_name("Client_Name_2");
        two.put_save_state("LAYER_THREE", three);
        two.put_int("layer_two.a", 5);
        let mut ss = SaveState::new();
        ss.put_save_state("LAYER_TWO", two);
        ss.put_string("layer_one.name", Some("zzzz"));
        let r = round_trip(&ss);
        let sub = r.get_save_state("LAYER_TWO").unwrap();
        assert_eq!(sub.get_name(), "Client_Name_2");
        assert_eq!(sub.get_int("layer_two.a", 0), 5);
        let subsub = sub.get_save_state("LAYER_THREE").unwrap();
        assert_eq!(subsub.get_name(), "Client_Name_3");
        assert!(!subsub.get_boolean("layer_three.power_on", true));
        assert_eq!(r, ss);
    }

    #[test]
    fn nested_save_state_is_a_g_properties_but_not_vice_versa() {
        let mut ss = SaveState::new();
        let mut sub = SaveState::with_name("sub");
        sub.put_int("a", 1);
        ss.put_save_state("S", sub);
        ss.put_g_properties("G", GProperties::new("g"));
        assert_eq!(ss.get_g_properties("S").unwrap().get_int("a", 0), 1);
        assert!(ss.get_save_state("G").is_none());
        // Through JSON a nested SaveState comes back as a GProperties (Java's behavior).
        let json = GProperties::from_json(&ss.save_to_json()).unwrap();
        assert_eq!(json.get_g_properties("S").unwrap().get_int("a", 0), 1);
    }

    #[test]
    fn file_round_trip() {
        let file = std::env::temp_dir().join(format!("SaveStateTest-{}.xml", std::process::id()));
        let mut ss = SaveState::with_name("Client");
        ss.put_long("L", -5);
        ss.save_to_file(&file).unwrap();
        let r = SaveState::from_file(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(r, ss);
    }
}
