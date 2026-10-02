//! Port of `generic.theme.GThemeValueMap`: the color, font, icon and Java-property values
//! of a theme, keyed by normalized id.
//!
//! Java's `getExternalIconFiles()` (icons under the user settings directory) is not
//! ported here; Java's `checkForUnresolvedReferences()` logs, while
//! [`GThemeValueMap::check_for_unresolved_references`] returns the failures.

use std::collections::HashMap;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::icon_value::{IconValue, ResolvedIcon};
use super::java_property_value::{JavaPropertyValue, PropertyValue};
use super::theme_value::UnresolvedReference;

/// A set of theme values. Adding a value with an existing id replaces it, so when maps are
/// [`load`](GThemeValueMap::load)ed in sequence the last one wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GThemeValueMap {
    color_map: HashMap<String, ColorValue>,
    font_map: HashMap<String, FontValue>,
    icon_map: HashMap<String, IconValue>,
    property_map: HashMap<String, JavaPropertyValue>,
}

impl GThemeValueMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// `GThemeValueMap(GThemeValueMap initial)`
    pub fn from_map(initial: &GThemeValueMap) -> Self {
        let mut map = Self::new();
        map.load(initial);
        map
    }

    /// `addColor`: returns the value previously stored under the same id.
    pub fn add_color(&mut self, value: ColorValue) -> Option<ColorValue> {
        self.color_map.insert(value.id().to_string(), value)
    }

    /// `addFont`: returns the value previously stored under the same id.
    pub fn add_font(&mut self, value: FontValue) -> Option<FontValue> {
        self.font_map.insert(value.id().to_string(), value)
    }

    /// `addIcon`: returns the value previously stored under the same id.
    pub fn add_icon(&mut self, value: IconValue) -> Option<IconValue> {
        self.icon_map.insert(value.id().to_string(), value)
    }

    /// `addProperty`: returns the value previously stored under the same id.
    pub fn add_property(&mut self, value: JavaPropertyValue) -> Option<JavaPropertyValue> {
        self.property_map.insert(value.id().to_string(), value)
    }

    /// `getColor`
    pub fn get_color(&self, id: &str) -> Option<&ColorValue> {
        self.color_map.get(id)
    }

    /// `getFont`
    pub fn get_font(&self, id: &str) -> Option<&FontValue> {
        self.font_map.get(id)
    }

    /// `getIcon`
    pub fn get_icon(&self, id: &str) -> Option<&IconValue> {
        self.icon_map.get(id)
    }

    /// `getProperty`
    pub fn get_property(&self, id: &str) -> Option<&JavaPropertyValue> {
        self.property_map.get(id)
    }

    /// `load(valueMap)`: adds every value of `other`, replacing values with the same id.
    pub fn load(&mut self, other: &GThemeValueMap) {
        for v in other.color_map.values() {
            self.add_color(v.clone());
        }
        for v in other.font_map.values() {
            self.add_font(v.clone());
        }
        for v in other.icon_map.values() {
            self.add_icon(v.clone());
        }
        for v in other.property_map.values() {
            self.add_property(v.clone());
        }
    }

    /// `getColors`
    pub fn colors(&self) -> impl Iterator<Item = &ColorValue> {
        self.color_map.values()
    }

    /// `getFonts`
    pub fn fonts(&self) -> impl Iterator<Item = &FontValue> {
        self.font_map.values()
    }

    /// `getIcons`
    pub fn icons(&self) -> impl Iterator<Item = &IconValue> {
        self.icon_map.values()
    }

    /// `getProperties`
    pub fn properties(&self) -> impl Iterator<Item = &JavaPropertyValue> {
        self.property_map.values()
    }

    /// `containsColor`
    pub fn contains_color(&self, id: &str) -> bool {
        self.color_map.contains_key(id)
    }

    /// `containsFont`
    pub fn contains_font(&self, id: &str) -> bool {
        self.font_map.contains_key(id)
    }

    /// `containsIcon`
    pub fn contains_icon(&self, id: &str) -> bool {
        self.icon_map.contains_key(id)
    }

    /// `containsProperty`
    pub fn contains_property(&self, id: &str) -> bool {
        self.property_map.contains_key(id)
    }

    /// `size()`: total number of values of all kinds.
    pub fn size(&self) -> usize {
        self.color_map.len() + self.font_map.len() + self.icon_map.len() + self.property_map.len()
    }

    /// `clear()`
    pub fn clear(&mut self) {
        self.color_map.clear();
        self.font_map.clear();
        self.icon_map.clear();
        self.property_map.clear();
    }

    /// `isEmpty()`
    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// `removeColor`
    pub fn remove_color(&mut self, id: &str) {
        self.color_map.remove(id);
    }

    /// `removeFont`
    pub fn remove_font(&mut self, id: &str) {
        self.font_map.remove(id);
    }

    /// `removeIcon`
    pub fn remove_icon(&mut self, id: &str) {
        self.icon_map.remove(id);
    }

    /// `removeProperty`
    pub fn remove_property(&mut self, id: &str) {
        self.property_map.remove(id);
    }

    /// `getChangedValues(base)`: the values in this map that differ from (or are absent in)
    /// `base`.
    pub fn get_changed_values(&self, base: &GThemeValueMap) -> GThemeValueMap {
        let mut map = GThemeValueMap::new();
        for v in self
            .color_map
            .values()
            .filter(|v| base.get_color(v.id()) != Some(*v))
        {
            map.add_color(v.clone());
        }
        for v in self
            .font_map
            .values()
            .filter(|v| base.get_font(v.id()) != Some(*v))
        {
            map.add_font(v.clone());
        }
        for v in self
            .icon_map
            .values()
            .filter(|v| base.get_icon(v.id()) != Some(*v))
        {
            map.add_icon(v.clone());
        }
        for v in self
            .property_map
            .values()
            .filter(|v| base.get_property(v.id()) != Some(*v))
        {
            map.add_property(v.clone());
        }
        map
    }

    /// `checkForUnresolvedReferences()`: every value whose reference chain can't be
    /// resolved.
    pub fn check_for_unresolved_references(&self) -> Vec<UnresolvedReference> {
        let colors = self.color_map.values().filter_map(|v| v.get(self).err());
        let fonts = self.font_map.values().filter_map(|v| v.get(self).err());
        let icons = self.icon_map.values().filter_map(|v| v.get(self).err());
        let properties = self.property_map.values().filter_map(|v| v.get(self).err());
        colors.chain(fonts).chain(icons).chain(properties).collect()
    }

    /// `getColorIds`
    pub fn color_ids(&self) -> impl Iterator<Item = &String> {
        self.color_map.keys()
    }

    /// `getFontIds`
    pub fn font_ids(&self) -> impl Iterator<Item = &String> {
        self.font_map.keys()
    }

    /// `getIconIds`
    pub fn icon_ids(&self) -> impl Iterator<Item = &String> {
        self.icon_map.keys()
    }

    /// `getPropertyIds`
    pub fn property_ids(&self) -> impl Iterator<Item = &String> {
        self.property_map.keys()
    }

    /// `getResolvedColor(id)`: `None` when `id` is not in the map.
    pub fn get_resolved_color(&self, id: &str) -> Option<Result<&str, UnresolvedReference>> {
        self.color_map.get(id).map(|v| v.get(self))
    }

    /// `getResolvedFont(id)`: `None` when `id` is not in the map.
    pub fn get_resolved_font(&self, id: &str) -> Option<Result<&str, UnresolvedReference>> {
        self.font_map.get(id).map(|v| v.get(self))
    }

    /// `getResolvedIcon(id)`: `None` when `id` is not in the map.
    pub fn get_resolved_icon(&self, id: &str) -> Option<Result<ResolvedIcon, UnresolvedReference>> {
        self.icon_map.get(id).map(|v| v.get(self))
    }

    /// `getResolvedProperty(id)`: `None` when `id` is not in the map.
    pub fn get_resolved_property(
        &self,
        id: &str,
    ) -> Option<Result<&PropertyValue, UnresolvedReference>> {
        self.property_map.get(id).map(|v| v.get(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::theme::icon_value::IconSpec;

    fn icon(id: &str, path: &str) -> IconValue {
        IconValue::new(id, IconSpec::Resource(path.into())).unwrap()
    }

    #[test]
    fn add_returns_previous_and_get_contains_remove() {
        let mut map = GThemeValueMap::new();
        assert!(map.is_empty());
        assert!(map.add_icon(icon("icon.a", "a.png")).is_none());
        let old = map.add_icon(icon("icon.a", "b.png")).unwrap();
        assert_eq!(old.raw_value(), Some(&IconSpec::Resource("a.png".into())));
        assert!(map.contains_icon("icon.a"));
        assert_eq!(map.size(), 1);
        assert!(map
            .add_color(ColorValue::parse("color.x", "red").unwrap())
            .is_none());
        assert!(map
            .add_font(
                FontValue::parse("font.x", "dialog-PLAIN-14")
                    .unwrap()
                    .unwrap()
            )
            .is_none());
        assert!(map
            .add_property(JavaPropertyValue::parse_string("[laf.string]A.b", "t").unwrap())
            .is_none());
        assert_eq!(map.size(), 4);
        assert!(map.contains_color("color.x") && map.contains_font("font.x"));
        assert!(map.contains_property("A.b"));
        map.remove_icon("icon.a");
        assert!(!map.contains_icon("icon.a"));
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn load_later_values_win() {
        let mut first = GThemeValueMap::new();
        first.add_icon(icon("icon.a", "a.png"));
        first.add_icon(icon("icon.b", "b.png"));
        let mut second = GThemeValueMap::new();
        second.add_icon(icon("icon.a", "override.png"));
        let mut map = GThemeValueMap::new();
        map.load(&first);
        map.load(&second);
        assert_eq!(
            map.get_icon("icon.a").unwrap().raw_value(),
            Some(&IconSpec::Resource("override.png".into()))
        );
        assert!(map.contains_icon("icon.b"));
        let mut ids = map.icon_ids().cloned().collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, ["icon.a", "icon.b"]);
    }

    #[test]
    fn resolved_icon_follows_references() {
        let mut map = GThemeValueMap::new();
        map.add_icon(icon("icon.left", "left.png"));
        map.add_icon(IconValue::reference("icon.prev", "icon.left").unwrap());
        assert_eq!(
            map.get_resolved_icon("icon.prev").unwrap().unwrap().base,
            IconSpec::Resource("left.png".into())
        );
        assert!(map.get_resolved_icon("icon.missing").is_none());
    }

    #[test]
    fn resolved_color_and_property_follow_references() {
        let mut map = GThemeValueMap::new();
        map.add_color(ColorValue::parse("color.b.1", "white").unwrap());
        map.add_color(ColorValue::parse("color.b.7", "color.b.1").unwrap());
        assert_eq!(
            map.get_resolved_color("color.b.7").unwrap().unwrap(),
            "white"
        );
        map.add_property(
            JavaPropertyValue::parse_string("[laf.string]Fake.title", "This is my title").unwrap(),
        );
        map.add_property(
            JavaPropertyValue::parse_string(
                "[laf.string]OtherFake.title",
                "[laf.string]Fake.title",
            )
            .unwrap(),
        );
        assert_eq!(
            map.get_resolved_property("OtherFake.title")
                .unwrap()
                .unwrap(),
            &PropertyValue::String("This is my title".into())
        );
    }

    #[test]
    fn changed_values_against_base() {
        let mut base = GThemeValueMap::new();
        base.add_icon(icon("icon.a", "a.png"));
        base.add_icon(icon("icon.b", "b.png"));
        let mut map = GThemeValueMap::from_map(&base);
        assert_eq!(map, base);
        map.add_icon(icon("icon.b", "changed.png"));
        let changed = map.get_changed_values(&base);
        assert_eq!(changed.size(), 1);
        assert!(changed.contains_icon("icon.b"));
    }
}
