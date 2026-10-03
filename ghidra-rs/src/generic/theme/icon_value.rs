//! Port of `generic.theme.IconValue`: an icon theme value (`icon.foo = images/foo.png`),
//! either a concrete icon or a reference to another icon id, plus an optional
//! [`IconModifier`].
//!
//! Toolkit-neutral: the concrete icon is an [`IconSpec`] naming the image resource
//! (`"images/left.png"`, `"left.png"`, `"[EXTERNAL]images/x.png"`) or Java's `EmptyIcon`.
//! Java loads the image during `parse` and reports a `ParseException` when the resource is
//! missing; here locating the file is deferred to
//! [`IconResourceLocator`](super::icon_resource_locator::IconResourceLocator) so parsing
//! needs no classpath.

use std::fmt;

use super::g_theme_value_map::GThemeValueMap;
use super::icon_modifier::{IconModifier, IconParseError};
use super::theme_value::{Resolved, ThemeValue, ThemeValueError, UnresolvedReference};

const EMPTY_ICON_STRING: &str = "EMPTY_ICON";
const STANDARD_EMPTY_ICON_SIZE: i32 = 16;

/// The concrete icon of an [`IconValue`], without any modifier applied.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IconSpec {
    /// `EMPTY_ICON`: Java's `EmptyIcon(width, height)`.
    Empty {
        /// Icon width in pixels.
        width: i32,
        /// Icon height in pixels.
        height: i32,
    },
    /// An image resource path as written in the theme file (Java's
    /// `UrlImageIcon.getOriginalPath()`), resolved by `ResourceManager.loadIcon` rules.
    Resource(String),
}

impl fmt::Display for IconSpec {
    /// Java's `IconValue.iconToString(Icon)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IconSpec::Empty { width, height }
                if *width == STANDARD_EMPTY_ICON_SIZE && *height == STANDARD_EMPTY_ICON_SIZE =>
            {
                f.write_str(EMPTY_ICON_STRING)
            }
            IconSpec::Empty { width, height } => {
                write!(f, "{EMPTY_ICON_STRING}[size({width},{height})]")
            }
            IconSpec::Resource(path) => f.write_str(path),
        }
    }
}

/// The result of resolving an icon id: the concrete base icon plus the modifiers to apply
/// to it, in order (what Java's `IconValue.get` would have painted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIcon {
    /// The concrete icon at the end of the reference chain.
    pub base: IconSpec,
    /// Modifiers to apply to `base`, first to last.
    pub modifiers: Vec<IconModifier>,
}

/// An icon theme value.
#[derive(Debug, Clone)]
pub struct IconValue {
    base: ThemeValue<IconSpec>,
    modifier: Option<IconModifier>,
}

/// Java's `ThemeValue.equals`: id, reference id and raw value; the modifier is not
/// compared.
impl PartialEq for IconValue {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base
    }
}
impl Eq for IconValue {}

impl AsRef<ThemeValue<IconSpec>> for IconValue {
    fn as_ref(&self) -> &ThemeValue<IconSpec> {
        &self.base
    }
}

impl IconValue {
    /// Normalized prefix of look-and-feel icon ids.
    pub const LAF_ID_PREFIX: &'static str = "laf.icon.";
    /// External (file) prefix of look-and-feel icon ids.
    pub const EXTERNAL_LAF_ID_PREFIX: &'static str = "[laf.icon]";
    /// Prefix of application icon ids.
    pub const ICON_ID_PREFIX: &'static str = "icon.";
    const EXTERNAL_PREFIX: &'static str = "[icon]";

    /// `new IconValue(id, icon)`: a value with a concrete icon.
    pub fn new(id: impl Into<String>, icon: IconSpec) -> Result<Self, ThemeValueError> {
        Ok(Self {
            base: ThemeValue::with_value(id, icon)?,
            modifier: None,
        })
    }

    /// `new IconValue(id, refId)`: a value inheriting from icon `ref_id`.
    pub fn reference(
        id: impl Into<String>,
        ref_id: impl Into<String>,
    ) -> Result<Self, ThemeValueError> {
        Ok(Self {
            base: ThemeValue::with_reference(id, ref_id)?,
            modifier: None,
        })
    }

    /// Java's `LAST_RESORT_DEFAULT` (`ResourceManager.getDefaultIcon()`).
    pub fn last_resort_default() -> IconSpec {
        IconSpec::Resource("images/core.png".to_string())
    }

    /// `getId()`
    pub fn id(&self) -> &str {
        self.base.id()
    }

    /// `getReferenceId()`
    pub fn reference_id(&self) -> Option<&str> {
        self.base.reference_id()
    }

    /// `getRawValue()`
    pub fn raw_value(&self) -> Option<&IconSpec> {
        self.base.raw_value()
    }

    /// The modifier parsed from the value text, if any.
    pub fn modifier(&self) -> Option<&IconModifier> {
        self.modifier.as_ref()
    }

    /// `isIndirect()`
    pub fn is_indirect(&self) -> bool {
        self.base.is_indirect()
    }

    /// `isExternal()`: true for ids not defined by the application (e.g. `laf.icon.*`).
    pub fn is_external(&self) -> bool {
        !self.id().starts_with(Self::ICON_ID_PREFIX)
    }

    /// `isIconKey(key)`
    pub fn is_icon_key(key: &str) -> bool {
        key.starts_with(Self::ICON_ID_PREFIX)
            || key.starts_with(Self::EXTERNAL_PREFIX)
            || key.starts_with(Self::EXTERNAL_LAF_ID_PREFIX)
    }

    /// `get(values)`: resolves references through `values` and collects the modifiers to
    /// apply. Like Java, only the modifier of the value that holds the concrete icon and
    /// this value's own modifier apply; modifiers on intermediate references are skipped.
    pub fn get(&self, values: &GThemeValueMap) -> Result<ResolvedIcon, UnresolvedReference> {
        let mut resolved = match self.base.resolve(|id| values.get_icon(id))? {
            Resolved::Own(spec) => ResolvedIcon {
                base: spec.clone(),
                modifiers: Vec::new(),
            },
            Resolved::Referred(referred) => referred.get(values)?,
        };
        if let Some(m) = &self.modifier {
            resolved.modifiers.push(m.clone());
        }
        Ok(resolved)
    }

    /// [`get`](Self::get), falling back like Java to [`last_resort_default`]
    /// (plus this value's modifier) when the reference chain can't be resolved.
    ///
    /// [`last_resort_default`]: Self::last_resort_default
    pub fn get_or_default(&self, values: &GThemeValueMap) -> ResolvedIcon {
        self.get(values).unwrap_or_else(|_| ResolvedIcon {
            base: Self::last_resort_default(),
            modifiers: self.modifier.iter().cloned().collect(),
        })
    }

    /// `hasResolvableValue(values)`
    pub fn has_resolvable_value(&self, values: &GThemeValueMap) -> bool {
        self.base.has_resolvable_value(|id| values.get_icon(id))
    }

    /// `inheritsFrom(ancestorId, values)`
    pub fn inherits_from(&self, ancestor_id: &str, values: &GThemeValueMap) -> bool {
        self.base
            .inherits_from(ancestor_id, |id| values.get_icon(id))
    }

    /// `parse(key, value)`: parses a theme file entry. `Ok(None)` for a blank icon value.
    pub fn parse(key: &str, value: &str) -> Result<Option<Self>, IconParseError> {
        let id = from_external_id(key);
        if Self::is_icon_key(value) {
            return Self::parse_ref_icon(id, value).map(Some);
        }
        Self::parse_icon(id, value)
    }

    fn parse_icon(id: String, value: &str) -> Result<Option<Self>, IconParseError> {
        let Some(modifier_index) = modifier_index(value) else {
            if value.trim().is_empty() {
                return Ok(None);
            }
            return Self::new(id, icon_spec(value))
                .map(Some)
                .map_err(construction_error);
        };
        let base_icon = value[..modifier_index].trim();
        if base_icon.is_empty() {
            return Ok(None);
        }
        let modifier = IconModifier::parse(&value[modifier_index..])?;
        let base = ThemeValue::with_value(id, icon_spec(base_icon)).map_err(construction_error)?;
        Ok(Some(Self { base, modifier }))
    }

    fn parse_ref_icon(id: String, value: &str) -> Result<Self, IconParseError> {
        let value = from_external_id(value);
        let Some(modifier_index) = modifier_index(&value) else {
            return Self::reference(id, value).map_err(construction_error);
        };
        let ref_id = value[..modifier_index].trim();
        let modifier = IconModifier::parse(&value[modifier_index..])?;
        let base = ThemeValue::with_reference(id, ref_id).map_err(construction_error)?;
        Ok(Self { base, modifier })
    }

    /// `getSerializationString()`: the `key = value` line for a theme file.
    pub fn serialization_string(&self) -> String {
        let mut output = match self.base.reference_id() {
            Some(r) => to_external_id(r),
            None => self
                .raw_value()
                .map(ToString::to_string)
                .unwrap_or_default(),
        };
        if let Some(m) = &self.modifier {
            output.push_str(&m.serialization_string());
        }
        format!("{} = {}", to_external_id(self.id()), output)
    }
}

impl fmt::Display for IconValue {
    /// Java's `ThemeValue.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base.describe("IconValue"))
    }
}

fn construction_error(e: ThemeValueError) -> IconParseError {
    IconParseError(e.to_string())
}

fn icon_spec(base_icon: &str) -> IconSpec {
    if base_icon == EMPTY_ICON_STRING {
        return IconSpec::Empty {
            width: STANDARD_EMPTY_ICON_SIZE,
            height: STANDARD_EMPTY_ICON_SIZE,
        };
    }
    IconSpec::Resource(base_icon.to_string())
}

/// Start of the modifier text: the first `{`, or the first `[` past index 0 (which may be
/// a valid `[EXTERNAL]` prefix).
fn modifier_index(value: &str) -> Option<usize> {
    let base = value
        .get(1..)
        .and_then(|rest| rest.find('['))
        .map(|i| i + 1);
    let overlay = value.find('{');
    match (base, overlay) {
        (Some(b), Some(o)) => Some(b.min(o)),
        (b, o) => b.or(o),
    }
}

fn to_external_id(internal_id: &str) -> String {
    if internal_id.starts_with(IconValue::ICON_ID_PREFIX) {
        return internal_id.to_string();
    }
    if let Some(base) = internal_id.strip_prefix(IconValue::LAF_ID_PREFIX) {
        return format!("{}{base}", IconValue::EXTERNAL_LAF_ID_PREFIX);
    }
    format!("{}{internal_id}", IconValue::EXTERNAL_PREFIX)
}

fn from_external_id(external_id: &str) -> String {
    if let Some(rest) = external_id.strip_prefix(IconValue::EXTERNAL_PREFIX) {
        return rest.to_string();
    }
    if let Some(rest) = external_id.strip_prefix(IconValue::EXTERNAL_LAF_ID_PREFIX) {
        return format!("{}{rest}", IconValue::LAF_ID_PREFIX);
    }
    external_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::theme::g_theme_value_map::GThemeValueMap;

    // Derived from IconValueTest. Java's ICON1 is ResourceManager.getDefaultIcon(),
    // i.e. "images/core.png".
    fn icon1() -> IconSpec {
        IconSpec::Resource("images/core.png".into())
    }

    #[test]
    fn direct_value() {
        let mut values = GThemeValueMap::new();
        let value = IconValue::new("icon.test", icon1()).unwrap();
        values.add_icon(value.clone());
        assert_eq!(value.id(), "icon.test");
        assert_eq!(value.raw_value(), Some(&icon1()));
        assert_eq!(value.reference_id(), None);
        assert_eq!(value.get(&values).unwrap().base, icon1());
    }

    #[test]
    fn indirect_value() {
        let mut values = GThemeValueMap::new();
        values.add_icon(IconValue::new("icon.parent", icon1()).unwrap());
        let value = IconValue::reference("icon.test", "icon.parent").unwrap();
        values.add_icon(value.clone());
        assert_eq!(value.raw_value(), None);
        assert_eq!(value.reference_id(), Some("icon.parent"));
        assert_eq!(value.get(&values).unwrap().base, icon1());
    }

    #[test]
    fn indirect_multi_hop_value() {
        let mut values = GThemeValueMap::new();
        values.add_icon(IconValue::new("icon.grandparent", icon1()).unwrap());
        values.add_icon(IconValue::reference("icon.parent", "icon.grandparent").unwrap());
        let value = IconValue::reference("icon.test", "icon.parent").unwrap();
        values.add_icon(value.clone());
        assert_eq!(value.get(&values).unwrap().base, icon1());
    }

    #[test]
    fn unresolved_indirect_value() {
        let mut values = GThemeValueMap::new();
        let value = IconValue::reference("icon.test", "icon.parent").unwrap();
        values.add_icon(value.clone());
        let err = value.get(&values).unwrap_err();
        assert_eq!(err.unresolved_id, "icon.parent");
        // Java falls back to LAST_RESORT_DEFAULT (images/core.png)
        assert_eq!(
            value.get_or_default(&values).base,
            IconValue::last_resort_default()
        );
        assert_eq!(IconValue::last_resort_default(), icon1());
    }

    #[test]
    fn reference_loop() {
        let mut values = GThemeValueMap::new();
        values.add_icon(IconValue::reference("icon.grandparent", "icon.test").unwrap());
        values.add_icon(IconValue::reference("icon.parent", "icon.grandparent").unwrap());
        let value = IconValue::reference("icon.test", "icon.parent").unwrap();
        assert!(value.get(&values).unwrap_err().is_loop);
        assert_eq!(
            value.get_or_default(&values).base,
            IconValue::last_resort_default()
        );
    }

    #[test]
    fn serialization_string() {
        let value = IconValue::new("icon.test", icon1()).unwrap();
        assert_eq!(value.serialization_string(), "icon.test = images/core.png");
        let value = IconValue::new("foo.bar", icon1()).unwrap();
        assert_eq!(
            value.serialization_string(),
            "[icon]foo.bar = images/core.png"
        );
        let value = IconValue::reference("icon.test", "xyz.abc").unwrap();
        assert_eq!(value.serialization_string(), "icon.test = [icon]xyz.abc");
    }

    #[test]
    fn parse() {
        let value = IconValue::parse("icon.test", "images/core.png")
            .unwrap()
            .unwrap();
        assert_eq!(value.id(), "icon.test");
        assert_eq!(value.raw_value(), Some(&icon1()));
        assert_eq!(value.reference_id(), None);

        let value = IconValue::parse("[icon]foo.bar", "images/core.png")
            .unwrap()
            .unwrap();
        assert_eq!(value.id(), "foo.bar");
        assert_eq!(value.raw_value(), Some(&icon1()));

        let value = IconValue::parse("icon.test", "[icon]xyz.abc")
            .unwrap()
            .unwrap();
        assert_eq!(value.raw_value(), None);
        assert_eq!(value.reference_id(), Some("xyz.abc"));
    }

    #[test]
    fn parse_blank_is_none() {
        assert!(IconValue::parse("icon.test", "  ").unwrap().is_none());
    }

    #[test]
    fn parse_with_overlays() {
        let mut values = GThemeValueMap::new();
        values.add_icon(
            IconValue::parse("icon.foo", "EMPTY_ICON{Plus2.png}")
                .unwrap()
                .unwrap(),
        );
        let value = IconValue::parse(
            "icon.test",
            "images/core.png[size(25,25)]{icon.foo[move(4,4)]}",
        )
        .unwrap()
        .unwrap();
        values.add_icon(value.clone());
        let resolved = value.get(&values).unwrap();
        assert_eq!(resolved.base, icon1());
        assert_eq!(resolved.modifiers.len(), 1);
        let m = &resolved.modifiers[0];
        assert_eq!(m.size, Some((25, 25)));
        assert_eq!(m.overlays.len(), 1);
        let overlay = m.overlays[0].get(&values).unwrap();
        assert_eq!(
            overlay.base,
            IconSpec::Empty {
                width: 16,
                height: 16
            }
        );
        // overlay's own [move] applied after the referred icon.foo's {Plus2.png} overlay
        assert_eq!(overlay.modifiers.len(), 2);
        assert_eq!(
            overlay.modifiers[0].overlays[0].raw_value(),
            Some(&IconSpec::Resource("Plus2.png".into()))
        );
        assert_eq!(overlay.modifiers[1].translation, Some((4, 4)));
    }

    #[test]
    fn reference_with_overlay_and_whitespace() {
        // project.theme.properties: icon.projectdata.find.checkouts.search = icon.search {icon.check}
        let value = IconValue::parse("icon.x", "icon.search {icon.check}")
            .unwrap()
            .unwrap();
        assert_eq!(value.reference_id(), Some("icon.search"));
        assert_eq!(
            value.modifier().unwrap().overlays[0].reference_id(),
            Some("icon.check")
        );
        assert_eq!(value.serialization_string(), "icon.x = icon.search");
    }

    #[test]
    fn is_icon_key() {
        assert!(IconValue::is_icon_key("icon.a.b.c"));
        assert!(IconValue::is_icon_key("[icon]a.b.c"));
        assert!(!IconValue::is_icon_key("a.b.c"));
    }

    #[test]
    fn inherits_from() {
        let mut values = GThemeValueMap::new();
        let grandparent = IconValue::new("icon.grandparent", icon1()).unwrap();
        let parent = IconValue::reference("icon.parent", "icon.grandparent").unwrap();
        let value = IconValue::reference("icon.test", "icon.parent").unwrap();
        values.add_icon(grandparent.clone());
        values.add_icon(parent.clone());
        values.add_icon(value.clone());
        assert!(value.inherits_from("icon.parent", &values));
        assert!(value.inherits_from("icon.grandparent", &values));
        assert!(parent.inherits_from("icon.grandparent", &values));
        assert!(!value.inherits_from("icon.test", &values));
        assert!(!parent.inherits_from("icon.test", &values));
        assert!(!grandparent.inherits_from("icon.test", &values));
    }

    #[test]
    fn parse_empty_icon() {
        let values = GThemeValueMap::new();
        let value = IconValue::parse("icon.test", "EMPTY_ICON")
            .unwrap()
            .unwrap();
        let resolved = value.get(&values).unwrap();
        assert_eq!(
            resolved.base,
            IconSpec::Empty {
                width: 16,
                height: 16
            }
        );
        assert!(resolved.modifiers.is_empty());
    }

    #[test]
    fn parse_empty_icon_with_size() {
        let values = GThemeValueMap::new();
        let value = IconValue::parse("icon.test", "EMPTY_ICON[size(12,15)]")
            .unwrap()
            .unwrap();
        let resolved = value.get(&values).unwrap();
        assert_eq!(
            resolved.base,
            IconSpec::Empty {
                width: 16,
                height: 16
            }
        );
        assert_eq!(resolved.modifiers[0].size, Some((12, 15)));
    }

    #[test]
    fn serialization_with_empty_icons() {
        let value = IconValue::new(
            "icon.test",
            IconSpec::Empty {
                width: 16,
                height: 16,
            },
        )
        .unwrap();
        assert_eq!(value.serialization_string(), "icon.test = EMPTY_ICON");
        let value = IconValue::new(
            "icon.test",
            IconSpec::Empty {
                width: 22,
                height: 13,
            },
        )
        .unwrap();
        assert_eq!(
            value.serialization_string(),
            "icon.test = EMPTY_ICON[size(22,13)]"
        );
    }

    #[test]
    fn modifier_round_trips_in_serialization() {
        let value = IconValue::parse("icon.a", "core.png[size(17,21)]")
            .unwrap()
            .unwrap();
        assert_eq!(
            value.serialization_string(),
            "icon.a = core.png[size(17,21)]"
        );
    }

    #[test]
    fn java_icon_value_round_trip() {
        let mut values = GThemeValueMap::new();
        let value = IconValue::parse("[laf.icon]FileChooser.homeFolderIcon", "images/go-home.png")
            .unwrap()
            .unwrap();
        values.add_icon(value.clone());
        assert_eq!(value.id(), "laf.icon.FileChooser.homeFolderIcon");
        assert!(value.is_external());
        assert_eq!(
            value.get(&values).unwrap().base,
            IconSpec::Resource("images/go-home.png".into())
        );
        assert_eq!(
            value.serialization_string(),
            "[laf.icon]FileChooser.homeFolderIcon = images/go-home.png"
        );
    }

    #[test]
    fn inherits_from_java_values() {
        let mut values = GThemeValueMap::new();
        values.add_icon(
            IconValue::parse("[laf.icon]FileChooser.homeFolderIcon", "images/go-home.png")
                .unwrap()
                .unwrap(),
        );
        let value = IconValue::parse(
            "[laf.icon]FileView.computerIcon",
            "[laf.icon]FileChooser.homeFolderIcon",
        )
        .unwrap()
        .unwrap();
        values.add_icon(value.clone());
        assert!(value.inherits_from("laf.icon.FileChooser.homeFolderIcon", &values));
    }

    #[test]
    fn intermediate_reference_modifiers_follow_java() {
        // Java: a = icon.b, b = icon.c[size(8,8)], c = x.png -> only the terminal value's and
        // the requesting value's modifiers apply (b's is skipped by ThemeValue.get's walk).
        let mut values = GThemeValueMap::new();
        values.add_icon(
            IconValue::parse("icon.c", "x.png[disabled]")
                .unwrap()
                .unwrap(),
        );
        values.add_icon(
            IconValue::parse("icon.b", "icon.c[size(8,8)]")
                .unwrap()
                .unwrap(),
        );
        let a = IconValue::parse("icon.a", "icon.b[mirror]")
            .unwrap()
            .unwrap();
        let resolved = a.get(&values).unwrap();
        assert_eq!(resolved.base, IconSpec::Resource("x.png".into()));
        assert_eq!(resolved.modifiers.len(), 2);
        assert!(resolved.modifiers[0].disabled);
        assert!(resolved.modifiers[1].mirror);
    }
}
