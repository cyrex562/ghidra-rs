//! Port of `generic.theme.IconModifier`'s value side: parsing and serializing the modifier
//! suffix of an icon theme value, e.g. `images/flag.png[size(12,16)][move(3,4)][disabled]`
//! or overlays such as `icon.search {icon.check}`.
//!
//! Java's `modify(Icon, GThemeValueMap)` (scaling, disabling, reflecting, rotating,
//! translating and overlaying an actual image) is rendering work and is left to the
//! toolkit; this type carries everything that method reads, in toolkit-neutral form.

use thiserror::Error;

use super::icon_value::IconValue;
use super::theme_value_utils::parse_groupings;

/// Error parsing an icon modifier or icon value (Java's `ParseException`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct IconParseError(pub String);

/// The modifications to apply to an icon, in the order Java's `modify` applies them:
/// size, disabled, mirror, flip, rotation, translation, overlays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IconModifier {
    /// `[size(w,h)]`: scale the icon to `(width, height)`.
    pub size: Option<(i32, i32)>,
    /// `[move(x,y)]`: translate the icon by `(x, y)`.
    pub translation: Option<(i32, i32)>,
    /// `[rotate(deg)]`: rotate by degrees.
    pub rotation: Option<i32>,
    /// `[disabled]`: render as disabled.
    pub disabled: bool,
    /// `[mirror]`: swap x values (left to right).
    pub mirror: bool,
    /// `[flip]`: swap y values (upside down).
    pub flip: bool,
    /// `{...}` groups: icons painted over the modified base icon, in order.
    pub overlays: Vec<IconValue>,
}

impl IconModifier {
    /// `IconModifier(size, translation, rotation, disabled, mirror, flip)`
    pub fn new(
        size: Option<(i32, i32)>,
        translation: Option<(i32, i32)>,
        rotation: Option<i32>,
        disabled: bool,
        mirror: bool,
        flip: bool,
    ) -> Self {
        Self {
            size,
            translation,
            rotation,
            disabled,
            mirror,
            flip,
            overlays: Vec::new(),
        }
    }

    /// `parse(String)`: parses one or more `[...]` base modifiers followed by `{...}`
    /// overlay icon values. Returns `None` for a blank string or one with no modifications.
    pub fn parse(icon_modifier_string: &str) -> Result<Option<Self>, IconParseError> {
        if icon_modifier_string.trim().is_empty() {
            return Ok(None);
        }
        let mut modifier = IconModifier::default();
        let (base, overlays) = match icon_modifier_string.find('{') {
            Some(i) => icon_modifier_string.split_at(i),
            None => (icon_modifier_string, ""),
        };
        modifier.parse_base_modifiers(base)?;
        modifier.parse_overlay_modifiers(overlays)?;
        Ok(modifier.had_modifications().then_some(modifier))
    }

    fn parse_overlay_modifiers(&mut self, overlays: &str) -> Result<(), IconParseError> {
        let groups =
            parse_groupings(overlays, '{', '}').map_err(|e| IconParseError(e.to_string()))?;
        for overlay in groups {
            // A blank overlay parses to no value; Java would add a null and fail later.
            if let Some(value) = IconValue::parse("", &overlay)? {
                self.overlays.push(value);
            }
        }
        Ok(())
    }

    fn parse_base_modifiers(&mut self, base: &str) -> Result<(), IconParseError> {
        let groups = parse_groupings(base, '[', ']').map_err(|e| IconParseError(e.to_string()))?;
        for group in groups {
            let m: String = group
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_lowercase();
            if let Some(args) = m.strip_prefix("size") {
                self.size = Some(parse_point_args(args)?);
            } else if let Some(args) = m.strip_prefix("move") {
                self.translation = Some(parse_point_args(args)?);
            } else if m.starts_with("mirror") {
                self.mirror = exact_flag(&m, "mirror")?;
            } else if m.starts_with("flip") {
                self.flip = exact_flag(&m, "flip")?;
            } else if let Some(args) = m.strip_prefix("rotate") {
                self.rotation = Some(parse_int_arg(args)?);
            } else if m.starts_with("disabled") {
                self.disabled = exact_flag(&m, "disabled")?;
            } else {
                return Err(IconParseError(format!("Invalid icon modifier: {m}")));
            }
        }
        Ok(())
    }

    fn had_modifications(&self) -> bool {
        self.size.is_some()
            || self.translation.is_some()
            || !self.overlays.is_empty()
            || self.rotation.is_some()
            || self.disabled
            || self.mirror
            || self.flip
    }

    /// `getSerializationString()`: the base modifiers in a form [`IconModifier::parse`]
    /// accepts. Like Java, overlays are not serialized.
    pub fn serialization_string(&self) -> String {
        let mut s = String::new();
        if let Some((w, h)) = self.size {
            s.push_str(&format!("[size({w},{h})]"));
        }
        if self.mirror {
            s.push_str("[mirror]");
        }
        if self.flip {
            s.push_str("[flip]");
        }
        if let Some(r) = self.rotation {
            s.push_str(&format!("[rotate({r})]"));
        }
        if let Some((x, y)) = self.translation {
            s.push_str(&format!("[move({x},{y})]"));
        }
        if self.disabled {
            s.push_str("[disabled]");
        }
        s
    }
}

fn exact_flag(modifier: &str, name: &str) -> Result<bool, IconParseError> {
    if modifier != name {
        return Err(IconParseError(format!("Illegal Icon modifier: {modifier}")));
    }
    Ok(true)
}

fn strip_parens(args: &str) -> Result<&str, IconParseError> {
    args.strip_prefix('(')
        .and_then(|a| a.strip_suffix(')'))
        .ok_or_else(|| IconParseError(format!("Invalid arguments: {args}")))
}

fn parse_point_args(args: &str) -> Result<(i32, i32), IconParseError> {
    let inner = strip_parens(args)?;
    let invalid = || IconParseError(format!("Invalid arguments: {inner}"));
    let parts: Vec<&str> = inner.split(',').collect();
    if parts.len() != 2 {
        return Err(invalid());
    }
    let x = parts[0].parse::<i32>().map_err(|_| invalid())?;
    let y = parts[1].parse::<i32>().map_err(|_| invalid())?;
    Ok((x, y))
}

fn parse_int_arg(args: &str) -> Result<i32, IconParseError> {
    let inner = strip_parens(args)?;
    inner
        .parse::<i32>()
        .map_err(|_| IconParseError(format!("Invalid arguments: {inner}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::theme::icon_value::IconSpec;

    // Derived from IconModifierTest (parse/serialization parts; the icon-painting
    // assertions belong to the renderer).

    #[test]
    fn parse_blank_is_none() {
        assert_eq!(IconModifier::parse("").unwrap(), None);
        assert_eq!(IconModifier::parse("   ").unwrap(), None);
    }

    #[test]
    fn parse_size() {
        let m = IconModifier::parse("[size(7,3)]").unwrap().unwrap();
        assert_eq!(m.size, Some((7, 3)));
        assert_eq!(m.serialization_string(), "[size(7,3)]");
    }

    #[test]
    fn parse_move_with_whitespace_and_case() {
        let m = IconModifier::parse("[ MOVE(8, 8) ]").unwrap().unwrap();
        assert_eq!(m.translation, Some((8, 8)));
        assert_eq!(m.serialization_string(), "[move(8,8)]");
    }

    #[test]
    fn parse_all_base_modifiers_serializes_in_java_order() {
        let m = IconModifier::parse("[disabled][move(1,2)][rotate(90)][flip][mirror][size(4,5)]")
            .unwrap()
            .unwrap();
        assert!(m.disabled && m.mirror && m.flip);
        assert_eq!(m.rotation, Some(90));
        assert_eq!(
            m.serialization_string(),
            "[size(4,5)][mirror][flip][rotate(90)][move(1,2)][disabled]"
        );
    }

    #[test]
    fn parse_overlays() {
        let m = IconModifier::parse("[size(25,25)]{icon.foo[move(4,4)]}{images/flag.png}")
            .unwrap()
            .unwrap();
        assert_eq!(m.size, Some((25, 25)));
        assert_eq!(m.overlays.len(), 2);
        assert_eq!(m.overlays[0].reference_id(), Some("icon.foo"));
        assert_eq!(m.overlays[0].modifier().unwrap().translation, Some((4, 4)));
        assert_eq!(
            m.overlays[1].raw_value(),
            Some(&IconSpec::Resource("images/flag.png".into()))
        );
    }

    #[test]
    fn invalid_modifiers_are_errors() {
        assert!(IconModifier::parse("[bogus]").is_err());
        assert!(IconModifier::parse("[size(1)]").is_err());
        assert!(IconModifier::parse("[size(a,b)]").is_err());
        assert!(IconModifier::parse("[rotate(x)]").is_err());
        assert!(IconModifier::parse("[disabledx]").is_err());
        assert!(IconModifier::parse("[size(1,2)").is_err());
    }
}
