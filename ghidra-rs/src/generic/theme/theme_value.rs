//! Port of `generic.theme.ThemeValue`: the generic base for theme values (colors, fonts,
//! icons, Java properties) that have a String id and either a concrete value or the id of
//! another value they inherit from.
//!
//! Java's `get(GThemeValueMap)` logs a warning and returns a type-specific "last resort"
//! default when a reference chain can't be resolved; here resolution returns an
//! [`UnresolvedReference`] error and each concrete value type offers its own
//! `get_or_default`. Lookup is abstracted as a closure so the generic walk does not depend
//! on [`GThemeValueMap`](super::g_theme_value_map::GThemeValueMap).

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use thiserror::Error;

/// Error from constructing a [`ThemeValue`] (Java throws `IllegalArgumentException`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ThemeValueError {
    /// The value's reference id equals its own id.
    #[error("Can't create a themeValue that referencs itself: {0}")]
    SelfReference(String),
    /// The id is still in external (`[color]x`) form instead of normalized.
    #[error("Theme values must be constructed with normalized, non-external ids: {0}")]
    ExternalId(String),
}

/// A reference chain that could not be followed to a concrete value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Could not resolve indirect reference \"{unresolved_id}\" for primary id \"{primary_id}\"{}", if *is_loop { " (reference loop)" } else { "" })]
pub struct UnresolvedReference {
    /// The id whose value was requested.
    pub primary_id: String,
    /// The reference id that could not be resolved (for a loop: the id that closed it).
    pub unresolved_id: String,
    /// True when the walk stopped because the chain loops back on itself.
    pub is_loop: bool,
}

/// Where a resolved value came from.
#[derive(Debug)]
pub enum Resolved<'a, T, V> {
    /// The value held directly by the value being resolved.
    Own(&'a T),
    /// The first value along the reference chain that holds a concrete value.
    Referred(&'a V),
}

/// Value or reference: Java keeps a nullable `value` and a nullable `referenceId`, exactly
/// one of which is set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Source<T> {
    Value(T),
    Reference(String),
}

/// A theme value with a normalized id and either a concrete `T` or a reference id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThemeValue<T> {
    id: String,
    source: Source<T>,
}

impl<T> ThemeValue<T> {
    /// A value holding a concrete `T`.
    pub fn with_value(id: impl Into<String>, value: T) -> Result<Self, ThemeValueError> {
        let id = Self::check_id(id.into())?;
        Ok(Self {
            id,
            source: Source::Value(value),
        })
    }

    /// A value inheriting from the value with id `reference_id`.
    pub fn with_reference(
        id: impl Into<String>,
        reference_id: impl Into<String>,
    ) -> Result<Self, ThemeValueError> {
        let id = id.into();
        let reference_id = reference_id.into();
        if id == reference_id {
            return Err(ThemeValueError::SelfReference(id));
        }
        let id = Self::check_id(id)?;
        Ok(Self {
            id,
            source: Source::Reference(reference_id),
        })
    }

    fn check_id(id: String) -> Result<String, ThemeValueError> {
        if id.starts_with('[') {
            return Err(ThemeValueError::ExternalId(id));
        }
        Ok(id)
    }

    /// `getId()`
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `getReferenceId()`: the id this value inherits from, if indirect.
    pub fn reference_id(&self) -> Option<&str> {
        match &self.source {
            Source::Reference(r) => Some(r),
            Source::Value(_) => None,
        }
    }

    /// `getRawValue()`: the stored value, without following references.
    pub fn raw_value(&self) -> Option<&T> {
        match &self.source {
            Source::Value(v) => Some(v),
            Source::Reference(_) => None,
        }
    }

    /// `isIndirect()`
    pub fn is_indirect(&self) -> bool {
        matches!(self.source, Source::Reference(_))
    }

    /// Follows references (via `lookup`) to the value that supplies the concrete `T`,
    /// mirroring the walk in Java's `ThemeValue.get`, including its loop detection.
    pub fn resolve<'a, V, F>(&'a self, lookup: F) -> Result<Resolved<'a, T, V>, UnresolvedReference>
    where
        V: AsRef<ThemeValue<T>> + 'a,
        F: Fn(&str) -> Option<&'a V>,
    {
        let reference_id = match &self.source {
            Source::Value(v) => return Ok(Resolved::Own(v)),
            Source::Reference(r) => r.as_str(),
        };
        let mut visited: HashSet<&str> = HashSet::new();
        visited.insert(&self.id);
        let mut current_ref = reference_id;
        while let Some(referred) = lookup(current_ref) {
            let base = referred.as_ref();
            let next_ref = match &base.source {
                Source::Value(_) => return Ok(Resolved::Referred(referred)),
                Source::Reference(r) => r.as_str(),
            };
            visited.insert(&base.id);
            if visited.contains(next_ref) {
                return Err(self.unresolved(next_ref, true));
            }
            current_ref = next_ref;
        }
        Err(self.unresolved(reference_id, false))
    }

    fn unresolved(&self, unresolved_id: &str, is_loop: bool) -> UnresolvedReference {
        UnresolvedReference {
            primary_id: self.id.clone(),
            unresolved_id: unresolved_id.to_string(),
            is_loop,
        }
    }

    /// `get(values)`: the concrete value, following references as needed.
    pub fn get<'a, V, F>(&'a self, lookup: F) -> Result<&'a T, UnresolvedReference>
    where
        V: AsRef<ThemeValue<T>> + 'a,
        F: Fn(&str) -> Option<&'a V>,
    {
        Ok(match self.resolve(lookup)? {
            Resolved::Own(v) => v,
            Resolved::Referred(r) => r
                .as_ref()
                .raw_value()
                .expect("resolve only returns referred values that hold a value"),
        })
    }

    /// `hasResolvableValue(values)`
    pub fn has_resolvable_value<'a, V, F>(&'a self, lookup: F) -> bool
    where
        V: AsRef<ThemeValue<T>> + 'a,
        F: Fn(&str) -> Option<&'a V>,
    {
        self.resolve(lookup).is_ok()
    }

    /// `inheritsFrom(ancestorId, values)`: true if this value derives its value from
    /// `ancestor_id` somewhere along its reference chain.
    pub fn inherits_from<'a, V, F>(&'a self, ancestor_id: &str, lookup: F) -> bool
    where
        V: AsRef<ThemeValue<T>> + 'a,
        F: Fn(&str) -> Option<&'a V>,
    {
        let Some(reference_id) = self.reference_id() else {
            return false;
        };
        if reference_id == ancestor_id {
            return true;
        }
        let mut visited: HashSet<&str> = HashSet::new();
        visited.insert(&self.id);
        let mut parent = lookup(reference_id);
        while let Some(p) = parent {
            let p = p.as_ref();
            let Some(parent_ref) = p.reference_id() else {
                return false;
            };
            if parent_ref == ancestor_id {
                return true;
            }
            visited.insert(&p.id);
            if visited.contains(parent_ref) {
                return false;
            }
            parent = lookup(parent_ref);
        }
        false
    }

    /// `compareTo`: theme values order by id.
    pub fn cmp_id(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T: fmt::Display> ThemeValue<T> {
    /// Java's `toString()`, given the concrete class's simple name.
    pub fn describe(&self, type_name: &str) -> String {
        match &self.source {
            Source::Value(v) => format!("{type_name} ({}, {v})", self.id),
            Source::Reference(r) => format!("{type_name} ({}, {r})", self.id),
        }
    }
}

impl<T> AsRef<ThemeValue<T>> for ThemeValue<T> {
    fn as_ref(&self) -> &ThemeValue<T> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    type Values = HashMap<String, ThemeValue<i32>>;

    fn add(values: &mut Values, v: ThemeValue<i32>) {
        values.insert(v.id().to_string(), v);
    }

    fn lookup<'a>(values: &'a Values) -> impl Fn(&str) -> Option<&'a ThemeValue<i32>> + 'a {
        move |id| values.get(id)
    }

    #[test]
    fn direct_value() {
        let v = ThemeValue::with_value("color.test", 7).unwrap();
        assert_eq!(v.id(), "color.test");
        assert_eq!(v.raw_value(), Some(&7));
        assert_eq!(v.reference_id(), None);
        assert!(!v.is_indirect());
        let values = Values::new();
        assert_eq!(v.get(lookup(&values)).unwrap(), &7);
    }

    #[test]
    fn indirect_multi_hop_value() {
        let mut values = Values::new();
        add(
            &mut values,
            ThemeValue::with_value("x.grandparent", 1).unwrap(),
        );
        add(
            &mut values,
            ThemeValue::with_reference("x.parent", "x.grandparent").unwrap(),
        );
        let v = ThemeValue::with_reference("x.test", "x.parent").unwrap();
        assert_eq!(v.raw_value(), None);
        assert_eq!(v.reference_id(), Some("x.parent"));
        assert!(v.is_indirect());
        assert_eq!(v.get(lookup(&values)).unwrap(), &1);
        assert!(v.has_resolvable_value(lookup(&values)));
        match v.resolve(lookup(&values)).unwrap() {
            Resolved::Referred(r) => assert_eq!(r.id(), "x.grandparent"),
            Resolved::Own(_) => panic!("expected referred"),
        }
    }

    #[test]
    fn unresolved_indirect_value() {
        let values = Values::new();
        let v = ThemeValue::with_reference("x.test", "x.parent").unwrap();
        let err = v.get(lookup(&values)).unwrap_err();
        assert_eq!(err.primary_id, "x.test");
        assert_eq!(err.unresolved_id, "x.parent");
        assert!(!err.is_loop);
        assert!(!v.has_resolvable_value(lookup(&values)));
    }

    #[test]
    fn reference_loop_is_detected() {
        let mut values = Values::new();
        add(
            &mut values,
            ThemeValue::with_reference("x.grandparent", "x.test").unwrap(),
        );
        add(
            &mut values,
            ThemeValue::with_reference("x.parent", "x.grandparent").unwrap(),
        );
        let v = ThemeValue::with_reference("x.test", "x.parent").unwrap();
        let err = v.get(lookup(&values)).unwrap_err();
        assert!(err.is_loop);
        assert_eq!(err.primary_id, "x.test");
        assert_eq!(err.unresolved_id, "x.test");
        assert!(!v.has_resolvable_value(lookup(&values)));
    }

    #[test]
    fn inherits_from() {
        let mut values = Values::new();
        let grandparent = ThemeValue::with_value("x.grandparent", 1).unwrap();
        let parent = ThemeValue::with_reference("x.parent", "x.grandparent").unwrap();
        let v = ThemeValue::with_reference("x.test", "x.parent").unwrap();
        add(&mut values, grandparent.clone());
        add(&mut values, parent.clone());
        add(&mut values, v.clone());
        assert!(v.inherits_from("x.parent", lookup(&values)));
        assert!(v.inherits_from("x.grandparent", lookup(&values)));
        assert!(parent.inherits_from("x.grandparent", lookup(&values)));
        assert!(!v.inherits_from("x.test", lookup(&values)));
        assert!(!parent.inherits_from("x.test", lookup(&values)));
        assert!(!grandparent.inherits_from("x.test", lookup(&values)));
    }

    #[test]
    fn self_reference_and_external_id_are_rejected() {
        assert_eq!(
            ThemeValue::<i32>::with_reference("x.a", "x.a").unwrap_err(),
            ThemeValueError::SelfReference("x.a".into())
        );
        assert_eq!(
            ThemeValue::with_value("[color]x.a", 1).unwrap_err(),
            ThemeValueError::ExternalId("[color]x.a".into())
        );
    }

    #[test]
    fn ordering_is_by_id_and_display_matches_java_to_string() {
        let a = ThemeValue::with_value("a", 1).unwrap();
        let b = ThemeValue::with_value("b", 0).unwrap();
        assert!(a.cmp_id(&b).is_lt());
        assert_eq!(a.describe("IconValue"), "IconValue (a, 1)");
        let r = ThemeValue::<i32>::with_reference("c", "a").unwrap();
        assert_eq!(r.describe("IconValue"), "IconValue (c, a)");
    }
}
