//! Toolkit-neutral icon reference: a Ghidra theme icon id (`GIcon` id such as
//! `"icon.provider.close"`). Renderers resolve it; the model never holds image data.

use std::fmt;

/// A theme icon id (`GIcon` id), resolved by the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IconId(String);

impl IconId {
    /// Wraps a theme icon id.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IconId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_its_id() {
        assert_eq!(IconId::new("icon.x").to_string(), "icon.x");
        assert_eq!(IconId::new("icon.x").as_str(), "icon.x");
    }
}
