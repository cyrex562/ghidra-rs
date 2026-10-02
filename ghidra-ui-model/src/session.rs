//! The root UI-session object every renderer talks to.

/// The application-wide UI session: the root object a renderer is handed at
/// startup. U1 grows this into the tool, provider and action registry.
#[derive(Debug, Clone)]
pub struct UiSession {
    app_name: String,
    version: String,
}

impl UiSession {
    /// Creates the session for this build of ghidra-rs.
    pub fn new() -> Self {
        Self {
            app_name: "Ghidra-rs".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Application name shown to users.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Application version (the crate version).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Main-window title, e.g. `"Ghidra-rs 0.1.0"`.
    pub fn title(&self) -> String {
        format!("{} {}", self.app_name, self.version)
    }
}

impl Default for UiSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_app_name_then_version() {
        let s = UiSession::new();
        assert_eq!(s.title(), format!("Ghidra-rs {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(UiSession::default().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(UiSession::default().app_name(), "Ghidra-rs");
    }
}
