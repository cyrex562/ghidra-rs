const DEFAULT_MESSAGE: &str = "No context register information";

/// Builder for the "Context Register Information" panel.
///
/// Mirrors `ghidra.bitpatterns.gui.ContextRegisterPanelBuilder`. The Swing
/// `JPanel`/`JTextArea` from the Java source is replaced by [`ContextRegisterPanel`],
/// a plain data struct whose `message` field is rendered by the egui layer.
pub struct ContextRegisterPanelBuilder {
    message: String,
}

/// Content data for a context register information panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRegisterPanel {
    pub message: String,
}

impl ContextRegisterPanelBuilder {
    /// Creates a builder for the panel displaying the context register extent.
    ///
    /// If `context_register_info` is `None` or empty, a default placeholder is used.
    pub fn new(context_register_info: Option<&str>) -> Self {
        let message = match context_register_info {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => DEFAULT_MESSAGE.to_string(),
        };
        Self { message }
    }

    /// Returns the panel content data for displaying the context register extent.
    pub fn build_context_register_panel(&self) -> ContextRegisterPanel {
        ContextRegisterPanel {
            message: self.message.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_uses_default() {
        let builder = ContextRegisterPanelBuilder::new(None);
        let panel = builder.build_context_register_panel();
        assert_eq!(panel.message, "No context register information");
    }

    #[test]
    fn test_empty_string_uses_default() {
        let builder = ContextRegisterPanelBuilder::new(Some(""));
        let panel = builder.build_context_register_panel();
        assert_eq!(panel.message, "No context register information");
    }

    #[test]
    fn test_non_empty_string_preserved() {
        let builder = ContextRegisterPanelBuilder::new(Some("TMode: 0x1..0x1"));
        let panel = builder.build_context_register_panel();
        assert_eq!(panel.message, "TMode: 0x1..0x1");
    }

    #[test]
    fn test_default_message_constant() {
        assert_eq!(DEFAULT_MESSAGE, "No context register information");
    }

    #[test]
    fn test_panel_clone_and_eq() {
        let panel = ContextRegisterPanel {
            message: "test".to_string(),
        };
        assert_eq!(panel.clone(), panel);
    }
}
