use crate::framework::model::{ToolChestChangeListener, ToolTemplate};

/// Interface to define methods to manage tools in a central location.
///
/// Port of `ghidra.framework.model.ToolChest`.
pub trait ToolChest {
    /// Get the tool template for the given tool name.
    ///
    /// # Arguments
    /// * `tool_name` - name of tool
    ///
    /// # Returns
    /// `None` if there is no tool template for the given tool name.
    fn get_tool_template(&self, tool_name: &str) -> Option<Box<dyn ToolTemplate>>;

    /// Get the tool templates from the tool chest.
    ///
    /// # Returns
    /// Vector of tool templates
    fn get_tool_templates(&self) -> Vec<Box<dyn ToolTemplate>>;

    /// Add a listener to be notified when the tool chest is changed.
    ///
    /// # Arguments
    /// * `listener` - listener to add
    fn add_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>);

    /// Remove a listener that is listening to when the tool chest is changed.
    ///
    /// # Arguments
    /// * `listener` - listener to remove
    fn remove_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>);

    /// Add tool template to the tool chest.
    ///
    /// Note: If the given tool template name already exists in the project, then the name will
    /// be altered by appending an underscore and a one-up value. The template's name is also
    /// updated with the new name.
    ///
    /// To simply replace a tool without changing its name, call [`replace_tool_template`](Self::replace_tool_template).
    ///
    /// # Arguments
    /// * `template` - tool template to add
    ///
    /// # Returns
    /// `true` if the template was successfully added, `false` otherwise
    fn add_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool;

    /// Remove entry (tool template or tool set) from the tool chest.
    ///
    /// # Arguments
    /// * `tool_name` - name of tool config or tool set to remove
    ///
    /// # Returns
    /// `true` if the tool config or tool set was successfully removed from the tool chest,
    /// `false` otherwise
    fn remove(&mut self, tool_name: &str) -> bool;

    /// Get the number of tools in this tool chest.
    fn get_tool_count(&self) -> i32;

    /// Performs the same action as calling [`remove`](Self::remove) and then
    /// [`add_tool_template`](Self::add_tool_template). However, calling this method prevents
    /// state from being lost in the transition, such as position in the tool chest and
    /// default tool status.
    ///
    /// # Arguments
    /// * `template` - the template to add to the tool chest, replacing any tools with the same name
    ///
    /// # Returns
    /// `true` if the template was added, `false` otherwise
    fn replace_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockToolTemplate {
        name: String,
    }

    impl ToolTemplate for MockToolTemplate {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_path(&self) -> Option<String> {
            None
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn get_icon_url(&self) -> Box<dyn crate::framework::seam_stubs::ToolIconURL> {
            struct Stub;
            impl crate::framework::seam_stubs::ToolIconURL for Stub {}
            Box::new(Stub)
        }

        fn get_icon(&self) -> Box<dyn crate::framework::seam_stubs::ImageIcon> {
            struct Stub;
            impl crate::framework::seam_stubs::ImageIcon for Stub {}
            Box::new(Stub)
        }

        fn get_supported_data_types(&self) -> Vec<String> {
            Vec::new()
        }

        fn save_to_xml(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct Stub;
            impl crate::framework::seam_stubs::JdomElement for Stub {}
            Box::new(Stub)
        }

        fn restore_from_xml(&mut self, _root: &dyn crate::framework::seam_stubs::JdomElement) {}

        fn create_tool(&self, _project: &dyn crate::framework::model::Project) -> Box<dyn crate::framework::seam_stubs::PluginTool> {
            struct Stub;
            impl crate::framework::seam_stubs::PluginTool for Stub {}
            Box::new(Stub)
        }

        fn get_tool_element(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct Stub;
            impl crate::framework::seam_stubs::JdomElement for Stub {}
            Box::new(Stub)
        }
    }

    struct MockToolChestChangeListener;

    impl ToolChestChangeListener for MockToolChestChangeListener {
        fn tool_template_added(&mut self, _tool: &dyn ToolTemplate) {}
        fn tool_set_added(&mut self, _toolset: &dyn crate::framework::model::ToolSet) {}
        fn tool_removed(&mut self, _tool_name: &str) {}
    }

    struct SimpleToolChest {
        templates: Vec<String>,
        count: i32,
    }

    impl SimpleToolChest {
        fn new() -> Self {
            SimpleToolChest { templates: Vec::new(), count: 0 }
        }
    }

    impl ToolChest for SimpleToolChest {
        fn get_tool_template(&self, tool_name: &str) -> Option<Box<dyn ToolTemplate>> {
            if self.templates.contains(&tool_name.to_string()) {
                Some(Box::new(MockToolTemplate { name: tool_name.to_string() }))
            } else {
                None
            }
        }

        fn get_tool_templates(&self) -> Vec<Box<dyn ToolTemplate>> {
            self.templates
                .iter()
                .map(|name| {
                    Box::new(MockToolTemplate { name: name.clone() }) as Box<dyn ToolTemplate>
                })
                .collect()
        }

        fn add_tool_chest_change_listener(&mut self, _listener: Box<dyn ToolChestChangeListener>) {
        }

        fn remove_tool_chest_change_listener(&mut self, _listener: Box<dyn ToolChestChangeListener>) {
        }

        fn add_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
            let name = template.get_name();
            if !self.templates.contains(&name) {
                self.templates.push(name);
                self.count += 1;
                true
            } else {
                false
            }
        }

        fn remove(&mut self, tool_name: &str) -> bool {
            if let Some(pos) = self.templates.iter().position(|x| x == tool_name) {
                self.templates.remove(pos);
                self.count -= 1;
                true
            } else {
                false
            }
        }

        fn get_tool_count(&self) -> i32 {
            self.count
        }

        fn replace_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
            let name = template.get_name();
            self.remove(&name);
            self.add_tool_template(template)
        }
    }

    #[test]
    fn test_get_tool_template_found() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "CodeBrowser".to_string() };
        chest.add_tool_template(&mut template);

        let result = chest.get_tool_template("CodeBrowser");
        assert!(result.is_some());
    }

    #[test]
    fn test_get_tool_template_not_found() {
        let chest = SimpleToolChest::new();
        let result = chest.get_tool_template("NonExistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_tool_templates_empty() {
        let chest = SimpleToolChest::new();
        let templates = chest.get_tool_templates();
        assert!(templates.is_empty());
    }

    #[test]
    fn test_get_tool_templates_multiple() {
        let mut chest = SimpleToolChest::new();
        let mut t1 = MockToolTemplate { name: "Tool1".to_string() };
        let mut t2 = MockToolTemplate { name: "Tool2".to_string() };

        chest.add_tool_template(&mut t1);
        chest.add_tool_template(&mut t2);

        let templates = chest.get_tool_templates();
        assert_eq!(templates.len(), 2);
    }

    #[test]
    fn test_add_tool_template_success() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "NewTool".to_string() };

        let result = chest.add_tool_template(&mut template);
        assert!(result);
        assert_eq!(chest.get_tool_count(), 1);
    }

    #[test]
    fn test_add_tool_template_duplicate() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "DupeTool".to_string() };

        chest.add_tool_template(&mut template);
        let result = chest.add_tool_template(&mut template);

        assert!(!result);
        assert_eq!(chest.get_tool_count(), 1);
    }

    #[test]
    fn test_remove_existing() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "RemoveTool".to_string() };
        chest.add_tool_template(&mut template);

        let result = chest.remove("RemoveTool");
        assert!(result);
        assert_eq!(chest.get_tool_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut chest = SimpleToolChest::new();
        let result = chest.remove("NoSuchTool");
        assert!(!result);
        assert_eq!(chest.get_tool_count(), 0);
    }

    #[test]
    fn test_get_tool_count() {
        let mut chest = SimpleToolChest::new();
        assert_eq!(chest.get_tool_count(), 0);

        let mut t1 = MockToolTemplate { name: "Tool1".to_string() };
        let mut t2 = MockToolTemplate { name: "Tool2".to_string() };

        chest.add_tool_template(&mut t1);
        assert_eq!(chest.get_tool_count(), 1);

        chest.add_tool_template(&mut t2);
        assert_eq!(chest.get_tool_count(), 2);

        chest.remove("Tool1");
        assert_eq!(chest.get_tool_count(), 1);
    }

    #[test]
    fn test_replace_tool_template_existing() {
        let mut chest = SimpleToolChest::new();
        let mut t1 = MockToolTemplate { name: "ReplaceTool".to_string() };
        let mut t2 = MockToolTemplate { name: "ReplaceTool".to_string() };

        chest.add_tool_template(&mut t1);
        assert_eq!(chest.get_tool_count(), 1);

        let result = chest.replace_tool_template(&mut t2);
        assert!(result);
        assert_eq!(chest.get_tool_count(), 1);
    }

    #[test]
    fn test_replace_tool_template_new() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "NewReplaceTool".to_string() };

        let result = chest.replace_tool_template(&mut template);
        assert!(result);
        assert_eq!(chest.get_tool_count(), 1);
    }

    #[test]
    fn test_add_listener() {
        let mut chest = SimpleToolChest::new();
        let listener = Box::new(MockToolChestChangeListener);
        chest.add_tool_chest_change_listener(listener);
    }

    #[test]
    fn test_remove_listener() {
        let mut chest = SimpleToolChest::new();
        let listener = Box::new(MockToolChestChangeListener);
        chest.remove_tool_chest_change_listener(listener);
    }

    #[test]
    fn test_usable_as_trait_object() {
        let mut chest = SimpleToolChest::new();
        let mut template = MockToolTemplate { name: "Tool".to_string() };

        let dyn_chest: &mut dyn ToolChest = &mut chest;
        let _ = dyn_chest.add_tool_template(&mut template);
        let _ = dyn_chest.get_tool_template("Tool");
        let _ = dyn_chest.get_tool_templates();
        let _ = dyn_chest.get_tool_count();
        let listener = Box::new(MockToolChestChangeListener);
        dyn_chest.add_tool_chest_change_listener(listener);
    }
}
