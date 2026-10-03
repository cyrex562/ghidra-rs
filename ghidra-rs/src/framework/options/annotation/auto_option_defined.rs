//! Port of `ghidra.framework.options.annotation.AutoOptionDefined`.

use std::any::TypeId;

use crate::framework::options::annotation::HelpInfo;
use crate::framework::options::option_type::OptionType;

/// Metadata for an option-definition point, mirroring Java's `@AutoOptionDefined` runtime
/// annotation.
///
/// In Java the annotation marks a field whose value `AutoOptions` registers as a tool option
/// (with the given category, name, type, help, description and editor). Rust has no reflective
/// annotations, so the same metadata is carried in this struct and handed to the options framework
/// by the owning type (per the recorded R4 decision: annotation types become metadata structs).
///
/// Java defaults: `category = {}`, `type = OptionType.NO_TYPE` (meaning "infer from the field's
/// value"), `help = @HelpInfo(topic = {})`, `editor = PropertyEditor.class` (meaning "no custom
/// editor", here `None`). `name` and `description` have no default and must be supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoOptionDefined {
    /// Category path components (Java: `category = {"A", "B"}`).
    pub category: Vec<String>,
    /// The option's type; [`OptionType::NoType`] (the default) defers to the value's own type.
    pub option_type: OptionType,
    /// Option name path components; must be non-empty.
    pub name: Vec<String>,
    /// Help location for the option.
    pub help: HelpInfo,
    /// Description of the option.
    pub description: String,
    /// The custom property editor type (Java's `Class<? extends PropertyEditor>`, keyed by
    /// [`TypeId`] per the recorded `Class<T>` decision); `None` is Java's default
    /// `PropertyEditor.class`, i.e. no custom editor.
    pub editor: Option<TypeId>,
}

impl AutoOptionDefined {
    /// Creates the metadata with only the required `name` and `description`; every other element
    /// takes its Java default.
    ///
    /// # Panics
    /// Panics when `name` is empty: Java requires `name()` to be supplied.
    pub fn new(
        name: impl IntoIterator<Item = impl Into<String>>,
        description: impl Into<String>,
    ) -> Self {
        let name: Vec<String> = name.into_iter().map(Into::into).collect();
        assert!(
            !name.is_empty(),
            "AutoOptionDefined: name must not be empty"
        );
        Self {
            category: Vec::new(),
            option_type: OptionType::NoType,
            name,
            help: HelpInfo::new(),
            description: description.into(),
            editor: None,
        }
    }

    /// Sets the category path (`category = {...}`).
    pub fn with_category(mut self, category: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.category = category.into_iter().map(Into::into).collect();
        self
    }

    /// Sets an explicit option type (`type = ...`).
    pub fn with_type(mut self, option_type: OptionType) -> Self {
        self.option_type = option_type;
        self
    }

    /// Sets the help location (`help = @HelpInfo(...)`).
    pub fn with_help(mut self, help: HelpInfo) -> Self {
        self.help = help;
        self
    }

    /// Sets a custom property editor type (`editor = MyEditor.class`).
    pub fn with_editor<E: 'static>(mut self) -> Self {
        self.editor = Some(TypeId::of::<E>());
        self
    }

    /// Returns `true` when an explicit type was given (anything other than the `NO_TYPE` default).
    pub fn has_explicit_type(&self) -> bool {
        self.option_type != OptionType::NoType
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_applies_java_defaults() {
        let a = AutoOptionDefined::new(["Opt"], "An option");
        assert!(a.category.is_empty());
        assert_eq!(a.option_type, OptionType::NoType);
        assert!(!a.has_explicit_type());
        assert_eq!(a.name, vec!["Opt"]);
        assert_eq!(a.help, HelpInfo::new());
        assert!(a.help.topic.is_empty());
        assert_eq!(a.description, "An option");
        assert_eq!(a.editor, None);
    }

    #[test]
    fn builders_set_each_element() {
        struct MyEditor;
        let a = AutoOptionDefined::new(["A", "B"], "d")
            .with_category(["Cat"])
            .with_type(OptionType::IntType)
            .with_help(HelpInfo::with_topic_and_anchor(["Topic"], "anchor"))
            .with_editor::<MyEditor>();
        assert_eq!(a.category, vec!["Cat"]);
        assert_eq!(a.option_type, OptionType::IntType);
        assert!(a.has_explicit_type());
        assert_eq!(a.name, vec!["A", "B"]);
        assert_eq!(a.help.anchor, "anchor");
        assert_eq!(a.editor, Some(TypeId::of::<MyEditor>()));
    }

    #[test]
    #[should_panic(expected = "name must not be empty")]
    fn empty_name_panics() {
        let _ = AutoOptionDefined::new(Vec::<String>::new(), "d");
    }
}
