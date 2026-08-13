//! Represents a demangled string.
//!
//! Port of `ghidra.app.util.demangler.DemangledType`.

use crate::demangler::seam_stubs::{strip_superfluous_signature_spaces, Demangled, DemangledTemplate};
use crate::program::model::symbol::namespace::DELIMITER;

/// Represents a demangled string. This class is really just a placeholder for demangled
/// information. See `DemangledObject` for a class that represents software concepts that can be
/// applied to a program. The `DemangledObject` may use instances of this class to compose its
/// internal state for namespace information, return types and parameters.
///
/// Port of `ghidra.app.util.demangler.DemangledType`.
pub struct DemangledType {
    /// The original mangled string.
    pub(crate) mangled: String,
    original_demangled: String,
    demangled_name: String,
    /// 'safe' name.
    name: String,

    pub(crate) namespace: Option<Box<dyn Demangled>>,
    pub(crate) template: Option<DemangledTemplate>,
    is_const: bool,
    is_volatile: bool,
}

impl DemangledType {
    /// Creates a new `DemangledType`.
    ///
    /// Mirrors `DemangledType(String mangled, String originalDemangled, String name)`.
    ///
    /// # Panics
    /// Panics if `name` is blank, mirroring the `IllegalArgumentException` the Java constructor
    /// throws via `setName`.
    pub fn new(
        mangled: impl Into<String>,
        original_demangled: impl Into<String>,
        name: &str,
    ) -> Self {
        let mut this = Self {
            mangled: mangled.into(),
            original_demangled: original_demangled.into(),
            demangled_name: String::new(),
            name: String::new(),
            namespace: None,
            template: None,
            is_const: false,
            is_volatile: false,
        };
        this.set_name(name);
        this
    }

    /// Returns whether this type is `const`.
    ///
    /// Mirrors `isConst()`.
    pub fn is_const(&self) -> bool {
        self.is_const
    }

    /// Marks this type as `const`.
    ///
    /// Mirrors `setConst()`.
    pub fn set_const(&mut self) {
        self.is_const = true;
    }

    /// Returns whether this type is `volatile`.
    ///
    /// Mirrors `isVolatile()`.
    pub fn is_volatile(&self) -> bool {
        self.is_volatile
    }

    /// Marks this type as `volatile`.
    ///
    /// Mirrors `setVolatile()`.
    pub fn set_volatile(&mut self) {
        self.is_volatile = true;
    }

    /// Returns the template, if any.
    ///
    /// Mirrors `getTemplate()`.
    pub fn template(&self) -> Option<&DemangledTemplate> {
        self.template.as_ref()
    }

    /// Sets the template.
    ///
    /// Mirrors `setTemplate(DemangledTemplate)`.
    pub fn set_template(&mut self, template: Option<DemangledTemplate>) {
        self.template = template;
    }

    /// The 'safe' name rendering shared by [`Demangled::get_namespace_string`] (with the
    /// namespace path prepended) and [`Demangled::get_namespace_name`] (without it).
    ///
    /// Mirrors the private `getName(boolean includeNamespace)`.
    fn name_with(&self, include_namespace: bool) -> String {
        let mut buffer = String::new();
        if include_namespace {
            if let Some(namespace) = &self.namespace {
                buffer.push_str(&namespace.get_namespace_string());
                buffer.push_str(DELIMITER);
            }
        }

        buffer.push_str(&self.demangled_name);
        if let Some(template) = &self.template {
            buffer.push_str(&template.to_template());
        }

        buffer
    }
}

impl Demangled for DemangledType {
    /// Mirrors `getMangledString()`.
    fn get_mangled_string(&self) -> String {
        self.mangled.clone()
    }

    /// Mirrors `getOriginalDemangled()`.
    fn get_original_demangled(&self) -> String {
        self.original_demangled.clone()
    }

    /// Mirrors `getName()`.
    fn get_name(&self) -> String {
        self.name.clone()
    }

    /// Mirrors `setName(String)`.
    ///
    /// # Panics
    /// Panics if `name` is blank, mirroring the Java `IllegalArgumentException`.
    fn set_name(&mut self, name: &str) {
        if is_blank(name) {
            panic!("Name cannot be blank");
        }

        self.demangled_name = name.to_string();
        // use safe name and omit common spaces where they are unwanted in names
        self.name = strip_superfluous_signature_spaces(name).replace(' ', "_");
    }

    /// Mirrors `getDemangledName()`.
    fn get_demangled_name(&self) -> String {
        self.demangled_name.clone()
    }

    /// Mirrors `getNamespace()`.
    fn get_namespace(&self) -> Option<&dyn Demangled> {
        self.namespace.as_deref()
    }

    /// Mirrors `setNamespace(Demangled)`.
    fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
        self.namespace = namespace;
    }

    /// Mirrors `getNamespaceString()`.
    fn get_namespace_string(&self) -> String {
        self.name_with(true)
    }

    /// Mirrors `getNamespaceName()`.
    fn get_namespace_name(&self) -> String {
        self.name.clone()
    }

    /// Mirrors `getSignature()`.
    fn get_signature(&self) -> String {
        self.get_namespace_name()
    }
}

impl std::fmt::Display for DemangledType {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_namespace_string())
    }
}

/// Mirrors `org.apache.commons.lang3.StringUtils.isBlank`: `true` for an empty string or one
/// containing only whitespace.
fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_safe_and_demangled_names() {
        let dt = DemangledType::new("_Zfoo", "foo bar", "foo bar");
        assert_eq!(dt.get_mangled_string(), "_Zfoo");
        assert_eq!(dt.get_original_demangled(), "foo bar");
        assert_eq!(dt.get_demangled_name(), "foo bar");
        // spaces replaced with underscores for the 'safe' name
        assert_eq!(dt.get_name(), "foo_bar");
    }

    #[test]
    #[should_panic(expected = "Name cannot be blank")]
    fn new_panics_on_blank_name() {
        DemangledType::new("_Z", "", "   ");
    }

    #[test]
    fn set_const_and_volatile() {
        let mut dt = DemangledType::new("m", "o", "n");
        assert!(!dt.is_const());
        assert!(!dt.is_volatile());
        dt.set_const();
        dt.set_volatile();
        assert!(dt.is_const());
        assert!(dt.is_volatile());
    }

    #[test]
    fn namespace_string_prepends_parent_with_delimiter() {
        let mut child = DemangledType::new("m", "o", "Bar");
        let parent: Box<dyn Demangled> = Box::new(DemangledType::new("m", "o", "Foo"));
        child.set_namespace(Some(parent));

        assert_eq!(child.get_namespace_string(), "Foo::Bar");
        // getNamespaceName omits the parent path
        assert_eq!(child.get_namespace_name(), "Bar");
        assert_eq!(child.get_signature(), "Bar");
        assert_eq!(child.to_string(), "Foo::Bar");
    }

    #[test]
    fn namespace_string_without_namespace_is_just_the_name() {
        let dt = DemangledType::new("m", "o", "Baz");
        assert_eq!(dt.get_namespace_string(), "Baz");
        assert!(dt.get_namespace().is_none());
    }

    #[test]
    fn template_is_appended_to_namespace_string() {
        let mut dt = DemangledType::new("m", "o", "Vector");
        let mut template = DemangledTemplate::default();
        template.add_parameter("int".to_string());
        dt.set_template(Some(template));

        assert_eq!(dt.get_namespace_string(), "Vector<int>");
        assert_eq!(dt.template().unwrap().to_template(), "<int>");
    }
}
