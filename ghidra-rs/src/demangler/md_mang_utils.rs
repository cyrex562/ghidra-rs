//! Utility operations for `MDMang` users (and perhaps internal).
//!
//! Mirrors `mdemangler.MDMangUtils`, cut to a trait to break a dependency cycle: it is a
//! cut-point between `MDParsableItem`/`MDComplexType`/`MDQualifiedName` (`mdemangler`/
//! `mdemangler.datatype.complex`/`mdemangler.naming`, none ported yet) and the already-ported
//! `MDModifierType`/`MDObjectCPP`/`MDQualification`/`MDQualifier`/`MDNestedName`. The original is
//! a static utility class (private constructor, every member `static`), so there is no instance
//! state to model; it is still ported as a trait -- with every method given a default
//! implementation delegating to a same-named free function -- so it can be selected as this
//! cycle's cut-point and used via `&dyn MdMangUtils` (see [`DefaultMdMangUtils`]).

use std::sync::OnceLock;

use regex::Regex;

use crate::app::util::symbol_path::{parse_symbol_path, SymbolPath, SymbolPathNode};
use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::naming::md_qualifier::MdQualifier;
use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::seam_stubs::{MdMangLike, MdParsableItemLike};

const ANONYMOUS_NAMESPACE_MANGLED: &str = "`anonymous-namespace'";
const ANONYMOUS_NAMESPACE: &str = "`anonymous namespace'";

// @formatter:off
const SEARCH_LIST: [&str; 27] = [
    "<class ", "<struct ", "<union ", "<coclass ", "<cointerface ", "<enum ",
    "(class ", "(struct ", "(union ", "(coclass ", "(cointerface ", "(enum ",
    "`class ", "`struct ", "`union ", "`coclass ", "`cointerface ", "`enum ",
    ",class ", ",struct ", ",union ", ",coclass ", ",cointerface ", ",enum ",
    " __ptr64", "__unaligned ", " __restrict", // purposeful trailing space on "__unaligned "
];

const REPLACEMENT_LIST: [&str; 27] = [
    "<", "<", "<", "<", "<", "<",
    "(", "(", "(", "(", "(", "(",
    "`", "`", "`", "`", "`", "`",
    ",", ",", ",", ",", ",", ",",
    "", "", "",
];
// @formatter:on

/// Utility operations for `MDMang` users (and perhaps internal).
///
/// Mirrors `mdemangler.MDMangUtils`. See the module docs for why a private-constructor,
/// all-`static` Java utility class is nonetheless ported as a trait.
pub trait MdMangUtils {
    /// Returns the [`SymbolPath`] for the demangled item.
    ///
    /// Mirrors `getSymbolPath(MDParsableItem)`.
    fn get_symbol_path(
        &self,
        dmang: &dyn MdMangLike,
        item: &dyn MdParsableItemLike,
    ) -> Option<Box<dyn SymbolPath>> {
        symbol_path(dmang, item, false)
    }

    /// Returns a more simple [`SymbolPath`] for the demangled item. Any embedded object found at
    /// the main namespace level will have its namespace components retrieved and inserted
    /// appropriately in the main `SymbolPath` namespace. However, embedded objects that are more
    /// deeply placed (such as when used for a template argument) don't and shouldn't take part in
    /// this simplification.
    ///
    /// Mirrors `getSimpleSymbolPath(MDParsableItem)`.
    fn get_simple_symbol_path(
        &self,
        dmang: &dyn MdMangLike,
        item: &dyn MdParsableItemLike,
    ) -> Option<Box<dyn SymbolPath>> {
        symbol_path(dmang, item, true)
    }

    /// Checks that the given string begins with the standard `"A0x"` (under-the-hood `MDMang`
    /// name) pattern or with the `` ` `` pattern found with the `MDQuestionModifier` type,
    /// returning the standardized anonymous namespace component (or the original string if it is
    /// not one of those two forms).
    ///
    /// Mirrors `createStandardAnonymousNamespaceNode(String)`.
    fn create_standard_anonymous_namespace_node(&self, anon: &str) -> String {
        create_standard_anonymous_namespace_node(anon)
    }

    /// Creates the standardized local namespace node string of the form `` __l2 `` where `2` is
    /// an example number.
    ///
    /// Mirrors `createStandardLocalNamespaceNode(String)`.
    fn create_standard_local_namespace_node(&self, local_number: &str) -> String {
        create_standard_local_namespace_node(local_number)
    }

    /// Consolidates the [`SymbolPath`] recovered from the demangled item with a symbol path
    /// parsed from `regular_path_name`, preferring the demangled parts but falling back to the
    /// regular parts for any additional (typically outer-namespace) components.
    ///
    /// Mirrors `consolidateSymbolPath(MDParsableItem, String, boolean)`.
    fn consolidate_symbol_path(
        &self,
        dmang: &dyn MdMangLike,
        item: &dyn MdParsableItemLike,
        regular_path_name: &str,
        simple: bool,
    ) -> Option<Box<dyn SymbolPath>> {
        consolidate_symbol_path(dmang, item, regular_path_name, simple)
    }

    /// Standardizes a [`SymbolPath`], replacing the local namespace `` __l# `` pattern with the
    /// `` `#' `` pattern.
    ///
    /// Mirrors `standarizeSymbolPathTicks(SymbolPath)`.
    fn standardize_symbol_path_ticks(&self, symbol_path: &dyn SymbolPath) -> Box<dyn SymbolPath> {
        standardize_symbol_path_ticks(symbol_path)
    }

    /// Standardizes a [`SymbolPath`], replacing the local namespace `` `#' `` pattern with the
    /// `` __l# `` pattern.
    ///
    /// Mirrors `standarizeSymbolPathUnderscores(SymbolPath)`.
    fn standardize_symbol_path_underscores(
        &self,
        symbol_path: &dyn SymbolPath,
    ) -> Box<dyn SymbolPath> {
        standardize_symbol_path_underscores(symbol_path)
    }
}

/// Stateless implementor of [`MdMangUtils`] using every default method.
///
/// Mirrors the fact that `MDMangUtils` has a private constructor and is never subclassed: there
/// is exactly one behavior, so this unit struct exists only to give that behavior a concrete,
/// `dyn`-usable home.
pub struct DefaultMdMangUtils;

impl MdMangUtils for DefaultMdMangUtils {}

/// Mirrors the private `getSymbolPath(MDParsableItem, boolean)`.
fn symbol_path(
    dmang: &dyn MdMangLike,
    item: &dyn MdParsableItemLike,
    simple: bool,
) -> Option<Box<dyn SymbolPath>> {
    let mut parts = Vec::new();
    recurse_namespace(dmang, &mut parts, item, simple);
    create_symbol_path(&parts)
}

/// Mirrors the private `recurseNamespace(List<String>, MDParsableItem, boolean)`.
fn recurse_namespace(
    dmang: &dyn MdMangLike,
    parts: &mut Vec<String>,
    item: &dyn MdParsableItemLike,
    recurse_nested: bool,
) {
    // When simple is true, we need to recurse the nested hierarchy to pull the names up to the
    // main namespace level, so we set recurse = true.
    let mut current = item;
    while let Some(next) = current.as_modifier_referenced_item() {
        current = next;
    }

    if let Some(complex) = current.as_complex_type() {
        let namespace = complex.namespace();
        recurse_qualification(dmang, parts, namespace.name(), namespace.qualification(), recurse_nested);
    } else if let Some(embedded) = current.as_object_cpp_embedded() {
        recurse_object_cpp(dmang, parts, embedded, recurse_nested);
    }
}

/// Shared tail of the `MDObjectCPP` branch of `recurseNamespace`, also used directly for the
/// `qual.isNested()` recursive case, which (unlike the top-level entry point) always supplies an
/// `MDObjectCPP` (`nestedName.getNestedObject()`), never a general `MDParsableItem`.
fn recurse_object_cpp(
    dmang: &dyn MdMangLike,
    parts: &mut Vec<String>,
    obj: &dyn MdObjectCpp,
    recurse_nested: bool,
) {
    if let Some(qualification) = obj.qualification() {
        recurse_qualification(dmang, parts, obj.name(), qualification, recurse_nested);
    }
}

/// Shared tail of `recurseNamespace` once `name`/`qualification` have been resolved from either
/// the `MDComplexType` or `MDObjectCPP` branch.
fn recurse_qualification(
    dmang: &dyn MdMangLike,
    parts: &mut Vec<String>,
    name: String,
    qualification: &dyn MdQualification,
    recurse_nested: bool,
) {
    // The qualification comes in reverse order... the last is nearest to namespace root.
    let mut my_parts: Vec<String> = Vec::new();
    for qual in qualification.qualifiers() {
        if qual.is_nested() && recurse_nested {
            if let Some(nested) = qual.name_nested() {
                let mut nested_parts = Vec::new();
                recurse_object_cpp(dmang, &mut nested_parts, nested.nested_object(), recurse_nested);
                nested_parts.extend(std::mem::take(&mut my_parts));
                my_parts = nested_parts;
            }
        } else if qual.is_anon() {
            // Instead of using the standard qual.toString() method, which returns
            // "`anonymous namespace'" for anonymous qualifiers, we use qual.getAnonymousName()
            // which will have the underlying anonymous name of the form "A0xfedcba98" to create
            // a standardized anonymous name that is distinguishable from other anonymous names.
            my_parts.insert(0, create_standard_anonymous_namespace_node(&qual.anonymous_name()));
        } else {
            let mut rendered = String::new();
            qual.insert(dmang, &mut rendered);
            dmang.clean_output(&mut rendered);
            my_parts.insert(0, strip_tags(&rendered));
        }
    }
    my_parts.push(strip_tags(&name));
    parts.extend(my_parts);
}

/// Mirrors the private `stripTags(String)`.
fn strip_tags(input: &str) -> String {
    let mut result = input.to_string();
    for (search, replacement) in SEARCH_LIST.iter().zip(REPLACEMENT_LIST.iter()) {
        result = result.replace(search, replacement);
    }
    result
}

/// Mirrors the private `createSymbolPath(List<String>)`.
fn create_symbol_path(parts: &[String]) -> Option<Box<dyn SymbolPath>> {
    if parts.is_empty() {
        return None;
    }
    SymbolPathNode::from_names(parts.to_vec()).ok().map(|node| Box::new(node) as Box<dyn SymbolPath>)
}

/// Mirrors `createStandardAnonymousNamespaceNode(String)`.
///
/// Note that we are converting to upper case and doing zero padding to 8 hex digits. Unlike the
/// original, which throws `NumberFormatException` on a malformed hex suffix, this returns the
/// input unchanged -- consistent with this crate's preference for graceful fallback over panics
/// in non-parsing helper code.
pub fn create_standard_anonymous_namespace_node(anon: &str) -> String {
    let stripped = if let Some(rest) = anon.strip_prefix("A0x") {
        rest
    }
    else if let Some(rest) = anon.strip_prefix('`') {
        rest
    }
    else {
        return anon.to_string();
    };
    match u64::from_str_radix(stripped, 16) {
        Ok(num) => format!("_anon_{num:08X}"),
        Err(_) => anon.to_string(),
    }
}

/// Mirrors `createStandardLocalNamespaceNode(String)`.
pub fn create_standard_local_namespace_node(local_number: &str) -> String {
    format!("__l{local_number}")
}

/// Mirrors the public static `consolidateSymbolPath(MDParsableItem, String, boolean)`.
pub fn consolidate_symbol_path(
    dmang: &dyn MdMangLike,
    item: &dyn MdParsableItemLike,
    regular_path_name: &str,
    simple: bool,
) -> Option<Box<dyn SymbolPath>> {
    let mut demangled_parts = Vec::new();
    // When simple is true, we need to recurse the nested hierarchy to pull the names up to the
    // main namespace level, so we set recurse = true.
    recurse_namespace(dmang, &mut demangled_parts, item, simple);

    if regular_path_name.is_empty() {
        return create_symbol_path(&demangled_parts);
    }
    let regular_parts = parse_symbol_path(regular_path_name).unwrap_or_default();

    let m = demangled_parts.len().min(regular_parts.len());

    let mut parts: Vec<String> = Vec::new();
    for i in 1..=m {
        let ni = demangled_parts.len() - i;
        // Prefer the mangled part, but could get more sophisticated and decide to use regular
        // parts too.
        parts.insert(0, demangled_parts[ni].clone());
    }
    for i in (m + 1)..=regular_parts.len() {
        let ri = regular_parts.len() - i;
        let r = &regular_parts[ri];
        if r == ANONYMOUS_NAMESPACE_MANGLED {
            parts.insert(0, ANONYMOUS_NAMESPACE.to_string());
        }
        else {
            parts.insert(0, r.clone());
        }
    }
    for i in (m + 1)..=demangled_parts.len() {
        let ni = demangled_parts.len() - i;
        parts.insert(0, demangled_parts[ni].clone());
    }

    create_symbol_path(&parts)
}

fn local_ns_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^__l([0-9]+)$").unwrap())
}

fn embedded_local_ns_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"::__l([0-9]+)::").unwrap())
}

fn demangled_local_ns_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^`([0-9]+)'$").unwrap())
}

fn demangled_embedded_local_ns_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"::`([0-9]+)'::").unwrap())
}

/// Mirrors the public static `standarizeSymbolPathTicks(SymbolPath)`.
pub fn standardize_symbol_path_ticks(symbol_path: &dyn SymbolPath) -> Box<dyn SymbolPath> {
    let parts: Vec<String> =
        symbol_path.as_list().iter().map(|part| standardize_ticks_part(part)).collect();
    Box::new(SymbolPathNode::from_names(parts).expect("SymbolPath::as_list is never empty"))
}

fn standardize_ticks_part(part: &str) -> String {
    // These anonymous namespaces are those that come in the clear (non-mangled). Note: mirrors
    // the original's `StringUtils.replace(part, ...)` call whose return value is discarded (a
    // no-op in the original), so no replacement happens here either.
    if let Some(caps) = local_ns_pattern().captures(part) {
        return format!("`{}'", &caps[1]);
    }
    embedded_local_ns_pattern().replace_all(part, "::`$1'::").into_owned()
}

/// Mirrors the public static `standarizeSymbolPathUnderscores(SymbolPath)`.
pub fn standardize_symbol_path_underscores(symbol_path: &dyn SymbolPath) -> Box<dyn SymbolPath> {
    let parts: Vec<String> =
        symbol_path.as_list().iter().map(|part| standardize_underscores_part(part)).collect();
    Box::new(SymbolPathNode::from_names(parts).expect("SymbolPath::as_list is never empty"))
}

fn standardize_underscores_part(part: &str) -> String {
    if let Some(caps) = demangled_local_ns_pattern().captures(part) {
        return format!("__l{}", &caps[1]);
    }
    demangled_embedded_local_ns_pattern().replace_all(part, "::__l$1::").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::naming::md_nested_name::MdNestedName;
    use crate::demangler::naming::md_reusable_name::MdReusableName;
    use crate::demangler::seam_stubs::{
        MdComplexTypeLike, MdFragmentNameLike, MdNumberedNamespaceLike, MdQualifiedNameLike,
    };

    struct MockMdMang;

    impl MdMangLike for MockMdMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            if builder.is_empty() || s.is_empty() {
                builder.insert_str(0, s);
                return;
            }
            builder.insert(0, ' ');
            builder.insert_str(0, s);
        }
    }

    struct MockReusableName {
        rendered: String,
    }

    impl MdReusableName for MockReusableName {
        fn fragment_name(&self) -> Option<&dyn MdFragmentNameLike> {
            None
        }

        fn template_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdTemplateNameAndArgumentsLike> {
            None
        }

        fn special_name(&self) -> Option<&str> {
            Some(&self.rendered)
        }

        fn set_special_name(&mut self, name: Option<String>) {
            self.rendered = name.unwrap_or_default();
        }

        fn set_name(&mut self, _name: &str) {}
    }

    struct MockObjectCpp {
        rendered_name: String,
        qualification: MockQualification,
    }

    impl MdObjectCpp for MockObjectCpp {
        fn qualified_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdQualifiedBasicNameLike> {
            None
        }

        fn type_info(&self) -> Option<&dyn crate::demangler::seam_stubs::MdTypeInfoLike> {
            None
        }

        fn hashed_object(
            &self,
        ) -> Option<&dyn crate::demangler::object::md_object_cpp::MdHashedObject> {
            None
        }

        fn embedded_object_flag(&self) -> bool {
            false
        }

        fn name(&self) -> String {
            self.rendered_name.clone()
        }

        fn qualification(&self) -> Option<&dyn MdQualification> {
            Some(&self.qualification)
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered_name);
        }
    }

    struct MockNestedName {
        object: MockObjectCpp,
    }

    impl MdNestedName for MockNestedName {
        fn nested_object(&self) -> &dyn MdObjectCpp {
            &self.object
        }

        fn mangled(&self) -> &str {
            "?mocked@@"
        }
    }

    /// Faithful field-based mock relying on [`MdQualifier`]'s real default `insert`/`is_anon`/
    /// `is_nested` dispatch (rather than overriding them), so tests exercise the actual dispatch
    /// logic `recurse_qualification` depends on.
    #[derive(Default)]
    struct MockQualifier {
        name: Option<MockReusableName>,
        name_anonymous: Option<MockReusableName>,
        name_nested: Option<MockNestedName>,
    }

    impl MdQualifier for MockQualifier {
        fn name(&self) -> Option<&dyn MdReusableName> {
            self.name.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn template_name(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn name_anonymous(&self) -> Option<&dyn MdReusableName> {
            self.name_anonymous.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn name_interface(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn name_nested(&self) -> Option<&dyn MdNestedName> {
            self.name_nested.as_ref().map(|n| n as &dyn MdNestedName)
        }

        fn name_numbered(&self) -> Option<&dyn MdNumberedNamespaceLike> {
            None
        }

        fn name_q(&self) -> Option<&dyn MdQualification> {
            None
        }

        fn name_c(&self) -> Option<&dyn MdFragmentNameLike> {
            None
        }
    }

    fn plain_qual(rendered: &str) -> Box<dyn MdQualifier> {
        Box::new(MockQualifier {
            name: Some(MockReusableName { rendered: rendered.to_string() }),
            ..Default::default()
        })
    }

    fn anon_qual(anon_source: &str) -> Box<dyn MdQualifier> {
        Box::new(MockQualifier {
            name_anonymous: Some(MockReusableName { rendered: anon_source.to_string() }),
            ..Default::default()
        })
    }

    fn nested_qual(nested: MockNestedName) -> Box<dyn MdQualifier> {
        Box::new(MockQualifier { name_nested: Some(nested), ..Default::default() })
    }

    #[derive(Default)]
    struct MockQualification {
        quals: Vec<Box<dyn MdQualifier>>,
    }

    impl MdQualification for MockQualification {
        fn qualifiers(&self) -> &[Box<dyn MdQualifier>] {
            &self.quals
        }
    }

    struct MockQualifiedName {
        name: String,
        qualification: MockQualification,
    }

    impl MdQualifiedNameLike for MockQualifiedName {
        fn name(&self) -> String {
            self.name.clone()
        }

        fn qualification(&self) -> &dyn MdQualification {
            &self.qualification
        }
    }

    struct MockComplexType {
        namespace: MockQualifiedName,
    }

    impl MdComplexTypeLike for MockComplexType {
        fn namespace(&self) -> &dyn MdQualifiedNameLike {
            &self.namespace
        }
    }

    #[derive(Default)]
    struct MockParsableItem {
        complex: Option<MockComplexType>,
        object_cpp: Option<MockObjectCpp>,
        modifier_referenced: Option<Box<MockParsableItem>>,
    }

    impl MdParsableItemLike for MockParsableItem {
        fn as_modifier_referenced_item(&self) -> Option<&dyn MdParsableItemLike> {
            self.modifier_referenced.as_deref().map(|i| i as &dyn MdParsableItemLike)
        }

        fn as_complex_type(&self) -> Option<&dyn MdComplexTypeLike> {
            self.complex.as_ref().map(|c| c as &dyn MdComplexTypeLike)
        }

        fn as_object_cpp_embedded(&self) -> Option<&dyn MdObjectCpp> {
            self.object_cpp.as_ref().map(|o| o as &dyn MdObjectCpp)
        }
    }

    fn complex_item(name: &str, quals: Vec<Box<dyn MdQualifier>>) -> MockParsableItem {
        MockParsableItem {
            complex: Some(MockComplexType {
                namespace: MockQualifiedName {
                    name: name.to_string(),
                    qualification: MockQualification { quals },
                },
            }),
            ..Default::default()
        }
    }

    #[test]
    fn get_symbol_path_walks_qualifiers_root_first() {
        // quals[0] is innermost, quals[last] is the namespace root -- see MdQualification.
        let item = complex_item("MyClass", vec![plain_qual("Bar"), plain_qual("Foo")]);
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        let path = utils.get_symbol_path(&dmang, &item).expect("non-empty path");

        assert_eq!(path.path(), "Foo::Bar::MyClass");
        assert_eq!(
            path.as_list(),
            vec!["Foo".to_string(), "Bar".to_string(), "MyClass".to_string()]
        );
    }

    #[test]
    fn get_symbol_path_returns_none_for_unrecognized_item() {
        let item = MockParsableItem::default();
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        assert!(utils.get_symbol_path(&dmang, &item).is_none());
    }

    #[test]
    fn anonymous_qualifier_renders_standardized_node() {
        let item = complex_item("Widget", vec![anon_qual("A0xdeadbeef")]);
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        let path = utils.get_symbol_path(&dmang, &item).unwrap();

        assert_eq!(path.path(), "_anon_DEADBEEF::Widget");
    }

    #[test]
    fn nested_qualifier_is_recursed_only_when_requested() {
        let nested = MockNestedName {
            object: MockObjectCpp {
                rendered_name: "Inner".to_string(),
                qualification: MockQualification { quals: vec![plain_qual("Outer")] },
            },
        };
        let item = complex_item("Leaf", vec![nested_qual(nested)]);
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        let simple_path = utils.get_simple_symbol_path(&dmang, &item).unwrap();
        assert_eq!(simple_path.path(), "Outer::Inner::Leaf");

        // With recurse_nested = false (get_symbol_path), the nested qualifier is rendered via its
        // own insert() (the toString()-equivalent) instead of being recursed into.
        let non_simple_path = utils.get_symbol_path(&dmang, &item).unwrap();
        assert_eq!(non_simple_path.path(), "`Inner'::Leaf");
    }

    #[test]
    fn consolidate_symbol_path_prefers_demangled_parts_and_falls_back_to_regular() {
        let item = complex_item("MyClass", vec![plain_qual("Bar")]);
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        let consolidated =
            utils.consolidate_symbol_path(&dmang, &item, "Outer::Bar::MyClass", false).unwrap();

        assert_eq!(consolidated.path(), "Outer::Bar::MyClass");
    }

    #[test]
    fn consolidate_symbol_path_falls_back_to_demangled_when_regular_path_is_empty() {
        let item = complex_item("MyClass", vec![plain_qual("Bar")]);
        let dmang = MockMdMang;
        let utils = DefaultMdMangUtils;

        let consolidated = utils.consolidate_symbol_path(&dmang, &item, "", false).unwrap();

        assert_eq!(consolidated.path(), "Bar::MyClass");
    }

    #[test]
    fn create_standard_anonymous_namespace_node_zero_pads_and_upper_cases() {
        let utils = DefaultMdMangUtils;

        assert_eq!(utils.create_standard_anonymous_namespace_node("A0xdeadbeef"), "_anon_DEADBEEF");
        assert_eq!(utils.create_standard_anonymous_namespace_node("`a"), "_anon_0000000A");
        assert_eq!(utils.create_standard_anonymous_namespace_node("unrecognized"), "unrecognized");
    }

    #[test]
    fn create_standard_local_namespace_node_formats_with_prefix() {
        let utils = DefaultMdMangUtils;

        assert_eq!(utils.create_standard_local_namespace_node("2"), "__l2");
    }

    #[test]
    fn standardize_symbol_path_ticks_converts_local_namespace_form() {
        let path = SymbolPathNode::from_names(vec!["Outer".to_string(), "__l2".to_string()]).unwrap();
        let utils = DefaultMdMangUtils;

        let standardized = utils.standardize_symbol_path_ticks(&path);

        assert_eq!(standardized.path(), "Outer::`2'");
    }

    #[test]
    fn standardize_symbol_path_underscores_converts_tick_form() {
        let path = SymbolPathNode::from_names(vec!["Outer".to_string(), "`2'".to_string()]).unwrap();
        let utils = DefaultMdMangUtils;

        let standardized = utils.standardize_symbol_path_underscores(&path);

        assert_eq!(standardized.path(), "Outer::__l2");
    }

    #[test]
    fn strip_tags_collapses_class_struct_and_calling_convention_tags() {
        assert_eq!(strip_tags("Foo<class Bar>"), "Foo<Bar>");
        assert_eq!(strip_tags("Foo(struct Bar)"), "Foo(Bar)");
        assert_eq!(strip_tags("int * __ptr64"), "int *");
    }

    #[test]
    fn trait_object_is_usable() {
        let item = complex_item("MyClass", vec![]);
        let dmang = MockMdMang;
        let utils: &dyn MdMangUtils = &DefaultMdMangUtils;

        let path = utils.get_symbol_path(&dmang, &item).unwrap();

        assert_eq!(path.path(), "MyClass");
    }
}
