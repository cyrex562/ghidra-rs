//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `mdemangler.MDMang`, needed by
/// [`crate::demangler::datatype::md_data_type::MdDataType`].
///
/// `MDMang` is the demangler driver/worker every `MDParsableItem` (including `MDDataType`, via
/// its `MDType`/`MDParsableItem` ancestors) carries a reference to. Only the two `StringBuilder`
/// insertion helpers `MDDataType.insert` calls are declared here; the real port carries the full
/// parse-and-emit driver.
pub trait MdMangLike {
    /// Inserts `s` at the front of `builder`, dropping a duplicate leading space where the
    /// existing content already starts with one and `s` ends with one.
    ///
    /// Mirrors `MDMang.insertString(StringBuilder, String)`.
    fn insert_string(&self, builder: &mut String, s: &str);

    /// Inserts `s` at the front of `builder`, normalizing the boundary so the two pieces are
    /// separated by exactly one space.
    ///
    /// Mirrors `MDMang.insertSpacedString(StringBuilder, String)`.
    fn insert_spaced_string(&self, builder: &mut String, s: &str);
}

/// Placeholder for `mdemangler.naming.MDFragmentName`, needed by
/// [`crate::demangler::naming::md_reusable_name::MdReusableName`].
///
/// Only the members `MDReusableName` touches (`getName`/`setName`/`insert`) are declared here;
/// the real port also carries the parsing logic (`parseInternal`, `parseFragmentName_*`).
pub trait MdFragmentNameLike {
    /// Returns the fragment's name text.
    ///
    /// Mirrors `MDFragmentName.getName()`.
    fn get_name(&self) -> String;

    /// Sets the fragment's name text.
    ///
    /// Mirrors `MDFragmentName.setName(String)`.
    fn set_name(&mut self, name: String);

    /// Inserts the fragment's rendered text into `builder`.
    ///
    /// Mirrors `MDFragmentName.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
}

/// Placeholder for `mdemangler.template.MDTemplateNameAndArguments`, needed by
/// [`crate::demangler::naming::md_reusable_name::MdReusableName`].
///
/// Only the members `MDReusableName` touches (`getName`/`insert`) are declared here; the real
/// port also carries constructor/destructor/type-cast queries and the arguments list.
pub trait MdTemplateNameAndArgumentsLike {
    /// Returns the template's name text.
    ///
    /// Mirrors `MDTemplateNameAndArguments.getName()`.
    fn get_name(&self) -> String;

    /// Inserts the template's rendered text (name and arguments) into `builder`.
    ///
    /// Mirrors `MDTemplateNameAndArguments.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
}
