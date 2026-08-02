//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::demangler::object::md_object_cpp::MdObjectCpp;

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

    /// Appends `s` to the end of `builder`, dropping a duplicate boundary space where the
    /// existing content already ends with one and `s` starts with one.
    ///
    /// Mirrors `MDMang.appendString(StringBuilder, String)`. Provided as a default (unlike
    /// [`MdMangLike::insert_string`]/[`MdMangLike::insert_spaced_string`]) since the original is
    /// never overridden by any `MDMang` subclass.
    fn append_string(&self, builder: &mut String, s: &str) {
        if !builder.is_empty() && !s.is_empty() && builder.ends_with(' ') && s.starts_with(' ') {
            builder.pop();
        }
        builder.push_str(s);
    }

    /// Returns whether anonymous-namespace qualifiers should render as the encoded
    /// `_anon_XXXXXXXX` form rather than the literal `` `anonymous namespace' `` text.
    ///
    /// Mirrors `dmang.getOutputOptions().useEncodedAnonymousNamespace()`, collapsed directly onto
    /// this seam since `MDMangOutputOptions` is not ported. Defaults to `false` (the literal-text
    /// form) so existing implementors are unaffected.
    fn use_encoded_anonymous_namespace(&self) -> bool {
        false
    }

    /// Returns whether a namespace qualification should render via the VS2015-style "all
    /// brackets" form (no unconditional trailing bracket) rather than the base "MD version" form.
    ///
    /// Mirrors the choice between `MDMang.insert(StringBuilder, MDQualification)` (which calls
    /// `insert_MdVersion`) and the `MDMangVS2015` override (which calls `insert_VSAll`). Defaults
    /// to `false` (the base `MDMang` behavior) so existing implementors are unaffected.
    fn use_vs_all_qualification(&self) -> bool {
        false
    }
}

/// Placeholder for `mdemangler.naming.MDNumberedNamespace`, needed by
/// [`crate::demangler::naming::md_qualifier::MdQualifier`].
///
/// Only the members `MDQualifier`'s ported (non-parsing) surface touches (`getName`,
/// `getNumber().toString()`, `insert`) are declared here; the real port also carries the
/// `MDEncodedNumber` parsing logic.
pub trait MdNumberedNamespaceLike {
    /// Returns the rendered name: the encoded number wrapped in the tick-mark convention.
    ///
    /// Mirrors `MDNumberedNamespace.getName()`.
    fn name(&self) -> String;

    /// Returns the rendered encoded number.
    ///
    /// Mirrors `MDNumberedNamespace.getNumber().toString()`.
    fn number_string(&self) -> String;

    /// Inserts the rendered name into `builder`.
    ///
    /// Mirrors `MDNumberedNamespace.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
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

/// Placeholder for `mdemangler.naming.MDQualifiedBasicName`, needed by
/// [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// Only the members `MDObjectCPP`'s ported (non-parsing) surface touches (`getBasicName`,
/// `getQualification`, `isString`, `getMDString`, `insert`) are declared here; the real port also
/// carries the RTTI-number/type-cast/name-modifier parsing surface.
pub trait MdQualifiedBasicNameLike {
    /// Returns the basic (innermost, unqualified) name component.
    ///
    /// Mirrors `MDQualifiedBasicName.getBasicName()`.
    fn basic_name(&self) -> &dyn MdBasicNameLike;

    /// Returns the namespace-qualification component.
    ///
    /// Mirrors `MDQualifiedBasicName.getQualification()`.
    fn qualification(&self) -> &dyn MdQualificationLike;

    /// Returns whether the basic name is an [`MdStringLike`] literal.
    ///
    /// Mirrors `MDQualifiedBasicName.isString()`.
    fn is_string(&self) -> bool;

    /// Returns the string literal, when [`MdQualifiedBasicNameLike::is_string`] is `true`.
    ///
    /// Mirrors `MDQualifiedBasicName.getMDString()`.
    fn md_string(&self) -> Option<&dyn MdStringLike>;

    /// Inserts the rendered qualified name into `builder`.
    ///
    /// Mirrors `MDQualifiedBasicName.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
}

/// Placeholder for `mdemangler.naming.MDBasicName`, needed by
/// [`MdQualifiedBasicNameLike`] and, transitively,
/// [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// Only the two members `MDObjectCPP`'s ported surface touches (`getEmbeddedObject`, `toString`)
/// are declared here; the real port carries the full basic-name variant hierarchy.
pub trait MdBasicNameLike {
    /// Returns the embedded object if there is one, else the object that owns this basic name.
    ///
    /// Mirrors `MDBasicName.getEmbeddedObject()`.
    fn embedded_object(&self) -> &dyn MdObjectCpp;

    /// Returns the rendered display text of this basic name.
    ///
    /// Mirrors `MDBasicName.toString()`.
    fn to_display_string(&self) -> String;
}

/// Placeholder for `mdemangler.naming.MDQualification`, needed by
/// [`MdQualifiedBasicNameLike`] and [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// `MDObjectCPP`'s ported surface only ever passes this type through (`getQualification`), never
/// calling a member on it, so no methods are declared yet.
pub trait MdQualificationLike {}

/// Placeholder for `mdemangler.MDString`, needed by [`MdQualifiedBasicNameLike`] and
/// [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// `MDObjectCPP`'s ported surface only ever passes this type through (`getMDString`), never
/// calling a member on it, so no methods are declared yet.
pub trait MdStringLike {}

/// Placeholder for `mdemangler.typeinfo.MDTypeInfo`, needed by
/// [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// Only `insert` -- the one member `MDObjectCPP.insert(StringBuilder)` calls -- is declared here;
/// the real port also carries `getMDType`/`setTypeCast`/`parse` and the RTTI-driven parse dispatch
/// (`MDTypeInfoParser`).
pub trait MdTypeInfoLike {
    /// Inserts the rendered type info into `builder`.
    ///
    /// Mirrors `MDTypeInfo.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
}
