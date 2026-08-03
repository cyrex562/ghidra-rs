//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::naming::md_qualified_name::MdQualifiedName;
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

    /// Truncates `builder` at the first embedded NUL character, if any.
    ///
    /// Mirrors `MDMang.cleanOutput(StringBuilder)`, added to clean up the lone-NUL sentinel
    /// mimicking the MSFT "based5 bug" (see [`crate::demangler::datatype::modifier::md_based_attribute`]).
    /// Given a real, deterministic default here (not overridden by any `MDMang` subclass), unlike
    /// the option-flag methods above.
    fn clean_output(&self, builder: &mut String) {
        if let Some(pos) = builder.find('\0') {
            builder.truncate(pos);
        }
    }

    /// Inserts the rendered CLI-array reference clause `ref_text` into `builder`, space-separated.
    ///
    /// Mirrors `MDMang.insertCLIArrayRefSuffix(StringBuilder, StringBuilder)`. Given a real
    /// default here (delegates to [`MdMangLike::insert_spaced_string`], matching the base
    /// implementation) since no other override is reachable from this seam.
    fn insert_cli_array_ref_suffix(&self, builder: &mut String, ref_text: &str) {
        self.insert_spaced_string(builder, ref_text);
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
/// [`crate::demangler::naming::md_reusable_name::MdReusableName`] and
/// [`crate::demangler::naming::md_basic_name::MdBasicName`].
///
/// Originally only `getName`/`insert` (the members `MDReusableName` touches) were declared here;
/// [`MdBasicName`](crate::demangler::naming::md_basic_name::MdBasicName)'s ported surface also
/// touches the constructor/destructor/type-cast queries, so those are declared too. The real port
/// also carries the arguments list and the mutating setters (`setName`/`setXtorQual`/
/// `setCastTypeString`/`setCastType`).
pub trait MdTemplateNameAndArgumentsLike {
    /// Returns the template's name text.
    ///
    /// Mirrors `MDTemplateNameAndArguments.getName()`.
    fn get_name(&self) -> String;

    /// Returns whether this template name represents a constructor.
    ///
    /// Mirrors `MDTemplateNameAndArguments.isConstructor()`.
    fn is_constructor(&self) -> bool;

    /// Returns whether this template name represents a destructor.
    ///
    /// Mirrors `MDTemplateNameAndArguments.isDestructor()`.
    fn is_destructor(&self) -> bool;

    /// Returns whether this template name represents a type-cast operator.
    ///
    /// Mirrors `MDTemplateNameAndArguments.isTypeCast()`.
    fn is_type_cast(&self) -> bool;

    /// Inserts the template's rendered text (name and arguments) into `builder`.
    ///
    /// Mirrors `MDTemplateNameAndArguments.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);
}

/// Placeholder for `mdemangler.naming.MDSpecialName`, needed by
/// [`crate::demangler::naming::md_basic_name::MdBasicName`].
///
/// Only the members `MDBasicName`'s ported (non-parsing) surface touches (`isConstructor`,
/// `isDestructor`, `isTypeCast`, `getRTTINumber`, `isString`, `getMDString`, `getName`, `insert`)
/// are declared here; the real port also carries the mutating setters (`setName`/`setXtorQual`/
/// `setCastTypeString`/`setCastType`) and the full RTTI/operator-name parse dispatch.
pub trait MdSpecialNameLike {
    /// Returns whether this special name represents a constructor.
    ///
    /// Mirrors `MDSpecialName.isConstructor()`.
    fn is_constructor(&self) -> bool;

    /// Returns whether this special name represents a destructor.
    ///
    /// Mirrors `MDSpecialName.isDestructor()`.
    fn is_destructor(&self) -> bool;

    /// Returns whether this special name represents a type-cast operator.
    ///
    /// Mirrors `MDSpecialName.isTypeCast()`.
    fn is_type_cast(&self) -> bool;

    /// Returns the RTTI number: `{0-4, or -1 if not an RTTI}`.
    ///
    /// Mirrors `MDSpecialName.getRTTINumber()`.
    fn rtti_number(&self) -> i32;

    /// Returns whether this special name is a string literal.
    ///
    /// Mirrors `MDSpecialName.isString()`.
    fn is_string(&self) -> bool;

    /// Returns the string literal, when [`MdSpecialNameLike::is_string`] is `true`.
    ///
    /// Mirrors `MDSpecialName.getMDString()`.
    fn md_string(&self) -> Option<&dyn MdStringLike>;

    /// Returns the rendered name text.
    ///
    /// Mirrors `MDSpecialName.getName()`.
    fn name(&self) -> String;

    /// Inserts the rendered text of this special name into `builder`.
    ///
    /// Mirrors `MDSpecialName.insert(StringBuilder)`.
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
    fn qualification(&self) -> &dyn MdQualification;

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

/// Placeholder for `mdemangler.MDString`, needed by [`MdQualifiedBasicNameLike`] and
/// [`crate::demangler::object::md_object_cpp::MdObjectCpp`].
///
/// `MDObjectCPP`'s ported surface only ever passes this type through (`getMDString`), never
/// calling a member on it, so no methods are declared yet.
pub trait MdStringLike {}

/// Placeholder for `mdemangler.datatype.MDDataType`, needed by
/// [`crate::demangler::naming::md_basic_name::MdBasicName`].
///
/// `MDBasicName`'s ported surface only ever passes this type through (`setCastType`), never
/// calling a member on it, so no methods are declared yet. Note: a full port already exists on
/// disk at `crate::demangler::datatype::md_data_type` (as `MdDataType`), but it isn't wired into
/// `datatype::mod` or marked `DONE` in `PORT_MANIFEST.tsv`, so it isn't reachable from this
/// crate; wiring it up is out of scope for this port.
pub trait MdDataTypeLike {}

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

/// Placeholder for `mdemangler.datatype.modifier.MDCVMod`, needed by
/// [`crate::demangler::datatype::modifier::md_modifier_type::MdModifierType`].
///
/// Only the members `MDModifierType`'s ported (non-parsing) surface touches -- the const/
/// volatile/pointer/reference/array/CLI-array/pin-pointer query flags, the based-name/
/// member-scope accessors, and the render-side `insert`/managed-properties helpers -- are
/// declared here; the real port also carries the parse dispatch (`parseInternal`,
/// `parseManagedProperty`, ...) and the `isFunction`/`getThisPointerMDCVMod` pair
/// `MDModifierType.parseInternal` uses, which is out of scope for the same reason parsing is
/// (see [`crate::demangler::datatype::modifier::md_modifier_type`]).
pub trait MdCvModLike {
    /// Returns whether this modifier is a `__ptr64` pointer.
    ///
    /// Mirrors `MDCVMod.isPointer64()`.
    fn is_pointer64(&self) -> bool;

    /// Returns whether this modifier is `__restrict`.
    ///
    /// Mirrors `MDCVMod.isRestricted()`.
    fn is_restricted(&self) -> bool;

    /// Returns whether this modifier is `__unaligned`.
    ///
    /// Mirrors `MDCVMod.isUnaligned()`.
    fn is_unaligned(&self) -> bool;

    /// Returns the rendered `__based(...)` clause name, if this modifier is based.
    ///
    /// Mirrors `MDCVMod.getBasedName()`.
    fn based_name(&self) -> Option<&str>;

    /// Returns the rendered member-pointer scope qualification, if this modifier is a
    /// pointer-to-member.
    ///
    /// Mirrors `MDCVMod.getMemberScope()`.
    fn member_scope(&self) -> Option<&str>;

    /// Returns whether this modifier is a CLI array (`cli::array<T>`).
    ///
    /// Mirrors `MDCVMod.isCLIArray()`.
    fn is_cli_array(&self) -> bool;

    /// Returns whether this modifier is a plain pointer (`*`).
    ///
    /// Mirrors `MDCVMod.isPointerType()`.
    fn is_pointer_type(&self) -> bool;

    /// Returns whether this modifier is a function pointer.
    ///
    /// Mirrors `MDCVMod.isFunctionPointerType()`.
    fn is_function_pointer_type(&self) -> bool;

    /// Returns whether this modifier is a reference (`&`).
    ///
    /// Mirrors `MDCVMod.isReferenceType()`.
    fn is_reference_type(&self) -> bool;

    /// Returns whether this modifier is a function reference.
    ///
    /// Mirrors `MDCVMod.isFunctionReferenceType()`.
    fn is_function_reference_type(&self) -> bool;

    /// Returns whether this modifier is an array.
    ///
    /// Mirrors `MDCVMod.isArrayType()`.
    fn is_array_type(&self) -> bool;

    /// Returns whether this modifier is a CLI pin pointer (`cli::pin_ptr<T>`).
    ///
    /// Mirrors `MDCVMod.isPinPointer()`.
    fn is_pin_pointer(&self) -> bool;

    /// Returns whether this modifier is the placeholder "question type" (unresolved/unknown
    /// modifier kind) set by the `MDModifierType` constructors before parsing runs.
    ///
    /// Mirrors `MDCVMod.isQuestionType()`.
    fn is_question_type(&self) -> bool;

    /// Inserts the rendered modifier text (GC/EI prefix, mod-type keyword, `F`/CV suffix) at the
    /// front of `builder`, space-separated.
    ///
    /// Mirrors `MDCVMod.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);

    /// Inserts this modifier's managed-properties prefix clause (e.g. `cli::array<`) at the
    /// front of `builder`.
    ///
    /// Mirrors `MDCVMod.insertManagedPropertiesPrefix(StringBuilder)`.
    fn insert_managed_properties_prefix(&self, dmang: &dyn MdMangLike, builder: &mut String);

    /// Appends this modifier's managed-properties suffix clause (e.g. `>`/`^`) to `builder`.
    ///
    /// Mirrors `MDCVMod.insertManagedPropertiesSuffix(StringBuilder)`.
    fn insert_managed_properties_suffix(&self, dmang: &dyn MdMangLike, builder: &mut String);
}

/// Placeholder for `mdemangler.MDType`, needed by
/// [`crate::demangler::datatype::modifier::md_modifier_type::MdModifierType`].
///
/// `MDType` is the base of every referenceable type `MDModifierType` wraps (via its `refType`
/// field). Only the members `MDModifierType`'s ported (non-parsing) surface touches -- rendering
/// (`insert`, and `MDDataType.insertAsArg` for the `instanceof MDDataType` case), and the three
/// `instanceof` type tests against still-unported sibling types (`MDFunctionType`,
/// `MDArrayReferencedType`, `MDVoidDataType`) -- are declared here, standing in for Rust's lack of
/// downcasting on trait objects. The real port also carries the full parse dispatch and the
/// concrete type hierarchy these query methods currently approximate.
pub trait MdTypeLike {
    /// Inserts this type's rendered text into `builder`.
    ///
    /// Mirrors `MDType.insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String);

    /// Inserts this type's rendered text into `builder`, as though it is a template or function
    /// argument.
    ///
    /// Mirrors `MDDataType.insertAsArg(StringBuilder)`, which most concrete `MDDataType`s never
    /// override (see the identical default on
    /// [`crate::demangler::datatype::md_data_type::MdDataType::insert_as_arg`]). Only reachable
    /// via [`MdTypeLike::is_data_type`] returning `true`, mirroring the `refType instanceof
    /// MDDataType` guard in the original.
    fn insert_as_arg(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        self.insert(dmang, builder);
    }

    /// Returns whether this type is (also) an `MDDataType`.
    ///
    /// Stands in for the `refType instanceof MDDataType` check guarding whether
    /// [`MdTypeLike::insert_as_arg`] is used at all, since Rust trait objects can't be downcast.
    fn is_data_type(&self) -> bool;

    /// Returns whether this type is an `MDFunctionType`.
    ///
    /// Stands in for `refType instanceof MDFunctionType`.
    fn is_function_type(&self) -> bool;

    /// Returns whether this type is an `MDArrayReferencedType`.
    ///
    /// Stands in for `refType instanceof MDArrayReferencedType`.
    fn is_array_referenced_type(&self) -> bool;

    /// Returns whether this type is an `MDVoidDataType`.
    ///
    /// Stands in for `refType instanceof MDVoidDataType`.
    fn is_void_data_type(&self) -> bool;

    /// Marks this type as reached via a modifier (pointer/reference/array) rather than
    /// standalone, affecting how an `MDFunctionType` renders its calling convention.
    ///
    /// Mirrors `MDFunctionType.setFromModifier()`. Only ever invoked when
    /// [`MdTypeLike::is_function_type`] is `true`; given a no-op default since non-function
    /// implementors have nothing to record. `MDFunctionType.insert` mutates during rendering in
    /// the original too, so a real implementor is expected to use interior mutability to honor
    /// this `&self` signature.
    fn mark_from_modifier(&self) {}
}

/// Placeholder for `mdemangler.MDParsableItem`, needed by
/// [`crate::demangler::md_mang_utils::MdMangUtils`].
///
/// `MDParsableItem` is the abstract base of every parse result `MDMangUtils` walks
/// (`MDComplexType` via `MDType`/`MDDataType`, `MDObjectCPP` via `MDObject`, and `MDModifierType`
/// via `MDType`), none of which share a common Rust base trait -- each was ported independently as
/// its own dependency-cycle cut-point, with no supertrait relationship among them. Rather than
/// retrofit one onto those existing, tested ports, this placeholder models exactly the three
/// `instanceof` dispatches `MDMangUtils.recurseNamespace`/`getReferencedType` perform, as
/// downcast-style accessors (the same pattern used by [`MdTypeLike`]'s
/// `is_function_type`/`is_data_type`/... query methods).
pub trait MdParsableItemLike {
    /// `Some(referenced)` when this item is an `MDModifierType`, giving its
    /// `getReferencedType()` (already unwrapped one level).
    ///
    /// Mirrors the `instanceof MDModifierType` branch of the private
    /// `MDMangUtils.getReferencedType(MDParsableItem)`.
    fn as_modifier_referenced_item(&self) -> Option<&dyn MdParsableItemLike> {
        None
    }

    /// `Some(complex)` when this item is an `MDComplexType`.
    ///
    /// Mirrors the `instanceof MDComplexType` branch of the private
    /// `MDMangUtils.recurseNamespace`.
    fn as_complex_type(&self) -> Option<&dyn MdComplexTypeLike> {
        None
    }

    /// `Some(embedded)` when this item is an `MDObjectCPP`, already resolved via
    /// `getEmbeddedObject()`.
    ///
    /// Mirrors the `instanceof MDObjectCPP` branch of the private `MDMangUtils.recurseNamespace`,
    /// pre-resolved because `MDObjectCPP.getEmbeddedObject()` requires `Self: Sized` (see
    /// [`MdObjectCpp::embedded_object`]) and so can't be called through this trait's object-safe
    /// accessors.
    fn as_object_cpp_embedded(&self) -> Option<&dyn MdObjectCpp> {
        None
    }
}

/// Placeholder for `mdemangler.datatype.complex.MDComplexType`, needed by
/// [`MdParsableItemLike`] and, transitively,
/// [`crate::demangler::md_mang_utils::MdMangUtils`].
///
/// Only `getNamespace()` -- the one member `MDMangUtils.recurseNamespace` touches -- is declared
/// here; the real port also carries the full complex-type (class/struct/union/enum/coclass/
/// cointerface) parse-and-render surface inherited from `MDDataType`/`MDType`. Unlike sibling
/// placeholders, no seam is needed for `getNamespace()`'s return type: `MDQualifiedName` is
/// already ported for real as [`MdQualifiedName`].
pub trait MdComplexTypeLike {
    /// Returns the namespace-qualified name of this complex type.
    ///
    /// Mirrors `MDComplexType.getNamespace()`.
    fn namespace(&self) -> &dyn MdQualifiedName;
}

/// Placeholder for `mdemangler.MDException`, needed by
/// [`crate::demangler::md_mang_genericize::MdMangGenericize`].
///
/// `MDException` carries three distinct payload shapes (wrapped cause, message, or an
/// `invalidMangledName` flag), none of which `MDMangGenericize`'s ported surface ever inspects --
/// it only ever propagates instances of this type through `Result`. So only the standard
/// `Debug`/`Display` bounds needed to use it as an error type are declared here; the real port
/// also carries the three constructors and `isInvalidMangledName()`.
pub trait MdExceptionLike: std::fmt::Debug + std::fmt::Display {}

/// Placeholder for `mdemangler.object.MDMangObjectParser`, needed by
/// [`crate::demangler::md_mang_genericize::MdMangGenericize::demangle`].
///
/// `MDMangObjectParser.determineItemAndParse(MDMang)` requires the full (unported) `MDMang`
/// grammar-dispatch surface (`setProcessingMode`, `resetState`, and the entire type/name parse
/// dispatch) to implement for real. Rather than reproduce that surface here, its single call site
/// is collapsed directly onto the required
/// [`MdMangGenericize::parse_item`](crate::demangler::md_mang_genericize::MdMangGenericize::parse_item)
/// method, which a concrete implementor supplies; this marker trait exists only to document that
/// collapse, mirroring the no-method [`MdStringLike`] placeholder above.
pub trait MdMangObjectParserLike {}
