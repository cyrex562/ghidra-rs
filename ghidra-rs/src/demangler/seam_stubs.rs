//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::naming::md_qualified_name::MdQualifiedName;
use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::program::model::symbol::{Namespace, DELIMITER};

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

    /// Returns whether a complex (class/struct/union/enum/coclass/cointerface) type used as a
    /// template or function argument should have its `insertAsArg` render the trailing signedness
    /// tag inherited from `MDDataType`.
    ///
    /// Mirrors `dmang.getOutputOptions().applyUdtArgumentTypeTag()`, collapsed directly onto this
    /// seam since `MDMangOutputOptions` is not ported (see [`MdMangLike::use_encoded_anonymous_namespace`]
    /// for the same treatment of another output option). Defaults to `true`, matching
    /// `MDOutputOptions.DEFAULT_APPLY_UDT_TAG`.
    fn apply_udt_argument_type_tag(&self) -> bool {
        true
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
/// [`crate::demangler::naming::md_basic_name::MdBasicName`] and
/// [`crate::demangler::datatype::complex::md_complex_type::MdComplexType`].
///
/// `MDBasicName`'s ported surface only ever passes this type through (`setCastType`), never
/// calling a member on it. `MDComplexType` (`MDDataType`'s subclass) needs its inherited
/// signedness state to mirror `super.insert(StringBuilder)`, so the two query methods backing
/// that -- `isSpecifiedSigned`/`isUnsigned` -- are declared too. Note: a full port already exists
/// on disk at `crate::demangler::datatype::md_data_type` (as `MdDataType`), but it isn't wired
/// into `datatype::mod` or marked `DONE` in `PORT_MANIFEST.tsv`, so it isn't reachable from this
/// crate; wiring it up is out of scope for this port.
pub trait MdDataTypeLike {
    /// True once `MDDataType.setSigned()` was explicitly called.
    ///
    /// Mirrors `MDDataType.isSpecifiedSigned()`.
    fn is_specified_signed(&self) -> bool;

    /// True once `MDDataType.setUnsigned()` was called.
    ///
    /// Mirrors `MDDataType.isUnsigned()`.
    fn is_unsigned(&self) -> bool;

    /// Returns the rendered display text of this data type.
    ///
    /// Mirrors `MDDataType.toString()` (inherited from `MDParsableItem`), needed by
    /// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`]. Given a
    /// placeholder default (empty string), the same treatment as
    /// [`MdParsableItemLike::to_string`] and for the same reason.
    fn to_string(&self) -> String {
        String::new()
    }
}

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

    /// Returns the rendered display text of this parsed item.
    ///
    /// Mirrors `MDParsableItem.toString()`, needed by
    /// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`]. Given a
    /// placeholder default (empty string) rather than a required method, so this addition doesn't
    /// disturb any existing implementor of this trait; the real port renders through the full
    /// `insert`/`append` StringBuilder machinery.
    fn to_string(&self) -> String {
        String::new()
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
/// already ported for real as [`MdQualifiedName`]. Note: a full (parsing aside) port of
/// `MDComplexType` now exists as
/// [`MdComplexType`](crate::demangler::datatype::complex::md_complex_type::MdComplexType), but
/// rewiring `MdParsableItemLike`/`MdMangUtils` onto it is out of scope for that port.
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

/// Placeholder for `ghidra.app.util.demangler.DemangledTemplate`, needed by
/// [`crate::demangler::demangled_type::DemangledType`].
///
/// Java is a concrete class, not an interface, so this is a plain struct rather than a trait.
/// The real class collects `DemangledDataType` parameters and renders each via `getSignature()`;
/// `DemangledDataType` is not yet ported, so this stub instead stores each parameter's
/// already-rendered signature text directly. Only the members `DemangledType` needs
/// (`addParameter`, `toTemplate`) are modeled; the real port also carries `getParameters()` and
/// `getDataType(int)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemangledTemplate {
    parameters: Vec<String>,
}

impl DemangledTemplate {
    /// Adds a parameter's rendered signature text.
    ///
    /// Mirrors `addParameter(DemangledDataType)`, collapsed onto the already-rendered
    /// `getSignature()` text since `DemangledDataType` is not yet ported.
    pub fn add_parameter(&mut self, parameter_signature: String) {
        self.parameters.push(parameter_signature);
    }

    /// Renders the template argument list, e.g. `<int,char>`.
    ///
    /// Mirrors `toTemplate()`.
    pub fn to_template(&self) -> String {
        let mut buffer = String::new();
        buffer.push('<');
        buffer.push_str(&self.parameters.join(","));
        buffer.push('>');
        buffer
    }
}

impl std::fmt::Display for DemangledTemplate {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_template())
    }
}

/// Placeholder for `ghidra.app.util.demangler.DemanglerUtil.stripSuperfluousSignatureSpaces`,
/// needed by [`crate::demangler::demangled_type::DemangledType::set_name`].
///
/// `DemanglerUtil` is a concrete class of static utility methods, not an interface, so this is a
/// plain free function rather than a trait; the rest of `DemanglerUtil`'s surface (the
/// `demangle(...)` overloads and `getDemanglers()`) is not modeled since nothing ported yet needs
/// it.
///
/// Removes superfluous function-signature spaces: the leading space before `*`/`&`/`)`, and the
/// trailing space after `(`/`,`.
pub fn strip_superfluous_signature_spaces(s: &str) -> String {
    let step1 = leading_parameter_space_pattern().replace_all(s, "$1");
    trailing_parameter_space_pattern().replace_all(&step1, "$1").into_owned()
}

fn leading_parameter_space_pattern() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r" ([*&)])").unwrap())
}

fn trailing_parameter_space_pattern() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"([(,]) ").unwrap())
}

/// Placeholder for `ghidra.app.util.NamespaceUtils.getNamespaceQualifiedName`, needed by
/// [`crate::demangler::demangled_object::DemangledObjectBase::create_namespace`].
///
/// `NamespaceUtils` is a concrete class of static utility methods, not an interface, so this is a
/// plain free function rather than a trait (the same treatment as
/// [`strip_superfluous_signature_spaces`] above); the rest of `NamespaceUtils` is not modeled
/// since nothing ported yet needs it.
///
/// Renders `symbol_name` prefixed by `namespace`'s full path, e.g. `Foo::Bar::baz`. The
/// original's third parameter, `excludeLibraryName`, is not modeled: its only caller here always
/// passes `false`, and the `true` branch needs the unported `getNamespacePathWithoutLibrary`.
pub fn namespace_qualified_name(namespace: &dyn Namespace, symbol_name: &str) -> String {
    let mut s = String::new();
    if !namespace.is_global() {
        s.push_str(&namespace.get_name_with_path(true));
        s.push_str(DELIMITER);
    }
    s.push_str(symbol_name);
    s
}

#[cfg(test)]
mod strip_superfluous_signature_spaces_tests {
    use super::strip_superfluous_signature_spaces;

    #[test]
    fn removes_spaces_around_parameter_punctuation() {
        // Only the space before `*`/`&`/`)` and the space after `(`/`,` are superfluous; the
        // space before `,` (from a preceding parameter) is left alone, matching Java.
        assert_eq!(
            strip_superfluous_signature_spaces("void foo (int * , char & )"),
            "void foo (int* ,char&)"
        );
    }

    #[test]
    fn leaves_unrelated_spaces_alone() {
        assert_eq!(strip_superfluous_signature_spaces("Foo Bar"), "Foo Bar");
    }
}

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

/// Placeholder for `ghidra.app.util.demangler.DemangledDataType`, needed by
/// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`].
///
/// `MicrosoftDemangler`'s ported surface only ever passes this type through (as the return type of
/// `demangleType`/`MicrosoftDemanglerUtil.convertToDemangledDataType`, via the `setMangledContext`
/// it inherits from [`crate::demangler::demangled::Demangled`]), never calling a
/// `DemangledDataType`-specific member, so no members beyond that supertrait are declared here; the
/// real port also carries the full pointer/array/signedness/template surface `DemangledDataType`
/// itself defines (see the much larger suggested stub for it in the dependency-context notes).
pub trait DemangledDataTypeLike: crate::demangler::demangled::Demangled {}

/// Placeholder for `ghidra.app.util.demangler.AbstractDemangledFunctionDefinitionDataType`,
/// referenced by `DemangledFunctionPointer`.
///
/// Java is an abstract base class with concrete subclasses like `DemangledFunctionPointer`.
/// This stub declares the public surface that `DemangledFunctionPointer` inherits and extends.
pub trait AbstractDemangledFunctionDefinitionDataType: DemangledDataTypeLike {
    fn get_signature(&self) -> String;
    fn set_return_type(&self, return_type: &dyn DemangledDataType);
    fn get_return_type(&self) -> Option<&dyn DemangledDataType>;
    fn set_calling_convention(&self, calling_convention: &str);
    fn get_calling_convention(&self) -> Option<&str>;
    fn set_modifier(&self, modifier: &str);
    fn is_const_pointer(&self) -> bool;
    fn set_const_pointer(&self);
    fn is_trailing_pointer64(&self) -> bool;
    fn set_trailing_pointer64(&self);
    fn is_trailing_unaligned(&self) -> bool;
    fn set_trailing_unaligned(&self);
    fn is_trailing_restrict(&self) -> bool;
    fn set_trailing_restrict(&self);
    fn add_parameter(&self, parameter: &dyn DemangledDataType);
    fn get_parameters(&self) -> Vec<&dyn DemangledDataType>;
    fn to_signature(&self, name: Option<&str>) -> String;
    fn get_pointer_levels(&self) -> i32;
    fn increment_pointer_levels(&self);
}

/// Placeholder for `ghidra.app.util.demangler.DemangledDataType`, used by
/// `AbstractDemangledFunctionDefinitionDataType`.
pub trait DemangledDataType: Send + Sync {
    fn get_signature(&self) -> String;
}

/// Placeholder for `mdemangler.MDOutputOptions`, needed by [`MdMangGhidra`].
///
/// Java is a concrete "quick stub" class in the original codebase (see its own doc comment: "Quick
/// stub for now. Full implementation was planned for another ticket"), not an interface, so this is
/// a plain struct rather than a trait -- the same treatment as [`DemangledTemplate`]. Only the two
/// members [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`] touches are
/// modeled.
#[derive(Debug, Clone, Copy)]
pub struct MdOutputOptions {
    use_encoded_anonymous_namespace: bool,
    apply_udt_argument_type_tag: bool,
}

impl Default for MdOutputOptions {
    /// Mirrors the field initializers `DEFAULT_USE_ANON_NS = false` /
    /// `DEFAULT_APPLY_UDT_TAG = true`.
    fn default() -> Self {
        Self { use_encoded_anonymous_namespace: false, apply_udt_argument_type_tag: true }
    }
}

impl MdOutputOptions {
    /// Mirrors `setUseEncodedAnonymousNamespace(boolean)`.
    pub fn set_use_encoded_anonymous_namespace(&mut self, use_encoded_number: bool) {
        self.use_encoded_anonymous_namespace = use_encoded_number;
    }

    /// Mirrors `useEncodedAnonymousNamespace()`.
    pub fn use_encoded_anonymous_namespace(&self) -> bool {
        self.use_encoded_anonymous_namespace
    }

    /// Mirrors `setApplyUdtArgumentTypeTag(boolean)`.
    pub fn set_apply_udt_argument_type_tag(&mut self, apply_udt_argument_type_tag: bool) {
        self.apply_udt_argument_type_tag = apply_udt_argument_type_tag;
    }

    /// Mirrors `applyUdtArgumentTypeTag()`.
    pub fn apply_udt_argument_type_tag(&self) -> bool {
        self.apply_udt_argument_type_tag
    }
}

/// Concrete error type backing [`MdMangGhidra`]'s [`MdExceptionLike`] results.
///
/// `mdemangler.MDException` itself is already modeled as the [`MdExceptionLike`] placeholder
/// trait (see its docs); this is a minimal, constructible implementor of that trait for
/// [`MdMangGhidra`]'s own internal use, standing in for `new MDException(String)`.
#[derive(Debug)]
struct MdMangError(String);

impl std::fmt::Display for MdMangError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MdExceptionLike for MdMangError {}

/// Placeholder for `mdemangler.MDMangGhidra`, needed by
/// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`].
///
/// Java is a concrete class (`MDMangGhidra extends MDMangVS2015 extends MDMang`), not an
/// interface, so this is a plain struct rather than a trait -- the same treatment as
/// [`DemangledTemplate`]. Models the members `MicrosoftDemangler` touches, including ones
/// inherited from `MDMang`/`MDMangVS2015` (`setMangledSymbol`, `setErrorOnRemainingChars`,
/// `setArchitectureSize`, `setIsFunction`, `getOutputOptions`). `MDMangGhidra`'s own
/// `demangleOnlyKnownPatterns` prefix filter is given a real, faithful implementation since it
/// doesn't depend on any unported type. The grammar dispatch behind it
/// (`MDMangObjectParser`/`MDDataTypeParser`, via the unported `MDMang`/`MDContext` chain -- see
/// [`crate::demangler::md_mang::MdMang`]'s module docs for the same cut) is not modeled, so
/// [`MdMangGhidra::demangle`]/[`MdMangGhidra::demangle_type`] report it as unavailable for any
/// mangled string that passes the filter and the blank-string check inherited from
/// `MDMang.initState()`.
pub struct MdMangGhidra {
    mangled_symbol: Option<String>,
    error_on_remaining_chars: bool,
    demangle_only_known_patterns: bool,
    architecture_size: i32,
    is_function: bool,
    output_options: MdOutputOptions,
}

impl Default for MdMangGhidra {
    fn default() -> Self {
        Self {
            mangled_symbol: None,
            error_on_remaining_chars: false,
            demangle_only_known_patterns: false,
            // Mirrors `MDMang.architectureSize`'s field initializer default of 32.
            architecture_size: 32,
            is_function: false,
            output_options: MdOutputOptions::default(),
        }
    }
}

impl MdMangGhidra {
    /// Mirrors `new MDMangGhidra()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `setMangledSymbol(String)` (inherited from `MDMang`).
    pub fn set_mangled_symbol(&mut self, mangled: impl Into<String>) {
        self.mangled_symbol = Some(mangled.into());
    }

    /// Mirrors `setErrorOnRemainingChars(boolean)` (inherited from `MDMang`).
    pub fn set_error_on_remaining_chars(&mut self, error_on_remaining_chars: bool) {
        self.error_on_remaining_chars = error_on_remaining_chars;
    }

    /// Mirrors `setDemangleOnlyKnownPatterns(boolean)`.
    pub fn set_demangle_only_known_patterns(&mut self, demangle_only_known_patterns: bool) {
        self.demangle_only_known_patterns = demangle_only_known_patterns;
    }

    /// Mirrors `setArchitectureSize(int)` (inherited from `MDMang`).
    pub fn set_architecture_size(&mut self, size: i32) {
        self.architecture_size = size;
    }

    /// Mirrors `setIsFunction(boolean)` (inherited from `MDMang`).
    pub fn set_is_function(&mut self, is_function: bool) {
        self.is_function = is_function;
    }

    /// Mirrors `getOutputOptions()` (inherited from `MDMang`), returning a mutable reference since
    /// every caller uses it to immediately call a setter.
    pub fn output_options(&mut self) -> &mut MdOutputOptions {
        &mut self.output_options
    }

    /// Mirrors the known-mangled-name-pattern predicate embedded in `MDMangGhidra.demangle()`:
    /// `mangled.startsWith("?") || mangled.startsWith(".") || mangled.startsWith("_") ||
    /// (mangled.charAt(0) < 'a') || (isLowerCase) || (isUpperCase)`.
    fn matches_known_pattern(mangled: &str) -> bool {
        match mangled.chars().next() {
            None => false,
            Some(c) => c == '?' || c == '.' || c == '_' || c < 'a' || c.is_ascii_alphabetic(),
        }
    }

    /// Mirrors `demangle()` (`throws MDException`).
    ///
    /// The known-pattern filter and the blank-mangled-string check (from the inherited
    /// `MDMang.initState()`) are faithfully reproduced; a non-blank mangled string that passes the
    /// filter reports the (unported) grammar dispatch as unavailable rather than a parsed item.
    pub fn demangle(&mut self) -> Result<Option<Box<dyn MdParsableItemLike>>, Box<dyn MdExceptionLike>> {
        let mangled = self.mangled_symbol.clone().unwrap_or_default();
        if self.demangle_only_known_patterns && !Self::matches_known_pattern(&mangled) {
            return Ok(None);
        }
        if mangled.trim().is_empty() {
            return Err(Box::new(MdMangError(
                "MDMang: Mangled string is null or blank.".to_string(),
            )));
        }
        Err(Box::new(MdMangError(
            "MDMangGhidra: grammar dispatch (MDMangObjectParser) not yet ported".to_string(),
        )))
    }

    /// Mirrors `demangleType()` (`throws MDException`).
    pub fn demangle_type(&mut self) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
        let mangled = self.mangled_symbol.clone().unwrap_or_default();
        if mangled.trim().is_empty() {
            return Err(Box::new(MdMangError(
                "MDMang: Mangled string is null or blank.".to_string(),
            )));
        }
        Err(Box::new(MdMangError(
            "MDMangGhidra: grammar dispatch (MDDataTypeParser) not yet ported".to_string(),
        )))
    }
}

/// Placeholder for `ghidra.app.util.demangler.microsoft.MicrosoftDemanglerOptions`, needed by
/// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`].
///
/// Java extends the already-ported [`crate::demangler::demangler_options::DemanglerOptions`] to
/// add Microsoft-specific fields; Rust has no struct inheritance, so this wraps a
/// `DemanglerOptions` by composition instead (the same treatment [`MicrosoftMangledContext`] gives
/// `MangledContext`). Only the members `MicrosoftDemangler` touches are modeled; the real port
/// also carries the `DEFAULT_UNDERLYING_OUTPUT` static and the `Json`-based `toString`.
#[derive(Debug, Clone)]
pub struct MicrosoftDemanglerOptions {
    base: crate::demangler::demangler_options::DemanglerOptions,
    error_on_remaining_chars: bool,
    interpretation: crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation,
    use_encoded_anonymous_namespace: bool,
    apply_udt_argument_type_tag: bool,
}

impl Default for MicrosoftDemanglerOptions {
    /// Mirrors the no-arg constructor's `defaultInits()`.
    fn default() -> Self {
        Self {
            base: crate::demangler::demangler_options::DemanglerOptions::new(),
            error_on_remaining_chars: true,
            interpretation:
                crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation::FunctionIfExists,
            // Mirrors `DEFAULT_MSD_USE_ANON_NS` / `DEFAULT_MSD_APPLY_UDT_TAG`.
            use_encoded_anonymous_namespace: true,
            apply_udt_argument_type_tag: false,
        }
    }
}

impl MicrosoftDemanglerOptions {
    /// Mirrors the default constructor `MicrosoftDemanglerOptions()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `MicrosoftDemanglerOptions(boolean errorOnRemainingCharsArg)`.
    pub fn with_error_on_remaining_chars(error_on_remaining_chars: bool) -> Self {
        Self { error_on_remaining_chars, ..Self::default() }
    }

    /// Mirrors the `MicrosoftDemanglerOptions(DemanglerOptions copy)` copy constructor's `else`
    /// branch: since a plain [`crate::demangler::demangler_options::DemanglerOptions`] is never
    /// also a `MicrosoftDemanglerOptions` in Rust (no downcasting), only the base fields are ever
    /// preserved and the Microsoft-specific ones always fall back to defaults -- the `if (copy
    /// instanceof MicrosoftDemanglerOptions mCopy)` branch is unreachable from this constructor.
    pub fn from_base(base: &crate::demangler::demangler_options::DemanglerOptions) -> Self {
        Self { base: base.clone(), ..Self::default() }
    }

    /// Mirrors `setErrorOnRemainingChars(boolean)`.
    pub fn set_error_on_remaining_chars(&mut self, error_on_remaining_chars_arg: bool) {
        self.error_on_remaining_chars = error_on_remaining_chars_arg;
    }

    /// Mirrors `errorOnRemainingChars()`.
    pub fn error_on_remaining_chars(&self) -> bool {
        self.error_on_remaining_chars
    }

    /// Mirrors `setInterpretation(MsCInterpretation)`.
    pub fn set_interpretation(
        &mut self,
        interpretation_arg: crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation,
    ) {
        self.interpretation = interpretation_arg;
    }

    /// Mirrors `getInterpretation()`.
    pub fn interpretation(
        &self,
    ) -> crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation {
        self.interpretation
    }

    /// Mirrors `setUseEncodedAnonymousNamespace(boolean)`.
    pub fn set_use_encoded_anonymous_namespace(&mut self, use_encoded_anonymous_namespace_arg: bool) {
        self.use_encoded_anonymous_namespace = use_encoded_anonymous_namespace_arg;
    }

    /// Mirrors `getUseEncodedAnonymousNamespace()`.
    pub fn use_encoded_anonymous_namespace(&self) -> bool {
        self.use_encoded_anonymous_namespace
    }

    /// Mirrors `setApplyUdtArgumentTypeTag(boolean)`.
    pub fn set_apply_udt_argument_type_tag(&mut self, apply_udt_argument_type_tag_arg: bool) {
        self.apply_udt_argument_type_tag = apply_udt_argument_type_tag_arg;
    }

    /// Mirrors `getApplyUdtArgumentTypeTag()`.
    pub fn apply_udt_argument_type_tag(&self) -> bool {
        self.apply_udt_argument_type_tag
    }

    /// Mirrors `demangleOnlyKnownPatterns()`, inherited unchanged from the base
    /// `DemanglerOptions`.
    pub fn demangle_only_known_patterns(&self) -> bool {
        self.base.demangle_only_known_patterns()
    }

    /// Returns the wrapped base options.
    ///
    /// Stands in for an upcast to `DemanglerOptions`, which Rust's lack of struct inheritance
    /// doesn't otherwise offer.
    pub fn base(&self) -> &crate::demangler::demangler_options::DemanglerOptions {
        &self.base
    }
}

/// Placeholder for `ghidra.app.util.demangler.microsoft.MicrosoftMangledContext`, needed by
/// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`].
///
/// Java extends the already-ported [`crate::demangler::mangled_context::MangledContext`]; Rust has
/// no struct inheritance, so this wraps the same four pieces by composition instead, with
/// [`MicrosoftDemanglerOptions`] in place of the base's plain `DemanglerOptions` (the base type has
/// no room for the Microsoft-specific fields -- see [`MicrosoftDemanglerOptions`]'s docs).
/// `shouldInterpretAsFunction`'s `FUNCTION_IF_EXISTS` branch (`getExistingFunction`) needs
/// `Program.getFunctionManager()`, which the already-ported `Program` trait only exposes via
/// `&mut self`; since this context only ever holds a shared `Arc<dyn Program>`, that branch
/// conservatively answers `false` (no existing function determinable) rather than performing the
/// lookup.
pub struct MicrosoftMangledContext {
    program: Option<std::sync::Arc<dyn crate::program::model::listing::Program>>,
    options: MicrosoftDemanglerOptions,
    mangled: String,
    address: Option<crate::program::model::address::Address>,
}

impl MicrosoftMangledContext {
    /// Mirrors `MicrosoftMangledContext(Program, MicrosoftDemanglerOptions, String, Address)`.
    pub fn new(
        program: Option<std::sync::Arc<dyn crate::program::model::listing::Program>>,
        options: MicrosoftDemanglerOptions,
        mangled: impl Into<String>,
        address: Option<crate::program::model::address::Address>,
    ) -> Self {
        Self { program, options, mangled: mangled.into(), address }
    }

    /// Mirrors `getProgram()` (inherited from `MangledContext`).
    pub fn program(&self) -> Option<std::sync::Arc<dyn crate::program::model::listing::Program>> {
        self.program.as_ref().map(std::sync::Arc::clone)
    }

    /// Mirrors the covariant-return override `getOptions()`.
    pub fn options(&self) -> &MicrosoftDemanglerOptions {
        &self.options
    }

    /// Mirrors `getMangled()` (inherited from `MangledContext`).
    pub fn mangled(&self) -> &str {
        &self.mangled
    }

    /// Mirrors `getAddress()` (inherited from `MangledContext`).
    pub fn address(&self) -> Option<crate::program::model::address::Address> {
        self.address.clone()
    }

    /// Mirrors `getArchitectureSize()`.
    pub fn architecture_size(&self) -> i32 {
        match &self.program {
            None => 0,
            Some(program) => program
                .get_address_factory()
                .and_then(|factory| factory.get_default_address_space())
                .map(|space| space.size())
                .unwrap_or(0),
        }
    }

    /// Mirrors the package-private `shouldInterpretAsFunction()`.
    pub fn should_interpret_as_function(&self) -> bool {
        use crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation;
        match self.options.interpretation() {
            MsCInterpretation::Function => true,
            MsCInterpretation::NonFunction => false,
            // See struct docs: the existing-function lookup needs a `&mut dyn Program`, which
            // isn't available from the shared `Arc<dyn Program>` this context holds.
            MsCInterpretation::FunctionIfExists => false,
        }
    }
}

/// Placeholder for `ghidra.app.util.demangler.microsoft.MicrosoftDemanglerUtil`, needed by
/// [`crate::demangler::microsoft::microsoft_demangler::MicrosoftDemangler`].
///
/// `MicrosoftDemanglerUtil` is a concrete class of static utility methods, not an interface, so
/// these are plain free functions -- the same treatment as [`strip_superfluous_signature_spaces`]
/// above. The real class recursively converts a parsed `MDParsableItem`/`MDDataType` tree into a
/// `DemangledObject`/`DemangledDataType`, dispatching across more than a dozen still-unported
/// `mdemangler.*` subpackages (`object`, `typeinfo`, `functiontype`, `template`,
/// `datatype.complex`, `datatype.modifier`, ...); reproducing that here is out of scope, so both
/// functions report the conversion as not yet available. Since [`MdMangGhidra::demangle`]/
/// [`MdMangGhidra::demangle_type`] never actually produce a parsed item for a non-blank mangled
/// string (see their docs), these are never reached in practice yet either -- they exist so the
/// calling code's structure mirrors the original faithfully.
pub fn convert_to_demangled_object(
    _item: &dyn MdParsableItemLike,
    _mangled: &str,
    _original_demangled: &str,
) -> Result<
    Option<Box<dyn crate::demangler::demangled_object::DemangledObject>>,
    crate::demangler::demangle_exception::DemangledException,
> {
    Err(crate::demangler::demangle_exception::DemangledException::from_message(
        "MicrosoftDemanglerUtil: MDParsableItem -> DemangledObject conversion not yet ported",
    ))
}

/// Mirrors `MicrosoftDemanglerUtil.convertToDemangledDataType`. See
/// [`convert_to_demangled_object`]'s docs for why this reports "not yet available" rather than
/// performing the conversion.
pub fn convert_to_demangled_data_type(
    _md_type: &dyn MdDataTypeLike,
    _mangled: &str,
    _original_demangled: &str,
) -> Option<Box<dyn DemangledDataTypeLike>> {
    None
}

/// Placeholder for `ghidra.app.util.sourcelanguage.SwiftSourceLanguage`, needed by
/// [`crate::demangler::swift::swift_demangler::SwiftDemangler`].
///
/// Java is an abstract class (implementing `SourceLanguage`) whose only member relevant here is
/// its `SWIFT_ID` constant; the rest of the (single-method) `SourceLanguage` surface isn't needed
/// by `SwiftDemangler`, so this is a free function returning that one value rather than a struct.
pub fn swift_source_language_id(
) -> crate::app::util::sourcelanguage::source_language_id::SourceLanguageIdValue {
    crate::app::util::sourcelanguage::source_language_id::SourceLanguageIdValue::new("Swift")
        .expect("\"Swift\" is a valid source language id")
}

/// Placeholder for `ghidra.app.util.demangler.swift.datatypes.SwiftDataTypeUtils.SWIFT_CATEGORY`,
/// needed by [`crate::demangler::swift::swift_demangler::SwiftDemangler`].
///
/// `SwiftDataTypeUtils` is a concrete class of static utility members, not an interface, so this
/// is a plain free function -- the same treatment as [`strip_superfluous_signature_spaces`].
/// Only the `SWIFT_CATEGORY` constant `SwiftDemangler::initialize` needs is modeled; the real
/// port also carries `isSwiftNamespace`/`getSwiftNamespace`/`getCategoryPath`/
/// `extractParameters`.
pub fn swift_category_path() -> crate::program::model::data::category_path::CategoryPath {
    crate::program::model::data::category_path::CategoryPath::parse("/Demangler")
        .expect("\"/Demangler\" is a valid category path")
}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, needed by
/// [`crate::demangler::swift::swift_demangler::SwiftDemangler`].
///
/// Decided STRUCT (see CONVENTION_QUEUE.tsv): becomes the concrete type, since there is nothing
/// to dispatch over. Only the no-arg constructor `SwiftDemangler::initialize` needs is modeled;
/// the real port also carries the message-accumulation surface.
#[derive(Debug, Clone, Default)]
pub struct MessageLog;

impl MessageLog {
    /// Mirrors `new MessageLog()`.
    pub fn new() -> Self {
        Self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.swift.SwiftTypeMetadata`, needed by
/// [`crate::demangler::swift::swift_demangler::SwiftDemangler`].
///
/// Java is a concrete class, not an interface (see the dependency-context notes), so this is a
/// plain struct rather than a trait. Only the constructor `SwiftDemangler::initialize` calls is
/// modeled; the real port also carries the full Swift type-metadata parsing/markup surface
/// (`getEntryPoints`, `getFieldDescriptors`, `markup`, ...).
pub struct SwiftTypeMetadata;

impl SwiftTypeMetadata {
    /// Mirrors `SwiftTypeMetadata(Program, TaskMonitor, MessageLog)`, which throws both
    /// `IOException` and `CancelledException`; those are collapsed onto a single `std::io::Error`
    /// here since the real parsing work (and so either failure mode) isn't ported yet.
    pub fn new(
        _program: &dyn crate::program::model::listing::Program,
        _monitor: &dyn crate::util::task::TaskMonitor,
        _log: &MessageLog,
    ) -> std::io::Result<Self> {
        Ok(Self)
    }
}

/// Placeholder for `ghidra.app.util.demangler.DemangledLabel`, needed by
/// [`crate::demangler::swift::swift_demangler::SwiftDemangler`].
///
/// Java extends `DemangledObject`; Rust has no struct inheritance, so this composes the
/// already-ported [`crate::demangler::demangled_object::DemangledObjectBase`] instead, the same
/// treatment [`DemangledUnknown`] below gives itself. The constructor and both overrides
/// (`applyTo`, `getSignature`) are modeled in full, since the Java class itself is tiny.
pub struct DemangledLabel {
    base: crate::demangler::demangled_object::DemangledObjectBase,
}

impl DemangledLabel {
    /// Mirrors `DemangledLabel(String mangled, String originalDemangled, String name)`.
    pub fn new(
        mangled: impl Into<String>,
        original_demangled: impl Into<String>,
        name: &str,
    ) -> Self {
        let mut base = crate::demangler::demangled_object::DemangledObjectBase::new(
            mangled,
            Some(original_demangled.into()),
        );
        base.set_name(Some(name));
        Self { base }
    }
}

impl crate::demangler::demangled::Demangled for DemangledLabel {
    fn get_mangled_string(&self) -> String {
        self.base.get_mangled_string().to_string()
    }

    fn get_original_demangled(&self) -> String {
        self.base.original_demangled.clone().unwrap_or_default()
    }

    fn get_name(&self) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }

    fn set_name(&mut self, name: &str) {
        self.base.set_name(Some(name));
    }

    fn get_demangled_name(&self) -> String {
        self.base.get_demangled_name().unwrap_or_default().to_string()
    }

    fn get_namespace(&self) -> Option<&dyn crate::demangler::demangled::Demangled> {
        self.base.get_namespace()
    }

    fn get_namespace_mut(&mut self) -> Option<&mut (dyn crate::demangler::demangled::Demangled + 'static)> {
        self.base.namespace.as_deref_mut()
    }

    fn set_namespace(&mut self, namespace: Option<Box<dyn crate::demangler::demangled::Demangled>>) {
        self.base.set_namespace(namespace);
    }

    fn get_namespace_string(&self) -> String {
        self.base.namespace_string_with(&self.get_name())
    }

    fn get_namespace_name(&self) -> String {
        self.get_name()
    }

    /// Mirrors `getSignature()`, which delegates to `getSignature(false)`; that override ignores
    /// `format` and returns the name (see the `DemangledObject::get_signature_formatted`
    /// override below), so this is inlined directly rather than reaching across traits.
    fn get_signature(&self) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }
}

impl crate::demangler::demangled_object::DemangledObject for DemangledLabel {
    fn base(&self) -> &crate::demangler::demangled_object::DemangledObjectBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut crate::demangler::demangled_object::DemangledObjectBase {
        &mut self.base
    }

    /// Mirrors `getSignature(boolean)`, which ignores `format` and returns the name.
    fn get_signature_formatted(&self, _format: bool) -> String {
        self.base.get_name().unwrap_or_default().to_string()
    }

    /// Mirrors `applyTo(Program, Address, DemanglerOptions, TaskMonitor)`.
    fn apply_to(
        &self,
        program: &mut dyn crate::program::model::listing::Program,
        address: &crate::program::model::address::Address,
        _options: &crate::demangler::demangler_options::DemanglerOptions,
        _monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Result<bool, crate::demangler::demangle_exception::DemangledException> {
        let symbol = self
            .base
            .apply_demangled_name(None, address, true, false, program)
            .map_err(crate::demangler::demangle_exception::DemangledException::from_cause)?;
        Ok(symbol.is_some())
    }
}

/// Placeholder for `ghidra.app.util.demangler.DemangledUnknown`, needed by
/// [`crate::demangler::swift::nodes::swift_node::SwiftNodeBase::unknown`].
///
/// Java extends `DemangledObject`; Rust has no struct inheritance, so this composes the
/// already-ported [`crate::demangler::demangled_object::DemangledObjectBase`] instead. Only the
/// constructor and the two overrides (`getSignature`, `getName`) are modeled -- the inherited
/// `applyTo`/`generatePlateComment` surface arrives with the real port -- but the
/// [`crate::demangler::demangled::Demangled`] implementation is provided so this can be used
/// wherever a `Demangled` is expected, as the original is.
pub struct DemangledUnknown {
    base: crate::demangler::demangled_object::DemangledObjectBase,
}

impl DemangledUnknown {
    /// Mirrors `DemangledUnknown(String mangled, String originalDemangled, String name)`.
    pub fn new(
        mangled: impl Into<String>,
        original_demangled: Option<String>,
        name: Option<&str>,
    ) -> Self {
        let mut base =
            crate::demangler::demangled_object::DemangledObjectBase::new(mangled, original_demangled);
        base.set_name(name);
        Self { base }
    }

    /// Mirrors the `getSignature(boolean)` override, which ignores `format` and returns the
    /// original demangled string.
    pub fn get_signature_formatted(&self, _format: bool) -> String {
        self.base.original_demangled.clone().unwrap_or_default()
    }
}

impl crate::demangler::demangled::Demangled for DemangledUnknown {
    /// Mirrors `getMangledString()`.
    fn get_mangled_string(&self) -> String {
        self.base.get_mangled_string().to_string()
    }

    /// Mirrors `getOriginalDemangled()`.
    fn get_original_demangled(&self) -> String {
        self.base.original_demangled.clone().unwrap_or_default()
    }

    /// Mirrors the `getName()` override: these items likely have no name, so fall back to the
    /// signature (with symbol-invalid characters replaced), then to `NO_NAME`.
    fn get_name(&self) -> String {
        if let Some(name) = self.base.get_name() {
            if !name.is_empty() {
                return name.to_string();
            }
        }

        let signature = self.get_signature_formatted(true);
        if !signature.is_empty() {
            use crate::program::model::symbol::symbol_utilities::{
                DefaultSymbolUtilities, SymbolUtilities,
            };
            return DefaultSymbolUtilities
                .replace_invalid_chars(Some(&signature), true)
                .unwrap_or_default();
        }

        "NO_NAME".to_string()
    }

    /// Mirrors `setName(String)`.
    fn set_name(&mut self, name: &str) {
        self.base.set_name(Some(name));
    }

    /// Mirrors `getDemangledName()`.
    fn get_demangled_name(&self) -> String {
        self.base.get_demangled_name().unwrap_or_default().to_string()
    }

    /// Mirrors `getNamespace()`.
    fn get_namespace(&self) -> Option<&dyn crate::demangler::demangled::Demangled> {
        self.base.get_namespace()
    }

    /// Mirrors mutable traversal of the namespace chain; see
    /// [`crate::demangler::demangled::Demangled::get_namespace_mut`].
    fn get_namespace_mut(&mut self) -> Option<&mut (dyn crate::demangler::demangled::Demangled + 'static)> {
        self.base.namespace.as_deref_mut()
    }

    /// Mirrors `setNamespace(Demangled)`.
    fn set_namespace(&mut self, namespace: Option<Box<dyn crate::demangler::demangled::Demangled>>) {
        self.base.set_namespace(namespace);
    }

    /// Mirrors `getNamespaceString()`.
    fn get_namespace_string(&self) -> String {
        self.base.namespace_string_with(&self.get_name())
    }

    /// Mirrors `getNamespaceName()`.
    fn get_namespace_name(&self) -> String {
        self.get_name()
    }

    /// Mirrors `getSignature()`, which delegates to `getSignature(false)`.
    fn get_signature(&self) -> String {
        self.get_signature_formatted(false)
    }
}

/// Placeholder for `ghidra.app.util.demangler.swift.SwiftNativeDemangler`, needed by
/// [`crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree`].
///
/// Java is a concrete class (it launches the native `swift`/`swift-demangle` binary via
/// `ProcessBuilder`), not an interface, so this is a plain struct rather than a trait. Only
/// `demangle`, the one method `SwiftDemangledTree`'s constructor calls, is modeled, and it reports
/// the underlying native-process invocation as not yet available -- the same treatment
/// [`MdMangGhidra::demangle`] gives its own unported grammar dispatch; the real port also carries
/// the constructor's demangler-binary discovery loop and the private
/// `demangle(String, List<String>)` process-launch helper.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwiftNativeDemangler;

impl SwiftNativeDemangler {
    /// Mirrors `SwiftNativeDemangler(File)`. The `swift_dir` argument is accepted for signature
    /// fidelity but not stored: the real constructor uses it to search for the native
    /// `swift`/`swift-demangle` binary, which isn't ported (see this struct's docs), so there is
    /// nothing here that would read it back.
    pub fn new(_swift_dir: Option<std::path::PathBuf>) -> std::io::Result<Self> {
        Ok(Self)
    }

    /// Mirrors `demangle(String)`.
    pub fn demangle(&self, _mangled: &str) -> std::io::Result<SwiftNativeDemangledOutput> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SwiftNativeDemangler: native Swift demangler invocation not yet ported",
        ))
    }
}

/// Placeholder for `ghidra.app.util.demangler.swift.SwiftNativeDemangler.SwiftNativeDemangledOutput`,
/// needed by [`crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree`].
///
/// Java record; immutable value carrier, hence public fields rather than accessor methods.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwiftNativeDemangledOutput {
    /// The demangled string, or `None` if demangling finished gracefully but returned nothing.
    pub demangled: Option<String>,
    /// The lines of the demangled expanded tree.
    pub tree: Vec<String>,
}

/// Placeholder for `ghidra.app.util.demangler.swift.nodes.SwiftUnsupportedNode`, needed by
/// [`crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree`].
///
/// Java is a concrete class, not an interface, so this is a plain struct implementing
/// [`SwiftNode`] rather than a trait. `SwiftNode.get`'s ~50-arm dispatch to concrete node
/// subclasses is not ported yet, so [`SwiftDemangledTree`](crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree)
/// currently constructs one of these for every tree node regardless of kind, carrying the real
/// parsed [`crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind`] (or its
/// `Unsupported` variant when the native demangler emitted a kind name the enum doesn't
/// recognize) in the node's properties either way.
pub struct SwiftUnsupportedNode {
    base: SwiftNodeBase,
    original_kind: String,
}

impl SwiftUnsupportedNode {
    /// Mirrors `SwiftUnsupportedNode(String originalKind, NodeProperties props)`.
    pub fn new(original_kind: impl Into<String>, properties: NodeProperties) -> Self {
        Self { base: SwiftNodeBase::new(properties), original_kind: original_kind.into() }
    }
}

impl SwiftNode for SwiftUnsupportedNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Mirrors `demangle(SwiftDemangler)`: marks itself as having skipped a child (faithfully
    /// reproducing the original's `skip(this)` self-call) and returns its `getUnknown()`.
    fn demangle(
        &self,
        _demangler: &crate::demangler::swift::swift_demangler::SwiftDemangler,
    ) -> Result<Option<Box<dyn crate::demangler::demangled::Demangled>>, crate::demangler::demangle_exception::DemangledException>
    {
        self.base.skip(self);
        Ok(Some(Box::new(self.base.unknown())))
    }
}

impl std::fmt::Display for SwiftUnsupportedNode {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.base, self.original_kind)
    }
}
