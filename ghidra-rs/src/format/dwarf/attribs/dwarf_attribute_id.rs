//! Port of `ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId`.
//!
//! # Departures from the Java enum
//!
//! * Java attaches the id and the `EnumSet<DWARFAttributeClass>` to each constant via its
//!   constructor and stores them as instance fields read back by `getId()`/`getAttributeClass()`.
//!   Both collapse here into a `match self` per method, the same closed dispatch.
//! * Java's `of()` looks the id up in a `HashMap` built once by a static initializer; this scans
//!   [`DWARFAttributeId::VALUES`], mirroring the approach already used by
//!   [`DWARFForm::of`](crate::format::dwarf::attribs::dwarf_form::DWARFForm::of). It returns
//!   [`None`] where Java returns `null`.
//! * The nested `DWARFAttributeId.AttrDef` extends the generic (and still unported)
//!   `DWARFAttributeDef<E extends Enum<E>>`. Since `AttrDef` is the only instantiation of that
//!   generic base needed here (`E = DWARFAttributeId`), [`AttrDef`] is ported as a concrete
//!   struct that inlines the base class's field storage and `read`/`withForm` logic rather than
//!   modeling the generic base itself; it implements the crate's existing
//!   [`DWARFAttributeDef`](crate::format::seam_stubs::DWARFAttributeDef) stub trait for the
//!   behavior other ported code already depends on that trait for (mirroring how
//!   [`DWARFLineContentTypeDef`](crate::format::seam_stubs::DWARFLineContentTypeDef) specializes
//!   the same Java base class for `DWARFLineContentType`).

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_attribute_class::DWARFAttributeClass;
use crate::format::dwarf::attribs::dwarf_form::{self, DWARFForm};
use crate::format::seam_stubs::DWARFAttributeDef;

use DWARFAttributeClass::{
    AddrPtr, Address, Block, Constant, ExprLoc, Flag, LinePtr, LocList, LocListsPtr, MacPtr,
    Reference, RngList, RngListsPtr, StrOffsetsPtr, String as StringClass,
};

/// Value used as the end of an attribute-spec list. Mirrors `DWARFAttributeId.EOL`.
pub const EOL: i32 = 0;

/// Defines the names and numeric ids of known DWARF attributes. Well-known attributes are also
/// constrained to certain value types (see [`DWARFAttributeClass`]).
///
/// Users of this enum should be tolerant of unknown attribute id values. See
/// [`AttrDef::get_raw_attribute_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DWARFAttributeId {
    DwAtSibling,
    DwAtLocation,
    DwAtName,
    DwAtOrdering,
    DwAtByteSize,
    DwAtBitOffset,
    DwAtBitSize,
    DwAtStmtList,
    DwAtLowPc,
    DwAtHighPc,
    DwAtLanguage,
    DwAtDiscr,
    DwAtDiscrValue,
    DwAtVisibility,
    DwAtImport,
    DwAtStringLength,
    DwAtCommonReference,
    DwAtCompDir,
    DwAtConstValue,
    DwAtContainingType,
    DwAtDefaultValue,
    DwAtInline,
    DwAtIsOptional,
    DwAtLowerBound,
    DwAtProducer,
    DwAtPrototyped,
    DwAtReturnAddr,
    DwAtStartScope,
    DwAtBitStride,
    DwAtUpperBound,
    DwAtAbstractOrigin,
    DwAtAccessibility,
    DwAtAddressClass,
    DwAtArtificial,
    DwAtBaseTypes,
    DwAtCallingConvention,
    DwAtCount,
    DwAtDataMemberLocation,
    DwAtDeclColumn,
    DwAtDeclFile,
    DwAtDeclLine,
    DwAtDeclaration,
    DwAtDiscrList,
    DwAtEncoding,
    DwAtExternal,
    DwAtFrameBase,
    DwAtFriend,
    DwAtIdentifierCase,
    DwAtMacroInfo,
    DwAtNamelistItem,
    DwAtPriority,
    DwAtSegment,
    DwAtSpecification,
    DwAtStaticLink,
    DwAtType,
    DwAtUseLocation,
    DwAtVariableParameter,
    DwAtVirtuality,
    DwAtVtableElemLocation,
    DwAtAllocated,
    DwAtAssociated,
    DwAtDataLocation,
    DwAtByteStride,
    DwAtEntryPc,
    DwAtUseUtf8,
    DwAtExtension,
    DwAtRanges,
    DwAtTrampoline,
    DwAtCallColumn,
    DwAtCallFile,
    DwAtCallLine,
    DwAtDescription,
    DwAtBinaryScale,
    DwAtDecimalScale,
    DwAtSmall,
    DwAtDecimalSign,
    DwAtDigitCount,
    DwAtPictureString,
    DwAtMutable,
    DwAtThreadsScaled,
    DwAtExplicit,
    DwAtObjectPointer,
    DwAtEndianity,
    DwAtElemental,
    DwAtPure,
    DwAtRecursive,
    DwAtSignature,
    DwAtMainSubprogram,
    DwAtDataBitOffset,
    DwAtConstExpr,
    DwAtEnumClass,
    DwAtLinkageName,
    DwAtStringLengthBitSize,
    DwAtStringLengthByteSize,
    DwAtRank,
    DwAtStrOffsetsBase,
    DwAtAddrBase,
    DwAtRnglistsBase,
    DwAtDwoName,
    DwAtReference,
    DwAtRvalueReference,
    DwAtMacros,
    DwAtCallAllCalls,
    DwAtCallAllSourceCalls,
    DwAtCallAllTailCalls,
    DwAtCallReturnPc,
    DwAtCallValue,
    DwAtCallOrigin,
    DwAtCallParameter,
    DwAtCallPc,
    DwAtCallTailCall,
    DwAtCallTarget,
    DwAtCallTargetClobbered,
    DwAtCallDataLocation,
    DwAtCallDataValue,
    DwAtNoreturn,
    DwAtAlignment,
    DwAtExportSymbols,
    DwAtDeleted,
    DwAtDefaulted,
    DwAtLoclistsBase,
    DwAtLoUser,
    DwAtHiUser,
    DwAtMipsLinkageName,
    DwAtGnuCallSiteValue,
    DwAtGnuCallSiteDataValue,
    DwAtGnuCallSiteTarget,
    DwAtGnuCallSiteTargetClobbered,
    DwAtGnuTailCall,
    DwAtGnuAllTailCallSites,
    DwAtGnuAllCallSites,
    DwAtGnuAllSourceCallSites,
    DwAtGnuMacros,
    DwAtGnuDeleted,
    DwAtGnuDwoName,
    DwAtGnuDwoId,
    DwAtGnuRangesBase,
    DwAtGnuAddrBase,
    DwAtGnuPubnames,
    DwAtGnuPubtypes,
    DwAtGnuDiscriminator,
    DwAtGnuLocviews,
    DwAtGnuEntryView,
    DwAtGnuAnnotation,
    DwAtGoKind,
    DwAtGoKey,
    DwAtGoElem,
    DwAtGoEmbeddedField,
    DwAtGoRuntimeType,
    DwAtGoPackageName,
    DwAtGoDictIndex,
    DwAtApplePtrauthKey,
    DwAtApplePtrauthAddressDiscriminated,
    DwAtApplePtrauthExtraDiscriminator,
    DwAtAppleOmitFramePtr,
    DwAtAppleOptimized,
}

impl DWARFAttributeId {
    /// Every attribute id, in Java enum declaration order. Mirrors `DWARFAttributeId.values()`.
    pub const VALUES: [DWARFAttributeId; 156] = [
        Self::DwAtSibling,
        Self::DwAtLocation,
        Self::DwAtName,
        Self::DwAtOrdering,
        Self::DwAtByteSize,
        Self::DwAtBitOffset,
        Self::DwAtBitSize,
        Self::DwAtStmtList,
        Self::DwAtLowPc,
        Self::DwAtHighPc,
        Self::DwAtLanguage,
        Self::DwAtDiscr,
        Self::DwAtDiscrValue,
        Self::DwAtVisibility,
        Self::DwAtImport,
        Self::DwAtStringLength,
        Self::DwAtCommonReference,
        Self::DwAtCompDir,
        Self::DwAtConstValue,
        Self::DwAtContainingType,
        Self::DwAtDefaultValue,
        Self::DwAtInline,
        Self::DwAtIsOptional,
        Self::DwAtLowerBound,
        Self::DwAtProducer,
        Self::DwAtPrototyped,
        Self::DwAtReturnAddr,
        Self::DwAtStartScope,
        Self::DwAtBitStride,
        Self::DwAtUpperBound,
        Self::DwAtAbstractOrigin,
        Self::DwAtAccessibility,
        Self::DwAtAddressClass,
        Self::DwAtArtificial,
        Self::DwAtBaseTypes,
        Self::DwAtCallingConvention,
        Self::DwAtCount,
        Self::DwAtDataMemberLocation,
        Self::DwAtDeclColumn,
        Self::DwAtDeclFile,
        Self::DwAtDeclLine,
        Self::DwAtDeclaration,
        Self::DwAtDiscrList,
        Self::DwAtEncoding,
        Self::DwAtExternal,
        Self::DwAtFrameBase,
        Self::DwAtFriend,
        Self::DwAtIdentifierCase,
        Self::DwAtMacroInfo,
        Self::DwAtNamelistItem,
        Self::DwAtPriority,
        Self::DwAtSegment,
        Self::DwAtSpecification,
        Self::DwAtStaticLink,
        Self::DwAtType,
        Self::DwAtUseLocation,
        Self::DwAtVariableParameter,
        Self::DwAtVirtuality,
        Self::DwAtVtableElemLocation,
        Self::DwAtAllocated,
        Self::DwAtAssociated,
        Self::DwAtDataLocation,
        Self::DwAtByteStride,
        Self::DwAtEntryPc,
        Self::DwAtUseUtf8,
        Self::DwAtExtension,
        Self::DwAtRanges,
        Self::DwAtTrampoline,
        Self::DwAtCallColumn,
        Self::DwAtCallFile,
        Self::DwAtCallLine,
        Self::DwAtDescription,
        Self::DwAtBinaryScale,
        Self::DwAtDecimalScale,
        Self::DwAtSmall,
        Self::DwAtDecimalSign,
        Self::DwAtDigitCount,
        Self::DwAtPictureString,
        Self::DwAtMutable,
        Self::DwAtThreadsScaled,
        Self::DwAtExplicit,
        Self::DwAtObjectPointer,
        Self::DwAtEndianity,
        Self::DwAtElemental,
        Self::DwAtPure,
        Self::DwAtRecursive,
        Self::DwAtSignature,
        Self::DwAtMainSubprogram,
        Self::DwAtDataBitOffset,
        Self::DwAtConstExpr,
        Self::DwAtEnumClass,
        Self::DwAtLinkageName,
        Self::DwAtStringLengthBitSize,
        Self::DwAtStringLengthByteSize,
        Self::DwAtRank,
        Self::DwAtStrOffsetsBase,
        Self::DwAtAddrBase,
        Self::DwAtRnglistsBase,
        Self::DwAtDwoName,
        Self::DwAtReference,
        Self::DwAtRvalueReference,
        Self::DwAtMacros,
        Self::DwAtCallAllCalls,
        Self::DwAtCallAllSourceCalls,
        Self::DwAtCallAllTailCalls,
        Self::DwAtCallReturnPc,
        Self::DwAtCallValue,
        Self::DwAtCallOrigin,
        Self::DwAtCallParameter,
        Self::DwAtCallPc,
        Self::DwAtCallTailCall,
        Self::DwAtCallTarget,
        Self::DwAtCallTargetClobbered,
        Self::DwAtCallDataLocation,
        Self::DwAtCallDataValue,
        Self::DwAtNoreturn,
        Self::DwAtAlignment,
        Self::DwAtExportSymbols,
        Self::DwAtDeleted,
        Self::DwAtDefaulted,
        Self::DwAtLoclistsBase,
        Self::DwAtLoUser,
        Self::DwAtHiUser,
        Self::DwAtMipsLinkageName,
        Self::DwAtGnuCallSiteValue,
        Self::DwAtGnuCallSiteDataValue,
        Self::DwAtGnuCallSiteTarget,
        Self::DwAtGnuCallSiteTargetClobbered,
        Self::DwAtGnuTailCall,
        Self::DwAtGnuAllTailCallSites,
        Self::DwAtGnuAllCallSites,
        Self::DwAtGnuAllSourceCallSites,
        Self::DwAtGnuMacros,
        Self::DwAtGnuDeleted,
        Self::DwAtGnuDwoName,
        Self::DwAtGnuDwoId,
        Self::DwAtGnuRangesBase,
        Self::DwAtGnuAddrBase,
        Self::DwAtGnuPubnames,
        Self::DwAtGnuPubtypes,
        Self::DwAtGnuDiscriminator,
        Self::DwAtGnuLocviews,
        Self::DwAtGnuEntryView,
        Self::DwAtGnuAnnotation,
        Self::DwAtGoKind,
        Self::DwAtGoKey,
        Self::DwAtGoElem,
        Self::DwAtGoEmbeddedField,
        Self::DwAtGoRuntimeType,
        Self::DwAtGoPackageName,
        Self::DwAtGoDictIndex,
        Self::DwAtApplePtrauthKey,
        Self::DwAtApplePtrauthAddressDiscriminated,
        Self::DwAtApplePtrauthExtraDiscriminator,
        Self::DwAtAppleOmitFramePtr,
        Self::DwAtAppleOptimized,
    ];

    /// Returns the id of this `DWARFAttributeId`. Mirrors `DWARFAttributeId.getId()`.
    pub fn get_id(&self) -> i32 {
        self.id_and_name().0
    }

    /// The `DW_AT_*` spelling Java's `Enum.name()` yields. Mirrors `DWARFAttributeId.name()`
    /// (used by `AttrDef.getAttributeName()`).
    pub fn name(&self) -> &'static str {
        self.id_and_name().1
    }

    fn id_and_name(&self) -> (i32, &'static str) {
        match self {
            Self::DwAtSibling => (0x1, "DW_AT_sibling"),
            Self::DwAtLocation => (0x2, "DW_AT_location"),
            Self::DwAtName => (0x3, "DW_AT_name"),
            Self::DwAtOrdering => (0x9, "DW_AT_ordering"),
            Self::DwAtByteSize => (0xb, "DW_AT_byte_size"),
            Self::DwAtBitOffset => (0xc, "DW_AT_bit_offset"),
            Self::DwAtBitSize => (0xd, "DW_AT_bit_size"),
            Self::DwAtStmtList => (0x10, "DW_AT_stmt_list"),
            Self::DwAtLowPc => (0x11, "DW_AT_low_pc"),
            Self::DwAtHighPc => (0x12, "DW_AT_high_pc"),
            Self::DwAtLanguage => (0x13, "DW_AT_language"),
            Self::DwAtDiscr => (0x15, "DW_AT_discr"),
            Self::DwAtDiscrValue => (0x16, "DW_AT_discr_value"),
            Self::DwAtVisibility => (0x17, "DW_AT_visibility"),
            Self::DwAtImport => (0x18, "DW_AT_import"),
            Self::DwAtStringLength => (0x19, "DW_AT_string_length"),
            Self::DwAtCommonReference => (0x1a, "DW_AT_common_reference"),
            Self::DwAtCompDir => (0x1b, "DW_AT_comp_dir"),
            Self::DwAtConstValue => (0x1c, "DW_AT_const_value"),
            Self::DwAtContainingType => (0x1d, "DW_AT_containing_type"),
            Self::DwAtDefaultValue => (0x1e, "DW_AT_default_value"),
            Self::DwAtInline => (0x20, "DW_AT_inline"),
            Self::DwAtIsOptional => (0x21, "DW_AT_is_optional"),
            Self::DwAtLowerBound => (0x22, "DW_AT_lower_bound"),
            Self::DwAtProducer => (0x25, "DW_AT_producer"),
            Self::DwAtPrototyped => (0x27, "DW_AT_prototyped"),
            Self::DwAtReturnAddr => (0x2a, "DW_AT_return_addr"),
            Self::DwAtStartScope => (0x2c, "DW_AT_start_scope"),
            Self::DwAtBitStride => (0x2e, "DW_AT_bit_stride"),
            Self::DwAtUpperBound => (0x2f, "DW_AT_upper_bound"),
            Self::DwAtAbstractOrigin => (0x31, "DW_AT_abstract_origin"),
            Self::DwAtAccessibility => (0x32, "DW_AT_accessibility"),
            Self::DwAtAddressClass => (0x33, "DW_AT_address_class"),
            Self::DwAtArtificial => (0x34, "DW_AT_artificial"),
            Self::DwAtBaseTypes => (0x35, "DW_AT_base_types"),
            Self::DwAtCallingConvention => (0x36, "DW_AT_calling_convention"),
            Self::DwAtCount => (0x37, "DW_AT_count"),
            Self::DwAtDataMemberLocation => (0x38, "DW_AT_data_member_location"),
            Self::DwAtDeclColumn => (0x39, "DW_AT_decl_column"),
            Self::DwAtDeclFile => (0x3a, "DW_AT_decl_file"),
            Self::DwAtDeclLine => (0x3b, "DW_AT_decl_line"),
            Self::DwAtDeclaration => (0x3c, "DW_AT_declaration"),
            Self::DwAtDiscrList => (0x3d, "DW_AT_discr_list"),
            Self::DwAtEncoding => (0x3e, "DW_AT_encoding"),
            Self::DwAtExternal => (0x3f, "DW_AT_external"),
            Self::DwAtFrameBase => (0x40, "DW_AT_frame_base"),
            Self::DwAtFriend => (0x41, "DW_AT_friend"),
            Self::DwAtIdentifierCase => (0x42, "DW_AT_identifier_case"),
            Self::DwAtMacroInfo => (0x43, "DW_AT_macro_info"),
            Self::DwAtNamelistItem => (0x44, "DW_AT_namelist_item"),
            Self::DwAtPriority => (0x45, "DW_AT_priority"),
            Self::DwAtSegment => (0x46, "DW_AT_segment"),
            Self::DwAtSpecification => (0x47, "DW_AT_specification"),
            Self::DwAtStaticLink => (0x48, "DW_AT_static_link"),
            Self::DwAtType => (0x49, "DW_AT_type"),
            Self::DwAtUseLocation => (0x4a, "DW_AT_use_location"),
            Self::DwAtVariableParameter => (0x4b, "DW_AT_variable_parameter"),
            Self::DwAtVirtuality => (0x4c, "DW_AT_virtuality"),
            Self::DwAtVtableElemLocation => (0x4d, "DW_AT_vtable_elem_location"),
            Self::DwAtAllocated => (0x4e, "DW_AT_allocated"),
            Self::DwAtAssociated => (0x4f, "DW_AT_associated"),
            Self::DwAtDataLocation => (0x50, "DW_AT_data_location"),
            Self::DwAtByteStride => (0x51, "DW_AT_byte_stride"),
            Self::DwAtEntryPc => (0x52, "DW_AT_entry_pc"),
            Self::DwAtUseUtf8 => (0x53, "DW_AT_use_UTF8"),
            Self::DwAtExtension => (0x54, "DW_AT_extension"),
            Self::DwAtRanges => (0x55, "DW_AT_ranges"),
            Self::DwAtTrampoline => (0x56, "DW_AT_trampoline"),
            Self::DwAtCallColumn => (0x57, "DW_AT_call_column"),
            Self::DwAtCallFile => (0x58, "DW_AT_call_file"),
            Self::DwAtCallLine => (0x59, "DW_AT_call_line"),
            Self::DwAtDescription => (0x5a, "DW_AT_description"),
            Self::DwAtBinaryScale => (0x5b, "DW_AT_binary_scale"),
            Self::DwAtDecimalScale => (0x5c, "DW_AT_decimal_scale"),
            Self::DwAtSmall => (0x5d, "DW_AT_small"),
            Self::DwAtDecimalSign => (0x5e, "DW_AT_decimal_sign"),
            Self::DwAtDigitCount => (0x5f, "DW_AT_digit_count"),
            Self::DwAtPictureString => (0x60, "DW_AT_picture_string"),
            Self::DwAtMutable => (0x61, "DW_AT_mutable"),
            Self::DwAtThreadsScaled => (0x62, "DW_AT_threads_scaled"),
            Self::DwAtExplicit => (0x63, "DW_AT_explicit"),
            Self::DwAtObjectPointer => (0x64, "DW_AT_object_pointer"),
            Self::DwAtEndianity => (0x65, "DW_AT_endianity"),
            Self::DwAtElemental => (0x66, "DW_AT_elemental"),
            Self::DwAtPure => (0x67, "DW_AT_pure"),
            Self::DwAtRecursive => (0x68, "DW_AT_recursive"),
            Self::DwAtSignature => (0x69, "DW_AT_signature"),
            Self::DwAtMainSubprogram => (0x6a, "DW_AT_main_subprogram"),
            Self::DwAtDataBitOffset => (0x6b, "DW_AT_data_bit_offset"),
            Self::DwAtConstExpr => (0x6c, "DW_AT_const_expr"),
            Self::DwAtEnumClass => (0x6d, "DW_AT_enum_class"),
            Self::DwAtLinkageName => (0x6e, "DW_AT_linkage_name"),
            Self::DwAtStringLengthBitSize => (0x6f, "DW_AT_string_length_bit_size"),
            Self::DwAtStringLengthByteSize => (0x70, "DW_AT_string_length_byte_size"),
            Self::DwAtRank => (0x71, "DW_AT_rank"),
            Self::DwAtStrOffsetsBase => (0x72, "DW_AT_str_offsets_base"),
            Self::DwAtAddrBase => (0x73, "DW_AT_addr_base"),
            Self::DwAtRnglistsBase => (0x74, "DW_AT_rnglists_base"),
            Self::DwAtDwoName => (0x76, "DW_AT_dwo_name"),
            Self::DwAtReference => (0x77, "DW_AT_reference"),
            Self::DwAtRvalueReference => (0x78, "DW_AT_rvalue_reference"),
            Self::DwAtMacros => (0x79, "DW_AT_macros"),
            Self::DwAtCallAllCalls => (0x7a, "DW_AT_call_all_calls"),
            Self::DwAtCallAllSourceCalls => (0x7b, "DW_AT_call_all_source_calls"),
            Self::DwAtCallAllTailCalls => (0x7c, "DW_AT_call_all_tail_calls"),
            Self::DwAtCallReturnPc => (0x7d, "DW_AT_call_return_pc"),
            Self::DwAtCallValue => (0x7e, "DW_AT_call_value"),
            Self::DwAtCallOrigin => (0x7f, "DW_AT_call_origin"),
            Self::DwAtCallParameter => (0x80, "DW_AT_call_parameter"),
            Self::DwAtCallPc => (0x81, "DW_AT_call_pc"),
            Self::DwAtCallTailCall => (0x82, "DW_AT_call_tail_call"),
            Self::DwAtCallTarget => (0x83, "DW_AT_call_target"),
            Self::DwAtCallTargetClobbered => (0x84, "DW_AT_call_target_clobbered"),
            Self::DwAtCallDataLocation => (0x85, "DW_AT_call_data_location"),
            Self::DwAtCallDataValue => (0x86, "DW_AT_call_data_value"),
            Self::DwAtNoreturn => (0x87, "DW_AT_noreturn"),
            Self::DwAtAlignment => (0x88, "DW_AT_alignment"),
            Self::DwAtExportSymbols => (0x89, "DW_AT_export_symbols"),
            Self::DwAtDeleted => (0x8a, "DW_AT_deleted"),
            Self::DwAtDefaulted => (0x8b, "DW_AT_defaulted"),
            Self::DwAtLoclistsBase => (0x8c, "DW_AT_loclists_base"),
            Self::DwAtLoUser => (0x2000, "DW_AT_lo_user"),
            Self::DwAtHiUser => (0x3fff, "DW_AT_hi_user"),
            Self::DwAtMipsLinkageName => (0x2007, "DW_AT_MIPS_linkage_name"),
            Self::DwAtGnuCallSiteValue => (0x2111, "DW_AT_GNU_call_site_value"),
            Self::DwAtGnuCallSiteDataValue => (0x2112, "DW_AT_GNU_call_site_data_value"),
            Self::DwAtGnuCallSiteTarget => (0x2113, "DW_AT_GNU_call_site_target"),
            Self::DwAtGnuCallSiteTargetClobbered => {
                (0x2114, "DW_AT_GNU_call_site_target_clobbered")
            }
            Self::DwAtGnuTailCall => (0x2115, "DW_AT_GNU_tail_call"),
            Self::DwAtGnuAllTailCallSites => (0x2116, "DW_AT_GNU_all_tail_call_sites"),
            Self::DwAtGnuAllCallSites => (0x2117, "DW_AT_GNU_all_call_sites"),
            Self::DwAtGnuAllSourceCallSites => (0x2118, "DW_AT_GNU_all_source_call_sites"),
            Self::DwAtGnuMacros => (0x2119, "DW_AT_GNU_macros"),
            Self::DwAtGnuDeleted => (0x211a, "DW_AT_GNU_deleted"),
            Self::DwAtGnuDwoName => (0x2130, "DW_AT_GNU_dwo_name"),
            Self::DwAtGnuDwoId => (0x2131, "DW_AT_GNU_dwo_id"),
            Self::DwAtGnuRangesBase => (0x2132, "DW_AT_GNU_ranges_base"),
            Self::DwAtGnuAddrBase => (0x2133, "DW_AT_GNU_addr_base"),
            Self::DwAtGnuPubnames => (0x2134, "DW_AT_GNU_pubnames"),
            Self::DwAtGnuPubtypes => (0x2135, "DW_AT_GNU_pubtypes"),
            Self::DwAtGnuDiscriminator => (0x2136, "DW_AT_GNU_discriminator"),
            Self::DwAtGnuLocviews => (0x2137, "DW_AT_GNU_locviews"),
            Self::DwAtGnuEntryView => (0x2138, "DW_AT_GNU_entry_view"),
            Self::DwAtGnuAnnotation => (0x2139, "DW_AT_GNU_annotation"),
            Self::DwAtGoKind => (0x2900, "DW_AT_go_kind"),
            Self::DwAtGoKey => (0x2901, "DW_AT_go_key"),
            Self::DwAtGoElem => (0x2902, "DW_AT_go_elem"),
            Self::DwAtGoEmbeddedField => (0x2903, "DW_AT_go_embedded_field"),
            Self::DwAtGoRuntimeType => (0x2904, "DW_AT_go_runtime_type"),
            Self::DwAtGoPackageName => (0x2905, "DW_AT_go_package_name"),
            Self::DwAtGoDictIndex => (0x2906, "DW_AT_go_dict_index"),
            Self::DwAtApplePtrauthKey => (0x3e04, "DW_AT_APPLE_ptrauth_key"),
            Self::DwAtApplePtrauthAddressDiscriminated => {
                (0x3e05, "DW_AT_APPLE_ptrauth_address_discriminated")
            }
            Self::DwAtApplePtrauthExtraDiscriminator => {
                (0x3e06, "DW_AT_APPLE_ptrauth_extra_discriminator")
            }
            Self::DwAtAppleOmitFramePtr => (0x3fe7, "DW_AT_APPLE_omit_frame_ptr"),
            Self::DwAtAppleOptimized => (0x3fe1, "DW_AT_APPLE_optimized"),
        }
    }

    /// The attribute classes this attribute's value may take. Mirrors
    /// `DWARFAttributeId.getAttributeClass()`; attributes declared without any classes in Java
    /// (unconstrained, or reserved/vendor ids Ghidra hasn't classified) report an empty slice
    /// rather than Java's empty `EnumSet`.
    pub fn get_attribute_class(&self) -> &'static [DWARFAttributeClass] {
        match self {
            Self::DwAtSibling => &[Reference],
            Self::DwAtLocation => &[ExprLoc, LocList, Block, Constant],
            Self::DwAtName => &[StringClass],
            Self::DwAtOrdering => &[Constant],
            Self::DwAtByteSize => &[Constant, ExprLoc, Reference],
            Self::DwAtBitSize => &[Constant, ExprLoc, Reference],
            Self::DwAtStmtList => &[LinePtr, Constant],
            Self::DwAtLowPc => &[Address],
            Self::DwAtHighPc => &[Address, Constant],
            Self::DwAtLanguage => &[Constant],
            Self::DwAtDiscr => &[Reference],
            Self::DwAtDiscrValue => &[Constant],
            Self::DwAtVisibility => &[Constant],
            Self::DwAtImport => &[Reference],
            Self::DwAtStringLength => &[ExprLoc, LocList, Reference],
            Self::DwAtCommonReference => &[Reference],
            Self::DwAtCompDir => &[StringClass],
            Self::DwAtConstValue => &[Block, Constant, StringClass],
            Self::DwAtContainingType => &[Reference],
            Self::DwAtDefaultValue => &[Constant, Reference, Flag],
            Self::DwAtInline => &[Constant],
            Self::DwAtIsOptional => &[Flag],
            Self::DwAtLowerBound => &[Constant, ExprLoc, Reference],
            Self::DwAtProducer => &[StringClass],
            Self::DwAtPrototyped => &[Flag],
            Self::DwAtReturnAddr => &[ExprLoc, LocList],
            Self::DwAtStartScope => &[Constant, RngList],
            Self::DwAtBitStride => &[Constant, ExprLoc, Reference],
            Self::DwAtUpperBound => &[Constant, ExprLoc, Reference],
            Self::DwAtAbstractOrigin => &[Reference],
            Self::DwAtAccessibility => &[Constant],
            Self::DwAtAddressClass => &[Constant],
            Self::DwAtArtificial => &[Flag],
            Self::DwAtBaseTypes => &[Reference],
            Self::DwAtCallingConvention => &[Constant],
            Self::DwAtCount => &[Constant, ExprLoc, Reference],
            Self::DwAtDataMemberLocation => &[Constant, ExprLoc, LocList, Block],
            Self::DwAtDeclColumn => &[Constant],
            Self::DwAtDeclFile => &[Constant],
            Self::DwAtDeclLine => &[Constant],
            Self::DwAtDeclaration => &[Flag],
            Self::DwAtDiscrList => &[Block],
            Self::DwAtEncoding => &[Constant],
            Self::DwAtExternal => &[Flag],
            Self::DwAtFrameBase => &[ExprLoc, LocList, Block, Constant],
            Self::DwAtFriend => &[Reference],
            Self::DwAtIdentifierCase => &[Constant],
            Self::DwAtMacroInfo => &[MacPtr],
            Self::DwAtNamelistItem => &[Reference],
            Self::DwAtPriority => &[Reference],
            Self::DwAtSegment => &[ExprLoc, LocList],
            Self::DwAtSpecification => &[Reference],
            Self::DwAtStaticLink => &[ExprLoc, LocList],
            Self::DwAtType => &[Reference],
            Self::DwAtUseLocation => &[ExprLoc, LocList],
            Self::DwAtVariableParameter => &[Flag],
            Self::DwAtVirtuality => &[Constant],
            Self::DwAtVtableElemLocation => &[ExprLoc, LocList, Block],
            Self::DwAtAllocated => &[Constant, ExprLoc, Reference],
            Self::DwAtAssociated => &[Constant, ExprLoc, Reference],
            Self::DwAtDataLocation => &[ExprLoc],
            Self::DwAtByteStride => &[Constant, ExprLoc, Reference],
            Self::DwAtEntryPc => &[Address, Constant],
            Self::DwAtUseUtf8 => &[Flag],
            Self::DwAtExtension => &[Reference],
            Self::DwAtRanges => &[RngList, Constant],
            Self::DwAtTrampoline => &[Address, Flag, Reference, StringClass],
            Self::DwAtCallColumn => &[Constant],
            Self::DwAtCallFile => &[Constant],
            Self::DwAtCallLine => &[Constant],
            Self::DwAtDescription => &[StringClass],
            Self::DwAtBinaryScale => &[Constant],
            Self::DwAtDecimalScale => &[Constant],
            Self::DwAtSmall => &[Reference],
            Self::DwAtDecimalSign => &[Constant],
            Self::DwAtDigitCount => &[Constant],
            Self::DwAtPictureString => &[StringClass],
            Self::DwAtMutable => &[Flag],
            Self::DwAtThreadsScaled => &[Flag],
            Self::DwAtExplicit => &[Flag],
            Self::DwAtObjectPointer => &[Reference],
            Self::DwAtEndianity => &[Constant],
            Self::DwAtElemental => &[Flag],
            Self::DwAtPure => &[Flag],
            Self::DwAtRecursive => &[Flag],
            Self::DwAtSignature => &[Reference],
            Self::DwAtMainSubprogram => &[Flag],
            Self::DwAtDataBitOffset => &[Constant],
            Self::DwAtConstExpr => &[Flag],
            Self::DwAtEnumClass => &[Flag],
            Self::DwAtLinkageName => &[StringClass],
            Self::DwAtStringLengthBitSize => &[Constant],
            Self::DwAtStringLengthByteSize => &[Constant],
            Self::DwAtRank => &[Constant, ExprLoc],
            Self::DwAtStrOffsetsBase => &[StrOffsetsPtr],
            Self::DwAtAddrBase => &[AddrPtr],
            Self::DwAtRnglistsBase => &[RngListsPtr],
            Self::DwAtDwoName => &[StringClass],
            Self::DwAtReference => &[Flag],
            Self::DwAtRvalueReference => &[Flag],
            Self::DwAtMacros => &[MacPtr],
            Self::DwAtCallAllCalls => &[Flag],
            Self::DwAtCallAllSourceCalls => &[Flag],
            Self::DwAtCallAllTailCalls => &[Flag],
            Self::DwAtCallReturnPc => &[Address],
            Self::DwAtCallValue => &[ExprLoc],
            Self::DwAtCallOrigin => &[Reference],
            Self::DwAtCallParameter => &[Reference],
            Self::DwAtCallPc => &[Address],
            Self::DwAtCallTailCall => &[Flag],
            Self::DwAtCallTarget => &[ExprLoc],
            Self::DwAtCallTargetClobbered => &[ExprLoc],
            Self::DwAtCallDataLocation => &[ExprLoc],
            Self::DwAtCallDataValue => &[ExprLoc],
            Self::DwAtNoreturn => &[Flag],
            Self::DwAtAlignment => &[Constant],
            Self::DwAtExportSymbols => &[Flag],
            Self::DwAtDeleted => &[Flag],
            Self::DwAtDefaulted => &[Constant],
            Self::DwAtLoclistsBase => &[LocListsPtr],

            // Declared in Java without any DWARFAttributeClass varargs: bit_offset (dwarf-3),
            // lo_user/hi_user, and every vendor extension (MIPS/GNU/Golang/Apple).
            Self::DwAtBitOffset
            | Self::DwAtLoUser
            | Self::DwAtHiUser
            | Self::DwAtMipsLinkageName
            | Self::DwAtGnuCallSiteValue
            | Self::DwAtGnuCallSiteDataValue
            | Self::DwAtGnuCallSiteTarget
            | Self::DwAtGnuCallSiteTargetClobbered
            | Self::DwAtGnuTailCall
            | Self::DwAtGnuAllTailCallSites
            | Self::DwAtGnuAllCallSites
            | Self::DwAtGnuAllSourceCallSites
            | Self::DwAtGnuMacros
            | Self::DwAtGnuDeleted
            | Self::DwAtGnuDwoName
            | Self::DwAtGnuDwoId
            | Self::DwAtGnuRangesBase
            | Self::DwAtGnuAddrBase
            | Self::DwAtGnuPubnames
            | Self::DwAtGnuPubtypes
            | Self::DwAtGnuDiscriminator
            | Self::DwAtGnuLocviews
            | Self::DwAtGnuEntryView
            | Self::DwAtGnuAnnotation
            | Self::DwAtGoKind
            | Self::DwAtGoKey
            | Self::DwAtGoElem
            | Self::DwAtGoEmbeddedField
            | Self::DwAtGoRuntimeType
            | Self::DwAtGoPackageName
            | Self::DwAtGoDictIndex
            | Self::DwAtApplePtrauthKey
            | Self::DwAtApplePtrauthAddressDiscriminated
            | Self::DwAtApplePtrauthExtraDiscriminator
            | Self::DwAtAppleOmitFramePtr
            | Self::DwAtAppleOptimized => &[],
        }
    }

    /// Find the attribute id given its raw int id. Mirrors `DWARFAttributeId.of(int)`, returning
    /// [`None`] where Java returns `null`.
    pub fn of(attribute_int: i32) -> Option<DWARFAttributeId> {
        Self::VALUES.into_iter().find(|attr| attr.get_id() == attribute_int)
    }
}

impl fmt::Display for DWARFAttributeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Represents how a specific DWARF attribute is stored in a DIE record. Mirrors the nested
/// `DWARFAttributeId.AttrDef`, a concrete specialization (for `E = DWARFAttributeId`) of the
/// generic, still-unported `DWARFAttributeDef<E extends Enum<E>>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrDef {
    attribute_id: Option<DWARFAttributeId>,
    raw_attribute_id: i32,
    attribute_form: DWARFForm,
    implicit_value: i64,
}

impl AttrDef {
    /// Mirrors the `AttrDef(DWARFAttributeId, int, DWARFForm, long)` constructor.
    pub fn new(
        attribute_id: Option<DWARFAttributeId>,
        raw_attribute_id: i32,
        attribute_form: DWARFForm,
        implicit_value: i64,
    ) -> Self {
        AttrDef { attribute_id, raw_attribute_id, attribute_form, implicit_value }
    }

    /// Reads an [`AttrDef`] instance from `reader`. Returns `Ok(None)` for an end-of-list marker.
    ///
    /// Mirrors `DWARFAttributeId.AttrDef.read(BinaryReader)`, inlining the generic
    /// `DWARFAttributeDef.read(BinaryReader, Function)` logic it delegates to in Java (specialized
    /// to `DWARFAttributeId::of` as the id mapper), since that generic base class isn't ported yet.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Option<AttrDef>> {
        let raw_attribute_id = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
        let form_id = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;

        if raw_attribute_id == EOL && form_id == dwarf_form::EOL {
            // end of attributespec list
            return Ok(None);
        }

        let attribute_form = DWARFForm::of(form_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown DWARFForm {form_id} (0x{form_id:x})"),
            )
        })?;

        let attribute_id = DWARFAttributeId::of(raw_attribute_id);

        // NOTE: implicit value is a space saving hack built into DWARF. It adds an extra field in
        // the attributespec that needs to be read now in the .debug_abbr. This is different than
        // DW_FORM_indirect, which is read from the DIE in .debug_info.
        let implicit_value = if attribute_form == DWARFForm::DwFormImplicitConst {
            LEB128Info::signed(reader)?.as_long()
        } else {
            0
        };

        Ok(Some(AttrDef { attribute_id, raw_attribute_id, attribute_form, implicit_value }))
    }

    /// Get the attribute id of the attribute specification. Mirrors
    /// `DWARFAttributeDef.getAttributeId()`.
    pub fn get_attribute_id(&self) -> Option<DWARFAttributeId> {
        self.attribute_id
    }

    /// Mirrors `DWARFAttributeDef.getRawAttributeId()`.
    pub fn get_raw_attribute_id(&self) -> i32 {
        self.raw_attribute_id
    }

    /// Mirrors `DWARFAttributeDef.getAttributeName()`.
    pub fn get_attribute_name(&self) -> String {
        match self.attribute_id {
            Some(id) => id.name().to_string(),
            None => self.raw_attribute_id_description(),
        }
    }

    /// Mirrors the overridden `AttrDef.getRawAttributeIdDescription()`.
    fn raw_attribute_id_description(&self) -> String {
        format!("DW_AT_???? {0} (0x{0:x})", self.raw_attribute_id)
    }

    /// Get the form of the attribute specification. Mirrors `DWARFAttributeDef.getAttributeForm()`.
    pub fn get_attribute_form(&self) -> DWARFForm {
        self.attribute_form
    }

    /// Mirrors `DWARFAttributeDef.isImplicit()`.
    pub fn is_implicit(&self) -> bool {
        self.attribute_form == DWARFForm::DwFormImplicitConst
    }

    /// Mirrors `DWARFAttributeDef.getImplicitValue()`.
    pub fn get_implicit_value(&self) -> i64 {
        self.implicit_value
    }

    /// Mirrors the overridden `AttrDef.withForm(DWARFForm)`.
    pub fn with_form(&self, new_form: DWARFForm) -> AttrDef {
        AttrDef { attribute_form: new_form, ..*self }
    }
}

impl DWARFAttributeDef for AttrDef {
    fn get_attribute_form(&self) -> DWARFForm {
        self.attribute_form
    }

    fn get_implicit_value(&self) -> i64 {
        self.implicit_value
    }

    fn with_form(&self, new_form: DWARFForm) -> Box<dyn DWARFAttributeDef> {
        Box::new(AttrDef::with_form(self, new_form))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(length).unwrap_or(usize::MAX);
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0 }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index })
        }
    }

    #[test]
    fn ids_match_the_dwarf_spec_and_of_round_trips() {
        // Spot-check ids against the DWARF standard / the Java enum's declarations.
        assert_eq!(DWARFAttributeId::DwAtSibling.get_id(), 0x1);
        assert_eq!(DWARFAttributeId::DwAtName.get_id(), 0x3);
        assert_eq!(DWARFAttributeId::DwAtLoclistsBase.get_id(), 0x8c);
        assert_eq!(DWARFAttributeId::DwAtLoUser.get_id(), 0x2000);
        assert_eq!(DWARFAttributeId::DwAtMipsLinkageName.get_id(), 0x2007);
        assert_eq!(DWARFAttributeId::DwAtGnuAnnotation.get_id(), 0x2139);
        assert_eq!(DWARFAttributeId::DwAtGoDictIndex.get_id(), 0x2906);
        assert_eq!(DWARFAttributeId::DwAtAppleOptimized.get_id(), 0x3fe1);

        assert_eq!(DWARFAttributeId::VALUES.len(), 156);
        for attr in DWARFAttributeId::VALUES {
            assert_eq!(DWARFAttributeId::of(attr.get_id()), Some(attr), "of() round trip for {attr}");
        }

        // 0xa (DW_AT_subscr_data) and 0x14 (DW_AT_member) are commented out in the Java source.
        assert_eq!(DWARFAttributeId::of(0xa), None);
        assert_eq!(DWARFAttributeId::of(0x14), None);
        assert_eq!(DWARFAttributeId::of(0x7fff_ffff), None);
    }

    #[test]
    fn names_match_the_java_enum_constant_spelling() {
        assert_eq!(DWARFAttributeId::DwAtUseUtf8.name(), "DW_AT_use_UTF8");
        assert_eq!(DWARFAttributeId::DwAtMipsLinkageName.name(), "DW_AT_MIPS_linkage_name");
        assert_eq!(DWARFAttributeId::DwAtGnuDwoId.name(), "DW_AT_GNU_dwo_id");
        assert_eq!(DWARFAttributeId::DwAtGoKind.name(), "DW_AT_go_kind");
        assert_eq!(DWARFAttributeId::DwAtApplePtrauthKey.name(), "DW_AT_APPLE_ptrauth_key");
        assert_eq!(format!("{}", DWARFAttributeId::DwAtName), "DW_AT_name");
    }

    #[test]
    fn attribute_classes_match_the_java_declarations() {
        assert_eq!(DWARFAttributeId::DwAtSibling.get_attribute_class(), &[Reference]);
        assert_eq!(
            DWARFAttributeId::DwAtLocation.get_attribute_class(),
            &[ExprLoc, LocList, Block, Constant]
        );
        assert_eq!(
            DWARFAttributeId::DwAtTrampoline.get_attribute_class(),
            &[Address, Flag, Reference, StringClass]
        );

        // Attributes declared with no varargs report an empty class list.
        assert!(DWARFAttributeId::DwAtBitOffset.get_attribute_class().is_empty());
        assert!(DWARFAttributeId::DwAtLoUser.get_attribute_class().is_empty());
        assert!(DWARFAttributeId::DwAtGnuDwoName.get_attribute_class().is_empty());
        assert!(DWARFAttributeId::DwAtAppleOptimized.get_attribute_class().is_empty());
    }

    #[test]
    fn attr_def_read_recognizes_the_eol_marker() {
        // Both attribute id and form are 0 (EOL/EOL): DWARFAttributeDef.read returns null.
        let mut reader = TestReader::new(vec![0x00, 0x00]);
        assert_eq!(AttrDef::read(&mut reader).unwrap(), None);
        assert_eq!(reader.get_pointer_index(), 2);
    }

    #[test]
    fn attr_def_read_decodes_a_known_attribute_and_form() {
        // DW_AT_name (0x3), DW_FORM_string (0x8), both single-byte ULEB128s.
        let mut reader = TestReader::new(vec![0x03, 0x08]);
        let def = AttrDef::read(&mut reader).unwrap().expect("not an EOL marker");

        assert_eq!(def.get_attribute_id(), Some(DWARFAttributeId::DwAtName));
        assert_eq!(def.get_raw_attribute_id(), 0x3);
        assert_eq!(def.get_attribute_form(), DWARFForm::DwFormString);
        assert_eq!(def.get_attribute_name(), "DW_AT_name");
        assert!(!def.is_implicit());
        assert_eq!(def.get_implicit_value(), 0);
    }

    #[test]
    fn attr_def_read_reports_unrecognized_forms() {
        // DW_AT_name (0x3) paired with form code 0x02, DWARF v1's unsupported DW_FORM_ref.
        let mut reader = TestReader::new(vec![0x03, 0x02]);
        let err = AttrDef::read(&mut reader).unwrap_err();
        assert!(err.to_string().contains("0x2"), "{err}");
    }

    #[test]
    fn attr_def_read_tolerates_an_unknown_attribute_id() {
        // Attribute id 0x1000 isn't a DWARFAttributeId constant, paired with DW_FORM_flag (0xc).
        let mut reader = TestReader::new(vec![0x80, 0x20, 0x0c]);
        let def = AttrDef::read(&mut reader).unwrap().expect("not an EOL marker");

        assert_eq!(def.get_attribute_id(), None);
        assert_eq!(def.get_raw_attribute_id(), 0x1000);
        assert_eq!(def.get_attribute_name(), "DW_AT_???? 4096 (0x1000)");
    }

    #[test]
    fn attr_def_read_decodes_the_implicit_value_for_implicit_const() {
        // DW_AT_const_value (0x1c), DW_FORM_implicit_const (0x21), then a signed LEB128 implicit
        // value of -1 (0x7f).
        let mut reader = TestReader::new(vec![0x1c, 0x21, 0x7f]);
        let def = AttrDef::read(&mut reader).unwrap().expect("not an EOL marker");

        assert!(def.is_implicit());
        assert_eq!(def.get_implicit_value(), -1);
        assert_eq!(reader.get_pointer_index(), 3);
    }

    #[test]
    fn with_form_retargets_only_the_form() {
        let def = AttrDef::new(Some(DWARFAttributeId::DwAtName), 0x3, DWARFForm::DwFormString, 0);
        let retargeted = def.with_form(DWARFForm::DwFormStrp);

        assert_eq!(retargeted.get_attribute_id(), Some(DWARFAttributeId::DwAtName));
        assert_eq!(retargeted.get_raw_attribute_id(), 0x3);
        assert_eq!(retargeted.get_attribute_form(), DWARFForm::DwFormStrp);

        let boxed: Box<dyn DWARFAttributeDef> = DWARFAttributeDef::with_form(&def, DWARFForm::DwFormStrp);
        assert_eq!(boxed.get_attribute_form(), DWARFForm::DwFormStrp);
    }
}
