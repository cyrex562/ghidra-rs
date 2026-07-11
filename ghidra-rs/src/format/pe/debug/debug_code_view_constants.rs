/// Constants defined in Code View debug information.

/// Signature bytes for .NET CodeView data ("RS").
pub const SIGNATURE_DOT_NET: u32 = 0x5253;
/// Signature bytes for N1 CodeView data ("N1").
pub const SIGNATURE_N1: u32 = 0x4e31;
/// Signature bytes for NB CodeView data ("NB").
pub const SIGNATURE_NB: u32 = 0x4e42;

/// CodeView version 0.9 ("09").
pub const VERSION_09: u32 = 0x3039;
/// CodeView version 1.0 ("10").
pub const VERSION_10: u32 = 0x3130;
/// CodeView version 1.1 ("11").
pub const VERSION_11: u32 = 0x3131;
/// CodeView version 1.2 ("12").
pub const VERSION_12: u32 = 0x3140;
/// CodeView version 1.3 ("13").
pub const VERSION_13: u32 = 0x30f0;
/// CodeView .NET version ("DS").
pub const VERSION_DOT_NET: u32 = 0x4453;

/// OMF subsection: module.
pub const SST_MODULE: u32 = 0x120;
/// OMF subsection: types.
pub const SST_TYPES: u32 = 0x121;
/// OMF subsection: public symbols.
pub const SST_PUBLIC: u32 = 0x122;
/// OMF subsection: publics as symbols (waiting for link).
pub const SST_PUBLIC_SYM: u32 = 0x123;
/// OMF subsection: symbols.
pub const SST_SYMBOLS: u32 = 0x124;
/// OMF subsection: aligned symbols.
pub const SST_ALIGN_SYM: u32 = 0x125;
/// OMF subsection: source line/segment (because link doesn't emit SrcModule).
pub const SST_SRC_LN_SEG: u32 = 0x126;
/// OMF subsection: source module.
pub const SST_SRC_MODULE: u32 = 0x127;
/// OMF subsection: libraries.
pub const SST_LIBRARIES: u32 = 0x128;
/// OMF subsection: global symbols.
pub const SST_GLOBAL_SYM: u32 = 0x129;
/// OMF subsection: global publics.
pub const SST_GLOBAL_PUB: u32 = 0x12a;
/// OMF subsection: global types.
pub const SST_GLOBAL_TYPES: u32 = 0x12b;
/// OMF subsection: MPC.
pub const SST_MPC: u32 = 0x12c;
/// OMF subsection: segment map.
pub const SST_SEG_MAP: u32 = 0x12d;
/// OMF subsection: segment names.
pub const SST_SEG_NAME: u32 = 0x12e;
/// OMF subsection: precompiled types.
pub const SST_PRE_COMP: u32 = 0x12f;
/// OMF subsection: map precompiled types in global types.
pub const SST_PRE_COMP_MAP: u32 = 0x130;
/// OMF subsection: 16-bit offset map.
pub const SST_OFFSET_MAP16: u32 = 0x131;
/// OMF subsection: 32-bit offset map.
pub const SST_OFFSET_MAP32: u32 = 0x132;
/// OMF subsection: index of file names.
pub const SST_FILE_INDEX: u32 = 0x133;
/// OMF subsection: static symbols.
pub const SST_STATIC_SYM: u32 = 0x134;

/// Compile flags symbol.
pub const S_COMPILE: u32 = 0x0001;
/// Register variable.
pub const S_REGISTER: u32 = 0x0002;
/// Constant symbol.
pub const S_CONSTANT: u32 = 0x0003;
/// User defined type.
pub const S_UDT: u32 = 0x0004;
/// Start search.
pub const S_SSEARCH: u32 = 0x0005;
/// Block, procedure, "with", or thunk end.
pub const S_END: u32 = 0x0006;
/// Reserve symbol space in $$Symbols table.
pub const S_SKIP: u32 = 0x0007;
/// Reserved symbol for CV internal use.
pub const S_CVRESERVE: u32 = 0x0008;
/// Path to object file name.
pub const S_OBJNAME: u32 = 0x0009;
/// End of argument/return list.
pub const S_ENDARG: u32 = 0x000a;
/// Special UDT for COBOL that does not symbol pack.
pub const S_COBOLUDT: u32 = 0x000b;
/// Multiple register variable.
pub const S_MANYREG: u32 = 0x000c;
/// Return description symbol.
pub const S_RETURN: u32 = 0x000d;
/// Description of this pointer on entry.
pub const S_ENTRYTHIS: u32 = 0x000e;

/// BP-relative (16-bit).
pub const S_BPREL16: u32 = 0x0100;
/// Module-local symbol (16-bit).
pub const S_LDATA16: u32 = 0x0101;
/// Global data symbol (16-bit).
pub const S_GDATA16: u32 = 0x0102;
/// Public symbol (16-bit).
pub const S_PUB16: u32 = 0x0103;
/// Local procedure start (16-bit).
pub const S_LPROC16: u32 = 0x0104;
/// Global procedure start (16-bit).
pub const S_GPROC16: u32 = 0x0105;
/// Thunk start (16-bit).
pub const S_THUNK16: u32 = 0x0106;
/// Block start (16-bit).
pub const S_BLOCK16: u32 = 0x0107;
/// With start (16-bit).
pub const S_WITH16: u32 = 0x0108;
/// Code label (16-bit).
pub const S_LABEL16: u32 = 0x0109;
/// Change execution model (16-bit).
pub const S_CEXMODEL16: u32 = 0x010a;
/// Address of virtual function table (16-bit).
pub const S_VFTABLE16: u32 = 0x010b;
/// Register relative address (16-bit).
pub const S_REGREL16: u32 = 0x010c;

/// BP-relative (32-bit).
pub const S_BPREL32: u32 = 0x0200;
/// Module-local symbol (32-bit).
pub const S_LDATA32: u32 = 0x0201;
/// Global data symbol (32-bit).
pub const S_GDATA32: u32 = 0x0202;
/// Public symbol (32-bit, CV internal reserved).
pub const S_PUB32: u32 = 0x0203;
/// Local procedure start (32-bit).
pub const S_LPROC32: u32 = 0x0204;
/// Global procedure start (32-bit).
pub const S_GPROC32: u32 = 0x0205;
/// Thunk start (32-bit).
pub const S_THUNK32: u32 = 0x0206;
/// Block start (32-bit).
pub const S_BLOCK32: u32 = 0x0207;
/// With start (32-bit).
pub const S_WITH32: u32 = 0x0208;
/// Code label (32-bit).
pub const S_LABEL32: u32 = 0x0209;
/// Change execution model (32-bit).
pub const S_CEXMODEL32: u32 = 0x020a;
/// Address of virtual function table (32-bit).
pub const S_VFTABLE32: u32 = 0x020b;
/// Register relative address (32-bit).
pub const S_REGREL32: u32 = 0x020c;
/// Local thread storage (32-bit).
pub const S_LTHREAD32: u32 = 0x020d;
/// Global thread storage (32-bit).
pub const S_GTHREAD32: u32 = 0x020e;
/// Static link for MIPS EH implementation (32-bit).
pub const S_SLINK32: u32 = 0x020f;

/// Local procedure start (MIPS).
pub const S_LPROCMIPS: u32 = 0x0300;
/// Global procedure start (MIPS).
pub const S_GPROCMIPS: u32 = 0x0301;

/// Reference to a procedure.
pub const S_PROCREF: u32 = 0x0400;
/// Reference to data.
pub const S_DATAREF: u32 = 0x0401;
/// Used for page alignment of symbol.
pub const S_ALIGN: u32 = 0x0402;
/// Maybe reference to a local procedure.
pub const S_LPROCREF: u32 = 0x0403;

/// Register variable (new CV).
pub const S_REGISTER32: u32 = 0x1001;
/// Constant symbol (new CV).
pub const S_CONSTANT32: u32 = 0x1002;
/// User defined type (new CV).
pub const S_UDT32: u32 = 0x1003;
/// Special UDT for COBOL that does not symbol pack (new CV).
pub const S_COBOLUDT32: u32 = 0x1004;
/// Multiple register variable (new CV).
pub const S_MANYREG32: u32 = 0x1005;
/// New CV info for BP-relative.
pub const S_BPREL32_NEW: u32 = 0x1006;
/// New CV info for module-local symbol.
pub const S_LDATA32_NEW: u32 = 0x1007;
/// New CV info for global data symbol.
pub const S_GDATA32_NEW: u32 = 0x1008;
/// Newer CV info for public symbol (defined after 1994).
pub const S_PUBSYM32_NEW: u32 = 0x1009;
/// New CV info for local procedure start.
pub const S_LPROC32_NEW: u32 = 0x100a;
/// New CV info for global procedure start.
pub const S_GPROC32_NEW: u32 = 0x100b;
/// New CV info for address of virtual function table.
pub const S_VFTABLE32_NEW: u32 = 0x100c;
/// New CV info for register relative address.
pub const S_REGREL32_NEW: u32 = 0x100d;
/// New CV info for local thread storage.
pub const S_LTHREAD32_NEW: u32 = 0x100e;
/// New CV info for global thread storage.
pub const S_GTHREAD32_NEW: u32 = 0x100f;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures() {
        assert_eq!(SIGNATURE_DOT_NET, 0x5253);
        assert_eq!(SIGNATURE_N1, 0x4e31);
        assert_eq!(SIGNATURE_NB, 0x4e42);
    }

    #[test]
    fn versions() {
        assert_eq!(VERSION_09, 0x3039);
        assert_eq!(VERSION_10, 0x3130);
        assert_eq!(VERSION_11, 0x3131);
        assert_eq!(VERSION_12, 0x3140);
        assert_eq!(VERSION_13, 0x30f0);
        assert_eq!(VERSION_DOT_NET, 0x4453);
    }

    #[test]
    fn sst_subsections() {
        assert_eq!(SST_MODULE, 0x120);
        assert_eq!(SST_TYPES, 0x121);
        assert_eq!(SST_PUBLIC, 0x122);
        assert_eq!(SST_PUBLIC_SYM, 0x123);
        assert_eq!(SST_SYMBOLS, 0x124);
        assert_eq!(SST_ALIGN_SYM, 0x125);
        assert_eq!(SST_SRC_LN_SEG, 0x126);
        assert_eq!(SST_SRC_MODULE, 0x127);
        assert_eq!(SST_LIBRARIES, 0x128);
        assert_eq!(SST_GLOBAL_SYM, 0x129);
        assert_eq!(SST_GLOBAL_PUB, 0x12a);
        assert_eq!(SST_GLOBAL_TYPES, 0x12b);
        assert_eq!(SST_MPC, 0x12c);
        assert_eq!(SST_SEG_MAP, 0x12d);
        assert_eq!(SST_SEG_NAME, 0x12e);
        assert_eq!(SST_PRE_COMP, 0x12f);
        assert_eq!(SST_PRE_COMP_MAP, 0x130);
        assert_eq!(SST_OFFSET_MAP16, 0x131);
        assert_eq!(SST_OFFSET_MAP32, 0x132);
        assert_eq!(SST_FILE_INDEX, 0x133);
        assert_eq!(SST_STATIC_SYM, 0x134);
    }

    #[test]
    fn s_general_symbols() {
        assert_eq!(S_COMPILE, 0x0001);
        assert_eq!(S_REGISTER, 0x0002);
        assert_eq!(S_CONSTANT, 0x0003);
        assert_eq!(S_UDT, 0x0004);
        assert_eq!(S_SSEARCH, 0x0005);
        assert_eq!(S_END, 0x0006);
        assert_eq!(S_SKIP, 0x0007);
        assert_eq!(S_CVRESERVE, 0x0008);
        assert_eq!(S_OBJNAME, 0x0009);
        assert_eq!(S_ENDARG, 0x000a);
        assert_eq!(S_COBOLUDT, 0x000b);
        assert_eq!(S_MANYREG, 0x000c);
        assert_eq!(S_RETURN, 0x000d);
        assert_eq!(S_ENTRYTHIS, 0x000e);
    }

    #[test]
    fn s_16bit_symbols() {
        assert_eq!(S_BPREL16, 0x0100);
        assert_eq!(S_LDATA16, 0x0101);
        assert_eq!(S_GDATA16, 0x0102);
        assert_eq!(S_PUB16, 0x0103);
        assert_eq!(S_LPROC16, 0x0104);
        assert_eq!(S_GPROC16, 0x0105);
        assert_eq!(S_THUNK16, 0x0106);
        assert_eq!(S_BLOCK16, 0x0107);
        assert_eq!(S_WITH16, 0x0108);
        assert_eq!(S_LABEL16, 0x0109);
        assert_eq!(S_CEXMODEL16, 0x010a);
        assert_eq!(S_VFTABLE16, 0x010b);
        assert_eq!(S_REGREL16, 0x010c);
    }

    #[test]
    fn s_32bit_symbols() {
        assert_eq!(S_BPREL32, 0x0200);
        assert_eq!(S_LDATA32, 0x0201);
        assert_eq!(S_GDATA32, 0x0202);
        assert_eq!(S_PUB32, 0x0203);
        assert_eq!(S_LPROC32, 0x0204);
        assert_eq!(S_GPROC32, 0x0205);
        assert_eq!(S_THUNK32, 0x0206);
        assert_eq!(S_BLOCK32, 0x0207);
        assert_eq!(S_WITH32, 0x0208);
        assert_eq!(S_LABEL32, 0x0209);
        assert_eq!(S_CEXMODEL32, 0x020a);
        assert_eq!(S_VFTABLE32, 0x020b);
        assert_eq!(S_REGREL32, 0x020c);
        assert_eq!(S_LTHREAD32, 0x020d);
        assert_eq!(S_GTHREAD32, 0x020e);
        assert_eq!(S_SLINK32, 0x020f);
    }

    #[test]
    fn s_mips_and_ref_symbols() {
        assert_eq!(S_LPROCMIPS, 0x0300);
        assert_eq!(S_GPROCMIPS, 0x0301);
        assert_eq!(S_PROCREF, 0x0400);
        assert_eq!(S_DATAREF, 0x0401);
        assert_eq!(S_ALIGN, 0x0402);
        assert_eq!(S_LPROCREF, 0x0403);
    }

    #[test]
    fn s_new_cv_symbols() {
        assert_eq!(S_REGISTER32, 0x1001);
        assert_eq!(S_CONSTANT32, 0x1002);
        assert_eq!(S_UDT32, 0x1003);
        assert_eq!(S_COBOLUDT32, 0x1004);
        assert_eq!(S_MANYREG32, 0x1005);
        assert_eq!(S_BPREL32_NEW, 0x1006);
        assert_eq!(S_LDATA32_NEW, 0x1007);
        assert_eq!(S_GDATA32_NEW, 0x1008);
        assert_eq!(S_PUBSYM32_NEW, 0x1009);
        assert_eq!(S_LPROC32_NEW, 0x100a);
        assert_eq!(S_GPROC32_NEW, 0x100b);
        assert_eq!(S_VFTABLE32_NEW, 0x100c);
        assert_eq!(S_REGREL32_NEW, 0x100d);
        assert_eq!(S_LTHREAD32_NEW, 0x100e);
        assert_eq!(S_GTHREAD32_NEW, 0x100f);
    }
}
