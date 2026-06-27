/// Mask for symbolic debugging entry bits in n_type.
pub const MASK_N_STAB: u32 = 0xe0;
/// Private external symbol bit in n_type.
pub const MASK_N_PEXT: u32 = 0x10;
/// Mask for the type bits in n_type.
pub const MASK_N_TYPE: u32 = 0x0e;
/// External symbol bit in n_type.
pub const MASK_N_EXT: u32 = 0x01;

/// Undefined symbol; n_sect == NO_SECT.
pub const TYPE_N_UNDF: u8 = 0x0;
/// Absolute symbol; n_sect == NO_SECT.
pub const TYPE_N_ABS: u8 = 0x2;
/// Indirect symbol.
pub const TYPE_N_INDR: u8 = 0xa;
/// Prebound undefined (defined in a dylib).
pub const TYPE_N_PBUD: u8 = 0xc;
/// Defined in section number n_sect.
pub const TYPE_N_SECT: u8 = 0xe;

/// Mask for reference type bits of the n_desc field of undefined symbols.
pub const REFERENCE_TYPE: u32 = 0x7;

pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u32 = 0x0;
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u32 = 0x1;
pub const REFERENCE_FLAG_DEFINED: u32 = 0x2;
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u32 = 0x3;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u32 = 0x4;
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u32 = 0x5;

pub const REFERENCED_DYNAMICALLY: u32 = 0x0010;

/// Symbol is not in any section.
pub const NO_SECT: u8 = 0;

/// Symbol is not to be dead stripped / symbol is discarded.
pub const DESC_N_NO_DEAD_STRIP: u16 = 0x0020;
/// Symbol is discarded.
pub const DESC_N_DESC_DISCARDED: u16 = 0x0020;
/// Symbol is weak referenced.
pub const DESC_N_WEAK_REF: u16 = 0x0040;
/// Coalesced symbol is a weak definition.
pub const DESC_N_WEAK_DEF: u16 = 0x0080;
/// Reference to a weak symbol.
pub const DESC_N_REF_TO_WEAK: u16 = 0x0080;
pub const DESC_N_ARM_THUMB_DEF: u16 = 0x0008;

// Symbolic debugger symbols

/// Global symbol: name,,NO_SECT,type,0
pub const DEBUG_N_GSYM: u8 = 0x20;
/// Procedure name (f77 kludge): name,,NO_SECT,0,0
pub const DEBUG_N_FNAME: u8 = 0x22;
/// Procedure: name,,n_sect,linenumber,address
pub const DEBUG_N_FUN: u8 = 0x24;
/// Static symbol: name,,n_sect,type,address
pub const DEBUG_N_STSYM: u8 = 0x26;
/// .lcomm symbol: name,,n_sect,type,address
pub const DEBUG_N_LCSYM: u8 = 0x28;
/// Begin nsect sym: 0,,n_sect,0,address
pub const DEBUG_N_BNSYM: u8 = 0x2e;
/// Emitted with gcc2_compiled and in gcc source.
pub const DEBUG_N_OPT: u8 = 0x3c;
/// Register sym: name,,NO_SECT,type,register
pub const DEBUG_N_RSYM: u8 = 0x40;
/// Src line: 0,,n_sect,linenumber,address
pub const DEBUG_N_SLINE: u8 = 0x44;
/// End nsect sym: 0,,n_sect,0,address
pub const DEBUG_N_ENSYM: u8 = 0x4e;
/// Structure elt: name,,NO_SECT,type,struct_offset
pub const DEBUG_N_SSYM: u8 = 0x60;
/// Source file name: name,,n_sect,0,address
pub const DEBUG_N_SO: u8 = 0x64;
/// Object file name: name,,0,0,st_mtime
pub const DEBUG_N_OSO: u8 = 0x66;
/// Local sym: name,,NO_SECT,type,offset
pub const DEBUG_N_LSYM: u8 = 0x80;
/// Include file beginning: name,,NO_SECT,0,sum
pub const DEBUG_N_BINCL: u8 = 0x82;
/// #included file name: name,,n_sect,0,address
pub const DEBUG_N_SOL: u8 = 0x84;
/// Compiler parameters: name,,NO_SECT,0,0
pub const DEBUG_N_PARAMS: u8 = 0x86;
/// Compiler version: name,,NO_SECT,0,0
pub const DEBUG_N_VERSION: u8 = 0x88;
/// Compiler -O level: name,,NO_SECT,0,0
pub const DEBUG_N_OLEVEL: u8 = 0x8a;
/// Parameter: name,,NO_SECT,type,offset
pub const DEBUG_N_PSYM: u8 = 0xa0;
/// Include file end: name,,NO_SECT,0,0
pub const DEBUG_N_EINCL: u8 = 0xa2;
/// Alternate entry: name,,n_sect,linenumber,address
pub const DEBUG_N_ENTRY: u8 = 0xa4;
/// Left bracket: 0,,NO_SECT,nesting level,address
pub const DEBUG_N_LBRAC: u8 = 0xc0;
/// Deleted include file: name,,NO_SECT,0,sum
pub const DEBUG_N_EXCL: u8 = 0xc2;
/// Right bracket: 0,,NO_SECT,nesting level,address
pub const DEBUG_N_RBRAC: u8 = 0xe0;
/// Begin common: name,,NO_SECT,0,0
pub const DEBUG_N_BCOMM: u8 = 0xe2;
/// End common: name,,n_sect,0,0
pub const DEBUG_N_ECOMM: u8 = 0xe4;
/// End common (local name): 0,,n_sect,0,address
pub const DEBUG_N_ECOML: u8 = 0xe8;
/// Second stab entry with length information.
pub const DEBUG_N_LENG: u8 = 0xfe;

pub const SELF_LIBRARY_ORDINAL: u8 = 0x00;
pub const MAX_LIBRARY_ORDINAL: u8 = 0xfd;
pub const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xfe;
pub const EXECUTABLE_ORDINAL: u8 = 0xff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n_type_masks_cover_full_byte() {
        assert_eq!(MASK_N_STAB | MASK_N_PEXT | MASK_N_TYPE | MASK_N_EXT, 0xff);
    }

    #[test]
    fn n_type_masks_are_disjoint() {
        let masks = [MASK_N_STAB, MASK_N_PEXT, MASK_N_TYPE, MASK_N_EXT];
        for i in 0..masks.len() {
            for j in 0..masks.len() {
                if i != j {
                    assert_eq!(masks[i] & masks[j], 0, "masks[{i}] and masks[{j}] overlap");
                }
            }
        }
    }

    #[test]
    fn type_constants_fit_in_n_type_mask() {
        let types = [TYPE_N_UNDF, TYPE_N_ABS, TYPE_N_INDR, TYPE_N_PBUD, TYPE_N_SECT];
        for t in types {
            assert_eq!(u32::from(t) & !MASK_N_TYPE, 0, "type 0x{t:x} exceeds MASK_N_TYPE");
        }
    }

    #[test]
    fn reference_type_mask_value() {
        assert_eq!(REFERENCE_TYPE, 0x7);
    }

    #[test]
    fn reference_flags_within_mask() {
        let flags = [
            REFERENCE_FLAG_UNDEFINED_NON_LAZY,
            REFERENCE_FLAG_UNDEFINED_LAZY,
            REFERENCE_FLAG_DEFINED,
            REFERENCE_FLAG_PRIVATE_DEFINED,
            REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY,
            REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY,
        ];
        for f in flags {
            assert_eq!(f & !REFERENCE_TYPE, 0, "flag 0x{f:x} exceeds REFERENCE_TYPE mask");
        }
    }

    #[test]
    fn no_sect_is_zero() {
        assert_eq!(NO_SECT, 0);
    }

    #[test]
    fn library_ordinal_ordering() {
        assert!(SELF_LIBRARY_ORDINAL < MAX_LIBRARY_ORDINAL);
        assert!(MAX_LIBRARY_ORDINAL < DYNAMIC_LOOKUP_ORDINAL);
        assert!(DYNAMIC_LOOKUP_ORDINAL < EXECUTABLE_ORDINAL);
    }

    #[test]
    fn debug_stab_constants_have_stab_bit_set() {
        let stabs: &[u8] = &[
            DEBUG_N_GSYM, DEBUG_N_FNAME, DEBUG_N_FUN, DEBUG_N_STSYM, DEBUG_N_LCSYM,
            DEBUG_N_BNSYM, DEBUG_N_OPT, DEBUG_N_RSYM, DEBUG_N_SLINE, DEBUG_N_ENSYM,
            DEBUG_N_SSYM, DEBUG_N_SO, DEBUG_N_OSO, DEBUG_N_LSYM, DEBUG_N_BINCL,
            DEBUG_N_SOL, DEBUG_N_PARAMS, DEBUG_N_VERSION, DEBUG_N_OLEVEL, DEBUG_N_PSYM,
            DEBUG_N_EINCL, DEBUG_N_ENTRY, DEBUG_N_LBRAC, DEBUG_N_EXCL, DEBUG_N_RBRAC,
            DEBUG_N_BCOMM, DEBUG_N_ECOMM, DEBUG_N_ECOML, DEBUG_N_LENG,
        ];
        for &s in stabs {
            assert_ne!(u32::from(s) & MASK_N_STAB, 0, "stab 0x{s:x} missing stab bits");
        }
    }
}
