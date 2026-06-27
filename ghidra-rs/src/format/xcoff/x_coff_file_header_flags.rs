/// Relocation info stripped from file.
pub const F_RELFLG: u16 = 0x0001;
/// File is executable (no unresolved external references).
pub const F_EXEC: u16 = 0x0002;
/// Line numbers stripped from file.
pub const F_LNNO: u16 = 0x0004;
/// Local symbols stripped from file.
pub const F_LSYMS: u16 = 0x0008;
/// File was profiled with fdpr command.
pub const F_FDPR_PROF: u16 = 0x0010;
/// File was reordered with fdpr command.
pub const F_FDPR_OPTI: u16 = 0x0020;
/// File uses Very Large Program Support.
pub const F_DSA: u16 = 0x0040;
/// File is 16-bit little-endian.
pub const F_AR16WR: u16 = 0x0080;
/// File is 32-bit little-endian.
pub const F_AR32WR: u16 = 0x0100;
/// File is 32-bit big-endian.
pub const F_AR32W: u16 = 0x0200;
/// rs/6000 aix: dynamically loadable w/imports and exports.
pub const F_DYNLOAD: u16 = 0x1000;
/// rs/6000 aix: file is a shared object.
pub const F_SHROBJ: u16 = 0x2000;
/// rs/6000 aix: if the object file is a member of an archive it can be loaded by the system
/// loader but the member is ignored by the binder.
pub const F_LOADONLY: u16 = 0x4000;

/// Returns `true` if relocation info is stripped from the file.
///
/// Mirrors `XCoffFileHeaderFlags.isStrip(XCoffFileHeader)`.
pub fn is_strip(flags: u16) -> bool {
    (flags & F_RELFLG) == F_RELFLG
}

/// Returns `true` if the file is executable (no unresolved external references).
///
/// Mirrors `XCoffFileHeaderFlags.isExec(XCoffFileHeader)`.
pub fn is_exec(flags: u16) -> bool {
    (flags & F_EXEC) == F_EXEC
}

/// Returns `true` if line-number debug info is present (i.e. the `F_LNNO` strip flag is NOT set).
///
/// Mirrors `XCoffFileHeaderFlags.isDebug(XCoffFileHeader)`.
pub fn is_debug(flags: u16) -> bool {
    !((flags & F_LNNO) == F_LNNO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(F_RELFLG, 0x0001);
        assert_eq!(F_EXEC, 0x0002);
        assert_eq!(F_LNNO, 0x0004);
        assert_eq!(F_LSYMS, 0x0008);
        assert_eq!(F_FDPR_PROF, 0x0010);
        assert_eq!(F_FDPR_OPTI, 0x0020);
        assert_eq!(F_DSA, 0x0040);
        assert_eq!(F_AR16WR, 0x0080);
        assert_eq!(F_AR32WR, 0x0100);
        assert_eq!(F_AR32W, 0x0200);
        assert_eq!(F_DYNLOAD, 0x1000);
        assert_eq!(F_SHROBJ, 0x2000);
        assert_eq!(F_LOADONLY, 0x4000);
    }

    #[test]
    fn constants_are_distinct_single_bits() {
        let flags = [
            F_RELFLG, F_EXEC, F_LNNO, F_LSYMS, F_FDPR_PROF, F_FDPR_OPTI, F_DSA, F_AR16WR,
            F_AR32WR, F_AR32W, F_DYNLOAD, F_SHROBJ, F_LOADONLY,
        ];
        for (i, &a) in flags.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "flag {i} should be a single bit");
            for (j, &b) in flags.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "flags {i} and {j} must not overlap");
                }
            }
        }
    }

    #[test]
    fn is_strip_set_when_bit_present() {
        assert!(is_strip(F_RELFLG));
        assert!(is_strip(0xFFFF));
    }

    #[test]
    fn is_strip_clear_when_bit_absent() {
        assert!(!is_strip(0x0000));
        assert!(!is_strip(F_EXEC | F_LNNO));
    }

    #[test]
    fn is_exec_set_when_bit_present() {
        assert!(is_exec(F_EXEC));
        assert!(is_exec(F_RELFLG | F_EXEC));
    }

    #[test]
    fn is_exec_clear_when_bit_absent() {
        assert!(!is_exec(0x0000));
        assert!(!is_exec(F_RELFLG | F_LNNO));
    }

    #[test]
    fn is_debug_true_when_lnno_clear() {
        assert!(is_debug(0x0000));
        assert!(is_debug(F_RELFLG | F_EXEC));
    }

    #[test]
    fn is_debug_false_when_lnno_set() {
        assert!(!is_debug(F_LNNO));
        assert!(!is_debug(0xFFFF));
    }

    #[test]
    fn combined_flags_behave_correctly() {
        let flags = F_RELFLG | F_EXEC | F_DYNLOAD | F_SHROBJ;
        assert!(is_strip(flags));
        assert!(is_exec(flags));
        assert!(is_debug(flags));
    }
}
