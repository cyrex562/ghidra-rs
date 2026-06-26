/// No entry.
pub const C_NULL: i32 = 0;
/// Automatic variable.
pub const C_AUTO: i32 = 1;
/// External (public) symbol — globals and externs.
pub const C_EXT: i32 = 2;
/// Static (private) symbol.
pub const C_STAT: i32 = 3;
/// Register variable.
pub const C_REG: i32 = 4;
/// External definition.
pub const C_EXTDEF: i32 = 5;
/// Label.
pub const C_LABEL: i32 = 6;
/// Undefined label.
pub const C_ULABEL: i32 = 7;
/// Member of structure.
pub const C_MOS: i32 = 8;
/// Function argument.
pub const C_ARG: i32 = 9;
/// Structure tag.
pub const C_STRTAG: i32 = 10;
/// Member of union.
pub const C_MOU: i32 = 11;
/// Union tag.
pub const C_UNTAG: i32 = 12;
/// Type definition.
pub const C_TPDEF: i32 = 13;
/// Undefined static.
pub const C_USTATIC: i32 = 14;
/// Enumeration tag.
pub const C_ENTAG: i32 = 15;
/// Member of enumeration.
pub const C_MOE: i32 = 16;
/// Register parameter.
pub const C_REGPARAM: i32 = 17;
/// Bit field.
pub const C_FIELD: i32 = 18;
/// Automatic argument.
pub const C_AUTOARG: i32 = 19;
/// Dummy entry (end of block).
pub const C_LASTENT: i32 = 20;
/// `.bb` or `.eb` — beginning or end of block.
pub const C_BLOCK: i32 = 100;
/// `.bf` or `.ef` — beginning or end of function.
pub const C_FCN: i32 = 101;
/// End of structure.
pub const C_EOS: i32 = 102;
/// File name.
pub const C_FILE: i32 = 103;
/// Line number, reformatted as symbol.
pub const C_LINE: i32 = 104;
/// Duplicate tag.
pub const C_ALIAS: i32 = 105;
/// External symbol in dmert public lib.
pub const C_HIDDEN: i32 = 106;
/// Physical end of function.
pub const C_EFCN: i32 = 107;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(C_NULL,     0);
        assert_eq!(C_AUTO,     1);
        assert_eq!(C_EXT,      2);
        assert_eq!(C_STAT,     3);
        assert_eq!(C_REG,      4);
        assert_eq!(C_EXTDEF,   5);
        assert_eq!(C_LABEL,    6);
        assert_eq!(C_ULABEL,   7);
        assert_eq!(C_MOS,      8);
        assert_eq!(C_ARG,      9);
        assert_eq!(C_STRTAG,  10);
        assert_eq!(C_MOU,     11);
        assert_eq!(C_UNTAG,   12);
        assert_eq!(C_TPDEF,   13);
        assert_eq!(C_USTATIC, 14);
        assert_eq!(C_ENTAG,   15);
        assert_eq!(C_MOE,     16);
        assert_eq!(C_REGPARAM,17);
        assert_eq!(C_FIELD,   18);
        assert_eq!(C_AUTOARG, 19);
        assert_eq!(C_LASTENT, 20);
        assert_eq!(C_BLOCK,  100);
        assert_eq!(C_FCN,    101);
        assert_eq!(C_EOS,    102);
        assert_eq!(C_FILE,   103);
        assert_eq!(C_LINE,   104);
        assert_eq!(C_ALIAS,  105);
        assert_eq!(C_HIDDEN, 106);
        assert_eq!(C_EFCN,   107);
    }

    #[test]
    fn all_values_are_distinct() {
        let mut all = vec![
            C_NULL, C_AUTO, C_EXT, C_STAT, C_REG, C_EXTDEF, C_LABEL, C_ULABEL,
            C_MOS, C_ARG, C_STRTAG, C_MOU, C_UNTAG, C_TPDEF, C_USTATIC, C_ENTAG,
            C_MOE, C_REGPARAM, C_FIELD, C_AUTOARG, C_LASTENT, C_BLOCK, C_FCN,
            C_EOS, C_FILE, C_LINE, C_ALIAS, C_HIDDEN, C_EFCN,
        ];
        all.sort();
        let count = all.len();
        all.dedup();
        assert_eq!(all.len(), count, "duplicate storage class value detected");
    }
}
