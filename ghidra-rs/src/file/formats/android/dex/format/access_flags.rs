/// DEX access flags as defined in the Dalvik executable format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.AccessFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFlags;

impl AccessFlags {
    /// visible everywhere
    pub const ACC_PUBLIC: u32 = 0x1;
    /// only visible to defining class
    pub const ACC_PRIVATE: u32 = 0x2;
    /// visible to package and subclasses
    pub const ACC_PROTECTED: u32 = 0x4;
    /// is not constructed with an outer this reference
    pub const ACC_STATIC: u32 = 0x8;
    /// not subclassable / immutable after construction / not overridable
    pub const ACC_FINAL: u32 = 0x10;
    /// associated lock automatically acquired around call to this method (only valid when ACC_NATIVE is set)
    pub const ACC_SYNCHRONIZED: u32 = 0x20;
    /// special access rules to help with thread safety
    pub const ACC_VOLATILE: u32 = 0x40;
    /// bridge method, added automatically by compiler as a type-safe bridge
    pub const ACC_BRIDGE: u32 = 0x40;
    /// not to be saved by default serialization
    pub const ACC_TRANSIENT: u32 = 0x80;
    /// last argument should be treated as a "rest" argument by compiler
    pub const ACC_VARARGS: u32 = 0x80;
    /// implemented in native code
    pub const ACC_NATIVE: u32 = 0x100;
    /// multiply-implementable abstract class
    pub const ACC_INTERFACE: u32 = 0x200;
    /// not directly instantiable / unimplemented by this class
    pub const ACC_ABSTRACT: u32 = 0x400;
    /// strict rules for floating-point arithmetic
    pub const ACC_STRICT: u32 = 0x800;
    /// not directly defined in source code
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    /// declared as an annotation class
    pub const ACC_ANNOTATION: u32 = 0x2000;
    /// declared as an enumerated type / declared as an enumerated value
    pub const ACC_ENUM: u32 = 0x4000;
    /// constructor method (class or instance initializer)
    pub const ACC_CONSTRUCTOR: u32 = 0x10000;
    /// declared synchronized; no effect on execution
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;

    /// Returns a tab-indented, newline-separated list of flag names set in `value`.
    ///
    /// Replicates the reflection-based `toString(int)` from the Java source, preserving
    /// declaration order and the duplicate names for aliased bit positions (e.g.
    /// `ACC_VOLATILE`/`ACC_BRIDGE` both at `0x40`).
    pub fn to_string(value: u32) -> String {
        const FLAGS: &[(&str, u32)] = &[
            ("ACC_PUBLIC", 0x1),
            ("ACC_PRIVATE", 0x2),
            ("ACC_PROTECTED", 0x4),
            ("ACC_STATIC", 0x8),
            ("ACC_FINAL", 0x10),
            ("ACC_SYNCHRONIZED", 0x20),
            ("ACC_VOLATILE", 0x40),
            ("ACC_BRIDGE", 0x40),
            ("ACC_TRANSIENT", 0x80),
            ("ACC_VARARGS", 0x80),
            ("ACC_NATIVE", 0x100),
            ("ACC_INTERFACE", 0x200),
            ("ACC_ABSTRACT", 0x400),
            ("ACC_STRICT", 0x800),
            ("ACC_SYNTHETIC", 0x1000),
            ("ACC_ANNOTATION", 0x2000),
            ("ACC_ENUM", 0x4000),
            ("ACC_CONSTRUCTOR", 0x10000),
            ("ACC_DECLARED_SYNCHRONIZED", 0x20000),
        ];
        let mut out = String::new();
        for &(name, flag) in FLAGS {
            if value & flag != 0 {
                out.push('\t');
                out.push_str(name);
                out.push('\n');
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(AccessFlags::ACC_PUBLIC, 0x1);
        assert_eq!(AccessFlags::ACC_PRIVATE, 0x2);
        assert_eq!(AccessFlags::ACC_PROTECTED, 0x4);
        assert_eq!(AccessFlags::ACC_STATIC, 0x8);
        assert_eq!(AccessFlags::ACC_FINAL, 0x10);
        assert_eq!(AccessFlags::ACC_SYNCHRONIZED, 0x20);
        assert_eq!(AccessFlags::ACC_VOLATILE, 0x40);
        assert_eq!(AccessFlags::ACC_BRIDGE, 0x40);
        assert_eq!(AccessFlags::ACC_TRANSIENT, 0x80);
        assert_eq!(AccessFlags::ACC_VARARGS, 0x80);
        assert_eq!(AccessFlags::ACC_NATIVE, 0x100);
        assert_eq!(AccessFlags::ACC_INTERFACE, 0x200);
        assert_eq!(AccessFlags::ACC_ABSTRACT, 0x400);
        assert_eq!(AccessFlags::ACC_STRICT, 0x800);
        assert_eq!(AccessFlags::ACC_SYNTHETIC, 0x1000);
        assert_eq!(AccessFlags::ACC_ANNOTATION, 0x2000);
        assert_eq!(AccessFlags::ACC_ENUM, 0x4000);
        assert_eq!(AccessFlags::ACC_CONSTRUCTOR, 0x10000);
        assert_eq!(AccessFlags::ACC_DECLARED_SYNCHRONIZED, 0x20000);
    }

    #[test]
    fn to_string_zero_is_empty() {
        assert_eq!(AccessFlags::to_string(0), "");
    }

    #[test]
    fn to_string_public() {
        assert_eq!(AccessFlags::to_string(0x1), "\tACC_PUBLIC\n");
    }

    #[test]
    fn to_string_aliased_bits_both_appear() {
        // 0x40 is shared by ACC_VOLATILE and ACC_BRIDGE; both names must appear.
        let s = AccessFlags::to_string(0x40);
        assert!(s.contains("ACC_VOLATILE"), "expected ACC_VOLATILE in {s:?}");
        assert!(s.contains("ACC_BRIDGE"), "expected ACC_BRIDGE in {s:?}");
    }

    #[test]
    fn to_string_varargs_transient_both_appear() {
        // 0x80 is shared by ACC_TRANSIENT and ACC_VARARGS.
        let s = AccessFlags::to_string(0x80);
        assert!(s.contains("ACC_TRANSIENT"), "expected ACC_TRANSIENT in {s:?}");
        assert!(s.contains("ACC_VARARGS"), "expected ACC_VARARGS in {s:?}");
    }

    #[test]
    fn to_string_multiple_flags() {
        let value = AccessFlags::ACC_PUBLIC | AccessFlags::ACC_STATIC | AccessFlags::ACC_FINAL;
        let s = AccessFlags::to_string(value);
        assert!(s.contains("ACC_PUBLIC"));
        assert!(s.contains("ACC_STATIC"));
        assert!(s.contains("ACC_FINAL"));
        assert!(!s.contains("ACC_PRIVATE"));
    }

    #[test]
    fn to_string_constructor() {
        let s = AccessFlags::to_string(AccessFlags::ACC_CONSTRUCTOR);
        assert_eq!(s, "\tACC_CONSTRUCTOR\n");
    }

    #[test]
    fn to_string_declared_synchronized() {
        let s = AccessFlags::to_string(AccessFlags::ACC_DECLARED_SYNCHRONIZED);
        assert_eq!(s, "\tACC_DECLARED_SYNCHRONIZED\n");
    }

    #[test]
    fn to_string_declaration_order_preserved() {
        let value = AccessFlags::ACC_PRIVATE | AccessFlags::ACC_PUBLIC;
        let s = AccessFlags::to_string(value);
        let pub_pos = s.find("ACC_PUBLIC").unwrap();
        let priv_pos = s.find("ACC_PRIVATE").unwrap();
        assert!(pub_pos < priv_pos, "ACC_PUBLIC must appear before ACC_PRIVATE");
    }

    #[test]
    fn unknown_bits_produce_empty_output() {
        // Bit 0x8000 is explicitly unused in the Java source.
        assert_eq!(AccessFlags::to_string(0x8000), "");
    }
}
