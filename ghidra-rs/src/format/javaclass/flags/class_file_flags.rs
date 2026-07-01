//! ClassFile access flags for Java class files.
//!
//! Ported from `ghidra.javaclass.flags.ClassFileFlags`.

/// Declared public; may be accessed from outside its package.
pub const ACC_PUBLIC: u16 = 0x0001;

/// Declared final; no subclasses allowed.
pub const ACC_FINAL: u16 = 0x0010;

/// Treat superclass methods specially when invoked by the invokespecial instruction.
pub const ACC_SUPER: u16 = 0x0020;

/// Is an interface, not a class.
pub const ACC_INTERFACE: u16 = 0x0200;

/// Declared abstract; must not be instantiated.
pub const ACC_ABSTRACT: u16 = 0x0400;

/// Declared synthetic; not present in the source code.
pub const ACC_SYNTHETIC: u16 = 0x1000;

/// Declared as an annotation type.
pub const ACC_ANNOTATION: u16 = 0x2000;

/// Declared as an enum type.
pub const ACC_ENUM: u16 = 0x4000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values_match_java_source() {
        assert_eq!(ACC_PUBLIC, 0x0001);
        assert_eq!(ACC_FINAL, 0x0010);
        assert_eq!(ACC_SUPER, 0x0020);
        assert_eq!(ACC_INTERFACE, 0x0200);
        assert_eq!(ACC_ABSTRACT, 0x0400);
        assert_eq!(ACC_SYNTHETIC, 0x1000);
        assert_eq!(ACC_ANNOTATION, 0x2000);
        assert_eq!(ACC_ENUM, 0x4000);
    }

    #[test]
    fn all_flags_are_distinct() {
        let mut all = vec![
            ACC_PUBLIC,
            ACC_FINAL,
            ACC_SUPER,
            ACC_INTERFACE,
            ACC_ABSTRACT,
            ACC_SYNTHETIC,
            ACC_ANNOTATION,
            ACC_ENUM,
        ];
        all.sort();
        let count = all.len();
        all.dedup();
        assert_eq!(all.len(), count, "duplicate flag value detected");
    }

    #[test]
    fn flags_are_powers_of_two_or_combinations() {
        let flags = [
            ACC_PUBLIC,
            ACC_FINAL,
            ACC_SUPER,
            ACC_INTERFACE,
            ACC_ABSTRACT,
            ACC_SYNTHETIC,
            ACC_ANNOTATION,
            ACC_ENUM,
        ];
        for flag in flags.iter() {
            assert_ne!(*flag, 0, "flag value should not be zero");
        }
    }

    #[test]
    fn flags_can_be_combined() {
        let public_final = ACC_PUBLIC | ACC_FINAL;
        assert_eq!(public_final, 0x0011);
        assert!(public_final & ACC_PUBLIC != 0);
        assert!(public_final & ACC_FINAL != 0);
        assert!(public_final & ACC_SUPER == 0);
    }
}
