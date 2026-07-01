//! Field access flags for Java class field members.
//!
//! Ported from `ghidra.javaclass.flags.FieldInfoAccessFlags`.

/// Declared public; may be accessed from outside its package.
pub const ACC_PUBLIC: u16 = 0x0001;

/// Declared private; usable only within the defining class.
pub const ACC_PRIVATE: u16 = 0x0002;

/// Declared protected; may be accessed within subclasses.
pub const ACC_PROTECTED: u16 = 0x0004;

/// Declared static.
pub const ACC_STATIC: u16 = 0x0008;

/// Declared final; never directly assigned to after object construction.
pub const ACC_FINAL: u16 = 0x0010;

/// Declared volatile; cannot be cached.
pub const ACC_VOLATILE: u16 = 0x0040;

/// Declared transient; not written or read by a persistent object manager.
pub const ACC_TRANSIENT: u16 = 0x0080;

/// Declared synthetic; not present in the source code.
pub const ACC_SYNTHETIC: u16 = 0x1000;

/// Declared as an element of an enum.
pub const ACC_ENUM: u16 = 0x4000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values_match_java_source() {
        assert_eq!(ACC_PUBLIC, 0x0001);
        assert_eq!(ACC_PRIVATE, 0x0002);
        assert_eq!(ACC_PROTECTED, 0x0004);
        assert_eq!(ACC_STATIC, 0x0008);
        assert_eq!(ACC_FINAL, 0x0010);
        assert_eq!(ACC_VOLATILE, 0x0040);
        assert_eq!(ACC_TRANSIENT, 0x0080);
        assert_eq!(ACC_SYNTHETIC, 0x1000);
        assert_eq!(ACC_ENUM, 0x4000);
    }

    #[test]
    fn all_flags_are_distinct() {
        let mut all = vec![
            ACC_PUBLIC,
            ACC_PRIVATE,
            ACC_PROTECTED,
            ACC_STATIC,
            ACC_FINAL,
            ACC_VOLATILE,
            ACC_TRANSIENT,
            ACC_SYNTHETIC,
            ACC_ENUM,
        ];
        all.sort();
        let count = all.len();
        all.dedup();
        assert_eq!(all.len(), count, "duplicate flag value detected");
    }

    #[test]
    fn flags_are_non_zero() {
        let flags = [
            ACC_PUBLIC,
            ACC_PRIVATE,
            ACC_PROTECTED,
            ACC_STATIC,
            ACC_FINAL,
            ACC_VOLATILE,
            ACC_TRANSIENT,
            ACC_SYNTHETIC,
            ACC_ENUM,
        ];
        for flag in flags.iter() {
            assert_ne!(*flag, 0, "flag value should not be zero");
        }
    }

    #[test]
    fn flags_can_be_combined() {
        let public_static = ACC_PUBLIC | ACC_STATIC;
        assert_eq!(public_static, 0x0009);
        assert!(public_static & ACC_PUBLIC != 0);
        assert!(public_static & ACC_STATIC != 0);
        assert!(public_static & ACC_PRIVATE == 0);

        let private_final = ACC_PRIVATE | ACC_FINAL;
        assert_eq!(private_final, 0x0012);
        assert!(private_final & ACC_PRIVATE != 0);
        assert!(private_final & ACC_FINAL != 0);
        assert!(private_final & ACC_PUBLIC == 0);
    }

    #[test]
    fn flag_combinations_are_valid() {
        let volatile_transient = ACC_VOLATILE | ACC_TRANSIENT;
        assert_eq!(volatile_transient, 0x00C0);
        assert!(volatile_transient & ACC_VOLATILE != 0);
        assert!(volatile_transient & ACC_TRANSIENT != 0);
    }
}
