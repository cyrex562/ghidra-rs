/// Architecture tag for PowerPC Code Fragment Manager binaries.
pub const K_POWER_PC_C_FRAG_ARCH: &str = "pwpc";

/// Architecture tag for Motorola 68K Code Fragment Manager binaries.
pub const K_MOTOROLA_68K_C_FRAG_ARCH: &str = "m68k";

/// Wildcard architecture tag — matches any CFM architecture.
pub const K_ANY_C_FRAG_ARCH: &str = "????";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powerpc_tag() {
        assert_eq!(K_POWER_PC_C_FRAG_ARCH, "pwpc");
    }

    #[test]
    fn motorola_68k_tag() {
        assert_eq!(K_MOTOROLA_68K_C_FRAG_ARCH, "m68k");
    }

    #[test]
    fn any_arch_tag() {
        assert_eq!(K_ANY_C_FRAG_ARCH, "????");
        assert_eq!(K_ANY_C_FRAG_ARCH.len(), 4);
    }

    #[test]
    fn all_tags_are_four_bytes() {
        assert_eq!(K_POWER_PC_C_FRAG_ARCH.len(), 4);
        assert_eq!(K_MOTOROLA_68K_C_FRAG_ARCH.len(), 4);
        assert_eq!(K_ANY_C_FRAG_ARCH.len(), 4);
    }

    #[test]
    fn tags_are_distinct() {
        assert_ne!(K_POWER_PC_C_FRAG_ARCH, K_MOTOROLA_68K_C_FRAG_ARCH);
        assert_ne!(K_POWER_PC_C_FRAG_ARCH, K_ANY_C_FRAG_ARCH);
        assert_ne!(K_MOTOROLA_68K_C_FRAG_ARCH, K_ANY_C_FRAG_ARCH);
    }
}
