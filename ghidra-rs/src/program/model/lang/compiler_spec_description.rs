use crate::program::model::lang::compiler_spec_id::CompilerSpecID;

/// A description of a compiler specification, used to enumerate and select from among the
/// compiler specifications compatible with a particular
/// [`Language`](crate::program::model::lang::language::Language), without having to load the
/// full [`CompilerSpec`](crate::program::model::lang::compiler_spec::CompilerSpec) itself.
///
/// Port of `ghidra.program.model.lang.CompilerSpecDescription`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods; the placeholder's (empty) surface is retained here as part of the full trait, so
/// existing mock implementations continue to compile.
pub trait CompilerSpecDescription {
    /// The identifier of the described compiler spec.
    fn get_compiler_spec_id(&self) -> CompilerSpecID;

    /// A concise, human readable name for the described compiler spec.
    fn get_compiler_spec_name(&self) -> String;

    /// The source of the described compiler spec, usually the file or facility it originated
    /// from.
    fn get_source(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCompilerSpecDescription;

    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }

        fn get_compiler_spec_name(&self) -> String {
            "GCC".to_string()
        }

        fn get_source(&self) -> String {
            "gcc.cspec".to_string()
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable() {
        let desc: Box<dyn CompilerSpecDescription> = Box::new(MockCompilerSpecDescription);
        assert_eq!(desc.get_compiler_spec_id(), CompilerSpecID::new(Some("gcc")));
        assert_eq!(desc.get_compiler_spec_name(), "GCC");
        assert_eq!(desc.get_source(), "gcc.cspec");
    }
}
