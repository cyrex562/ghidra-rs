//! Port of `ghidra.app.util.demangler.swift.SwiftDemangledBuiltinType`.
//!
//! Kinds of Swift demangling `SwiftNode`s.
//!
//! See <https://github.com/swiftlang/swift/blob/main/include/swift/Demangling/DemangleNodes.def>.

/// Mirrors `SwiftDemangledBuiltinType`, a closed enum with no declared fields or methods in the
/// Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwiftDemangledBuiltinType {
    Int1,
    Word,
    RawPointer,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let all = [
            SwiftDemangledBuiltinType::Int1,
            SwiftDemangledBuiltinType::Word,
            SwiftDemangledBuiltinType::RawPointer,
            SwiftDemangledBuiltinType::Unsupported,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }

    #[test]
    fn is_copy_and_clone() {
        let a = SwiftDemangledBuiltinType::RawPointer;
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format_uses_variant_name() {
        assert_eq!(format!("{:?}", SwiftDemangledBuiltinType::Word), "Word");
    }
}
