/// Method invocation type for bytecode verification, mirroring
/// `ghidra.file.formats.android.verifier.MethodType`.
///
/// Source:
/// <https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodType {
    MethodUnknown,
    MethodDirect,
    MethodStatic,
    MethodVirtual,
    MethodSuper,
    MethodInterface,
    MethodPolymorphic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(MethodType::MethodUnknown, MethodType::MethodDirect);
        assert_ne!(MethodType::MethodDirect, MethodType::MethodStatic);
        assert_ne!(MethodType::MethodStatic, MethodType::MethodVirtual);
        assert_ne!(MethodType::MethodVirtual, MethodType::MethodSuper);
        assert_ne!(MethodType::MethodSuper, MethodType::MethodInterface);
        assert_ne!(MethodType::MethodInterface, MethodType::MethodPolymorphic);
        assert_ne!(MethodType::MethodUnknown, MethodType::MethodPolymorphic);
    }

    #[test]
    fn variants_are_copy() {
        let t = MethodType::MethodVirtual;
        let _t2 = t;
        let _t3 = t;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", MethodType::MethodUnknown), "MethodUnknown");
        assert_eq!(format!("{:?}", MethodType::MethodDirect), "MethodDirect");
        assert_eq!(format!("{:?}", MethodType::MethodStatic), "MethodStatic");
        assert_eq!(format!("{:?}", MethodType::MethodVirtual), "MethodVirtual");
        assert_eq!(format!("{:?}", MethodType::MethodSuper), "MethodSuper");
        assert_eq!(format!("{:?}", MethodType::MethodInterface), "MethodInterface");
        assert_eq!(format!("{:?}", MethodType::MethodPolymorphic), "MethodPolymorphic");
    }

    #[test]
    fn variants_clone() {
        let t = MethodType::MethodInterface;
        assert_eq!(t.clone(), MethodType::MethodInterface);
    }
}
