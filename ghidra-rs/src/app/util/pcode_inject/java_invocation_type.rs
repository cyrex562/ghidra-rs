/// Represents the type of Java method invocation bytecode.
/// These correspond to the JVM's five invocation instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JavaInvocationType {
    /// INVOKEDYNAMIC instruction - dynamic method invocation (Java 7+).
    InvokeDynamic,
    /// INVOKEINTERFACE instruction - interface method invocation.
    InvokeInterface,
    /// INVOKESPECIAL instruction - special method invocation (constructors, private, super).
    InvokeSpecial,
    /// INVOKESTATIC instruction - static method invocation.
    InvokeStatic,
    /// INVOKEVIRTUAL instruction - virtual (instance) method invocation.
    InvokeVirtual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_format() {
        assert_eq!(format!("{:?}", JavaInvocationType::InvokeDynamic), "InvokeDynamic");
        assert_eq!(format!("{:?}", JavaInvocationType::InvokeInterface), "InvokeInterface");
        assert_eq!(format!("{:?}", JavaInvocationType::InvokeSpecial), "InvokeSpecial");
        assert_eq!(format!("{:?}", JavaInvocationType::InvokeStatic), "InvokeStatic");
        assert_eq!(format!("{:?}", JavaInvocationType::InvokeVirtual), "InvokeVirtual");
    }

    #[test]
    fn test_clone() {
        let invocation = JavaInvocationType::InvokeDynamic;
        let cloned = invocation.clone();
        assert_eq!(invocation, cloned);
    }

    #[test]
    fn test_copy() {
        let inv1 = JavaInvocationType::InvokeStatic;
        let inv2 = inv1;
        assert_eq!(inv1, inv2);
    }

    #[test]
    fn test_equality() {
        assert_eq!(JavaInvocationType::InvokeDynamic, JavaInvocationType::InvokeDynamic);
        assert_ne!(JavaInvocationType::InvokeDynamic, JavaInvocationType::InvokeInterface);
        assert_ne!(JavaInvocationType::InvokeSpecial, JavaInvocationType::InvokeStatic);
        assert_ne!(JavaInvocationType::InvokeVirtual, JavaInvocationType::InvokeDynamic);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(JavaInvocationType::InvokeDynamic);
        set.insert(JavaInvocationType::InvokeInterface);
        set.insert(JavaInvocationType::InvokeSpecial);
        set.insert(JavaInvocationType::InvokeStatic);
        set.insert(JavaInvocationType::InvokeVirtual);

        assert_eq!(set.len(), 5);
        assert!(set.contains(&JavaInvocationType::InvokeDynamic));
        assert!(set.contains(&JavaInvocationType::InvokeInterface));
        assert!(set.contains(&JavaInvocationType::InvokeSpecial));
        assert!(set.contains(&JavaInvocationType::InvokeStatic));
        assert!(set.contains(&JavaInvocationType::InvokeVirtual));
    }

    #[test]
    fn test_as_match_patterns() {
        let invocation = JavaInvocationType::InvokeInterface;
        match invocation {
            JavaInvocationType::InvokeDynamic => assert!(false),
            JavaInvocationType::InvokeInterface => assert!(true),
            JavaInvocationType::InvokeSpecial => assert!(false),
            JavaInvocationType::InvokeStatic => assert!(false),
            JavaInvocationType::InvokeVirtual => assert!(false),
        }
    }
}
