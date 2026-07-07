/// Marker trait indicating that a type can serve as a context field value
/// within the struct-mapping framework.
///
/// In the Java source `@ContextField` is a runtime annotation placed on struct
/// fields to signal that the mapping framework should inject either a
/// `DataTypeMapper` or a `StructureContext` into that field via reflection.  In
/// Rust the same contract is expressed as a marker trait: any type that can be
/// injected as a context object implements `ContextField`.
pub trait ContextField {}

#[cfg(test)]
mod tests {
    use super::ContextField;

    struct FakeDataTypeMapper;
    struct FakeStructureContext;

    impl ContextField for FakeDataTypeMapper {}
    impl ContextField for FakeStructureContext {}

    fn accepts_context<T: ContextField>(_ctx: &T) -> bool {
        true
    }

    #[test]
    fn data_type_mapper_satisfies_context_field() {
        let ctx = FakeDataTypeMapper;
        assert!(accepts_context(&ctx));
    }

    #[test]
    fn structure_context_satisfies_context_field() {
        let ctx = FakeStructureContext;
        assert!(accepts_context(&ctx));
    }

    #[test]
    fn trait_is_object_safe_via_box() {
        let _boxed: Box<dyn ContextField> = Box::new(FakeDataTypeMapper);
    }
}
