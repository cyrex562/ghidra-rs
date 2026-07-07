/// Marker trait for DomainObjects used to store user-data associated with another DomainObject.
///
/// Port of `ghidra.framework.model.UserData`.
///
/// This is a marker trait that serves as a type-level tag to indicate that an object
/// can be used to store user-data. It has no methods, but provides compile-time type safety
/// for objects that implement it.
pub trait UserData: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUserData;

    impl UserData for MockUserData {}

    #[test]
    fn user_data_trait_can_be_implemented() {
        let _obj: Box<dyn UserData> = Box::new(MockUserData);
    }

    #[test]
    fn user_data_object_is_send_sync() {
        fn check_send_sync<T: Send + Sync>() {}
        check_send_sync::<MockUserData>();
    }

    #[test]
    fn user_data_trait_object_preserved_through_type_erasing() {
        let obj: Box<dyn UserData> = Box::new(MockUserData);
        let _any_obj = obj as Box<dyn std::any::Any + Send + Sync>;
    }

    struct AnotherUserData {
        data: i32,
    }

    impl UserData for AnotherUserData {}

    #[test]
    fn multiple_types_implement_user_data() {
        let _obj1: Box<dyn UserData> = Box::new(MockUserData);
        let _obj2: Box<dyn UserData> = Box::new(AnotherUserData { data: 42 });
    }

    #[test]
    fn user_data_in_vector() {
        let items: Vec<Box<dyn UserData>> = vec![
            Box::new(MockUserData),
            Box::new(AnotherUserData { data: 100 }),
        ];
        assert_eq!(items.len(), 2);
    }
}
