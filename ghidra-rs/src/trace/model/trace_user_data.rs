use crate::framework::model::UserData;

/// Marker trait for DomainObjects used to store trace-specific user data.
///
/// Port of `ghidra.trace.model.TraceUserData`.
///
/// This is a marker trait that extends UserData to tag objects that can store
/// user data within the context of a trace. It has no methods, but provides
/// compile-time type safety for trace-specific user data implementations.
pub trait TraceUserData: UserData {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTraceUserData;

    impl UserData for MockTraceUserData {}
    impl TraceUserData for MockTraceUserData {}

    #[test]
    fn trace_user_data_trait_can_be_implemented() {
        let _obj: Box<dyn TraceUserData> = Box::new(MockTraceUserData);
    }

    #[test]
    fn trace_user_data_is_user_data() {
        let _obj: Box<dyn UserData> = Box::new(MockTraceUserData);
    }

    #[test]
    fn trace_user_data_object_is_send_sync() {
        fn check_send_sync<T: Send + Sync>() {}
        check_send_sync::<MockTraceUserData>();
    }

    struct AnotherTraceUserData {
        value: String,
    }

    impl UserData for AnotherTraceUserData {}
    impl TraceUserData for AnotherTraceUserData {}

    #[test]
    fn multiple_types_implement_trace_user_data() {
        let _obj1: Box<dyn TraceUserData> = Box::new(MockTraceUserData);
        let _obj2: Box<dyn TraceUserData> = Box::new(AnotherTraceUserData {
            value: "test".to_string(),
        });
    }

    #[test]
    fn trace_user_data_in_collection() {
        let items: Vec<Box<dyn TraceUserData>> = vec![
            Box::new(MockTraceUserData),
            Box::new(AnotherTraceUserData {
                value: "data".to_string(),
            }),
        ];
        assert_eq!(items.len(), 2);
    }
}
