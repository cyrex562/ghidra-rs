//! The future result of invoking a RemoteMethod.
//!
//! Corresponds to `ghidra.debug.api.tracermi.RemoteAsyncResult`.

use crate::debug::seam_stubs::RemoteMethod;
use crate::trace::model::target::trace_object::TraceObject;

/// The future result of invoking a [`RemoteMethod`].
///
/// While this can technically result in an object, returning values from remote methods is highly
/// discouraged. This has led to several issues in the past, including duplication of information
/// (and a lot of it) over the connection. Instead, most methods should just update the trace
/// database, and the client can retrieve the relevant information from it. One exception might be
/// the `execute` method. This is typically for executing a CLI command with captured output.
/// There is generally no place for such output to go into the trace, and the use cases for such a
/// method to return the output are compelling. For other cases, perhaps the most you can do is
/// return a [`TraceObject`], so that a client can quickly associate the trace changes with the
/// method. Otherwise, please return null/void/None for all methods.
///
/// Corresponds to `ghidra.debug.api.tracermi.RemoteAsyncResult`.
pub trait RemoteAsyncResult: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the trait can be used as a generic bound
    fn accepts_remote_async_result<T: RemoteAsyncResult>(_result: &T) {}

    // Test implementation for a concrete type
    struct TestAsyncResult;

    impl RemoteAsyncResult for TestAsyncResult {}

    #[test]
    fn test_async_result_marker_trait() {
        let result = TestAsyncResult;
        accepts_remote_async_result(&result);
    }

    #[test]
    fn test_async_result_trait_object() {
        let result: Box<dyn RemoteAsyncResult> = Box::new(TestAsyncResult);
        let _: &dyn RemoteAsyncResult = &*result;
    }

    #[test]
    fn test_async_result_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<TestAsyncResult>();
        assert_sync::<TestAsyncResult>();
    }
}
