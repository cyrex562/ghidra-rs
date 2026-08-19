//! A connection to a TraceRmi back end.
//!
//! Corresponds to `ghidra.debug.api.tracermi.TraceRmiConnection`.

use std::net::SocketAddr;

use crate::debug::api::tracermi::RemoteMethodRegistry;
use crate::debug::seam_stubs::Target;
use crate::trace::model::trace::Trace;
use crate::util::exception::TimeoutException;
use std::io;

/// A connection to a TraceRmi back end.
///
/// TraceRmi is a two-way request-reply channel, usually over TCP. The back end, i.e., the
/// trace-rmi plugin hosted in the target platform's actual debugger, is granted a fixed set of
/// methods/messages for creating and populating a [`Trace`]. Each such trace is designated as a
/// target. The back end provides a set of methods for the front-end to use to control the
/// connection and its targets. For a given connection, the methods are fixed, but each back end
/// may provide a different set of methods to best describe/model its command set. The same
/// methods are applicable to all of the back end's targets. While uncommon, one back end may
/// create several targets. E.g., if a target creates a child process, and the back-end debugger
/// is configured to remain attached to both parent and child, then it should create and publish a
/// second target.
///
/// Corresponds to `ghidra.debug.api.tracermi.TraceRmiConnection`. The Java interface extends
/// `AutoCloseable`; that is modeled here as an ordinary [`close`](Self::close) method, mirroring
/// the convention used by [`TerminalSession`](crate::debug::api::tracermi::TerminalSession).
pub trait TraceRmiConnection {
    /// Get the client-given description of this connection.
    ///
    /// If the connection is still being negotiated, this returns a string indicating that.
    fn description(&self) -> String;

    /// Get the address of the back end debugger, usually the IP of the host and port for the
    /// trace-rmi plugin.
    fn remote_address(&self) -> SocketAddr;

    /// Get the methods provided by the back end.
    fn methods(&self) -> &dyn RemoteMethodRegistry;

    /// Wait for the first trace created by the back end.
    ///
    /// Typically, a connection handles only a single target. A shell script handles launching the
    /// back-end debugger, creating its first target, and connecting back to the front end via
    /// TraceRmi. If a secondary target does appear, it usually happens only after the initial
    /// target has run. Thus, this method is useful for waiting on and getting a handle to that
    /// initial target.
    ///
    /// Returns an error if no trace is created after `timeout_millis` milliseconds. This usually
    /// indicates there was an error launching the initial target, e.g., the target's binary was
    /// not found on the target's host.
    fn wait_for_trace(&self, timeout_millis: u64) -> Result<Box<dyn Trace>, TimeoutException>;

    /// Get the last snapshot created by the back end for the given trace.
    ///
    /// Back ends that support timeless or time-travel debugging have not been integrated yet, but
    /// in those cases, this is anticipated to return the current snapshot (however the back end
    /// defines that with respect to its own definition of time), whether or not it is the last
    /// snapshot it created. If the back end has not created a snapshot yet, `0` is returned.
    ///
    /// Returns `None` if the given trace is not a target for this connection (mirrors Java's
    /// `NoSuchElementException`).
    fn last_snapshot(&self, trace: &dyn Trace) -> Option<i64>;

    /// Forcefully remove the given trace from the connection.
    ///
    /// This removes the back end's access to the given trace and removes this connection from the
    /// trace's list of consumers (thus, freeing it if this was the only remaining consumer.) For
    /// all intents and purposes, the given trace is no longer a target for this connection.
    ///
    /// **NOTE:** This method should only be used if gracefully killing the target has failed. In
    /// some cases, it may be better to terminate the entire connection (see
    /// [`close`](Self::close)) or to terminate the back end debugger. The back end gets no
    /// notification that its trace was forcefully removed. However, subsequent requests involving
    /// that trace will result in errors.
    fn force_close_trace(&mut self, trace: &dyn Trace);

    /// Close the TraceRmi connection.
    ///
    /// Upon closing, all the connection's targets (there's usually only one) will be withdrawn and
    /// invalidated.
    fn close(&mut self) -> io::Result<()>;

    /// Check if the connection has been closed.
    fn is_closed(&self) -> bool;

    /// Wait for the connection to become closed.
    ///
    /// This is usually just for clean-up purposes during automated testing.
    fn wait_closed(&self);

    /// Check if the given trace represents one of this connection's targets.
    fn is_target(&self, trace: &dyn Trace) -> bool;

    /// Get all the valid targets created by this connection.
    fn targets(&self) -> Vec<Box<dyn Target>>;

    /// Check if the connection has a transaction open on any of its targets.
    ///
    /// This generally means the connection has an open transaction. It does *not* indicate the
    /// execution state of the target/debuggee.
    fn is_busy(&self) -> bool;

    /// Check if the given target has a transaction open.
    fn is_target_busy(&self, target: &dyn Target) -> bool;

    /// Forcibly commit all transactions this connection has on the given target.
    ///
    /// This may cause undefined behavior in the back-end, especially if it still needs the
    /// transaction.
    fn forcibly_close_transactions(&mut self, target: &dyn Target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::seam_stubs::{ActionName, RemoteMethod};
    use crate::program::model::address::AddressFactory;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use std::collections::{HashMap, HashSet};

    struct TestRegistry;

    impl RemoteMethodRegistry for TestRegistry {
        fn all(&self) -> HashMap<String, Box<dyn RemoteMethod>> {
            HashMap::new()
        }
        fn get(&self, _name: &str) -> Option<Box<dyn RemoteMethod>> {
            None
        }
        fn get_by_action(&self, _action: &dyn ActionName) -> HashSet<Box<dyn RemoteMethod>> {
            HashSet::new()
        }
    }

    struct TestTarget;
    impl Target for TestTarget {}

    /// A `Trace` whose members are never called by the smoke tests below: they only need a
    /// `&dyn Trace`/`Box<dyn Trace>` to type-check, not to run. Mirrors the `UnusedTrace` pattern
    /// used elsewhere in the crate (e.g. `scheduler::tests::UnusedTrace`).
    struct TestTrace;

    struct MockDataTypeManager;
    impl crate::program::model::data::data_type_manager::DataTypeManager for MockDataTypeManager {}

    impl crate::framework::model::DomainObject for TestTrace {}

    impl crate::app::merge::DataTypeManagerOwner for TestTrace {
        fn get_data_type_manager(&self) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            static MANAGER: MockDataTypeManager = MockDataTypeManager;
            &MANAGER
        }
    }

    impl DataTypeManagerDomainObject for TestTrace {}

    impl Trace for TestTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager>
        {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_memory_manager(
            &self,
        ) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_stack_manager(
            &self,
        ) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unreachable!("not exercised by TraceRmiConnection smoke test")
        }
    }

    struct TestConnection {
        description: String,
        address: SocketAddr,
        registry: TestRegistry,
        closed: bool,
    }

    impl TraceRmiConnection for TestConnection {
        fn description(&self) -> String {
            self.description.clone()
        }

        fn remote_address(&self) -> SocketAddr {
            self.address
        }

        fn methods(&self) -> &dyn RemoteMethodRegistry {
            &self.registry
        }

        fn wait_for_trace(&self, timeout_millis: u64) -> Result<Box<dyn Trace>, TimeoutException> {
            if timeout_millis == 0 {
                return Err(TimeoutException::new("no trace created"));
            }
            Ok(Box::new(TestTrace))
        }

        fn last_snapshot(&self, _trace: &dyn Trace) -> Option<i64> {
            Some(0)
        }

        fn force_close_trace(&mut self, _trace: &dyn Trace) {}

        fn close(&mut self) -> io::Result<()> {
            self.closed = true;
            Ok(())
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn wait_closed(&self) {}

        fn is_target(&self, _trace: &dyn Trace) -> bool {
            true
        }

        fn targets(&self) -> Vec<Box<dyn Target>> {
            vec![Box::new(TestTarget)]
        }

        fn is_busy(&self) -> bool {
            false
        }

        fn is_target_busy(&self, _target: &dyn Target) -> bool {
            false
        }

        fn forcibly_close_transactions(&mut self, _target: &dyn Target) {}
    }

    fn make_connection() -> TestConnection {
        TestConnection {
            description: "gdb @ localhost:12345".to_string(),
            address: "127.0.0.1:12345".parse().unwrap(),
            registry: TestRegistry,
            closed: false,
        }
    }

    #[test]
    fn description_returns_configured_string() {
        let conn = make_connection();
        assert_eq!(conn.description(), "gdb @ localhost:12345");
    }

    #[test]
    fn remote_address_returns_configured_address() {
        let conn = make_connection();
        assert_eq!(conn.remote_address(), "127.0.0.1:12345".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn wait_for_trace_times_out_on_zero_timeout() {
        let conn = make_connection();
        assert!(conn.wait_for_trace(0).is_err());
    }

    #[test]
    fn wait_for_trace_succeeds_with_nonzero_timeout() {
        let conn = make_connection();
        assert!(conn.wait_for_trace(1000).is_ok());
    }

    #[test]
    fn close_marks_connection_closed() {
        let mut conn = make_connection();
        assert!(!conn.is_closed());
        conn.close().unwrap();
        assert!(conn.is_closed());
    }

    #[test]
    fn targets_returns_all_valid_targets() {
        let conn = make_connection();
        assert_eq!(conn.targets().len(), 1);
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let conn: Box<dyn TraceRmiConnection> = Box::new(make_connection());
        assert!(!conn.is_busy());
        assert!(conn.is_target(&TestTrace));
    }
}
