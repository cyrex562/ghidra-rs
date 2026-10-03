//! Port of `ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin`.
//!
//! Provides a means for connecting to back-end debuggers via Trace RMI. This is an alternative
//! to the (unported) `DebuggerModel` and is meant to replace it.
//!
//! # Shape
//!
//! Java's `TraceRmiPlugin` is a concrete class (nothing extends it), so it becomes a plain
//! `struct` (rule R14a-concrete-leaf). It extends `Plugin` and implements
//! `InternalTraceRmiService` (which extends `TraceRmiService`), all three ported as traits, so
//! the methods it `@Override`s are implemented through those traits. The state Java inherits
//! from the `Plugin` base class -- the provided-service registry, the consumed-event set and the
//! disposed flag -- has no base struct to live in, so this struct holds it directly, exactly as
//! [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin) does.
//!
//! # Seams
//!
//! Four sibling classes this file references are not ported yet, and none of them is a
//! dependency this crate can stub its way around, because each is the *entire reason* the
//! corresponding method exists: `TraceRmiServer` (the accept-loop backing `start_server`),
//! `TraceRmiHandler` (the connection backing `connect`), `DefaultTraceRmiAcceptor` (backing
//! `accept_one`) and `TraceRmiTarget` (the targets a handler publishes). Rather than invent
//! speculative shapes for them:
//!
//! * `start_server`/`stop_server`/`get_server_address`/`set_server_address` are fully real: they
//!   bind an actual [`TcpListener`], mirroring Java's "get its actual address" comment for
//!   ephemeral ports. No accept loop is spawned, since accepted sockets would need to become
//!   `TraceRmiHandler`s to do anything.
//! * `connect`/`accept_one`/`connect_internal`/`accept_one_internal` perform the real socket
//!   operation Java performs first (`Socket.connect`/binding the listener) so callers see real
//!   I/O errors, then fail with [`io::ErrorKind::Unsupported`] where Java would construct a
//!   `TraceRmiHandler`/`DefaultTraceRmiAcceptor`, mirroring the established "not yet ported"
//!   convention used elsewhere in this crate's seam stubs (e.g. `ZipFileSystem::mount`).
//! * `handlers`/`acceptors` (Java's `LinkedHashSet`s) are consequently never populated -- nothing
//!   in this port can construct a `TraceRmiHandler` or `DefaultTraceRmiAcceptor` to add to them
//!   -- so `get_all_connections`/`get_all_acceptors` simply return empty, and the package-private
//!   `addHandler`/`removeHandler`/`addAcceptor`/`removeAcceptor`/`publishTarget`/`withdrawTarget`
//!   helpers (which exist only for those unported classes to call back into on construction/
//!   teardown) are omitted rather than kept as permanently-dead code.
//! * [`Self::set_target_service`] mirrors `setTargetService`'s field assignment, but not its body:
//!   that loop republishes every open connection's targets, and with `handlers` always empty
//!   there is never anything to republish. It also could not type-check as-is even with
//!   handlers: `TraceRmiConnection::targets()` returns
//!   `Box<dyn crate::debug::seam_stubs::Target>`, while
//!   [`DebuggerTargetService::publish_target`] takes `Box<dyn crate::app::seam_stubs::Target>` --
//!   two independently-grown placeholders for the same Java `ghidra.debug.api.target.Target`
//!   that have not yet been unified.
//!
//! `@AutoServiceConsumed` is annotation metadata with no Rust equivalent (nothing in this crate
//! models Java field/method reflection), so Java's `targetService`/`progressService` fields
//! become plain fields set through explicit setters ([`Self::set_target_service`],
//! [`Self::set_progress_service`]) instead of the framework injecting them by scanning
//! annotations; the constructor accordingly does not call `AutoService.wireServicesProvidedAndConsumed`.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::{DebuggerPluginPackage, DefaultTraceRmiAcceptor, TraceRmiHandler};
use crate::app::services::{
    DebuggerTargetService, InternalTraceRmiService, ProgressService, TraceRmiService,
};
use crate::debug::api::progress::CloseableTaskMonitor;
use crate::debug::api::tracermi::{TraceRmiAcceptor, TraceRmiConnection, TraceRmiServiceListener};
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{PluginPackageLike, PluginTool};
use crate::util::classfinder::ExtensionPoint;
use crate::util::exception::CancelledException;
use crate::util::task::{CancelledListener, TaskMonitor};
use crate::util::Msg;

/// Default Trace RMI server port, mirroring the private `DEFAULT_PORT`.
const DEFAULT_PORT: u16 = 15432;

const PLUGIN_CLASS_NAME: &str =
    "ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin";
const SHORT_DESCRIPTION: &str = "Connect to back-end debuggers via Trace RMI";
const DESCRIPTION: &str = "Provides a means for connecting to back-end debuggers.\n\
     NOTE this is an alternative to the DebuggerModel and is meant to replace it.\n";
const SERVICE_DEBUGGER_TARGET: &str = "ghidra.app.services.DebuggerTargetService";
const SERVICE_TRACE_RMI: &str = "ghidra.app.services.TraceRmiService";
const SERVICE_INTERNAL_TRACE_RMI: &str = "ghidra.app.services.InternalTraceRmiService";
const EVENT_TRACE_ACTIVATED: &str =
    "ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent";
const EVENT_TRACE_CLOSED: &str = "ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent";

/// Provides a means for connecting to back-end debuggers via Trace RMI.
///
/// Port of `ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin`.
pub struct TraceRmiPlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,

    // State Java inherits from the `Plugin` base class; see the module docs.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<HashSet<String>>,
    disposed: AtomicBool,
    description: TraceRmiPluginDescription,

    /// `@AutoServiceConsumed private volatile DebuggerTargetService targetService`, set through
    /// [`Self::set_target_service`] rather than reflectively; see the module docs.
    target_service: Option<Box<dyn DebuggerTargetService + Send + Sync>>,

    /// `@AutoServiceConsumed private ProgressService progressService`, set through
    /// [`Self::set_progress_service`] rather than reflectively; see the module docs.
    progress_service: Option<Box<dyn ProgressService + Send + Sync>>,

    /// `private SocketAddress serverAddress`. `None` mirrors Java's `null`, meaning "bind an
    /// ephemeral port"; the field otherwise starts at `127.0.0.1:DEFAULT_PORT`, matching Java's
    /// initializer.
    server_address: Option<SocketAddr>,

    /// `private TraceRmiServer server`. `TraceRmiServer` is not ported (see the module docs), so
    /// this holds the real, bound [`TcpListener`] that stands in for it: `Some` once
    /// [`Self::start_server`] has bound a socket, `None` otherwise.
    server: Option<TcpListener>,

    /// `final ListenerSet<TraceRmiServiceListener> listeners`. `ListenerSet` is not ported;
    /// modeled directly as the list it wraps, since nothing here needs its proxy-invocation
    /// machinery beyond iterate-and-call.
    listeners: Vec<Box<dyn TraceRmiServiceListener>>,
}

impl TraceRmiPlugin {
    /// Port of `TraceRmiPlugin(PluginTool)`.
    ///
    /// Java's constructor also calls `AutoService.wireServicesProvidedAndConsumed(this)`; see the
    /// module docs for why that is not modeled here.
    pub fn new(tool: Arc<dyn PluginTool + Send + Sync>) -> Self {
        Self {
            tool,
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(HashSet::new()),
            disposed: AtomicBool::new(false),
            description: TraceRmiPluginDescription,
            target_service: None,
            progress_service: None,
            server_address: Some(SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT))),
            server: None,
            listeners: Vec::new(),
        }
    }

    /// Port of `@AutoServiceConsumed setTargetService(DebuggerTargetService)`, less the
    /// republishing loop; see the module docs for why that loop cannot run yet.
    pub fn set_target_service(
        &mut self,
        target_service: Option<Box<dyn DebuggerTargetService + Send + Sync>>,
    ) {
        self.target_service = target_service;
    }

    /// The [`DebuggerTargetService`] most recently passed to [`Self::set_target_service`].
    pub fn target_service(&self) -> Option<&(dyn DebuggerTargetService + Send + Sync)> {
        self.target_service.as_deref()
    }

    /// Sets the `@AutoServiceConsumed ProgressService progressService` field; see the module
    /// docs for why this crate uses an explicit setter rather than reflective injection.
    pub fn set_progress_service(
        &mut self,
        progress_service: Option<Box<dyn ProgressService + Send + Sync>>,
    ) {
        self.progress_service = progress_service;
    }

    /// Port of the protected `createMonitor()`.
    ///
    /// Java caches a single `fallbackMonitor` instance for the no-service case; a
    /// [`FallbackTaskMonitor`] carries no state, so constructing a fresh one here is equivalent.
    pub fn create_monitor(&self) -> Box<dyn CloseableTaskMonitor> {
        match &self.progress_service {
            None => Box::new(FallbackTaskMonitor),
            Some(service) => service.publish_task(),
        }
    }
}

impl TraceRmiService for TraceRmiPlugin {
    /// Port of `getServerAddress()`.
    fn get_server_address(&self) -> Option<SocketAddr> {
        match &self.server {
            // In case serverAddress is ephemeral, get its actual address.
            Some(listener) => listener.local_addr().ok(),
            None => self.server_address,
        }
    }

    /// Port of `setServerAddress(SocketAddress)`.
    ///
    /// # Panics
    /// Mirrors Java's `IllegalStateException` if the server is already started.
    fn set_server_address(&mut self, server_address: Option<SocketAddr>) {
        assert!(
            self.server.is_none(),
            "Cannot change server address while it is started"
        );
        self.server_address = server_address;
    }

    /// Port of `startServer()`.
    ///
    /// # Panics
    /// Mirrors Java's `IllegalStateException` if the server is already started.
    fn start_server(&mut self) -> io::Result<()> {
        assert!(self.server.is_none(), "Server is already started");
        let bind_addr = self
            .server_address
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let listener = TcpListener::bind(bind_addr)?;
        let actual_address = listener.local_addr()?;
        self.server = Some(listener);
        for listener in &self.listeners {
            listener.server_started(actual_address);
        }
        Ok(())
    }

    /// Port of `stopServer()`.
    fn stop_server(&mut self) {
        if self.server.take().is_some() {
            for listener in &self.listeners {
                listener.server_stopped();
            }
        }
    }

    /// Port of `isServerStarted()`.
    fn is_server_started(&self) -> bool {
        self.server.is_some()
    }

    /// Port of `connect(SocketAddress)`.
    ///
    /// Establishes the real socket connection, as Java does, but cannot go further: wrapping it
    /// in a `TraceRmiHandler` and returning it (Java's `TraceRmiHandler implements
    /// TraceRmiConnection`) needs that unported class. See the module docs.
    fn connect(&self, address: SocketAddr) -> io::Result<Box<dyn TraceRmiConnection>> {
        let _socket = TcpStream::connect(address)?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TraceRmiPlugin::connect established the socket but cannot build a \
             TraceRmiHandler: TraceRmiHandler is not yet ported",
        ))
    }

    /// Port of `acceptOne(SocketAddress)`.
    ///
    /// Binds the real listening socket, as `DefaultTraceRmiAcceptor`'s constructor does, but
    /// cannot go further: that class is not ported. See the module docs.
    fn accept_one(&self, address: Option<SocketAddr>) -> io::Result<Box<dyn TraceRmiAcceptor>> {
        let bind_addr = address.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _listener = TcpListener::bind(bind_addr)?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TraceRmiPlugin::accept_one bound a listener but cannot build a \
             DefaultTraceRmiAcceptor: DefaultTraceRmiAcceptor is not yet ported",
        ))
    }

    /// Port of `getAllConnections()`. Always empty; see the module docs.
    fn get_all_connections(&self) -> Vec<Box<dyn TraceRmiConnection>> {
        Vec::new()
    }

    /// Port of `getAllAcceptors()`. Always empty; see the module docs.
    fn get_all_acceptors(&self) -> Vec<Box<dyn TraceRmiAcceptor>> {
        Vec::new()
    }

    /// Port of `addTraceServiceListener(TraceRmiServiceListener)`.
    fn add_trace_service_listener(&mut self, listener: Box<dyn TraceRmiServiceListener>) {
        self.listeners.push(listener);
    }

    /// Port of `removeTraceServiceListener(TraceRmiServiceListener)`.
    fn remove_trace_service_listener(&mut self, listener: &dyn TraceRmiServiceListener) {
        let target = listener as *const dyn TraceRmiServiceListener as *const ();
        self.listeners
            .retain(|l| (l.as_ref() as *const dyn TraceRmiServiceListener as *const ()) != target);
    }
}

impl InternalTraceRmiService for TraceRmiPlugin {
    /// Port of the covariant-return `acceptOne(SocketAddress)` override. See
    /// [`TraceRmiService::accept_one`] and the module docs.
    fn accept_one_internal(
        &self,
        address: Option<SocketAddr>,
    ) -> io::Result<Box<dyn DefaultTraceRmiAcceptor>> {
        let bind_addr = address.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _listener = TcpListener::bind(bind_addr)?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TraceRmiPlugin::accept_one_internal bound a listener but cannot build a \
             DefaultTraceRmiAcceptor: DefaultTraceRmiAcceptor is not yet ported",
        ))
    }

    /// Port of the covariant-return `connect(SocketAddress)` override. See
    /// [`TraceRmiService::connect`] and the module docs.
    fn connect_internal(&self, address: SocketAddr) -> io::Result<Box<dyn TraceRmiHandler>> {
        let _socket = TcpStream::connect(address)?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TraceRmiPlugin::connect_internal established the socket but cannot build a \
             TraceRmiHandler: TraceRmiHandler is not yet ported",
        ))
    }
}

impl ExtensionPoint for TraceRmiPlugin {}

impl PluginEventListener for TraceRmiPlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for TraceRmiPlugin {
    /// Java's `TraceRmiPlugin` overrides neither `serviceAdded` nor `serviceRemoved`; the
    /// `Plugin` base class's bodies are empty.
    fn service_added(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}

    fn service_removed(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}
}

impl Plugin for TraceRmiPlugin {
    fn name(&self) -> String {
        "TraceRmiPlugin".to_string()
    }

    fn tool(&self) -> Arc<dyn PluginTool> {
        self.tool.clone()
    }

    fn plugin_description(&self) -> &dyn PluginDescription {
        &self.description
    }

    fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }

    fn service_classes(&self) -> Vec<String> {
        self.services_provided.lock().unwrap().keys().cloned().collect()
    }

    fn service_provider_instances(&self, interface_class: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        self.services_provided
            .lock()
            .unwrap()
            .get(interface_class)
            .cloned()
            .unwrap_or_default()
    }

    fn register_service_provided(&self, interface_class: &str, service: Arc<dyn Any + Send + Sync>) {
        self.services_provided
            .lock()
            .unwrap()
            .entry(interface_class.to_string())
            .or_default()
            .push(service);
    }

    fn deregister_service(&self, interface_class: &str, service: &Arc<dyn Any + Send + Sync>) {
        let mut services = self.services_provided.lock().unwrap();
        if let Some(instances) = services.get_mut(interface_class) {
            instances.retain(|registered| !Arc::ptr_eq(registered, service));
            if instances.is_empty() {
                services.remove(interface_class);
            }
        }
    }

    fn internal_register_event_consumed(&self, event_class: &str) {
        self.events_consumed.lock().unwrap().insert(event_class.to_string());
    }

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, Ordering::SeqCst);
    }
}

/// The `@PluginInfo` metadata declared on `TraceRmiPlugin`, as a [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations
/// to read, the values are stated directly here.
struct TraceRmiPluginDescription;

impl PluginCategoryNames for TraceRmiPluginDescription {}

impl PluginDescription for TraceRmiPluginDescription {
    fn plugin_class_name(&self) -> String {
        PLUGIN_CLASS_NAME.to_string()
    }

    fn name(&self) -> String {
        "TraceRmiPlugin".to_string()
    }

    fn short_description(&self) -> String {
        SHORT_DESCRIPTION.to_string()
    }

    fn description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn category(&self) -> String {
        Self::DEBUGGER.to_string()
    }

    fn status(&self) -> PluginStatus {
        PluginStatus::Released
    }

    fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
        Box::new(DebuggerPluginPackage)
    }

    fn is_slow_installation(&self) -> bool {
        false
    }

    fn services_required(&self) -> Vec<String> {
        vec![SERVICE_DEBUGGER_TARGET.to_string()]
    }

    fn services_provided(&self) -> Vec<String> {
        vec![
            SERVICE_TRACE_RMI.to_string(),
            SERVICE_INTERNAL_TRACE_RMI.to_string(),
        ]
    }

    fn events_consumed(&self) -> Vec<String> {
        vec![
            EVENT_TRACE_ACTIVATED.to_string(),
            EVENT_TRACE_CLOSED.to_string(),
        ]
    }

    fn events_produced(&self) -> Vec<String> {
        Vec::new()
    }

    fn source_location(&self) -> String {
        String::new()
    }

    fn module_name(&self) -> String {
        "Debugger-rmi-trace".to_string()
    }

    fn is_in_extension(&self) -> bool {
        false
    }
}

/// Port of the private nested `static class FallbackTaskMonitor extends ConsoleTaskMonitor
/// implements CloseableTaskMonitor`, used by [`TraceRmiPlugin::create_monitor`] when no
/// [`ProgressService`] is available.
///
/// `ConsoleTaskMonitor` (Java's superclass) is not ported. Its only behavior this type actually
/// changes is `close()` (a no-op override) and `reportError` (delegates to [`Msg::error`]);
/// every other [`TaskMonitor`] member is otherwise a plain do-nothing/no-progress default, so
/// this implements [`TaskMonitor`] directly rather than through that unported base, mirroring
/// this crate's `DummyMonitor`.
struct FallbackTaskMonitor;

impl TaskMonitor for FallbackTaskMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn set_show_progress_value(&self, _show: bool) {}

    fn set_message(&self, _message: &str) {}

    fn get_message(&self) -> String {
        String::new()
    }

    fn set_progress(&self, _value: i64) {}

    fn initialize(&self, _max: i64) {}

    fn set_maximum(&self, _max: i64) {}

    fn get_maximum(&self) -> i64 {
        0
    }

    fn set_indeterminate(&self, _indeterminate: bool) {}

    fn is_indeterminate(&self) -> bool {
        false
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        Ok(())
    }

    fn increment_progress(&self, _amount: i64) {}

    fn get_progress(&self) -> i64 {
        -1
    }

    fn cancel(&self) {}

    fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}

    fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}

    fn set_cancel_enabled(&self, _enabled: bool) {}

    fn is_cancel_enabled(&self) -> bool {
        true
    }

    fn clear_cancelled(&self) {}
}

impl CloseableTaskMonitor for FallbackTaskMonitor {
    /// Java's override does nothing.
    fn close(&self) {}

    /// Mirrors `Msg.error(e.getMessage(), e)`.
    fn report_error(&self, error: Box<dyn std::error::Error + Send + Sync>) {
        let message = error.to_string();
        Msg::error(&message, &message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct MockTool;

    impl PluginTool for MockTool {}

    fn plugin() -> TraceRmiPlugin {
        TraceRmiPlugin::new(Arc::new(MockTool))
    }

    // --- construction / description ------------------------------------------------------

    #[test]
    fn new_plugin_defaults_to_localhost_default_port_and_not_started() {
        let p = plugin();
        assert_eq!(
            p.get_server_address(),
            Some(SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)))
        );
        assert!(!p.is_server_started());
    }

    #[test]
    fn plugin_description_matches_pluginfo_annotation() {
        let p = plugin();
        let desc = p.plugin_description();
        assert_eq!(desc.name(), "TraceRmiPlugin");
        assert_eq!(desc.plugin_class_name(), PLUGIN_CLASS_NAME);
        assert_eq!(desc.short_description(), SHORT_DESCRIPTION);
        assert_eq!(desc.category(), "Debugger");
        assert_eq!(desc.status(), PluginStatus::Released);
        assert_eq!(desc.plugin_package().name(), "Debugger");
        assert_eq!(
            desc.services_required(),
            vec![SERVICE_DEBUGGER_TARGET.to_string()]
        );
        assert_eq!(
            desc.services_provided(),
            vec![
                SERVICE_TRACE_RMI.to_string(),
                SERVICE_INTERNAL_TRACE_RMI.to_string()
            ]
        );
        assert_eq!(
            desc.events_consumed(),
            vec![
                EVENT_TRACE_ACTIVATED.to_string(),
                EVENT_TRACE_CLOSED.to_string()
            ]
        );
    }

    // --- server lifecycle ------------------------------------------------------------------

    #[test]
    fn set_server_address_then_start_binds_that_address() {
        let mut p = plugin();
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        p.set_server_address(Some(addr));
        p.start_server().unwrap();
        assert!(p.is_server_started());
        // Port 0 resolves to a real ephemeral port once bound.
        assert_ne!(p.get_server_address().unwrap().port(), 0);
    }

    #[test]
    #[should_panic(expected = "Server is already started")]
    fn start_server_twice_panics() {
        let mut p = plugin();
        p.set_server_address(Some(SocketAddr::from(([127, 0, 0, 1], 0))));
        p.start_server().unwrap();
        let _ = p.start_server();
    }

    #[test]
    #[should_panic(expected = "Cannot change server address while it is started")]
    fn set_server_address_while_started_panics() {
        let mut p = plugin();
        p.set_server_address(Some(SocketAddr::from(([127, 0, 0, 1], 0))));
        p.start_server().unwrap();
        p.set_server_address(Some(SocketAddr::from(([127, 0, 0, 1], 1))));
    }

    #[test]
    fn stop_server_clears_started_flag_and_notifies_listeners() {
        let mut p = plugin();
        p.set_server_address(Some(SocketAddr::from(([127, 0, 0, 1], 0))));

        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        p.add_trace_service_listener(Box::new(RecordingListener {
            started: started.clone(),
            stopped: stopped.clone(),
        }));

        p.start_server().unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);

        p.stop_server();
        assert!(!p.is_server_started());
        assert_eq!(stopped.load(Ordering::SeqCst), 1);

        // Stopping an already-stopped server does not renotify.
        p.stop_server();
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
    }

    struct RecordingListener {
        started: Arc<AtomicUsize>,
        stopped: Arc<AtomicUsize>,
    }

    impl TraceRmiServiceListener for RecordingListener {
        fn server_started(&self, _address: SocketAddr) {
            self.started.fetch_add(1, Ordering::SeqCst);
        }

        fn server_stopped(&self) {
            self.stopped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn remove_trace_service_listener_stops_future_notifications() {
        let mut p = plugin();
        p.set_server_address(Some(SocketAddr::from(([127, 0, 0, 1], 0))));

        let started = Arc::new(AtomicUsize::new(0));
        let listener: Box<dyn TraceRmiServiceListener> = Box::new(RecordingListener {
            started: started.clone(),
            stopped: Arc::new(AtomicUsize::new(0)),
        });
        // Keep a raw pointer to identify the listener for removal, mirroring identity-based
        // removal from Java's `ListenerSet`.
        let listener_ptr = listener.as_ref() as *const dyn TraceRmiServiceListener;
        p.add_trace_service_listener(listener);
        // SAFETY: the listener is still owned by `p.listeners` at this point, so the pointer is
        // valid for the duration of this call, which only compares addresses.
        p.remove_trace_service_listener(unsafe { &*listener_ptr });

        p.start_server().unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    // --- unported-dependency seams ----------------------------------------------------------

    #[test]
    fn connect_surfaces_real_io_error_for_unreachable_address() {
        let p = plugin();
        // Port 0 is never listening; connecting to it fails at the OS level before this method
        // would even reach the "TraceRmiHandler is not yet ported" seam.
        let err = match p.connect(SocketAddr::from(([127, 0, 0, 1], 1))) {
            Ok(_) => panic!("expected a connection error"),
            Err(e) => e,
        };
        assert_ne!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn accept_one_reports_unsupported_once_bound() {
        let p = plugin();
        let err = match p.accept_one(Some(SocketAddr::from(([127, 0, 0, 1], 0)))) {
            Ok(_) => panic!("expected an unsupported error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn accept_one_internal_reports_unsupported_once_bound() {
        let p = plugin();
        let err = match p.accept_one_internal(Some(SocketAddr::from(([127, 0, 0, 1], 0)))) {
            Ok(_) => panic!("expected an unsupported error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_all_connections_and_acceptors_are_always_empty() {
        let p = plugin();
        assert!(p.get_all_connections().is_empty());
        assert!(p.get_all_acceptors().is_empty());
    }

    // --- consumed services -------------------------------------------------------------------

    #[test]
    fn set_target_service_then_target_service_round_trips() {
        struct MockTargetService;
        impl DebuggerTargetService for MockTargetService {
            fn publish_target(&mut self, _target: Box<dyn crate::app::seam_stubs::Target>) {}
            fn withdraw_target(&mut self, _target: &dyn crate::app::seam_stubs::Target) {}
            fn get_published_targets(&self) -> Vec<Box<dyn crate::app::seam_stubs::Target>> {
                Vec::new()
            }
            fn get_target(
                &self,
                _trace: &dyn crate::trace::model::trace::Trace,
            ) -> Option<Box<dyn crate::app::seam_stubs::Target>> {
                None
            }
            fn add_target_publication_listener(
                &mut self,
                _listener: Box<dyn crate::debug::api::target::TargetPublicationListener>,
            ) {
            }
            fn remove_target_publication_listener(
                &mut self,
                _listener: &dyn crate::debug::api::target::TargetPublicationListener,
            ) {
            }
        }

        let mut p = plugin();
        assert!(p.target_service().is_none());
        p.set_target_service(Some(Box::new(MockTargetService)));
        assert!(p.target_service().is_some());
        p.set_target_service(None);
        assert!(p.target_service().is_none());
    }

    #[test]
    fn create_monitor_without_progress_service_uses_fallback() {
        let p = plugin();
        let monitor = p.create_monitor();
        assert!(!monitor.is_cancelled());
        monitor.close();
        monitor.report_error(Box::new(io::Error::new(io::ErrorKind::Other, "boom")));
    }
}
