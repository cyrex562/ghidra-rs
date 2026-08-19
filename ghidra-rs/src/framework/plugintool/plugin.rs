//! Port of `ghidra.framework.plugintool.Plugin`.
//!
//! Plugins are a basic building block in Ghidra, used to bundle features or capabilities into a
//! unit that can be enabled or disabled by the user in their Tool. Selected as a
//! dependency-cycle cut-point, so it is ported as an object-safe trait rather than an abstract
//! base class.
//!
//! Java's `Plugin` is an abstract class that carries private mutable state (`tool`, `name`,
//! `pluginDescription`, the `eventsProduced`/`eventsConsumed`/`services` lists, and the
//! `constructorFinished`/`disposed` flags) alongside methods meant to be overridden by
//! subclasses. Rust traits cannot hold fields, so every accessor that Java derives from that
//! private state (`getName()`, `getTool()`, `getPluginDescription()`, `isDisposed()`,
//! service/event bookkeeping) becomes a required method here with no default body -- a concrete
//! implementation is expected to back these with its own storage, exactly as
//! [`PluginDescription`] and [`PluginUtils`](crate::framework::plugintool::util::PluginUtils)
//! already do for their own state. The overridable lifecycle hooks (`init()`, `dispose()`,
//! `processEvent(PluginEvent)`, etc.) keep their Java default (no-op/trivial) bodies. The
//! `final`, purely-derived methods (`dependsUpon`, `getMissingRequiredServices`,
//! `hasMissingRequiredService`, `firePluginEvent`, `equals`) are reproduced as default methods
//! that only call other trait methods.
//!
//! Mirrors `implements ExtensionPoint, PluginEventListener, ServiceListener` via supertraits;
//! implementations provide the trivial one-line `event_sent`/`service_added`/`service_removed`
//! bodies Java gets for free through class inheritance (see
//! [`Plugin::handle_plugin_event`] for the shared `eventSent` logic to delegate to).
//!
//! Java's private construction/teardown helpers (`registerPluginImplementedServices`,
//! `registerStaticEvents`, `registerQueuedServices`, `doRegisterServiceProvided`,
//! `unregisterEvents`, `unregisterServices`) are implementation details of the concrete base
//! class, never called by other classes, so they are not part of this trait's surface; a
//! concrete `Plugin` implementation performs the equivalent bookkeeping internally.

use std::any::Any;
use std::sync::Arc;

use crate::framework::model::{DomainFile, DomainObject};
use crate::framework::plugintool::plugin_event::PluginEvent;
use crate::framework::plugintool::util::{PluginDescription, PluginEventListener, ServiceListener};
use crate::framework::seam_stubs::{PluginTool, SaveState};
use crate::util::classfinder::ExtensionPoint;

/// A basic building block used to bundle features or capabilities into a unit that can be
/// enabled or disabled by the user in their Tool.
///
/// Mirrors `ghidra.framework.plugintool.Plugin`.
pub trait Plugin: ExtensionPoint + PluginEventListener + ServiceListener {
    /// Returns this plugin's name, derived from its simple class name in Java.
    ///
    /// Mirrors the final `getName()`.
    fn name(&self) -> String;

    /// Get the [`PluginTool`] that hosts/contains this plugin.
    ///
    /// Mirrors the final `getTool()`.
    fn tool(&self) -> Arc<dyn PluginTool>;

    /// Returns the static [`PluginDescription`] describing this plugin, derived from its
    /// `PluginInfo` metadata.
    ///
    /// Mirrors the final `getPluginDescription()`.
    fn plugin_description(&self) -> &dyn PluginDescription;

    /// Returns true once this plugin has been disposed (its `cleanup()` has run).
    ///
    /// Mirrors `isDisposed()`.
    fn is_disposed(&self) -> bool;

    /// Names of the `PluginEvent` types this plugin has registered as producing.
    ///
    /// Mirrors the package-private `eventsProduced` field/`getEventsProduced()` on
    /// `PluginDescription`, tracked here as this plugin instance's own registered subset.
    fn events_produced(&self) -> Vec<String> {
        Vec::new()
    }

    /// Names of the `PluginEvent` types this plugin has registered as consuming, mirroring the
    /// package-private `eventsConsumed` field.
    fn events_consumed(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns the service interface names this plugin currently provides, mirroring the
    /// package-private `getServiceClasses()`.
    fn service_classes(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns the provider instances currently registered for the given service interface,
    /// mirroring the package-private `getServiceProviderInstances(Class<?>)`.
    fn service_provider_instances(&self, _interface_class: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        Vec::new()
    }

    /// Returns true if this plugin currently provides the given service interface, mirroring
    /// the package-private `providesService(Class<?>)`.
    fn provides_service(&self, interface_class: &str) -> bool {
        !self.service_provider_instances(interface_class).is_empty()
    }

    /// Registers `service` as this plugin's implementation of `interface_class`, mirroring
    /// `registerServiceProvided(Class<? super T>, T)`.
    fn register_service_provided(&self, interface_class: &str, service: Arc<dyn Any + Send + Sync>);

    /// Registers `service` dynamically, at runtime rather than during construction, mirroring
    /// `registerDynamicServiceProvided(Class<? super T>, T)`. In Java both overloads share one
    /// private implementation that differs only in an (currently disabled) constructor-phase
    /// assertion, so this defaults to [`Self::register_service_provided`].
    fn register_dynamic_service_provided(
        &self,
        interface_class: &str,
        service: Arc<dyn Any + Send + Sync>,
    ) {
        self.register_service_provided(interface_class, service);
    }

    /// Unregisters a previously-registered service, mirroring `deregisterService(Class<?>,
    /// Object)`.
    fn deregister_service(&self, interface_class: &str, service: &Arc<dyn Any + Send + Sync>);

    /// Registers a `PluginEvent` type this plugin consumes outside of its static
    /// `PluginInfo` metadata, mirroring the protected final
    /// `internalRegisterEventConsumed(Class<? extends PluginEvent>)`.
    fn internal_register_event_consumed(&self, event_class: &str);

    /// Called by the framework after construction finishes, to publish any services queued
    /// during the constructor with the [`PluginTool`], mirroring the package-private
    /// `initServices()`. No-op by default.
    fn init_services(&self) {}

    /// Called by the framework to process any events fired before this plugin registered to
    /// consume them, mirroring the package-private `processLastEvents(PluginEvent[])`.
    fn process_last_events(&self, last_events: &[PluginEvent]) {
        for event in last_events {
            if self.events_consumed().iter().any(|name| name == event.event_name()) {
                self.process_event(event);
            }
        }
    }

    /// Called by the framework to dispose of this plugin and unregister its events and
    /// services, mirroring the protected `cleanup()`. Subclasses should override [`Self::dispose`]
    /// rather than this method; the default here only calls [`Self::dispose`], since the
    /// service/event de-registration Java performs alongside it requires state this trait does
    /// not hold.
    fn cleanup(&self) {
        self.dispose();
    }

    /// Initialization hook; override to add initialization for this plugin. Called once all
    /// plugins have been instantiated in the tool and this plugin's required services are
    /// available.
    ///
    /// Mirrors the protected `init()`. No-op by default.
    fn init(&self) {}

    /// Tells this plugin it is no longer needed and should release any resources it holds.
    ///
    /// Mirrors the protected `dispose()`. No-op by default.
    fn dispose(&self) {}

    /// Processes a plugin event. Override if this plugin consumes `PluginEvent`s.
    ///
    /// Mirrors `processEvent(PluginEvent)`. No-op by default.
    fn process_event(&self, _event: &PluginEvent) {}

    /// Return the type names of data types that this plugin can support, mirroring
    /// `getSupportedDataTypes()`.
    fn get_supported_data_types(&self) -> Vec<String> {
        Vec::new()
    }

    /// Called if the plugin supports the given domain files, mirroring
    /// `acceptData(DomainFile[])`.
    fn accept_data(&self, _data: &[Box<dyn DomainFile>]) -> bool {
        false
    }

    /// Requests this plugin to process a URL if supported, mirroring `accept(URL)`.
    fn accept(&self, _url: &str) -> bool {
        false
    }

    /// Get the domain files that this plugin has open, mirroring `getData()`.
    fn get_data(&self) -> Vec<Box<dyn DomainFile>> {
        Vec::new()
    }

    /// Reads this plugin's data-independent (preferences) properties, mirroring
    /// `readConfigState(SaveState)`. No-op by default.
    fn read_config_state(&self, _save_state: &dyn SaveState) {}

    /// Writes this plugin's data-independent (preferences) properties, mirroring
    /// `writeConfigState(SaveState)`. No-op by default.
    fn write_config_state(&self, _save_state: &mut dyn SaveState) {}

    /// Writes this plugin's data-dependent state, mirroring `writeDataState(SaveState)`. No-op
    /// by default.
    fn write_data_state(&self, _save_state: &mut dyn SaveState) {}

    /// Reads this plugin's data-dependent state, mirroring `readDataState(SaveState)`. No-op by
    /// default.
    fn read_data_state(&self, _save_state: &dyn SaveState) {}

    /// Forces this plugin to terminate any running tasks and apply unsaved data, mirroring the
    /// protected `canClose()`. Returns `true` by default.
    fn can_close(&self) -> bool {
        true
    }

    /// Allows this plugin to cancel the closing of a domain object, mirroring the protected
    /// `canCloseDomainObject(DomainObject)`. Returns `true` by default.
    fn can_close_domain_object(&self, _domain_object: &dyn DomainObject) -> bool {
        true
    }

    /// Allows this plugin to flush caches to the domain object before it is saved, mirroring
    /// the protected `prepareToSave(DomainObject)`. No-op by default.
    fn prepare_to_save(&self, _domain_object: &dyn DomainObject) {}

    /// Forces this plugin to save any domain object data it is controlling, mirroring the
    /// protected `saveData()`. Returns `true` by default.
    fn save_data(&self) -> bool {
        true
    }

    /// Returns true if this plugin has data that needs saving, mirroring the protected
    /// `hasUnsaveData()`. Returns `false` by default.
    fn has_unsaved_data(&self) -> bool {
        false
    }

    /// Releases resources this plugin obtained from other services, called before
    /// [`Self::dispose`], mirroring the protected `close()`. No-op by default.
    fn close(&self) {}

    /// Notification that all plugins have had their data states restored, mirroring
    /// `dataStateRestoreCompleted()`. No-op by default.
    fn data_state_restore_completed(&self) {}

    /// Returns this plugin's undo/redo state for the given domain object, mirroring
    /// `getUndoRedoState(DomainObject)`. Returns `None` by default.
    fn get_undo_redo_state(&self, _domain_object: &dyn DomainObject) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }

    /// Updates this plugin's state from a previously-saved undo/redo state, mirroring
    /// `restoreUndoRedoState(DomainObject, Object)`. No-op by default.
    fn restore_undo_redo_state(
        &self,
        _domain_object: &dyn DomainObject,
        _state: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    /// Shared `eventSent(PluginEvent)` logic: dispatches to [`Self::process_event`] unless this
    /// plugin was the immediate source of the event. Java gets this for free as a `final` method
    /// on the `Plugin` base class; implementations of the supertrait
    /// [`PluginEventListener::event_sent`] should delegate to this method.
    fn handle_plugin_event(&self, event: &PluginEvent) {
        if event.source_name() != self.name() {
            self.process_event(event);
        }
    }

    /// Fires the given plugin event; the tool notifies all other plugins interested in
    /// receiving it, mirroring `firePluginEvent(PluginEvent)`.
    fn fire_plugin_event(&self, mut event: PluginEvent) {
        event.set_source_name(self.name());
        self.tool().fire_plugin_event(event);
    }

    /// Returns the required services that are not currently available via the [`PluginTool`],
    /// mirroring `getMissingRequiredServices()`.
    fn missing_required_services(&self) -> Vec<String> {
        self.plugin_description()
            .services_required()
            .into_iter()
            .filter(|interface_class| self.tool().get_service(interface_class).is_none())
            .collect()
    }

    /// Checks if this plugin is missing a required service, mirroring
    /// `hasMissingRequiredService()`.
    fn has_missing_required_service(&self) -> bool {
        !self.missing_required_services().is_empty()
    }

    /// Determine if this plugin is the sole active provider of the given service interface,
    /// mirroring the private `isOnlyProviderOfService(Class<?>)`.
    fn is_only_provider_of_service(&self, interface_class: &str) -> bool {
        let active_instances = self.tool().get_services(interface_class);
        if active_instances.is_empty() {
            return false;
        }
        active_instances.len() == self.service_provider_instances(interface_class).len()
    }

    /// Check if this plugin depends on `other`, mirroring `dependsUpon(Plugin)`.
    fn depends_upon(&self, other: &dyn Plugin) -> bool {
        self.plugin_description()
            .services_required()
            .iter()
            .any(|interface_class| other.is_only_provider_of_service(interface_class))
    }

    /// Compares two plugins for equality by tool identity and name, mirroring
    /// `equals(Object)`/`hashCode()`.
    fn is_same_plugin(&self, other: &dyn Plugin) -> bool {
        Arc::ptr_eq(&self.tool(), &other.tool()) && self.name() == other.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::util::PluginStatus;
    use crate::framework::seam_stubs::PluginPackageLike;
    use std::sync::Mutex;

    struct MockPackage;
    impl PluginPackageLike for MockPackage {
        fn name(&self) -> String {
            "Core".to_string()
        }
    }

    struct MockDescription {
        services_required: Vec<String>,
    }

    impl PluginDescription for MockDescription {
        fn plugin_class_name(&self) -> String {
            "com.example.MockPlugin".to_string()
        }
        fn name(&self) -> String {
            "MockPlugin".to_string()
        }
        fn short_description(&self) -> String {
            String::new()
        }
        fn description(&self) -> String {
            String::new()
        }
        fn category(&self) -> String {
            "Common".to_string()
        }
        fn status(&self) -> PluginStatus {
            PluginStatus::Stable
        }
        fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
            Box::new(MockPackage)
        }
        fn is_slow_installation(&self) -> bool {
            false
        }
        fn services_required(&self) -> Vec<String> {
            self.services_required.clone()
        }
        fn services_provided(&self) -> Vec<String> {
            Vec::new()
        }
        fn events_consumed(&self) -> Vec<String> {
            Vec::new()
        }
        fn events_produced(&self) -> Vec<String> {
            Vec::new()
        }
        fn source_location(&self) -> String {
            String::new()
        }
        fn module_name(&self) -> String {
            String::new()
        }
        fn is_in_extension(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct MockTool {
        services: Mutex<Vec<(String, Arc<dyn Any + Send + Sync>)>>,
    }

    impl PluginTool for MockTool {
        fn get_service(&self, iface: &str) -> Option<Arc<dyn Any + Send + Sync>> {
            self.services
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == iface)
                .map(|(_, svc)| svc.clone())
        }

        fn get_services(&self, iface: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
            self.services
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name == iface)
                .map(|(_, svc)| svc.clone())
                .collect()
        }
    }

    struct MockPlugin {
        name: String,
        tool: Arc<MockTool>,
        description: MockDescription,
        disposed: Mutex<bool>,
        processed_events: Mutex<Vec<String>>,
        provided: Mutex<Vec<(String, Arc<dyn Any + Send + Sync>)>>,
    }

    impl MockPlugin {
        fn new(name: &str, tool: Arc<MockTool>, services_required: Vec<String>) -> Self {
            Self {
                name: name.to_string(),
                tool,
                description: MockDescription { services_required },
                disposed: Mutex::new(false),
                processed_events: Mutex::new(Vec::new()),
                provided: Mutex::new(Vec::new()),
            }
        }
    }

    impl ExtensionPoint for MockPlugin {}

    impl PluginEventListener for MockPlugin {
        fn event_sent(&self, event: &PluginEvent) {
            self.handle_plugin_event(event);
        }
    }

    impl ServiceListener for MockPlugin {
        fn service_added(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}
        fn service_removed(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}
    }

    impl Plugin for MockPlugin {
        fn name(&self) -> String {
            self.name.clone()
        }

        fn tool(&self) -> Arc<dyn PluginTool> {
            self.tool.clone()
        }

        fn plugin_description(&self) -> &dyn PluginDescription {
            &self.description
        }

        fn is_disposed(&self) -> bool {
            *self.disposed.lock().unwrap()
        }

        fn service_provider_instances(&self, interface_class: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
            self.provided
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name == interface_class)
                .map(|(_, svc)| svc.clone())
                .collect()
        }

        fn register_service_provided(&self, interface_class: &str, service: Arc<dyn Any + Send + Sync>) {
            self.provided.lock().unwrap().push((interface_class.to_string(), service.clone()));
            self.tool.services.lock().unwrap().push((interface_class.to_string(), service));
        }

        fn deregister_service(&self, interface_class: &str, _service: &Arc<dyn Any + Send + Sync>) {
            self.provided.lock().unwrap().retain(|(name, _)| name != interface_class);
        }

        fn internal_register_event_consumed(&self, _event_class: &str) {}

        fn process_event(&self, event: &PluginEvent) {
            self.processed_events.lock().unwrap().push(event.event_name().to_string());
        }

        fn dispose(&self) {
            *self.disposed.lock().unwrap() = true;
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let tool = Arc::new(MockTool::default());
        let plugin: Box<dyn Plugin> = Box::new(MockPlugin::new("MockPlugin", tool, Vec::new()));
        assert_eq!(plugin.name(), "MockPlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn event_sent_from_other_source_dispatches_to_process_event() {
        let tool = Arc::new(MockTool::default());
        let plugin = MockPlugin::new("MockPlugin", tool, Vec::new());

        let event = PluginEvent::new("OtherPlugin", "SomeEvent");
        plugin.event_sent(&event);

        assert_eq!(plugin.processed_events.lock().unwrap().as_slice(), ["SomeEvent"]);
    }

    #[test]
    fn event_sent_from_self_is_not_reprocessed() {
        let tool = Arc::new(MockTool::default());
        let plugin = MockPlugin::new("MockPlugin", tool, Vec::new());

        let event = PluginEvent::new("MockPlugin", "SelfEvent");
        plugin.event_sent(&event);

        assert!(plugin.processed_events.lock().unwrap().is_empty());
    }

    #[test]
    fn dispose_marks_plugin_disposed_via_cleanup_default() {
        let tool = Arc::new(MockTool::default());
        let plugin = MockPlugin::new("MockPlugin", tool, Vec::new());

        assert!(!plugin.is_disposed());
        plugin.cleanup();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn missing_required_services_reports_unavailable_services() {
        let tool = Arc::new(MockTool::default());
        let plugin = MockPlugin::new(
            "MockPlugin",
            tool,
            vec!["com.example.NeededService".to_string()],
        );

        assert!(plugin.has_missing_required_service());
        assert_eq!(
            plugin.missing_required_services(),
            vec!["com.example.NeededService".to_string()]
        );
    }

    #[test]
    fn registering_required_service_clears_missing_service() {
        let tool = Arc::new(MockTool::default());
        let plugin = MockPlugin::new(
            "MockPlugin",
            tool,
            vec!["com.example.NeededService".to_string()],
        );

        plugin.register_service_provided("com.example.NeededService", Arc::new(42i32));

        assert!(!plugin.has_missing_required_service());
    }

    #[test]
    fn depends_upon_true_when_other_is_sole_provider() {
        let tool = Arc::new(MockTool::default());
        let provider = MockPlugin::new("ProviderPlugin", tool.clone(), Vec::new());
        let consumer = MockPlugin::new(
            "ConsumerPlugin",
            tool,
            vec!["com.example.SharedService".to_string()],
        );

        provider.register_service_provided("com.example.SharedService", Arc::new("impl"));

        assert!(consumer.depends_upon(&provider));
    }

    #[test]
    fn depends_upon_false_when_multiple_providers_exist() {
        let tool = Arc::new(MockTool::default());
        let provider_a = MockPlugin::new("ProviderA", tool.clone(), Vec::new());
        let provider_b = MockPlugin::new("ProviderB", tool.clone(), Vec::new());
        let consumer = MockPlugin::new(
            "ConsumerPlugin",
            tool,
            vec!["com.example.SharedService".to_string()],
        );

        provider_a.register_service_provided("com.example.SharedService", Arc::new("impl-a"));
        provider_b.register_service_provided("com.example.SharedService", Arc::new("impl-b"));

        assert!(!consumer.depends_upon(&provider_a));
        assert!(!consumer.depends_upon(&provider_b));
    }

    #[test]
    fn is_same_plugin_compares_tool_identity_and_name() {
        let tool_a = Arc::new(MockTool::default());
        let tool_b = Arc::new(MockTool::default());

        let a1 = MockPlugin::new("SamePlugin", tool_a.clone(), Vec::new());
        let a2 = MockPlugin::new("SamePlugin", tool_a, Vec::new());
        let b = MockPlugin::new("SamePlugin", tool_b, Vec::new());

        assert!(a1.is_same_plugin(&a2));
        assert!(!a1.is_same_plugin(&b));
    }
}
