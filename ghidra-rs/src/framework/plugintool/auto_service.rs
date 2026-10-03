use std::any::Any;
use std::sync::Arc;

use crate::framework::plugintool::util::ServiceListener;
use crate::framework::seam_stubs::{AutoServiceListenerLike, PluginLike, PluginTool};

/// Handle for the wiring installed by [`AutoService`]'s wiring methods; disposing it releases the
/// wiring's strong reference to its listener.
///
/// Mirrors the nested `ghidra.framework.plugintool.AutoService.Wiring` interface.
pub trait Wiring {
    /// Releases this wiring, mirroring `Wiring.dispose()`.
    fn dispose(&mut self);
}

/// Trait for wiring a plugin-tool receiver's provided and consumed services.
///
/// Mirrors `ghidra.framework.plugintool.AutoService`. In Java this is a static utility interface
/// that uses field reflection (`@AutoServiceProvided`/`@AutoServiceConsumed`) to discover which
/// services a `Plugin` provides and which services an arbitrary receiver object consumes. Rust has
/// no field reflection, so -- mirroring how
/// [`PluginUtils`](crate::framework::plugintool::util::PluginUtils) turns its own reflection-based
/// discovery into an explicit registry -- this becomes a registry trait: implementations declare a
/// provider's provided services, and build a paired listener/service-listener for a receiver's
/// consumed services, explicitly instead of discovering them by scanning annotated fields.
///
/// Was selected as a dependency-cycle cut-point.
pub trait AutoService {
    /// Returns the `(interface name, current value)` pairs `provider` currently provides,
    /// mirroring the reflective field walk in the static `registerServicesProvided(Plugin,
    /// Class<?>, Object)` helper (which reads every `@AutoServiceProvided`-annotated field,
    /// including those declared on superclasses).
    fn provided_services(
        &self,
        provider: &dyn PluginLike,
    ) -> Vec<(String, Arc<dyn Any + Send + Sync>)>;

    /// Builds the paired listener registration for `receiver`: an [`AutoServiceListenerLike`]
    /// handle (for notifying current services, and for the returned [`Wiring`] to hold a strong
    /// reference to) and its [`ServiceListener`] view (for registering with the tool). Mirrors
    /// `new AutoServiceListener<>(receiver)`, which is itself both things at once (`class
    /// AutoServiceListener<R> implements ServiceListener`); here they are two views of one
    /// implementor, since Rust trait objects cannot be upcast to an unrelated trait.
    fn listener_for(
        &self,
        receiver: Arc<dyn Any + Send + Sync>,
    ) -> (Arc<dyn AutoServiceListenerLike>, Arc<dyn ServiceListener>);

    /// Registers every service `provider` provides (per [`Self::provided_services`]) with
    /// `plugin`, mirroring the static `registerServicesProvided(Plugin, Class<?>, Object)` helper
    /// (called there with `provider` initially equal to `plugin` itself, and `cls` walked up from
    /// `plugin.getClass()` to collect inherited fields; here the class-hierarchy walk is
    /// [`Self::provided_services`]'s job instead, so no recursion is needed here).
    fn register_services_provided(&self, plugin: &dyn PluginLike, provider: &dyn PluginLike) {
        for (iface, service) in self.provided_services(provider) {
            plugin.register_service_provided(&iface, service);
        }
    }

    /// Wires `receiver` to be notified of every currently-available service it consumes, and to
    /// receive future service add/remove notifications from `tool`, mirroring the static
    /// `wireServicesConsumed(PluginTool, Object)`.
    fn wire_services_consumed(
        &self,
        tool: &dyn PluginTool,
        receiver: Arc<dyn Any + Send + Sync>,
    ) -> Box<dyn Wiring> {
        let (listener, as_service_listener) = self.listener_for(receiver);
        tool.add_service_listener(as_service_listener);
        listener.notify_current_services(tool);
        Box::new(AutoServiceWiring {
            listener: Some(listener),
        })
    }

    /// Wires `receiver` via `plugin`'s tool, mirroring the two-argument
    /// `wireServicesConsumed(Plugin, Object)` overload.
    fn wire_services_consumed_via_plugin(
        &self,
        plugin: &dyn PluginLike,
        receiver: Arc<dyn Any + Send + Sync>,
    ) -> Box<dyn Wiring> {
        self.wire_services_consumed(plugin.tool().as_ref(), receiver)
    }

    /// Registers `plugin`'s own provided services and wires `receiver` to `plugin`'s consumed
    /// services, mirroring `wireServicesProvidedAndConsumed(Plugin)`. Java's version always uses
    /// `plugin` itself as both the provider and the receiver; here the receiver is passed
    /// explicitly, since an object-safe `&dyn PluginLike` cannot manufacture an `Arc` handle to
    /// itself -- callers wire a plugin to its own consumed services by passing their own `Arc`
    /// handle to that same plugin as `receiver`.
    fn wire_services_provided_and_consumed(
        &self,
        plugin: &dyn PluginLike,
        receiver: Arc<dyn Any + Send + Sync>,
    ) -> Box<dyn Wiring> {
        self.register_services_provided(plugin, plugin);
        self.wire_services_consumed_via_plugin(plugin, receiver)
    }
}

/// Default [`Wiring`] returned by [`AutoService`]'s wiring methods, mirroring the private
/// `AutoService.WiringImpl` class. Holds the sole strong reference to its listener -- Java's
/// `WiringImpl` comment notes its own field is kept only to hold a "strong reference", implying the
/// tool itself holds listeners more weakly -- so dropping/disposing it is what allows the listener
/// to eventually be released.
struct AutoServiceWiring {
    listener: Option<Arc<dyn AutoServiceListenerLike>>,
}

impl Wiring for AutoServiceWiring {
    fn dispose(&mut self) {
        self.listener = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::sync::Mutex;

    struct MockListener {
        receiver_log: Arc<Mutex<Vec<String>>>,
    }

    impl AutoServiceListenerLike for MockListener {
        fn notify_current_services(&self, tool: &dyn PluginTool) {
            if let Some(service) = tool.get_service("com.example.FooService") {
                if let Some(name) = service.downcast_ref::<String>() {
                    self.receiver_log.lock().unwrap().push(name.clone());
                }
            }
        }
    }

    impl ServiceListener for MockListener {
        fn service_added(&self, _interface_class: TypeId, service: Arc<dyn Any + Send + Sync>) {
            if let Some(name) = service.downcast_ref::<String>() {
                self.receiver_log.lock().unwrap().push(name.clone());
            }
        }

        fn service_removed(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}
    }

    struct MockTool {
        foo_service: Option<Arc<dyn Any + Send + Sync>>,
        listeners: Mutex<Vec<Arc<dyn ServiceListener>>>,
    }

    impl PluginTool for MockTool {
        fn get_service(&self, iface: &str) -> Option<Arc<dyn Any + Send + Sync>> {
            if iface == "com.example.FooService" {
                self.foo_service.clone()
            } else {
                None
            }
        }

        fn add_service_listener(&self, listener: Arc<dyn ServiceListener>) {
            self.listeners.lock().unwrap().push(listener);
        }
    }

    struct MockPlugin {
        tool: Arc<MockTool>,
        provided: Mutex<Vec<(String, Arc<dyn Any + Send + Sync>)>>,
    }

    impl PluginLike for MockPlugin {
        fn register_service_provided(&self, iface: &str, service: Arc<dyn Any + Send + Sync>) {
            self.provided
                .lock()
                .unwrap()
                .push((iface.to_string(), service));
        }

        fn tool(&self) -> Arc<dyn PluginTool> {
            self.tool.clone()
        }
    }

    struct MockAutoService {
        receiver_log: Arc<Mutex<Vec<String>>>,
    }

    impl AutoService for MockAutoService {
        fn provided_services(
            &self,
            _provider: &dyn PluginLike,
        ) -> Vec<(String, Arc<dyn Any + Send + Sync>)> {
            vec![(
                "com.example.BarService".to_string(),
                Arc::new("bar-impl".to_string()) as Arc<dyn Any + Send + Sync>,
            )]
        }

        fn listener_for(
            &self,
            _receiver: Arc<dyn Any + Send + Sync>,
        ) -> (Arc<dyn AutoServiceListenerLike>, Arc<dyn ServiceListener>) {
            let listener = Arc::new(MockListener {
                receiver_log: self.receiver_log.clone(),
            });
            (listener.clone(), listener)
        }
    }

    #[test]
    fn wire_services_provided_and_consumed_registers_and_notifies() {
        let tool = Arc::new(MockTool {
            foo_service: Some(Arc::new("foo-impl".to_string())),
            listeners: Mutex::new(Vec::new()),
        });
        let plugin = MockPlugin {
            tool: tool.clone(),
            provided: Mutex::new(Vec::new()),
        };
        let receiver_log = Arc::new(Mutex::new(Vec::new()));
        let auto_service: Box<dyn AutoService> = Box::new(MockAutoService {
            receiver_log: receiver_log.clone(),
        });

        let receiver: Arc<dyn Any + Send + Sync> = Arc::new("receiver".to_string());
        let mut wiring = auto_service.wire_services_provided_and_consumed(&plugin, receiver);

        let provided = plugin.provided.lock().unwrap();
        assert_eq!(provided.len(), 1);
        assert_eq!(provided[0].0, "com.example.BarService");
        drop(provided);

        assert_eq!(tool.listeners.lock().unwrap().len(), 1);
        assert_eq!(receiver_log.lock().unwrap().as_slice(), ["foo-impl"]);

        wiring.dispose();
    }

    #[test]
    fn wire_services_consumed_notifies_and_service_listener_pushes_updates() {
        let tool = Arc::new(MockTool {
            foo_service: None,
            listeners: Mutex::new(Vec::new()),
        });
        let receiver_log = Arc::new(Mutex::new(Vec::new()));
        let auto_service: Box<dyn AutoService> = Box::new(MockAutoService {
            receiver_log: receiver_log.clone(),
        });

        let receiver: Arc<dyn Any + Send + Sync> = Arc::new("receiver".to_string());
        let _wiring = auto_service.wire_services_consumed(tool.as_ref(), receiver);

        // No service was available yet, so notify_current_services found nothing.
        assert!(receiver_log.lock().unwrap().is_empty());

        // Simulate the tool later announcing a newly-available service via the registered
        // ServiceListener view.
        let listeners = tool.listeners.lock().unwrap();
        assert_eq!(listeners.len(), 1);
        let service: Arc<dyn Any + Send + Sync> = Arc::new("late-impl".to_string());
        listeners[0].service_added(TypeId::of::<String>(), service);

        assert_eq!(receiver_log.lock().unwrap().as_slice(), ["late-impl"]);
    }
}
