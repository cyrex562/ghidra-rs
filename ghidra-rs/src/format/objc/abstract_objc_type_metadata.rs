//! Port of `ghidra.app.util.bin.format.objc.AbstractObjcTypeMetadata`.
//!
//! Java's abstract class stores the fields shared by every Objective-C type-metadata processor
//! (the owning [`Program`], a cancellable [`TaskMonitor`], a [`MessageLog`], and the shared
//! [`ObjcState`]) and declares one abstract method, `applyTo()`, plus two logging convenience
//! methods and a `Closeable::close()` override. Following the composition-over-inheritance split
//! already established by [`ObjcTypeMetadataStructureBase`]/[`ObjcTypeMetadataStructure`] (a
//! sibling class in this same package): the shared fields live in
//! [`AbstractObjcTypeMetadataBase`], and the [`AbstractObjcTypeMetadata`] trait supplies the
//! concrete (logging/`close`) methods plus the one abstract `apply_to` member.

use std::sync::{Arc, Mutex};

use crate::app::util::importer::message_log::MessageLog;
use crate::format::objc::objc_state::ObjcState;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// The shared state every [`AbstractObjcTypeMetadata`] implementor carries.
///
/// Java: the `program`, `monitor`, `log`, and `state` fields on the abstract
/// `AbstractObjcTypeMetadata` class, all set once by its constructor.
///
/// `log` is wrapped in a [`Mutex`] (rather than stored bare) so that
/// [`AbstractObjcTypeMetadata::log`]/[`AbstractObjcTypeMetadata::log_with_error`] can take `&self`
/// -- matching [`ObjcTypeMetadataStructure::apply_to`](super::objc_type_metadata_structure::ObjcTypeMetadataStructure::apply_to)'s
/// own `&self` signature on the sibling trait, so a real `apply_to` implementation can log
/// through `&self` without needing `&mut self` -- mirroring Java, where `log.appendMsg(...)`
/// mutates the field's referent without needing `this` itself to be `mutable` in any sense Java
/// would recognize. `state` is `Arc<Mutex<ObjcState>>` for the same shared-mutable-reference
/// reason already documented on [`ObjcTypeMetadataStructureBase`]'s own `state` field.
pub struct AbstractObjcTypeMetadataBase {
    program: Arc<dyn Program>,
    monitor: Box<dyn TaskMonitor>,
    log: Mutex<MessageLog>,
    state: Arc<Mutex<ObjcState>>,
}

impl AbstractObjcTypeMetadataBase {
    /// Creates a new [`AbstractObjcTypeMetadataBase`].
    ///
    /// Java: `AbstractObjcTypeMetadata(ObjcState state, Program program, TaskMonitor monitor,
    /// MessageLog log) throws IOException, CancelledException`. The declared checked exceptions
    /// exist purely so that concrete subclasses' constructors -- which typically do real
    /// reading/cancellation-checking work of their own right after calling `super(...)` -- can
    /// declare the same `throws` clause; this base constructor's own body is just four field
    /// assignments and never actually throws either exception, so this port returns `Self`
    /// directly rather than a `Result`.
    pub fn new(
        state: Arc<Mutex<ObjcState>>,
        program: Arc<dyn Program>,
        monitor: Box<dyn TaskMonitor>,
        log: MessageLog,
    ) -> Self {
        Self { program, monitor, log: Mutex::new(log), state }
    }

    /// Java: direct access to the protected `program` field.
    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// Java: direct access to the protected `monitor` field.
    pub fn get_monitor(&self) -> &dyn TaskMonitor {
        self.monitor.as_ref()
    }

    /// Java: direct access to the protected `state` field.
    pub fn get_state(&self) -> &Arc<Mutex<ObjcState>> {
        &self.state
    }
}

/// Returns `Self`'s unqualified type name, standing in for Java's `getClass().getSimpleName()`.
///
/// Matches the same convention already established by
/// [`ObjcTypeMetadataStructure::to_display_string`](super::objc_type_metadata_structure::ObjcTypeMetadataStructure::to_display_string)
/// and [`AbstractParsableItem::emit`](crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem::emit).
fn simple_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full)
}

/// Implemented by all Objective-C type-metadata processors.
///
/// Port of the abstract `ghidra.app.util.bin.format.objc.AbstractObjcTypeMetadata` class, which
/// also `implements Closeable`; see [`AbstractObjcTypeMetadata::close`].
pub trait AbstractObjcTypeMetadata {
    /// Accessor to the shared state every implementor carries.
    fn metadata_base(&self) -> &AbstractObjcTypeMetadataBase;

    /// Applies the type metadata to the program.
    ///
    /// Java: `applyTo()` (abstract, no declared checked exceptions, no return value).
    fn apply_to(&self);

    /// Convenience method to perform logging.
    ///
    /// Java: `log(String message)`, which calls `log.appendMsg(getClass().getSimpleName(),
    /// message)`. `getClass().getSimpleName()` is reproduced via [`simple_type_name`], which
    /// resolves to the *concrete* implementor's name because `Self` in a default trait method
    /// binds to whatever concrete type calls it -- the same polymorphism Java gets from
    /// `getClass()`.
    fn log(&self, message: &str) {
        let originator = simple_type_name::<Self>();
        self.metadata_base().log.lock().unwrap().append_msg_from(Some(originator), message);
    }

    /// Convenience method to perform logging (with exception).
    ///
    /// Java: `log(String message, Exception e)`, which appends `message + ": " +
    /// e.getMessage()`. See [`Self::log`] for the `getClass().getSimpleName()` note.
    fn log_with_error(&self, message: &str, e: &dyn std::error::Error) {
        let originator = simple_type_name::<Self>();
        let full_message = format!("{message}: {e}");
        self.metadata_base().log.lock().unwrap().append_msg_from(Some(originator), &full_message);
    }

    /// Closes this type metadata processor, releasing the shared [`ObjcState`].
    ///
    /// Java: `close()` (implements `Closeable`; the override declares no checked exceptions,
    /// narrowing `Closeable.close()`'s `throws IOException`).
    fn close(&self) {
        self.metadata_base().get_state().lock().unwrap().close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::objc::objc_method::ObjcMethod;
    use crate::format::seam_stubs::{LibObjcOptimization, Objc1TypeEncodings, Objc2Class, Objc2InstanceVariable};
    use crate::framework::model::DomainObject;
    use crate::util::task::DummyMonitor;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct StubEncodings;
    impl Objc1TypeEncodings for StubEncodings {
        fn to_string(&self) -> String {
            "stub".to_string()
        }
        fn process_method_signature(
            &self,
            _program: &dyn Program,
            _method_address: &crate::program::model::address::Address,
            _mangled_signature: &str,
            _method_type: &crate::format::objc::objc_method_type::ObjcMethodType,
        ) {
        }
        fn to_function_signature(
            &self,
            _method_name: &str,
            _mangled_signature: &str,
        ) -> Box<dyn crate::format::seam_stubs::FunctionSignature> {
            unimplemented!("not needed for this test")
        }
        fn process_instance_variable_signature(
            &self,
            _program: &dyn Program,
            _instance_variable_address: &crate::program::model::address::Address,
            _mangled_type: &str,
            _instance_variable_size: i32,
        ) {
        }
    }

    fn make_state() -> Arc<Mutex<ObjcState>> {
        Arc::new(Mutex::new(ObjcState {
            been_applied: HashSet::new(),
            method_map: HashMap::<crate::program::model::address::Address, Box<dyn ObjcMethod>>::new(),
            thumb_code_locations: HashSet::new(),
            class_index_map: HashMap::<i64, Box<dyn Objc2Class>>::new(),
            variable_map: HashMap::<crate::program::model::address::Address, Box<dyn Objc2InstanceVariable>>::new(),
            lib_objc_optimization: None::<Box<dyn LibObjcOptimization>>,
            encodings: Box::new(StubEncodings),
        }))
    }

    struct TestMetadata {
        base: AbstractObjcTypeMetadataBase,
        applied: AtomicBool,
    }

    impl AbstractObjcTypeMetadata for TestMetadata {
        fn metadata_base(&self) -> &AbstractObjcTypeMetadataBase {
            &self.base
        }

        fn apply_to(&self) {
            self.applied.store(true, Ordering::SeqCst);
        }
    }

    fn make_metadata() -> TestMetadata {
        TestMetadata {
            base: AbstractObjcTypeMetadataBase::new(
                make_state(),
                Arc::new(MockProgram),
                Box::new(DummyMonitor),
                MessageLog::new(),
            ),
            applied: AtomicBool::new(false),
        }
    }

    #[test]
    fn apply_to_invokes_the_concrete_implementation() {
        let metadata = make_metadata();
        assert!(!metadata.applied.load(Ordering::SeqCst));
        metadata.apply_to();
        assert!(metadata.applied.load(Ordering::SeqCst));
    }

    #[test]
    fn get_program_reaches_the_constructed_program() {
        let metadata = make_metadata();
        assert_eq!(
            crate::program::model::listing::program::Program::get_name(
                metadata.metadata_base().get_program().as_ref()
            ),
            "mock_program"
        );
    }

    #[test]
    fn log_appends_a_message_prefixed_by_the_concrete_simple_name() {
        let metadata = make_metadata();
        metadata.log("hello");
        let log = metadata.metadata_base().log.lock().unwrap();
        assert!(log.to_string().contains("TestMetadata> hello"));
    }

    #[test]
    fn log_with_error_appends_the_message_and_error_text() {
        let metadata = make_metadata();
        let err = std::io::Error::new(std::io::ErrorKind::Other, "boom");
        metadata.log_with_error("failed", &err);
        let log = metadata.metadata_base().log.lock().unwrap();
        assert!(log.to_string().contains("TestMetadata> failed: boom"));
    }

    #[test]
    fn close_clears_the_shared_state() {
        let metadata = make_metadata();
        metadata.metadata_base().get_state().lock().unwrap().been_applied.insert(1);
        assert!(!metadata.metadata_base().get_state().lock().unwrap().been_applied.is_empty());
        metadata.close();
        assert!(metadata.metadata_base().get_state().lock().unwrap().been_applied.is_empty());
    }

    #[test]
    fn trait_object_is_object_safe_and_log_resolves_the_concrete_type_name() {
        let metadata = make_metadata();
        let as_trait: &dyn AbstractObjcTypeMetadata = &metadata;
        as_trait.apply_to();
        as_trait.log("via trait object");
        as_trait.close();
        let log = metadata.metadata_base().log.lock().unwrap();
        // Even dispatched through `dyn AbstractObjcTypeMetadata`, `Self` inside the default
        // `log` method still resolves to the concrete `TestMetadata`, matching Java's
        // `getClass().getSimpleName()` polymorphism.
        assert!(log.to_string().contains("TestMetadata> via trait object"));
    }
}
