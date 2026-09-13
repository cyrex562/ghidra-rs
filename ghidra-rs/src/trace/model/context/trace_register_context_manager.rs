use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::context::trace_register_context_operations::TraceRegisterContextOperations;
use crate::trace::model::context::trace_register_context_space::TraceRegisterContextSpace;
use crate::trace::model::thread::TraceThread;

/// Manages register (processor context) values recorded across all address spaces and threads
/// of a trace.
///
/// Port of `ghidra.trace.model.context.TraceRegisterContextManager`.
pub trait TraceRegisterContextManager: TraceRegisterContextOperations {
    /// Obtain a register context space bound to a particular address space.
    ///
    /// * `create_if_absent` - true to create the space if it's not already present.
    ///
    /// Mirrors `getRegisterContextSpace(AddressSpace, boolean)`.
    fn get_register_context_space(
        &self,
        address_space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceRegisterContextSpace>>;

    /// Obtain a register context space bound to the register address space for a given thread.
    ///
    /// * `create_if_absent` - true to create the space if it's not already present.
    ///
    /// Mirrors `getRegisterContextRegisterSpace(TraceThread, boolean)`.
    fn get_register_context_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceRegisterContextSpace>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSetView, AddressSpaceType};
    use crate::program::model::lang::{Language, Register};
    use crate::program::seam_stubs::RegisterValue;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::guest::trace_platform::TracePlatform;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::model::target::trace_object::TraceObject;
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::seam_stubs::ObjectKey;

    /// Minimal implementor proving `TraceRegisterContextManager` is object-safe and that its two
    /// space accessors honor `create_if_absent`.
    struct MockManager {
        space: Arc<AddressSpace>,
        has_space: bool,
        has_thread_space: bool,
    }

    impl TraceRegisterContextOperations for MockManager {
        fn get_default_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn set_value(
            &mut self,
            _language: &dyn Language,
            _value: &dyn RegisterValue,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) {
        }

        fn remove_value(
            &mut self,
            _language: &dyn Language,
            _register: &Register,
            _span: Lifespan,
            _range: &AddressRange,
        ) {
        }

        fn get_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_entry(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)> {
            None
        }

        fn get_value_with_default(
            &self,
            _platform: &dyn TracePlatform,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_register_value_address_ranges_within(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_value_address_ranges(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_register_value_in_address_range(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> bool {
            false
        }

        fn has_register_value(&self, _language: &dyn Language, _register: &Register, _snap: i64) -> bool {
            false
        }

        fn clear(&mut self, _span: Lifespan, _range: &AddressRange) {}
    }

    struct MockContextSpace {
        space: Arc<AddressSpace>,
    }

    impl TraceRegisterContextOperations for MockContextSpace {
        fn get_default_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_value(
            &mut self,
            _language: &dyn Language,
            _value: &dyn RegisterValue,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) {
        }
        fn remove_value(
            &mut self,
            _language: &dyn Language,
            _register: &Register,
            _span: Lifespan,
            _range: &AddressRange,
        ) {
        }
        fn get_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_entry(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)> {
            None
        }
        fn get_value_with_default(
            &self,
            _platform: &dyn TracePlatform,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_register_value_address_ranges_within(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_value_address_ranges(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_register_value_in_address_range(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> bool {
            false
        }

        fn has_register_value(&self, _language: &dyn Language, _register: &Register, _snap: i64) -> bool {
            false
        }

        fn clear(&mut self, _span: Lifespan, _range: &AddressRange) {}
    }

    impl TraceRegisterContextSpace for MockContextSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some_and(|other| other.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockThread {
        name: String,
    }

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_key(&self) -> i64 {
            1
        }

        fn get_path(&self) -> String {
            self.name.clone()
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            self.name = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) {
            self.name = name.to_string();
        }

        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}

        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }

        fn delete(&mut self) {}

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, _snap: i64) -> bool {
            true
        }

        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    impl TraceRegisterContextManager for MockManager {
        fn get_register_context_space(
            &self,
            _address_space: &Arc<AddressSpace>,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceRegisterContextSpace>> {
            if self.has_space || create_if_absent {
                Some(Box::new(MockContextSpace { space: self.space.clone() }))
            } else {
                None
            }
        }

        fn get_register_context_register_space(
            &self,
            _thread: &dyn TraceThread,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceRegisterContextSpace>> {
            if self.has_thread_space || create_if_absent {
                Some(Box::new(MockContextSpace { space: self.space.clone() }))
            } else {
                None
            }
        }
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    #[test]
    fn get_register_context_space_returns_none_when_absent_and_not_created() {
        let manager = MockManager { space: register_space(), has_space: false, has_thread_space: false };
        let addr_space = register_space();
        assert!(manager.get_register_context_space(&addr_space, false).is_none());
    }

    #[test]
    fn get_register_context_space_creates_when_requested() {
        let manager = MockManager { space: register_space(), has_space: false, has_thread_space: false };
        let addr_space = register_space();
        let space = manager.get_register_context_space(&addr_space, true);
        assert!(space.is_some());
    }

    #[test]
    fn get_register_context_register_space_honors_create_if_absent() {
        let manager = MockManager { space: register_space(), has_space: false, has_thread_space: false };
        let thread = MockThread { name: "thread0".to_string() };
        assert!(manager.get_register_context_register_space(&thread, false).is_none());
        assert!(manager.get_register_context_register_space(&thread, true).is_some());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let manager: Box<dyn TraceRegisterContextManager> =
            Box::new(MockManager { space: register_space(), has_space: true, has_thread_space: true });
        let addr_space = register_space();
        assert!(manager.get_register_context_space(&addr_space, false).is_some());
    }
}
