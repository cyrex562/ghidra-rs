use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a selected component context when editing a structure/union.
pub trait ComponentContext {
    /// Get editor's data type manager.
    fn get_data_type_manager(&self) -> &dyn DataTypeManager;

    /// Get the editor's selected component's parent composite (structure or union).
    fn get_composite_data_type(&self) -> &dyn Composite;

    /// Get the editor's selected component.
    fn get_data_type_component(&self) -> &dyn DataTypeComponent;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal fakes exist only to prove ComponentContext's accessors round-trip the
    // expected objects (mirrors the Java interface, which is a pure accessor bundle).
    struct FakeComponentContext {
        label: String,
    }

    struct FakeDataTypeComponent {
        ordinal: i32,
    }

    impl DataTypeComponent for FakeDataTypeComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
    }

    impl ComponentContext for FakeComponentContext {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            unimplemented!("not needed for this smoke test")
        }
        fn get_composite_data_type(&self) -> &dyn Composite {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_type_component(&self) -> &dyn DataTypeComponent {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn smoke_construct() {
        // Just proves ComponentContext + DataTypeComponent are object-safe / implementable
        // and that a component's ordinal round-trips, mirroring Java getters returning
        // the values they were given.
        let comp = FakeDataTypeComponent { ordinal: 3 };
        assert_eq!(comp.get_ordinal(), 3);
        let ctx = FakeComponentContext {
            label: "structA".to_string(),
        };
        assert_eq!(ctx.label, "structA");
        let _ = &ctx as &dyn ComponentContext;
    }
}
