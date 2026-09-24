//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiTraceObjectValue`, the Java
//! `record` for one value returned by a `getValues` query.

use std::fmt;
use std::sync::Arc;

use crate::app::plugin::core::debug::client::tracermi::{RmiTraceObject, RmiValue};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::TraceObjectSchema;

/// One value of a trace object: its parent, lifespan, key, value, and the schema of the value's
/// type. A record, so the components are plain fields.
#[derive(Clone)]
pub struct RmiTraceObjectValue {
    /// The object holding the value.
    pub parent: RmiTraceObject,
    /// When the value is in effect.
    pub span: Lifespan,
    /// The attribute or element key.
    pub key: String,
    /// The value itself.
    pub value: RmiValue,
    /// The schema of the value's type.
    pub schema: Arc<dyn TraceObjectSchema>,
}

impl fmt::Debug for RmiTraceObjectValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiTraceObjectValue")
            .field("parent", &self.parent)
            .field("span", &self.span)
            .field("key", &self.key)
            .field("value", &self.value)
            .field("schema", &self.schema.get_name())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::SchemaName;

    struct Named;
    impl TraceObjectSchema for Named {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("LONG")
        }
        fn to_string(&self) -> String {
            "LONG".into()
        }
    }

    #[test]
    fn components_are_readable_and_clone_shares_schema() {
        let v = RmiTraceObjectValue {
            parent: RmiTraceObject::from_path(1, "Processes[1]"),
            span: Lifespan::span(2, 4),
            key: "_pid".into(),
            value: RmiValue::Long(99),
            schema: Arc::new(Named),
        };
        let c = v.clone();
        assert_eq!(c.parent.get_path(), Some("Processes[1]"));
        assert_eq!(c.span, Lifespan::span(2, 4));
        assert_eq!(c.key, "_pid");
        assert!(matches!(c.value, RmiValue::Long(99)));
        assert!(Arc::ptr_eq(&v.schema, &c.schema));
        assert!(format!("{c:?}").contains("LONG"));
    }
}
