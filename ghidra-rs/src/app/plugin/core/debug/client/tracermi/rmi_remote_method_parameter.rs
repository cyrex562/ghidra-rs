//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiRemoteMethodParameter`.

use std::fmt;
use std::sync::Arc;

use crate::app::plugin::core::debug::client::tracermi::RmiValue;
use crate::debug::rmi::proto::ValueType;
use crate::trace::seam_stubs::TraceObjectSchema;

/// One parameter of an [`RmiRemoteMethod`](super::RmiRemoteMethod), as advertised to the front
/// end during negotiation.
#[derive(Clone)]
pub struct RmiRemoteMethodParameter {
    name: String,
    schema: Arc<dyn TraceObjectSchema>,
    required: bool,
    default_value: RmiValue,
    display: String,
    description: String,
}

impl fmt::Debug for RmiRemoteMethodParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiRemoteMethodParameter")
            .field("name", &self.name)
            .field("schema", &self.schema.get_name())
            .field("required", &self.required)
            .field("default_value", &self.default_value)
            .finish_non_exhaustive()
    }
}

impl RmiRemoteMethodParameter {
    /// Mirrors `RmiRemoteMethodParameter(String, TraceObjectSchema, boolean, Object, String,
    /// String)`. A Java `null` default is [`RmiValue::Null`].
    pub fn new(
        name: impl Into<String>,
        schema: Arc<dyn TraceObjectSchema>,
        required: bool,
        default_value: RmiValue,
        display: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            schema,
            required,
            default_value,
            display: display.into(),
            description: description.into(),
        }
    }

    /// Mirrors `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Mirrors `getDescription()`.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Mirrors `getDisplay()`.
    pub fn get_display(&self) -> &str {
        &self.display
    }

    /// Mirrors `getType()`: the wire type, named by the parameter's schema.
    pub fn get_type(&self) -> ValueType {
        ValueType { name: self.schema.get_name().to_string() }
    }

    /// The parameter's schema.
    pub fn get_schema(&self) -> &Arc<dyn TraceObjectSchema> {
        &self.schema
    }

    /// Mirrors `getDefaultValue()`.
    pub fn get_default_value(&self) -> &RmiValue {
        &self.default_value
    }

    /// Mirrors `isRequired()`.
    pub fn is_required(&self) -> bool {
        self.required
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::debug::api::tracermi::SchemaName;

    pub(crate) struct Named(pub &'static str);
    impl TraceObjectSchema for Named {
        fn get_name(&self) -> SchemaName {
            SchemaName::new(self.0)
        }
        fn to_string(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn type_is_named_after_schema() {
        let p = RmiRemoteMethodParameter::new(
            "thread",
            Arc::new(Named("Thread")),
            true,
            RmiValue::Null,
            "Thread",
            "The thread to step",
        );
        assert_eq!(p.get_type(), ValueType { name: "Thread".into() });
        assert_eq!(p.get_name(), "thread");
        assert_eq!(p.get_display(), "Thread");
        assert_eq!(p.get_description(), "The thread to step");
        assert!(p.is_required());
        assert!(matches!(p.get_default_value(), RmiValue::Null));
    }
}
