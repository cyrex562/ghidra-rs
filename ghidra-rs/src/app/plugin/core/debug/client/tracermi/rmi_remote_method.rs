//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiRemoteMethod`: a method the client
//! offers the front end, with its display metadata and parameters.
//!
//! Java builds this from a `java.lang.reflect.Method` on an `RmiMethods` container: it derives
//! each parameter from the method's annotated `java.lang.reflect.Parameter`s
//! (`ParameterDescription.annotated`, resolving primitive types to their primitive schema and
//! `RmiTraceObject` parameters to a schema named in the annotation), and later calls
//! `Method.invoke(container, args)`. Rust has no reflection, so the caller supplies the resolved
//! [`RmiRemoteMethodParameter`]s and a callable that stands for the container's method.

use std::fmt;
use std::sync::Arc;

use crate::app::plugin::core::debug::client::tracermi::{
    RmiRemoteMethodParameter, RmiValue, TraceRmiMethod,
};
use crate::trace::model::target::schema::trace_object_schema::TraceObjectSchema;

/// The callable behind an [`RmiRemoteMethod`]: Java's `Method.invoke(container, args)`.
///
/// It receives the arguments positionally, as Java's `Object[]`, and returns the method's
/// result (`None` for Java's `void`/`null`), or an error message where Java's `invoke` throws.
pub type RmiMethodInvoker =
    Box<dyn Fn(Vec<RmiValue>) -> Result<Option<RmiValue>, String> + Send + Sync>;

/// A remotely invocable method. See the module documentation.
pub struct RmiRemoteMethod {
    name: String,
    action: String,
    display: String,
    description: String,
    ok_text: String,
    icon: String,
    params: Vec<RmiRemoteMethodParameter>,
    schema: Arc<dyn TraceObjectSchema>,
    method: RmiMethodInvoker,
}

impl fmt::Debug for RmiRemoteMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiRemoteMethod")
            .field("name", &self.name)
            .field("action", &self.action)
            .field("params", &self.params)
            .field("schema", &self.schema.get_name())
            .finish_non_exhaustive()
    }
}

impl RmiRemoteMethod {
    /// Mirrors `RmiRemoteMethod(SchemaContext, String, String, String, String, String, String,
    /// TraceObjectSchema, RmiMethods, Method)`, with the reflected parameters and method replaced
    /// by `params` and `method` (see the module documentation).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        action: impl Into<String>,
        display: impl Into<String>,
        description: impl Into<String>,
        ok_text: impl Into<String>,
        icon: impl Into<String>,
        schema: Arc<dyn TraceObjectSchema>,
        params: Vec<RmiRemoteMethodParameter>,
        method: RmiMethodInvoker,
    ) -> Self {
        Self {
            name: name.into(),
            action: action.into(),
            display: display.into(),
            description: description.into(),
            ok_text: ok_text.into(),
            icon: icon.into(),
            params,
            schema,
            method,
        }
    }

    /// Builds a method whose display metadata comes from its [`TraceRmiMethod`] annotation, as
    /// Java's registration code reads it off the annotated method.
    pub fn annotated(
        name: impl Into<String>,
        annotation: &TraceRmiMethod,
        schema: Arc<dyn TraceObjectSchema>,
        params: Vec<RmiRemoteMethodParameter>,
        method: RmiMethodInvoker,
    ) -> Self {
        Self::new(
            name,
            annotation.action.clone(),
            annotation.display.clone(),
            annotation.description.clone(),
            annotation.ok_text.clone(),
            annotation.icon.clone(),
            schema,
            params,
            method,
        )
    }

    /// Mirrors `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Mirrors `getDescription()`.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Mirrors `getOkText()`.
    pub fn get_ok_text(&self) -> &str {
        &self.ok_text
    }

    /// Mirrors `getIcon()`.
    pub fn get_icon(&self) -> &str {
        &self.icon
    }

    /// Mirrors `getAction()`.
    pub fn get_action(&self) -> &str {
        &self.action
    }

    /// Mirrors `getDisplay()`.
    pub fn get_display(&self) -> &str {
        &self.display
    }

    /// Mirrors `getParameters()`.
    pub fn get_parameters(&self) -> &[RmiRemoteMethodParameter] {
        &self.params
    }

    /// Mirrors `getSchema()`.
    pub fn get_schema(&self) -> &Arc<dyn TraceObjectSchema> {
        &self.schema
    }

    /// Invokes the method: Java's `getMethod().invoke(getContainer(), args)`.
    pub fn invoke(&self, args: Vec<RmiValue>) -> Result<Option<RmiValue>, String> {
        (self.method)(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_remote_method_parameter::tests::named;

    #[test]
    fn annotated_copies_metadata_and_invokes() {
        let ann = TraceRmiMethod {
            action: "step_into".into(),
            display: "Step Into".into(),
            description: "Step one instruction".into(),
            ok_text: "Step".into(),
            icon: "stepinto".into(),
        };
        let param = RmiRemoteMethodParameter::new(
            "count",
            named("INT"),
            false,
            RmiValue::Int(1),
            "Count",
            "",
        );
        let m = RmiRemoteMethod::annotated(
            "step_into",
            &ann,
            named("Thread"),
            vec![param],
            Box::new(|args| match args.as_slice() {
                [RmiValue::Int(n)] => Ok(Some(RmiValue::Int(n * 2))),
                other => Err(format!("bad args: {other:?}")),
            }),
        );
        assert_eq!(m.get_name(), "step_into");
        assert_eq!(m.get_action(), "step_into");
        assert_eq!(m.get_display(), "Step Into");
        assert_eq!(m.get_description(), "Step one instruction");
        assert_eq!(m.get_ok_text(), "Step");
        assert_eq!(m.get_icon(), "stepinto");
        assert_eq!(m.get_parameters().len(), 1);
        assert!(matches!(m.invoke(vec![RmiValue::Int(4)]), Ok(Some(RmiValue::Int(8)))));
        assert!(m.invoke(vec![]).is_err());
    }
}
