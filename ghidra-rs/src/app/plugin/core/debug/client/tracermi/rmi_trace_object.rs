//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiTraceObject`: a client-side proxy
//! for an object in a trace, identified by path, by id, or both.
//!
//! Java's `RmiTraceObject` holds its `RmiTrace` and reaches the client through `trace.client`;
//! here it holds the trace's id and operations take the [`RmiClient`] as a call-time argument
//! (OWNERSHIP_MIGRATION.md, "Decisions recorded 2026-09-24"). Java's
//! `result.thenAccept(id -> this.id = (Long) id)` -- which fills in the `volatile` id once the
//! front end answers `createObject` -- is modeled by keeping the pending [`RequestResult`] and
//! reading its reply when the id is needed, which observes exactly the same value.

use std::collections::HashSet;

use crate::app::plugin::core::debug::client::tracermi::{
    RequestResult, RmiClient, RmiClientError, RmiReply, RmiValue,
};
use crate::debug::rmi::proto::{Resolution, ValueKinds};
use crate::trace::model::lifespan::Lifespan;

/// A proxy for an object in a trace. See the module documentation.
#[derive(Debug, Clone)]
pub struct RmiTraceObject {
    trace_id: i32,
    path: Option<String>,
    id: Option<i64>,
    pending_id: Option<RequestResult>,
}

impl RmiTraceObject {
    /// Mirrors `RmiTraceObject(RmiTrace, String)`: a proxy by path, id unknown.
    pub fn new(trace_id: i32, path: &str) -> Self {
        Self { trace_id, path: Some(path.to_string()), id: None, pending_id: None }
    }

    /// Mirrors the package-private `RmiTraceObject(RmiTrace, String, RequestResult)`: a proxy
    /// by path whose id arrives with the reply to `result`.
    pub fn with_pending_id(trace_id: i32, path: &str, result: RequestResult) -> Self {
        Self { trace_id, path: Some(path.to_string()), id: None, pending_id: Some(result) }
    }

    /// Mirrors `RmiTraceObject(RmiTrace, Long, String)`.
    pub fn with_id(trace_id: i32, id: Option<i64>, path: Option<String>) -> Self {
        Self { trace_id, path, id, pending_id: None }
    }

    /// Mirrors `fromId(RmiTrace, long)`.
    pub fn from_id(trace_id: i32, id: i64) -> Self {
        Self::with_id(trace_id, Some(id), None)
    }

    /// Mirrors `fromPath(RmiTrace, String)`.
    pub fn from_path(trace_id: i32, path: &str) -> Self {
        Self::with_id(trace_id, None, Some(path.to_string()))
    }

    /// The id of the trace containing this object (Java: `trace.getId()`).
    pub fn get_trace_id(&self) -> i32 {
        self.trace_id
    }

    /// The object's id, if known: given at construction, or delivered by the `createObject`
    /// reply (Java's `volatile Long id`).
    pub fn get_id(&self) -> Option<i64> {
        self.id.or_else(|| match self.pending_id.as_ref()?.get_now()? {
            Ok(RmiReply::Long(id)) => Some(id),
            _ => None,
        })
    }

    /// The pending `createObject` reply this object takes its id from, if any.
    pub fn pending_result(&self) -> Option<&RequestResult> {
        self.pending_id.as_ref()
    }

    fn require_path(&self) -> Result<&str, RmiClientError> {
        self.path
            .as_deref()
            .ok_or_else(|| RmiClientError::Invalid(format!("Object has no path: {self:?}")))
    }

    /// Mirrors `insert(long, Resolution)`: inserts from `snap` on, by id when known and by path
    /// otherwise; a `None` resolution means `CR_ADJUST`. Returns the lifespan used.
    pub fn insert(
        &self,
        client: &RmiClient,
        snap: i64,
        resolution: Option<Resolution>,
    ) -> Result<Lifespan, RmiClientError> {
        let resolution = resolution.unwrap_or(Resolution::CrAdjust);
        let span = Lifespan::now_on(snap);
        match self.get_id() {
            Some(id) => client.insert_object_id(self.trace_id, id, span, resolution)?,
            None => client.insert_object_path(self.trace_id, self.require_path()?, span, resolution)?,
        }
        Ok(span)
    }

    /// Mirrors `remove(long, boolean)`: removes from `snap` on, by id when known and by path
    /// otherwise. Returns the lifespan used.
    pub fn remove(&self, client: &RmiClient, snap: i64, tree: bool) -> Result<Lifespan, RmiClientError> {
        let span = Lifespan::now_on(snap);
        match self.get_id() {
            Some(id) => client.remove_object_id(self.trace_id, id, span, tree)?,
            None => client.remove_object_path(self.trace_id, self.require_path()?, span, tree)?,
        }
        Ok(span)
    }

    /// Mirrors `setValue(String, Object, long, String)`: sets from `snap` on; `resolution` is a
    /// `TraceRmiResolution` constant name, `None` meaning `CR_ADJUST`.
    pub fn set_value(
        &self,
        client: &RmiClient,
        key: &str,
        value: &RmiValue,
        snap: i64,
        resolution: Option<&str>,
    ) -> Result<(), RmiClientError> {
        let span = Lifespan::now_on(snap);
        client.set_value(self.trace_id, self.require_path()?, span, key, value, resolution)
    }

    /// Mirrors `retainValues(Set<String>, long, ValueKinds)`.
    pub fn retain_values(
        &self,
        client: &RmiClient,
        keys: &HashSet<String>,
        snap: i64,
        kinds: ValueKinds,
    ) -> Result<(), RmiClientError> {
        let span = Lifespan::now_on(snap);
        client.retain_values(self.trace_id, self.require_path()?, span, kinds, keys)
    }

    /// Mirrors `activate()`.
    pub fn activate(&self, client: &RmiClient) -> Result<(), RmiClientError> {
        client.activate(self.trace_id, self.require_path()?)
    }

    /// Mirrors `getPath()`; `None` for an object proxied by id alone.
    pub fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_client::tests::Harness;
    use crate::debug::rmi::proto::{obj_spec, root_message, ObjPath, ObjSpec, Span};

    #[test]
    fn insert_by_id_when_known_else_by_path() {
        let h = Harness::new();
        let by_id = RmiTraceObject::with_id(2, Some(17), Some("Threads[1]".into()));
        let span = by_id.insert(&h.client, 5, Some(Resolution::CrTruncate)).unwrap();
        assert_eq!(span, Lifespan::now_on(5));
        match h.recv() {
            root_message::Msg::RequestInsertObject(r) => {
                assert_eq!(r.oid.unwrap().id, 2);
                assert_eq!(r.object, Some(ObjSpec { key: Some(obj_spec::Key::Id(17)) }));
                assert_eq!(r.span, Some(Span { min: 5, max: i64::MAX }));
                assert_eq!(r.resolution, Resolution::CrTruncate as i32);
            }
            other => panic!("unexpected {other:?}"),
        }
        let by_path = RmiTraceObject::from_path(2, "Threads[2]");
        by_path.insert(&h.client, 6, None).unwrap();
        match h.recv() {
            root_message::Msg::RequestInsertObject(r) => {
                assert_eq!(
                    r.object,
                    Some(ObjSpec {
                        key: Some(obj_spec::Key::Path(ObjPath { path: "Threads[2]".into() }))
                    })
                );
                assert_eq!(r.resolution, Resolution::CrAdjust as i32);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn remove_sends_tree_flag() {
        let h = Harness::new();
        RmiTraceObject::from_id(0, 4).remove(&h.client, 8, true).unwrap();
        match h.recv() {
            root_message::Msg::RequestRemoveObject(r) => {
                assert_eq!(r.object, Some(ObjSpec { key: Some(obj_spec::Key::Id(4)) }));
                assert!(r.tree);
                assert_eq!(r.span, Some(Span { min: 8, max: i64::MAX }));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn path_operations_need_a_path() {
        let h = Harness::new();
        let obj = RmiTraceObject::from_id(0, 4);
        assert_eq!(obj.get_path(), None);
        assert!(obj.activate(&h.client).is_err());
        let with_path = RmiTraceObject::new(0, "Processes[1]");
        with_path
            .set_value(&h.client, "_state", &RmiValue::String("RUNNING".into()), 2, None)
            .unwrap();
        match h.recv() {
            root_message::Msg::RequestSetValue(r) => {
                let v = r.value.unwrap();
                assert_eq!(v.key, "_state");
                assert_eq!(
                    v.parent,
                    Some(ObjSpec {
                        key: Some(obj_spec::Key::Path(ObjPath { path: "Processes[1]".into() }))
                    })
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        let keys: HashSet<String> = ["_pc".to_string()].into_iter().collect();
        with_path.retain_values(&h.client, &keys, 2, ValueKinds::VkAttributes).unwrap();
        match h.recv() {
            root_message::Msg::RequestRetainValues(r) => {
                assert_eq!(r.keys, vec!["_pc".to_string()]);
                assert_eq!(r.kinds, ValueKinds::VkAttributes as i32);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn pending_id_is_read_from_the_create_reply() {
        let result = RequestResult::new(Default::default());
        let obj = RmiTraceObject::with_pending_id(0, "Processes[3]", result.clone());
        assert_eq!(obj.get_id(), None);
        result.complete(RmiReply::Long(33));
        assert_eq!(obj.get_id(), Some(33));
        // A null reply leaves the id unknown, as Java's `(Long) null` does.
        let r2 = RequestResult::new(Default::default());
        let obj2 = RmiTraceObject::with_pending_id(0, "Processes[4]", r2.clone());
        r2.complete(RmiReply::Null);
        assert_eq!(obj2.get_id(), None);
    }
}
