//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiTrace`: the client's handle on one
//! trace it created on the front end.
//!
//! Java's `RmiTrace` holds a `final RmiClient client` back-reference. Here the [`RmiClient`] owns
//! its traces (keyed by id) and every operation that talks to the front end takes the client as
//! a call-time argument instead (OWNERSHIP_MIGRATION.md, "Decisions recorded 2026-09-24"). The
//! trace's own mutable state is individually synchronized because, as in Java, both the caller's
//! thread and the client's reply thread use it.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::app::plugin::core::debug::client::tracermi::{
    MemoryMapper, RegisterMapper, RequestResult, RmiClient, RmiClientError, RmiReply,
    RmiTraceObject, RmiTraceObjectValue, RmiTransaction, RmiValue,
};
use crate::debug::rmi::proto::{
    MemoryState, ObjDesc, ReplyCreateObject, ReplyCreateTrace, ReplyDisassemble, ReplyGetValues,
    Resolution, Value, ValueKinds, XReplyInvokeMethod, XRequestInvokeMethod,
};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::register_value::RegisterValue;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::util::msg::Msg;

/// A trace created through an [`RmiClient`]. See the module documentation.
pub struct RmiTrace {
    id: i32,
    create_result: RequestResult,
    next_tx: AtomicI32,
    /// Java's `overlays` set. Java consults it in `createOverlaySpace` but never adds to it, so
    /// every overlay request is sent; that is preserved.
    overlays: Mutex<HashSet<String>>,
    /// Java's `currentSnap`, guarded there by a read/write lock whose only compound operation
    /// (`++currentSnap`) is an atomic increment here.
    current_snap: AtomicI64,
    /// Java's `closed` flag. As in Java, nothing sets it, so [`close`](Self::close) always sends.
    closed: AtomicBool,
    memory_mapper: RwLock<Option<Arc<dyn MemoryMapper>>>,
    register_mapper: RwLock<Option<Arc<dyn RegisterMapper>>>,
}

impl fmt::Debug for RmiTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiTrace")
            .field("id", &self.id)
            .field("current_snap", &self.get_snap())
            .finish_non_exhaustive()
    }
}

impl RmiTrace {
    /// Mirrors `RmiTrace(RmiClient, int, RequestResult)`; `create_result` is the pending reply
    /// to the `RequestCreateTrace` that made this trace.
    pub fn new(id: i32, create_result: RequestResult) -> Self {
        Self {
            id,
            create_result,
            next_tx: AtomicI32::new(0),
            overlays: Mutex::new(HashSet::new()),
            current_snap: AtomicI64::new(-1),
            closed: AtomicBool::new(false),
            memory_mapper: RwLock::new(None),
            register_mapper: RwLock::new(None),
        }
    }

    /// Mirrors `checkResult(long)`: waits up to `timeout` for the front end to confirm the trace
    /// was created.
    pub fn check_result(&self, timeout: Duration) -> Result<(), RmiClientError> {
        self.create_result.get_timeout(timeout).map(|_| ())
    }

    /// Mirrors `close()`.
    pub fn close(&self, client: &RmiClient) -> Result<(), RmiClientError> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        client.close_trace(self.id)
    }

    /// Mirrors `save()`.
    pub fn save(&self, client: &RmiClient) -> Result<(), RmiClientError> {
        client.save_trace(self.id)
    }

    /// Mirrors `startTx(String, boolean)`: allocates the next transaction id and opens it.
    pub fn start_tx(
        &self,
        client: &RmiClient,
        description: &str,
        undoable: bool,
    ) -> Result<RmiTransaction, RmiClientError> {
        let txid = self.next_tx.fetch_add(1, Ordering::SeqCst);
        client.start_tx(self.id, description, undoable, txid)?;
        Ok(RmiTransaction::new(client.clone(), self.id, txid))
    }

    /// Mirrors `openTx(String)`: a non-undoable transaction.
    pub fn open_tx(
        &self,
        client: &RmiClient,
        description: &str,
    ) -> Result<RmiTransaction, RmiClientError> {
        self.start_tx(client, description, false)
    }

    /// Mirrors `endTx(int, boolean)`.
    pub fn end_tx(&self, client: &RmiClient, txid: i32, abort: bool) -> Result<(), RmiClientError> {
        client.end_tx(self.id, txid, abort)
    }

    /// Mirrors `nextSnap()`: advances and returns the current snap.
    pub fn next_snap(&self) -> i64 {
        self.current_snap.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Mirrors `snapshot(String, String, Long)`: a `None` datetime becomes `""`, a `None` snap
    /// becomes [`next_snap`](Self::next_snap). As in Java, the snap is narrowed to an `int`
    /// (`snap.intValue()`) before being sent, while the full value is returned.
    pub fn snapshot(
        &self,
        client: &RmiClient,
        description: &str,
        datetime: Option<&str>,
        snap: Option<i64>,
    ) -> Result<i64, RmiClientError> {
        let datetime = datetime.unwrap_or("");
        let snap = snap.unwrap_or_else(|| self.next_snap());
        client.snapshot(self.id, description, datetime, snap as i32 as i64)?;
        Ok(snap)
    }

    /// Mirrors `getSnap()`.
    pub fn get_snap(&self) -> i64 {
        self.current_snap.load(Ordering::SeqCst)
    }

    /// Mirrors `setSnap(long)`.
    pub fn set_snap(&self, snap: i64) {
        self.current_snap.store(snap, Ordering::SeqCst);
    }

    /// Mirrors `snapOrCurrent(Long)`.
    pub fn snap_or_current(&self, snap: Option<i64>) -> i64 {
        snap.unwrap_or_else(|| self.get_snap())
    }

    /// Mirrors `createOverlaySpace(String, String)`.
    pub fn create_overlay_space(
        &self,
        client: &RmiClient,
        base: &str,
        name: &str,
    ) -> Result<(), RmiClientError> {
        if self.overlays.lock().unwrap_or_else(|e| e.into_inner()).contains(name) {
            return Ok(());
        }
        client.create_overlay_space(self.id, base, name)
    }

    /// Mirrors `createOverlaySpace(Address, Address)`: the base is `repl`'s space and the name
    /// is `orig`'s.
    pub fn create_overlay_space_for(
        &self,
        client: &RmiClient,
        repl: &Address,
        orig: &Address,
    ) -> Result<(), RmiClientError> {
        self.create_overlay_space(client, repl.space().name(), orig.space().name())
    }

    /// Mirrors `putBytes(Address, byte[], Long)`.
    pub fn put_bytes(
        &self,
        client: &RmiClient,
        addr: &Address,
        data: &[u8],
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.put_bytes(self.id, self.snap_or_current(snap), addr, data)
    }

    /// Mirrors `setMemoryState(AddressRange, MemoryState, Long)`.
    pub fn set_memory_state(
        &self,
        client: &RmiClient,
        range: &AddressRange,
        state: MemoryState,
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.set_memory_state(self.id, self.snap_or_current(snap), range, state)
    }

    /// Mirrors `deleteBytes(AddressRange, Long)`.
    pub fn delete_bytes(
        &self,
        client: &RmiClient,
        range: &AddressRange,
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.delete_bytes(self.id, self.snap_or_current(snap), range)
    }

    /// Mirrors `putRegisters(String, RegisterValue[], Long)`.
    pub fn put_registers(
        &self,
        client: &RmiClient,
        ppath: &str,
        values: &[RegisterValue],
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.put_registers(self.id, self.snap_or_current(snap), ppath, values)
    }

    /// Mirrors `deleteRegisters(String, String[], Long)`.
    pub fn delete_registers(
        &self,
        client: &RmiClient,
        ppath: &str,
        names: &[&str],
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.delete_registers(self.id, self.snap_or_current(snap), ppath, names)
    }

    /// Mirrors `createRootObject(SchemaContext, String)`. See
    /// [`RmiClient::create_root_object`] for why the serialized context is passed in.
    pub fn create_root_object(
        &self,
        client: &RmiClient,
        schema_context: Arc<dyn SchemaContext>,
        schema_context_xml: &str,
        schema: &str,
    ) -> Result<(), RmiClientError> {
        client.create_root_object(self.id, schema_context, schema_context_xml, schema)
    }

    /// Mirrors `createObject(String)`: the returned proxy learns its id when the reply arrives.
    pub fn create_object(
        &self,
        client: &RmiClient,
        path: &str,
    ) -> Result<RmiTraceObject, RmiClientError> {
        let result = client.create_object(self.id, path)?;
        Ok(RmiTraceObject::with_pending_id(self.id, path, result))
    }

    /// Mirrors `createAndInsertObject(String)`: creates the object and inserts it from the
    /// current snap on.
    pub fn create_and_insert_object(
        &self,
        client: &RmiClient,
        path: &str,
    ) -> Result<RmiTraceObject, RmiClientError> {
        let object = self.create_object(client, path)?;
        object.insert(client, self.get_snap(), None)?;
        Ok(object)
    }

    /// Mirrors the package-private `handleCreateObject(ReplyCreateObject)`: the new object's id
    /// (0 when the reply identifies it by path or not at all, as protobuf's `getId()` does).
    pub fn handle_create_object(&self, reply: &ReplyCreateObject) -> i64 {
        match reply.object.as_ref().and_then(|o| o.key.as_ref()) {
            Some(crate::debug::rmi::proto::obj_spec::Key::Id(id)) => *id,
            _ => 0,
        }
    }

    /// Mirrors `handleCreateTrace(ReplyCreateTrace)`, which completes with `Void`.
    pub fn handle_create_trace(&self, _reply: &ReplyCreateTrace) -> RmiReply {
        RmiReply::Null
    }

    /// Mirrors `handleGetValues(ReplyGetValues)`: decodes each returned value, with its parent
    /// proxy, lifespan and the schema named by its type.
    pub fn handle_get_values(
        &self,
        client: &RmiClient,
        reply: &ReplyGetValues,
    ) -> Result<Vec<RmiTraceObjectValue>, RmiClientError> {
        let mut result = Vec::with_capacity(reply.values.len());
        for d in &reply.values {
            let parent = self.proxy_object(d.parent.as_ref().unwrap_or(&ObjDesc::default()));
            let span = d.span.unwrap_or_default();
            let span = Lifespan::try_span(span.min, span.max).ok_or_else(|| {
                RmiClientError::Invalid(format!("max < min: min={},max={}", span.min, span.max))
            })?;
            let default = Value::default();
            let wire = d.value.as_ref().unwrap_or(&default);
            let value = client.arg_to_object(self.id, wire)?;
            let schema = client.get_schema(client.arg_to_type(wire))?;
            result.push(RmiTraceObjectValue { parent, span, key: d.key.clone(), value, schema });
        }
        Ok(result)
    }

    /// Mirrors `handleDisassemble(ReplyDisassemble)`.
    pub fn handle_disassemble(&self, reply: &ReplyDisassemble) -> i64 {
        Msg::info("RmiTrace", &format!("Disassembled {} bytes", reply.length));
        reply.length
    }

    /// Mirrors `insertObject(String)`: inserts from the current snap on, adjusting conflicts.
    pub fn insert_object(&self, client: &RmiClient, path: &str) -> Result<(), RmiClientError> {
        client.insert_object_path(self.id, path, self.get_lifespan(), Resolution::CrAdjust)
    }

    fn get_lifespan(&self) -> Lifespan {
        Lifespan::now_on(self.get_snap())
    }

    /// Mirrors `setValue(String, String, Object)`: sets from the current snap on.
    pub fn set_value(
        &self,
        client: &RmiClient,
        ppath: &str,
        key: &str,
        value: &RmiValue,
    ) -> Result<(), RmiClientError> {
        client.set_value(self.id, ppath, self.get_lifespan(), key, value, None)
    }

    /// Mirrors `retainValues(String, Set<String>, ValueKinds)`.
    pub fn retain_values(
        &self,
        client: &RmiClient,
        ppath: &str,
        keys: &HashSet<String>,
        kinds: ValueKinds,
    ) -> Result<(), RmiClientError> {
        client.retain_values(self.id, ppath, self.get_lifespan(), kinds, keys)
    }

    /// Mirrors the private `doSync(RequestResult)`: waits for the values, unless a batch is in
    /// progress, in which case the reply is collected by the batch and this yields `None`.
    fn do_sync(
        &self,
        client: &RmiClient,
        r: RequestResult,
    ) -> Result<Option<Vec<RmiTraceObjectValue>>, RmiClientError> {
        if client.has_batch() {
            return Ok(None);
        }
        match r.get()? {
            RmiReply::Values(values) => Ok(Some(values)),
            RmiReply::Null => Ok(None),
            other => Err(RmiClientError::Invalid(format!("Unexpected reply: {other:?}"))),
        }
    }

    /// Mirrors `getValuesAsync(String)`.
    pub fn get_values_async(
        &self,
        client: &RmiClient,
        pattern: &str,
    ) -> Result<RequestResult, RmiClientError> {
        client.get_values(self.id, self.get_lifespan(), pattern)
    }

    /// Mirrors `getValues(String)`.
    pub fn get_values(
        &self,
        client: &RmiClient,
        pattern: &str,
    ) -> Result<Option<Vec<RmiTraceObjectValue>>, RmiClientError> {
        let r = self.get_values_async(client, pattern)?;
        self.do_sync(client, r)
    }

    /// Mirrors `getValuesRngAsync(Address, long)`.
    pub fn get_values_rng_async(
        &self,
        client: &RmiClient,
        start: &Address,
        length: u64,
    ) -> Result<RequestResult, RmiClientError> {
        let range = AddressRange::from_start_len(start.clone(), length)
            .map_err(|e| RmiClientError::Invalid(e.to_string()))?;
        client.get_values_intersecting(self.id, self.get_lifespan(), &range, "")
    }

    /// Mirrors `getValuesRng(Address, long)`.
    pub fn get_values_rng(
        &self,
        client: &RmiClient,
        start: &Address,
        length: u64,
    ) -> Result<Option<Vec<RmiTraceObjectValue>>, RmiClientError> {
        let r = self.get_values_rng_async(client, start, length)?;
        self.do_sync(client, r)
    }

    /// Mirrors `activate(String)`: a `None` path is logged and ignored.
    pub fn activate(&self, client: &RmiClient, path: Option<&str>) -> Result<(), RmiClientError> {
        match path {
            None => {
                Msg::error("RmiTrace", &"Attempt to activate null");
                Ok(())
            }
            Some(path) => client.activate(self.id, path),
        }
    }

    /// Mirrors `disassemble(Address, Long)`.
    pub fn disassemble(
        &self,
        client: &RmiClient,
        start: &Address,
        snap: Option<i64>,
    ) -> Result<(), RmiClientError> {
        client.disassemble(self.id, self.snap_or_current(snap), start)
    }

    /// Mirrors `handleInvokeMethod(XRequestInvokeMethod)`: invokes the method inside a
    /// non-undoable `"InvokeMethod"` transaction, committed when done.
    pub fn handle_invoke_method(
        &self,
        client: &RmiClient,
        req: &XRequestInvokeMethod,
    ) -> Result<XReplyInvokeMethod, RmiClientError> {
        let tx = self.start_tx(client, "InvokeMethod", false)?;
        let reply = client.handle_invoke_method(self.id, req);
        tx.close()?;
        reply
    }

    fn proxy_object(&self, desc: &ObjDesc) -> RmiTraceObject {
        let path = desc.path.as_ref().map(|p| p.path.clone()).unwrap_or_default();
        RmiTraceObject::with_id(self.id, Some(desc.id), Some(path))
    }

    /// Mirrors `proxyObjectId(Long)`.
    pub fn proxy_object_id(&self, object_id: i64) -> RmiTraceObject {
        RmiTraceObject::from_id(self.id, object_id)
    }

    /// Mirrors `proxyObjectPath(String)`.
    pub fn proxy_object_path(&self, path: &str) -> RmiTraceObject {
        RmiTraceObject::from_path(self.id, path)
    }

    /// Mirrors `proxyObjectPath(Long, String)`.
    pub fn proxy_object_path_with_id(&self, object_id: Option<i64>, path: &str) -> RmiTraceObject {
        RmiTraceObject::with_id(self.id, object_id, Some(path.to_string()))
    }

    /// Mirrors `getId()`.
    pub fn get_id(&self) -> i32 {
        self.id
    }

    /// Java's public `memoryMapper` field (read).
    pub fn get_memory_mapper(&self) -> Option<Arc<dyn MemoryMapper>> {
        self.memory_mapper.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Java's public `memoryMapper` field (write).
    pub fn set_memory_mapper(&self, mapper: Arc<dyn MemoryMapper>) {
        *self.memory_mapper.write().unwrap_or_else(|e| e.into_inner()) = Some(mapper);
    }

    /// Java's public `registerMapper` field (read).
    pub fn get_register_mapper(&self) -> Option<Arc<dyn RegisterMapper>> {
        self.register_mapper.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Java's public `registerMapper` field (write).
    pub fn set_register_mapper(&self, mapper: Arc<dyn RegisterMapper>) {
        *self.register_mapper.write().unwrap_or_else(|e| e.into_inner()) = Some(mapper);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_client::tests::{
        ram, Harness, RamMapper,
    };
    use crate::debug::api::tracermi::SchemaName;
    use crate::debug::rmi::proto::{
        obj_spec, root_message, value, DomObjId, ObjPath, ObjSpec, RequestCreateObject, Span,
        ValDesc,
    };
    use crate::program::model::lang::LanguageID;
    use crate::trace::seam_stubs::TraceObjectSchema;

    const WAIT: Duration = Duration::from_secs(10);

    fn new_trace(h: &Harness) -> Arc<RmiTrace> {
        let lang = LanguageID::new("x86:LE:64:default").unwrap();
        let trace = h.client.create_trace("/t", &lang, None).unwrap();
        let _ = h.recv();
        h.reply(root_message::Msg::ReplyCreateTrace(Default::default()));
        trace.check_result(WAIT).unwrap();
        trace
    }

    struct NamedSchema(SchemaName);
    impl TraceObjectSchema for NamedSchema {
        fn get_name(&self) -> SchemaName {
            self.0.clone()
        }
        fn to_string(&self) -> String {
            self.0.to_string()
        }
    }

    struct NameEchoContext;
    impl SchemaContext for NameEchoContext {
        fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
            Box::new(NamedSchema(name.clone()))
        }
        fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
            Some(self.get_schema(name))
        }
        fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
            Vec::new()
        }
    }

    #[test]
    fn transactions_get_sequential_ids_and_commit_once() {
        let h = Harness::new();
        let trace = new_trace(&h);
        let tx0 = trace.start_tx(&h.client, "first", true).unwrap();
        let tx1 = trace.open_tx(&h.client, "second").unwrap();
        match h.recv() {
            root_message::Msg::RequestStartTx(r) => {
                assert_eq!((r.txid.unwrap().id, r.undoable), (0, true))
            }
            other => panic!("unexpected {other:?}"),
        }
        match h.recv() {
            root_message::Msg::RequestStartTx(r) => {
                assert_eq!((r.txid.unwrap().id, r.undoable), (1, false))
            }
            other => panic!("unexpected {other:?}"),
        }
        tx1.abort().unwrap();
        tx1.commit().unwrap(); // already closed: no second request
        drop(tx0); // close-on-drop commits
        match h.recv() {
            root_message::Msg::RequestEndTx(r) => assert_eq!((r.txid.unwrap().id, r.abort), (1, true)),
            other => panic!("unexpected {other:?}"),
        }
        match h.recv() {
            root_message::Msg::RequestEndTx(r) => assert_eq!((r.txid.unwrap().id, r.abort), (0, false)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn snapshot_defaults_and_narrows_snap_to_int() {
        let h = Harness::new();
        let trace = new_trace(&h);
        assert_eq!(trace.get_snap(), -1);
        assert_eq!(trace.snapshot(&h.client, "boot", None, None).unwrap(), 0);
        match h.recv() {
            root_message::Msg::RequestSnapshot(r) => {
                assert_eq!(r.description, "boot");
                assert_eq!(r.datetime, "");
                assert_eq!(
                    r.time,
                    Some(crate::debug::rmi::proto::request_snapshot::Time::Snap(
                        crate::debug::rmi::proto::Snap { snap: 0 }
                    ))
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(trace.get_snap(), 0);
        // Java: `snap.intValue()` -- 0x1_0000_0005 is sent as 5 but returned whole.
        let big = 0x1_0000_0005i64;
        assert_eq!(trace.snapshot(&h.client, "big", Some("now"), Some(big)).unwrap(), big);
        match h.recv() {
            root_message::Msg::RequestSnapshot(r) => assert_eq!(
                r.time,
                Some(crate::debug::rmi::proto::request_snapshot::Time::Snap(
                    crate::debug::rmi::proto::Snap { snap: 5 }
                ))
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn set_value_and_insert_use_now_on_current_snap() {
        let h = Harness::new();
        let trace = new_trace(&h);
        trace.set_snap(10);
        trace.set_value(&h.client, "Processes[1]", "_name", &RmiValue::String("init".into())).unwrap();
        match h.recv() {
            root_message::Msg::RequestSetValue(r) => {
                let v = r.value.unwrap();
                assert_eq!(v.span, Some(Span { min: 10, max: i64::MAX }));
                assert_eq!(v.value.unwrap().value, Some(value::Value::StringValue("init".into())));
            }
            other => panic!("unexpected {other:?}"),
        }
        trace.insert_object(&h.client, "Processes[1]").unwrap();
        match h.recv() {
            root_message::Msg::RequestInsertObject(r) => {
                assert_eq!(r.span, Some(Span { min: 10, max: i64::MAX }));
                assert_eq!(r.resolution, Resolution::CrAdjust as i32);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn create_and_insert_object_inserts_by_path_before_id_is_known() {
        let h = Harness::new();
        let trace = new_trace(&h);
        trace.set_snap(3);
        let obj = trace.create_and_insert_object(&h.client, "Processes[2]").unwrap();
        assert_eq!(
            h.recv(),
            root_message::Msg::RequestCreateObject(RequestCreateObject {
                oid: Some(DomObjId { id: 0 }),
                path: Some(ObjPath { path: "Processes[2]".into() }),
            })
        );
        match h.recv() {
            root_message::Msg::RequestInsertObject(r) => assert_eq!(
                r.object,
                Some(ObjSpec {
                    key: Some(obj_spec::Key::Path(ObjPath { path: "Processes[2]".into() }))
                })
            ),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(obj.get_id(), None);
    }

    #[test]
    fn get_values_decodes_reply_with_schema_from_root_context() {
        let h = Harness::new();
        let trace = new_trace(&h);
        trace.set_memory_mapper(Arc::new(RamMapper));
        trace
            .create_root_object(&h.client, Arc::new(NameEchoContext), "<context/>", "Session")
            .unwrap();
        match h.recv() {
            root_message::Msg::RequestCreateRootObject(r) => {
                assert_eq!(r.schema_context, "<context/>");
                assert_eq!(r.root_schema, "Session");
            }
            other => panic!("unexpected {other:?}"),
        }
        // The root object's reply shares ReplyCreateObject; answer it before the query.
        h.reply(root_message::Msg::ReplyCreateObject(Default::default()));

        let client = h.client.clone();
        let t2 = trace.clone();
        let waiter = std::thread::spawn(move || t2.get_values(&client, "Processes[]").unwrap());
        match h.recv() {
            root_message::Msg::RequestGetValues(r) => {
                assert_eq!(r.pattern.unwrap().path, "Processes[]")
            }
            other => panic!("unexpected {other:?}"),
        }
        h.reply(root_message::Msg::ReplyGetValues(ReplyGetValues {
            values: vec![ValDesc {
                parent: Some(ObjDesc { id: 5, path: Some(ObjPath { path: "Processes[1]".into() }) }),
                span: Some(Span { min: 0, max: 9 }),
                key: "_pc".into(),
                value: Some(Value {
                    value: Some(value::Value::AddressValue(crate::debug::rmi::proto::Addr {
                        space: "ram".into(),
                        offset: 0x401000,
                    })),
                }),
            }],
        }));
        let values = waiter.join().unwrap().expect("not batching");
        assert_eq!(values.len(), 1);
        let v = &values[0];
        assert_eq!(v.parent.get_path(), Some("Processes[1]"));
        assert_eq!(v.parent.get_id(), Some(5));
        assert_eq!(v.span, Lifespan::span(0, 9));
        assert_eq!(v.key, "_pc");
        match &v.value {
            RmiValue::Address(a) => {
                assert_eq!(a.offset(), 0x401000);
                assert!(a.same_address_space(&ram().address(0)));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(v.schema.get_name(), SchemaName::new("ADDRESS"));
    }

    #[test]
    fn get_values_yields_none_while_batching() {
        let h = Harness::new();
        let trace = new_trace(&h);
        let batch = h.client.start_batch();
        assert!(trace.get_values(&h.client, "x").unwrap().is_none());
        let _ = h.recv();
        h.reply(root_message::Msg::ReplyGetValues(Default::default()));
        batch.close().unwrap();
        assert!(!h.client.has_batch());
    }

    #[test]
    fn overlay_and_activate_requests() {
        let h = Harness::new();
        let trace = new_trace(&h);
        let reg = crate::program::model::address::AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            0,
        );
        trace.create_overlay_space_for(&h.client, &ram().address(0), &reg.address(0)).unwrap();
        match h.recv() {
            root_message::Msg::RequestCreateOverlay(r) => {
                assert_eq!((r.base_space.as_str(), r.name.as_str()), ("ram", "register"))
            }
            other => panic!("unexpected {other:?}"),
        }
        trace.activate(&h.client, None).unwrap(); // logged, nothing sent
        trace.activate(&h.client, Some("Processes[1]")).unwrap();
        match h.recv() {
            root_message::Msg::RequestActivate(r) => assert_eq!(
                r.object,
                Some(ObjSpec {
                    key: Some(obj_spec::Key::Path(ObjPath { path: "Processes[1]".into() }))
                })
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn handle_create_object_reads_id_key_or_zero() {
        let trace = RmiTrace::new(0, RequestResult::new(Default::default()));
        let by_id = ReplyCreateObject { object: Some(ObjSpec { key: Some(obj_spec::Key::Id(9)) }) };
        assert_eq!(trace.handle_create_object(&by_id), 9);
        assert_eq!(trace.handle_create_object(&ReplyCreateObject::default()), 0);
        assert_eq!(trace.handle_disassemble(&ReplyDisassemble { length: 12 }), 12);
    }
}
