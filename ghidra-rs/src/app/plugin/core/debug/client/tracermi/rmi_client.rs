//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiClient`, the Java-side *client* of
//! the Trace RMI protocol: it connects to a Ghidra front end, creates and populates traces by
//! sending `RootMessage` requests, and serves method invocations the front end sends back.
//!
//! # Rust shape
//!
//! * `RmiClient` is a cheap-to-clone handle (`Arc` inside). Java hands `this` to the
//!   `RmiReplyHandlerThread` it starts, so the client is genuinely shared between the caller's
//!   thread and the reply thread; every mutable member is individually synchronized, as in Java.
//! * The client owns its traces (`traces`, keyed by trace id, exactly as Java's
//!   `Map<Integer, RmiTrace>`). Java's `RmiTrace.client` / `RmiTraceObject.trace` back-references
//!   become call-time `&RmiClient` arguments and trace ids (OWNERSHIP_MIGRATION.md, "Decisions
//!   recorded 2026-09-24").
//! * Java's untyped `Object` values (`buildValue`, `argToObject`, method arguments and results)
//!   are the closed enum [`RmiValue`]; Java's `Object` request results are [`RmiReply`].
//! * Java's `RequestResult extends CompletableFuture<Object>` is [`RequestResult`]: callers of
//!   this client block on results (`get()`, `get(timeout)`) from ordinary threads, and the reply
//!   thread completes them, so it is a blocking completion cell (`Mutex` + `Condvar`, as in
//!   `JdiEventHandler`), not an `async` future.
//!
//! # Deviations from Java (deliberate)
//!
//! * **Reply matching is FIFO.** Java queues pending requests with `Deque.push` (add *first*) and
//!   takes them with `poll` (remove *first*), i.e. LIFO, which pairs a reply with the *newest*
//!   outstanding request. The server answers requests in order, so any pipelining (e.g. an
//!   [`RmiBatch`]) makes Java pair replies with the wrong requests. This port pairs them in
//!   order.
//! * **Replies that cannot be processed fail their request** instead of leaving it pending
//!   forever (Java logs the exception in the reply thread and never completes the future, which
//!   hangs any `get()` or batch waiting on it).
//! * **The method registry is per client**, not a `static` field shared by every client in the
//!   JVM.
//! * `RequestResult.get()`'s assertion against waiting on the Swing thread has no counterpart:
//!   there is no Swing thread.
//! * **`loadSchema` reads a file**, not a class-path resource, and reports failure as an error
//!   rather than an `AssertionError`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use prost::Message;

use crate::app::plugin::core::debug::client::tracermi::{
    ProtobufSocket, RmiBatch, RmiMethodRegistry, RmiRemoteMethod, RmiRemoteMethodParameter,
    RmiReplyHandlerThread, RmiTrace, RmiTraceObject, RmiTraceObjectValue,
};
use crate::app::seam_stubs::TRACE_RMI_HANDLER_VERSION;
use crate::debug::api::tracermi::SchemaName;
use crate::debug::rmi::proto::{
    obj_spec, request_snapshot, root_message, value, Addr, AddrRange, BoolArr, Box as SpanBox,
    Compiler, DomObjId, FilePath, IntArr, Language, LongArr, MemoryState, Method,
    MethodArgument, MethodParameter, Null, ObjPath, ObjSpec, RegVal, RequestActivate,
    RequestCloseTrace, RequestCreateObject, RequestCreateOverlaySpace, RequestCreateRootObject,
    RequestCreateTrace, RequestDeleteBytes, RequestDeleteRegisterValue, RequestDisassemble,
    RequestEndTx, RequestGetObject, RequestGetValues, RequestGetValuesIntersecting,
    RequestInsertObject, RequestNegotiate, RequestPutBytes, RequestPutRegisterValue,
    RequestRemoveObject, RequestRetainValues, RequestSaveTrace, RequestSetMemoryState,
    RequestSetValue, RequestSnapshot, RequestStartTx, Resolution, RootMessage, ShortArr, Snap,
    Span, StringArr, TxId, ValSpec, Value, ValueKinds, XReplyInvokeMethod, XRequestInvokeMethod,
};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::{CompilerSpecID, LanguageID};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::model::target::schema::xml_schema_context::{XmlSchemaContext, XmlSchemaError};
use crate::trace::model::target::schema::trace_object_schema::TraceObjectSchema;
use crate::util::msg::Msg;

/// An error reported by the remote end of a Trace RMI connection.
///
/// Port of the nested `RmiClient.RmiException extends RuntimeException`. The reply thread
/// completes a request with this when the front end answers it with a `ReplyError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmiException {
    message: String,
}

impl RmiException {
    /// Mirrors `RmiException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// The error message, as Java's `getMessage()`.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RmiException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RmiException {}

/// Everything an [`RmiClient`] operation can fail with.
///
/// Java lets these escape as unchecked exceptions: `IOException`s from the socket are wrapped in
/// `RuntimeException`, remote failures surface as [`RmiException`] through
/// `ExecutionException`, waits can time out, and bad arguments or missing state raise
/// `IllegalArgumentException`/`NullPointerException`/`RuntimeException`.
#[derive(Debug)]
pub enum RmiClientError {
    /// Writing to or reading from the socket failed.
    Io(io::Error),
    /// The front end answered the request with an error.
    Remote(RmiException),
    /// A bounded wait for a reply elapsed (Java's `TimeoutException`).
    TimedOut,
    /// An argument or the client's state does not permit the operation.
    Invalid(String),
}

impl fmt::Display for RmiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RmiClientError::Io(e) => write!(f, "{e}"),
            RmiClientError::Remote(e) => write!(f, "{e}"),
            RmiClientError::TimedOut => f.write_str("timed out waiting for reply"),
            RmiClientError::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for RmiClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RmiClientError::Io(e) => Some(e),
            RmiClientError::Remote(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RmiClientError {
    fn from(e: io::Error) -> Self {
        RmiClientError::Io(e)
    }
}

impl From<RmiException> for RmiClientError {
    fn from(e: RmiException) -> Self {
        RmiClientError::Remote(e)
    }
}

/// A value exchanged with the front end: attribute values, method arguments, method results and
/// parameter defaults.
///
/// Java passes these as `Object` and dispatches with `instanceof` in `buildValue`; the set of
/// accepted types is closed, so it is an enum here. Note which variants each direction produces:
/// [`RmiClient::build_value`] accepts every variant, while [`RmiClient::arg_to_object`] returns
/// Java's *boxed wire types* -- the protobuf getters for `byte`, `char` and `short` values all
/// return `int`, so those arrive as [`RmiValue::Int`] (and `short` arrays as
/// [`RmiValue::IntArr`]), and a `char` array arrives as a [`RmiValue::String`].
#[derive(Debug, Clone)]
pub enum RmiValue {
    /// Java `null` (and the protobuf `Null` message).
    Null,
    /// `String`.
    String(String),
    /// `Boolean`.
    Bool(bool),
    /// `Byte`.
    Byte(i8),
    /// `Character`, a UTF-16 code unit.
    Char(u16),
    /// `Short`.
    Short(i16),
    /// `Integer`.
    Int(i32),
    /// `Long`.
    Long(i64),
    /// `ByteString`.
    Bytes(Vec<u8>),
    /// `List<String>`.
    StringArr(Vec<String>),
    /// `List<Boolean>`.
    BoolArr(Vec<bool>),
    /// `List<Short>`.
    ShortArr(Vec<i16>),
    /// `List<Integer>`.
    IntArr(Vec<i32>),
    /// `List<Long>`.
    LongArr(Vec<i64>),
    /// `Address`.
    Address(Address),
    /// `AddressRange`.
    Range(AddressRange),
    /// `RmiTraceObject`, sent as a reference to the object's path.
    Object(RmiTraceObject),
}

/// The value a [`RequestResult`] completes with -- Java's `CompletableFuture<Object>` payload.
///
/// The reply thread produces exactly these: `Void`/`null` for most replies, a `Long` for created
/// objects and disassembly lengths, and a `List<RmiTraceObjectValue>` for value queries.
#[derive(Debug, Clone)]
pub enum RmiReply {
    /// Java `null` (including `handleCreateTrace`'s `Void`).
    Null,
    /// A `Long`: the new object id (`handleCreateObject`) or the disassembled length
    /// (`handleDisassemble`).
    Long(i64),
    /// The values returned by `handleGetValues`.
    Values(Vec<RmiTraceObjectValue>),
}

struct RequestResultInner {
    request: RootMessage,
    outcome: Mutex<Option<Result<RmiReply, RmiException>>>,
    done: Condvar,
}

/// A pending request and, eventually, its reply.
///
/// Port of the nested `RmiClient.RequestResult extends CompletableFuture<Object>`, which pairs the
/// future with the `RootMessage` it answers. Clones share the same completion, just as every
/// holder of a Java `CompletableFuture` reference sees the same outcome. See the module docs for
/// why this blocks rather than being an `async` future.
#[derive(Clone)]
pub struct RequestResult {
    inner: Arc<RequestResultInner>,
}

impl fmt::Debug for RequestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestResult")
            .field("request", &self.inner.request)
            .field("done", &self.is_done())
            .finish()
    }
}

impl RequestResult {
    /// Mirrors `RequestResult(RootMessage req)`.
    pub fn new(request: RootMessage) -> Self {
        Self {
            inner: Arc::new(RequestResultInner {
                request,
                outcome: Mutex::new(None),
                done: Condvar::new(),
            }),
        }
    }

    /// The request this result answers (Java's public `request` field).
    pub fn request(&self) -> &RootMessage {
        &self.inner.request
    }

    fn settle(&self, outcome: Result<RmiReply, RmiException>) -> bool {
        let mut slot = self.inner.outcome.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return false;
        }
        *slot = Some(outcome);
        self.inner.done.notify_all();
        true
    }

    /// Mirrors `CompletableFuture.complete`: returns `true` if this call completed the result.
    pub fn complete(&self, reply: RmiReply) -> bool {
        self.settle(Ok(reply))
    }

    /// Mirrors `CompletableFuture.completeExceptionally`.
    pub fn complete_exceptionally(&self, error: RmiException) -> bool {
        self.settle(Err(error))
    }

    /// Mirrors `CompletableFuture.isDone`.
    pub fn is_done(&self) -> bool {
        self.inner.outcome.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// The outcome if already complete, without waiting.
    pub fn get_now(&self) -> Option<Result<RmiReply, RmiException>> {
        self.inner.outcome.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Mirrors `get()`: waits for the reply.
    pub fn get(&self) -> Result<RmiReply, RmiException> {
        let mut slot = self.inner.outcome.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(outcome) = slot.as_ref() {
                return outcome.clone();
            }
            slot = self.inner.done.wait(slot).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Mirrors `get(long, TimeUnit)`: waits at most `timeout` for the reply.
    pub fn get_timeout(&self, timeout: Duration) -> Result<RmiReply, RmiClientError> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.inner.outcome.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(outcome) = slot.as_ref() {
                return outcome.clone().map_err(RmiClientError::Remote);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(RmiClientError::TimedOut);
            }
            slot = self
                .inner
                .done
                .wait_timeout(slot, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// Conflict resolution names accepted by [`RmiClient::set_value`].
///
/// Port of the nested `RmiClient.TraceRmiResolution` enum. Java's `setValue` looks constants up
/// with `valueOf`, i.e. by *constant name* (`"RES_ADJUST"`), not by [`val`](Self::val).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceRmiResolution {
    /// `RES_ADJUST("adjust", CR_ADJUST)`.
    ResAdjust,
    /// `RES_DENY("deny", CR_DENY)`.
    ResDeny,
    /// `RES_TRUNCATE("truncate", CR_TRUNCATE)`.
    ResTruncate,
}

impl TraceRmiResolution {
    /// The constants in declaration order, as Java's `values()`.
    pub const VALUES: [TraceRmiResolution; 3] = [
        TraceRmiResolution::ResAdjust,
        TraceRmiResolution::ResDeny,
        TraceRmiResolution::ResTruncate,
    ];

    /// The constant's name, as Java's `name()`.
    pub fn name(self) -> &'static str {
        match self {
            TraceRmiResolution::ResAdjust => "RES_ADJUST",
            TraceRmiResolution::ResDeny => "RES_DENY",
            TraceRmiResolution::ResTruncate => "RES_TRUNCATE",
        }
    }

    /// Java's `val` field.
    pub fn val(self) -> &'static str {
        match self {
            TraceRmiResolution::ResAdjust => "adjust",
            TraceRmiResolution::ResDeny => "deny",
            TraceRmiResolution::ResTruncate => "truncate",
        }
    }

    /// Java's `description` field: the wire [`Resolution`].
    pub fn description(self) -> Resolution {
        match self {
            TraceRmiResolution::ResAdjust => Resolution::CrAdjust,
            TraceRmiResolution::ResDeny => Resolution::CrDeny,
            TraceRmiResolution::ResTruncate => Resolution::CrTruncate,
        }
    }

    /// Java's `valueOf(String)`, returning `None` where Java throws `IllegalArgumentException`.
    pub fn value_of(name: &str) -> Option<TraceRmiResolution> {
        Self::VALUES.into_iter().find(|r| r.name() == name)
    }
}

/// Value-kind names for [`RmiClient::retain_values`] callers.
///
/// Port of the nested `RmiClient.TraceRmiValueKinds` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceRmiValueKinds {
    /// `ATTRIBUTES("attributes", VK_ATTRIBUTES)`.
    Attributes,
    /// `ELEMENTS("elements", VK_ELEMENTS)`.
    Elements,
    /// `BOTH("both", VK_BOTH)`.
    Both,
}

impl TraceRmiValueKinds {
    /// The constants in declaration order, as Java's `values()`.
    pub const VALUES: [TraceRmiValueKinds; 3] = [
        TraceRmiValueKinds::Attributes,
        TraceRmiValueKinds::Elements,
        TraceRmiValueKinds::Both,
    ];

    /// The constant's name, as Java's `name()`.
    pub fn name(self) -> &'static str {
        match self {
            TraceRmiValueKinds::Attributes => "ATTRIBUTES",
            TraceRmiValueKinds::Elements => "ELEMENTS",
            TraceRmiValueKinds::Both => "BOTH",
        }
    }

    /// Java's `val` field.
    pub fn val(self) -> &'static str {
        match self {
            TraceRmiValueKinds::Attributes => "attributes",
            TraceRmiValueKinds::Elements => "elements",
            TraceRmiValueKinds::Both => "both",
        }
    }

    /// Java's `description` field: the wire [`ValueKinds`].
    pub fn description(self) -> ValueKinds {
        match self {
            TraceRmiValueKinds::Attributes => ValueKinds::VkAttributes,
            TraceRmiValueKinds::Elements => ValueKinds::VkElements,
            TraceRmiValueKinds::Both => ValueKinds::VkBoth,
        }
    }

    /// Java's `valueOf(String)`, returning `None` where Java throws `IllegalArgumentException`.
    pub fn value_of(name: &str) -> Option<TraceRmiValueKinds> {
        Self::VALUES.into_iter().find(|k| k.name() == name)
    }
}

struct ClientInner {
    socket: Arc<ProtobufSocket<RootMessage>>,
    description: String,
    next_trace_id: AtomicI32,
    current_batch: Mutex<Option<RmiBatch>>,
    traces: Mutex<HashMap<i32, Arc<RmiTrace>>>,
    schema_context: RwLock<Option<Arc<dyn SchemaContext>>>,
    handler: Mutex<Option<RmiReplyHandlerThread>>,
    method_registry: RwLock<Option<Arc<RmiMethodRegistry>>>,
    requests: Mutex<VecDeque<RequestResult>>,
}

/// A Trace RMI client connection. See the module documentation.
#[derive(Clone)]
pub struct RmiClient {
    inner: Arc<ClientInner>,
}

fn oid(id: i32) -> Option<DomObjId> {
    // Java's `DomObjId.setId(int)` on a `uint32` field: the int's bits are sent unchanged.
    Some(DomObjId { id: id as u32 })
}

fn snap_msg(snap: i64) -> Option<Snap> {
    Some(Snap { snap })
}

fn span_msg(span: Lifespan) -> Option<Span> {
    Some(Span { min: span.lmin(), max: span.lmax() })
}

fn path_spec(path: &str) -> Option<ObjSpec> {
    Some(ObjSpec { key: Some(obj_spec::Key::Path(ObjPath { path: path.to_string() })) })
}

fn id_spec(id: i64) -> Option<ObjSpec> {
    Some(ObjSpec { key: Some(obj_spec::Key::Id(id)) })
}

fn addr_msg(address: &Address) -> Addr {
    Addr { space: address.space().name().to_string(), offset: address.offset() as u64 }
}

/// Java's `AddrRange` for `range`, with `extend` given explicitly: most requests send
/// `getLength() - 1`, but `getValuesIntersecting` sends `getLength()`.
fn range_msg(range: &AddressRange, extend: u64) -> AddrRange {
    AddrRange {
        space: range.space().name().to_string(),
        offset: range.min_address().offset() as u64,
        extend,
    }
}

fn root(msg: root_message::Msg) -> RootMessage {
    RootMessage { msg: Some(msg) }
}

impl RmiClient {
    /// Mirrors `RmiClient(SocketChannel channel, String description)`: wraps the connection and
    /// starts the reply-handler thread.
    pub fn new(stream: TcpStream, description: impl Into<String>) -> Self {
        let socket = Arc::new(ProtobufSocket::new(
            stream,
            |msg: &RootMessage| msg.encode_to_vec(),
            |buf: &[u8]| {
                RootMessage::decode(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            },
        ));
        let client = RmiClient {
            inner: Arc::new(ClientInner {
                socket: socket.clone(),
                description: description.into(),
                next_trace_id: AtomicI32::new(0),
                current_batch: Mutex::new(None),
                traces: Mutex::new(HashMap::new()),
                schema_context: RwLock::new(None),
                handler: Mutex::new(None),
                method_registry: RwLock::new(None),
                requests: Mutex::new(VecDeque::new()),
            }),
        };
        let mut handler = RmiReplyHandlerThread::new(client.clone(), socket);
        handler.start();
        *client.inner.handler.lock().unwrap_or_else(|e| e.into_inner()) = Some(handler);
        client
    }

    /// Mirrors `getDescription()`: the description plus the remote address (`"null"` if it
    /// cannot be determined, as Java's string concatenation renders a `null`).
    pub fn get_description(&self) -> String {
        let addr = self.inner.socket.get_remote_address().unwrap_or_else(|| "null".to_string());
        format!("{} at {}", self.inner.description, addr)
    }

    /// Mirrors `close()`: stops the reply thread and closes the socket.
    ///
    /// Unlike Java, this also waits for the reply thread to exit (unless called *from* that
    /// thread), so that nothing is still running against the connection after `close` returns.
    pub fn close(&self) {
        let handler = self.inner.handler.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handler) = &handler {
            handler.close();
        }
        self.inner.socket.close();
        if let Some(mut handler) = handler {
            handler.join();
        }
    }

    fn send(&self, msg: RootMessage) -> Result<RequestResult, RmiClientError> {
        let result = RequestResult::new(msg);
        {
            let mut requests = self.inner.requests.lock().unwrap_or_else(|e| e.into_inner());
            self.inner.socket.send(result.request())?;
            requests.push_back(result.clone());
        }
        let current = self.inner.current_batch.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(batch) = current {
            batch.append(result.clone());
        }
        Ok(result)
    }

    /// The trace this client created with the given id, if still open. Java code reads the
    /// package-private `traces` map directly.
    pub fn get_trace(&self, id: i32) -> Option<Arc<RmiTrace>> {
        self.inner.traces.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
    }

    /// Mirrors `createTrace(String, LanguageID, CompilerSpecID)`; a `None` compiler becomes
    /// `"default"`.
    pub fn create_trace(
        &self,
        path: &str,
        language: &LanguageID,
        compiler: Option<&CompilerSpecID>,
    ) -> Result<Arc<RmiTrace>, RmiClientError> {
        let compiler = compiler.map(|c| c.get_id_as_string()).unwrap_or("default").to_string();
        let trace_id = self.inner.next_trace_id.fetch_add(1, Ordering::SeqCst);
        let result = self.send(root(root_message::Msg::RequestCreateTrace(RequestCreateTrace {
            oid: oid(trace_id),
            language: Some(Language { id: language.get_id_as_string().to_string() }),
            compiler: Some(Compiler { id: compiler }),
            path: Some(FilePath { path: path.to_string() }),
        })))?;
        let trace = Arc::new(RmiTrace::new(trace_id, result));
        self.inner
            .traces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(trace_id, trace.clone());
        Ok(trace)
    }

    /// Mirrors `closeTrace(int)`.
    pub fn close_trace(&self, id: i32) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestCloseTrace(RequestCloseTrace { oid: oid(id) })))?;
        self.inner.traces.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        Ok(())
    }

    /// Mirrors `saveTrace(int)`.
    pub fn save_trace(&self, id: i32) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestSaveTrace(RequestSaveTrace { oid: oid(id) })))?;
        Ok(())
    }

    /// Mirrors `startTx(int, String, boolean, int)`.
    pub fn start_tx(
        &self,
        trace_id: i32,
        desc: &str,
        undoable: bool,
        tx_id: i32,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestStartTx(RequestStartTx {
            oid: oid(trace_id),
            txid: Some(TxId { id: tx_id }),
            description: desc.to_string(),
            undoable,
        })))?;
        Ok(())
    }

    /// Mirrors `endTx(int, int, boolean)`.
    pub fn end_tx(&self, trace_id: i32, tx_id: i32, abort: bool) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestEndTx(RequestEndTx {
            oid: oid(trace_id),
            txid: Some(TxId { id: tx_id }),
            abort,
        })))?;
        Ok(())
    }

    /// Mirrors `snapshot(int, String, String, long)`.
    pub fn snapshot(
        &self,
        trace_id: i32,
        desc: &str,
        datetime: &str,
        snap: i64,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestSnapshot(RequestSnapshot {
            oid: oid(trace_id),
            description: desc.to_string(),
            datetime: datetime.to_string(),
            time: Some(request_snapshot::Time::Snap(Snap { snap })),
        })))?;
        Ok(())
    }

    /// Mirrors `createOverlaySpace(int, String, String)`.
    pub fn create_overlay_space(
        &self,
        trace_id: i32,
        base: &str,
        name: &str,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestCreateOverlay(RequestCreateOverlaySpace {
            oid: oid(trace_id),
            base_space: base.to_string(),
            name: name.to_string(),
        })))?;
        Ok(())
    }

    /// Mirrors `putBytes(int, long, Address, byte[])`.
    pub fn put_bytes(
        &self,
        trace_id: i32,
        snap: i64,
        start: &Address,
        data: &[u8],
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestPutBytes(RequestPutBytes {
            oid: oid(trace_id),
            snap: snap_msg(snap),
            start: Some(addr_msg(start)),
            data: data.to_vec(),
        })))?;
        Ok(())
    }

    /// Mirrors `setMemoryState(int, long, AddressRange, MemoryState)`.
    pub fn set_memory_state(
        &self,
        trace_id: i32,
        snap: i64,
        range: &AddressRange,
        state: MemoryState,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestSetMemoryState(RequestSetMemoryState {
            oid: oid(trace_id),
            snap: snap_msg(snap),
            range: Some(range_msg(range, range.length().wrapping_sub(1))),
            state: state as i32,
        })))?;
        Ok(())
    }

    /// Mirrors `deleteBytes(int, long, AddressRange)`.
    pub fn delete_bytes(
        &self,
        trace_id: i32,
        snap: i64,
        range: &AddressRange,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestDeleteBytes(RequestDeleteBytes {
            oid: oid(trace_id),
            snap: snap_msg(snap),
            range: Some(range_msg(range, range.length().wrapping_sub(1))),
        })))?;
        Ok(())
    }

    /// Mirrors `putRegisters(int, long, String, RegisterValue[])`: each value is sent as its
    /// register's name and `RegisterValue.toBytes()` (mask bytes followed by value bytes).
    pub fn put_registers(
        &self,
        trace_id: i32,
        snap: i64,
        ppath: &str,
        values: &[RegisterValue],
    ) -> Result<(), RmiClientError> {
        let values = values
            .iter()
            .map(|rv| RegVal {
                name: rv.register().name().to_string(),
                value: rv.to_bytes(),
            })
            .collect();
        self.send(root(root_message::Msg::RequestPutRegisterValue(RequestPutRegisterValue {
            oid: oid(trace_id),
            snap: snap_msg(snap),
            space: ppath.to_string(),
            values,
        })))?;
        Ok(())
    }

    /// Mirrors `deleteRegisters(int, long, String, String[])`.
    pub fn delete_registers(
        &self,
        trace_id: i32,
        snap: i64,
        ppath: &str,
        names: &[&str],
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestDeleteRegisterValue(
            RequestDeleteRegisterValue {
                oid: oid(trace_id),
                snap: snap_msg(snap),
                space: ppath.to_string(),
                names: names.iter().map(|n| n.to_string()).collect(),
            },
        )))?;
        Ok(())
    }

    /// Mirrors `createRootObject(int, SchemaContext, String)`: remembers `schema_context` (for
    /// [`get_schema`](Self::get_schema)) and sends it, serialized by
    /// [`XmlSchemaContext::serialize`], with the root schema's name.
    pub fn create_root_object(
        &self,
        trace_id: i32,
        schema_context: Arc<dyn SchemaContext>,
        schema: &str,
    ) -> Result<(), RmiClientError> {
        let xml_ctx = XmlSchemaContext::serialize(schema_context.as_ref());
        *self.inner.schema_context.write().unwrap_or_else(|e| e.into_inner()) =
            Some(schema_context);
        self.send(root(root_message::Msg::RequestCreateRootObject(RequestCreateRootObject {
            oid: oid(trace_id),
            schema_context: xml_ctx,
            root_schema: schema.to_string(),
        })))?;
        Ok(())
    }

    /// Mirrors the package-private `createObject(int, String)`; the result completes with the
    /// new object's id.
    pub fn create_object(&self, trace_id: i32, path: &str) -> Result<RequestResult, RmiClientError> {
        self.send(root(root_message::Msg::RequestCreateObject(RequestCreateObject {
            oid: oid(trace_id),
            path: Some(ObjPath { path: path.to_string() }),
        })))
    }

    /// Mirrors `insertObject(int, String, Lifespan, Resolution)`.
    pub fn insert_object_path(
        &self,
        trace_id: i32,
        path: &str,
        span: Lifespan,
        r: Resolution,
    ) -> Result<(), RmiClientError> {
        self.send_insert(trace_id, path_spec(path), span, r)
    }

    /// Mirrors `insertObject(int, long, Lifespan, Resolution)`.
    pub fn insert_object_id(
        &self,
        trace_id: i32,
        id: i64,
        span: Lifespan,
        r: Resolution,
    ) -> Result<(), RmiClientError> {
        self.send_insert(trace_id, id_spec(id), span, r)
    }

    fn send_insert(
        &self,
        trace_id: i32,
        object: Option<ObjSpec>,
        span: Lifespan,
        r: Resolution,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestInsertObject(RequestInsertObject {
            oid: oid(trace_id),
            object,
            span: span_msg(span),
            resolution: r as i32,
        })))?;
        Ok(())
    }

    /// Mirrors `removeObject(int, String, Lifespan, boolean)`.
    pub fn remove_object_path(
        &self,
        trace_id: i32,
        path: &str,
        span: Lifespan,
        tree: bool,
    ) -> Result<(), RmiClientError> {
        self.send_remove(trace_id, path_spec(path), span, tree)
    }

    /// Mirrors `removeObject(int, long, Lifespan, boolean)`.
    pub fn remove_object_id(
        &self,
        trace_id: i32,
        id: i64,
        span: Lifespan,
        tree: bool,
    ) -> Result<(), RmiClientError> {
        self.send_remove(trace_id, id_spec(id), span, tree)
    }

    fn send_remove(
        &self,
        trace_id: i32,
        object: Option<ObjSpec>,
        span: Lifespan,
        tree: bool,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestRemoveObject(RequestRemoveObject {
            oid: oid(trace_id),
            object,
            span: span_msg(span),
            tree,
        })))?;
        Ok(())
    }

    /// Mirrors `setValue(int, String, Lifespan, String, Object, String)`. `resolution` is a
    /// [`TraceRmiResolution`] constant *name*; `None` means `CR_ADJUST`.
    pub fn set_value(
        &self,
        trace_id: i32,
        ppath: &str,
        span: Lifespan,
        key: &str,
        value: &RmiValue,
        resolution: Option<&str>,
    ) -> Result<(), RmiClientError> {
        let r = match resolution {
            None => Resolution::CrAdjust,
            Some(name) => TraceRmiResolution::value_of(name)
                .ok_or_else(|| {
                    RmiClientError::Invalid(format!(
                        "No enum constant TraceRmiResolution.{name}"
                    ))
                })?
                .description(),
        };
        let value = self.build_value(value)?;
        self.send(root(root_message::Msg::RequestSetValue(RequestSetValue {
            oid: oid(trace_id),
            value: Some(ValSpec {
                span: span_msg(span),
                parent: path_spec(ppath),
                key: key.to_string(),
                value: Some(value),
            }),
            resolution: r as i32,
        })))?;
        Ok(())
    }

    /// Mirrors `retainValues(int, String, Lifespan, ValueKinds, Set<String>)`.
    pub fn retain_values(
        &self,
        trace_id: i32,
        ppath: &str,
        span: Lifespan,
        kinds: ValueKinds,
        keys: &HashSet<String>,
    ) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestRetainValues(RequestRetainValues {
            oid: oid(trace_id),
            object: path_spec(ppath),
            span: span_msg(span),
            kinds: kinds as i32,
            keys: keys.iter().cloned().collect(),
        })))?;
        Ok(())
    }

    /// Mirrors `getObject(int, String)`.
    pub fn get_object(&self, trace_id: i32, path: &str) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestGetObject(RequestGetObject {
            oid: oid(trace_id),
            object: path_spec(path),
        })))?;
        Ok(())
    }

    /// Mirrors the package-private `getValues(int, Lifespan, String)`.
    pub fn get_values(
        &self,
        trace_id: i32,
        span: Lifespan,
        pattern: &str,
    ) -> Result<RequestResult, RmiClientError> {
        self.send(root(root_message::Msg::RequestGetValues(RequestGetValues {
            oid: oid(trace_id),
            span: span_msg(span),
            pattern: Some(ObjPath { path: pattern.to_string() }),
        })))
    }

    /// Mirrors the package-private `getValuesIntersecting(int, Lifespan, AddressRange, String)`.
    /// Note that, unlike every other request here, Java sends the range's full length (not
    /// `length - 1`) as `extend`.
    pub fn get_values_intersecting(
        &self,
        trace_id: i32,
        span: Lifespan,
        range: &AddressRange,
        key: &str,
    ) -> Result<RequestResult, RmiClientError> {
        self.send(root(root_message::Msg::RequestGetValuesIntersecting(
            RequestGetValuesIntersecting {
                oid: oid(trace_id),
                r#box: Some(SpanBox {
                    span: span_msg(span),
                    range: Some(range_msg(range, range.length())),
                }),
                key: key.to_string(),
            },
        )))
    }

    /// Mirrors `proxyObjectId(int, Long)`.
    pub fn proxy_object_id(&self, trace_id: i32, id: i64) -> RmiTraceObject {
        RmiTraceObject::from_id(trace_id, id)
    }

    /// Mirrors `proxyObjectPath(int, String)`.
    pub fn proxy_object_path(&self, trace_id: i32, path: &str) -> RmiTraceObject {
        RmiTraceObject::from_path(trace_id, path)
    }

    /// Mirrors `proxyObjectPath(int, Long, String)`.
    pub fn proxy_object_path_with_id(
        &self,
        trace_id: i32,
        id: Option<i64>,
        path: Option<&str>,
    ) -> RmiTraceObject {
        RmiTraceObject::with_id(trace_id, id, path.map(str::to_string))
    }

    /// Mirrors the private `buildValue(Object)`: encodes a value for the wire.
    ///
    /// Java throws when handed an unsupported type, an empty list (it inspects `list.get(0)`) or
    /// an object with no path; the typed [`RmiValue`] rules out the first two, and the third is
    /// an [`RmiClientError::Invalid`].
    pub fn build_value(&self, value: &RmiValue) -> Result<Value, RmiClientError> {
        let v = match value {
            RmiValue::Null => value::Value::NullValue(Null {}),
            RmiValue::String(s) => value::Value::StringValue(s.clone()),
            RmiValue::Bool(b) => value::Value::BoolValue(*b),
            RmiValue::Short(s) => value::Value::ShortValue(*s as i32),
            RmiValue::Int(i) => value::Value::IntValue(*i),
            RmiValue::Long(l) => value::Value::LongValue(*l),
            RmiValue::Bytes(b) => value::Value::BytesValue(b.clone()),
            RmiValue::Byte(b) => value::Value::ByteValue(*b as i32),
            RmiValue::Char(c) => value::Value::CharValue(*c as u32),
            RmiValue::Address(address) => value::Value::AddressValue(addr_msg(address)),
            RmiValue::Range(range) => {
                value::Value::RangeValue(range_msg(range, range.length().wrapping_sub(1)))
            }
            RmiValue::Object(obj) => {
                let path = obj.get_path().ok_or_else(|| {
                    RmiClientError::Invalid(format!("Unhandled type for buildValue: {obj:?}"))
                })?;
                value::Value::ChildSpec(ObjSpec {
                    key: Some(obj_spec::Key::Path(ObjPath { path: path.to_string() })),
                })
            }
            RmiValue::StringArr(arr) => value::Value::StringArrValue(StringArr { arr: arr.clone() }),
            RmiValue::BoolArr(arr) => value::Value::BoolArrValue(BoolArr { arr: arr.clone() }),
            RmiValue::ShortArr(arr) => value::Value::ShortArrValue(ShortArr {
                arr: arr.iter().map(|s| *s as i32).collect(),
            }),
            RmiValue::IntArr(arr) => value::Value::IntArrValue(IntArr { arr: arr.clone() }),
            RmiValue::LongArr(arr) => value::Value::LongArrValue(LongArr { arr: arr.clone() }),
        };
        Ok(Value { value: Some(v) })
    }

    /// Mirrors `activate(int, String)`.
    pub fn activate(&self, trace_id: i32, path: &str) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestActivate(RequestActivate {
            oid: oid(trace_id),
            object: path_spec(path),
        })))?;
        Ok(())
    }

    /// Mirrors `disassemble(int, long, Address)`.
    pub fn disassemble(&self, trace_id: i32, snap: i64, start: &Address) -> Result<(), RmiClientError> {
        self.send(root(root_message::Msg::RequestDisassemble(RequestDisassemble {
            oid: oid(trace_id),
            snap: snap_msg(snap),
            start: Some(addr_msg(start)),
        })))?;
        Ok(())
    }

    /// Mirrors `negotiate(String)`: announces the protocol version and every registered method.
    /// Fails if no registry was set (Java dereferences the `null` static).
    pub fn negotiate(&self, desc: &str) -> Result<(), RmiClientError> {
        let registry = self.registry()?;
        let methods = registry
            .get_map()
            .values()
            .map(|m| self.build_method(m))
            .collect::<Result<Vec<_>, _>>()?;
        self.send(root(root_message::Msg::RequestNegotiate(RequestNegotiate {
            version: TRACE_RMI_HANDLER_VERSION.to_string(),
            methods,
            description: desc.to_string(),
        })))?;
        Ok(())
    }

    fn build_method(&self, method: &RmiRemoteMethod) -> Result<Method, RmiClientError> {
        let parameters = method
            .get_parameters()
            .iter()
            .map(|p| self.build_parameter(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Method {
            name: method.get_name().to_string(),
            action: method.get_action().to_string(),
            display: method.get_display().to_string(),
            description: method.get_description().to_string(),
            parameters,
            return_type: None,
            ok_text: method.get_ok_text().to_string(),
            icon: method.get_icon().to_string(),
        })
    }

    fn build_parameter(
        &self,
        param: &RmiRemoteMethodParameter,
    ) -> Result<MethodParameter, RmiClientError> {
        Ok(MethodParameter {
            name: param.get_name().to_string(),
            display: param.get_display().to_string(),
            description: param.get_description().to_string(),
            r#type: Some(param.get_type()),
            default_value: Some(self.build_value(param.get_default_value())?),
            required: param.is_required(),
        })
    }

    /// Mirrors `handleInvokeMethod(int, XRequestInvokeMethod)`: decodes the arguments (in the
    /// method's parameter order, skipping parameters the request omits, padded with nulls to
    /// the request's argument count, exactly as Java fills its `Object[]`), invokes the method,
    /// and encodes its result -- `true` when it returns nothing -- or its error.
    ///
    /// Errors decoding the request (unknown method, undecodable argument) are returned, as Java
    /// throws them to the reply thread, which answers with an error reply.
    pub fn handle_invoke_method(
        &self,
        trace_id: i32,
        req: &XRequestInvokeMethod,
    ) -> Result<XReplyInvokeMethod, RmiClientError> {
        let rm = self
            .get_method(&req.name)
            .ok_or_else(|| RmiClientError::Invalid(format!("No such method: {}", req.name)))?;
        let mut argmap: HashMap<&str, &MethodArgument> = HashMap::new();
        for arg in &req.arguments {
            argmap.insert(arg.name.as_str(), arg);
        }
        let mut arglist = vec![RmiValue::Null; req.arguments.len()];
        let mut i = 0;
        for p in rm.get_parameters() {
            if let Some(arg) = argmap.get(p.get_name()) {
                let default = Value::default();
                let obj = self.arg_to_object(trace_id, arg.value.as_ref().unwrap_or(&default))?;
                if i < arglist.len() {
                    arglist[i] = obj;
                }
                i += 1;
            }
        }
        match rm.invoke(arglist) {
            Ok(ret) => Ok(XReplyInvokeMethod {
                error: String::new(),
                return_value: Some(self.build_value(&ret.unwrap_or(RmiValue::Bool(true)))?),
            }),
            Err(message) => {
                Msg::error("RmiClient", &format!("Error handling method invocation:{message}"));
                Ok(XReplyInvokeMethod { error: message, return_value: None })
            }
        }
    }

    /// Mirrors the package-private `argToObject(int, Value)`: decodes a wire value into the
    /// boxed type Java's protobuf getter returns (see [`RmiValue`]). Addresses and ranges are
    /// resolved through the trace's [`MemoryMapper`](super::MemoryMapper); an unset value or a
    /// `child_spec` falls through, as in Java, to a proxy for the (empty) `child_desc` path.
    pub fn arg_to_object(&self, trace_id: i32, value: &Value) -> Result<RmiValue, RmiClientError> {
        Ok(match &value.value {
            Some(value::Value::StringValue(s)) => RmiValue::String(s.clone()),
            Some(value::Value::StringArrValue(a)) => RmiValue::StringArr(a.arr.clone()),
            Some(value::Value::BoolValue(b)) => RmiValue::Bool(*b),
            Some(value::Value::BoolArrValue(a)) => RmiValue::BoolArr(a.arr.clone()),
            Some(value::Value::CharValue(c)) => RmiValue::Int(*c as i32),
            Some(value::Value::CharArrValue(s)) => RmiValue::String(s.clone()),
            Some(value::Value::ShortValue(s)) => RmiValue::Int(*s),
            Some(value::Value::ShortArrValue(a)) => RmiValue::IntArr(a.arr.clone()),
            Some(value::Value::IntValue(i)) => RmiValue::Int(*i),
            Some(value::Value::IntArrValue(a)) => RmiValue::IntArr(a.arr.clone()),
            Some(value::Value::LongValue(l)) => RmiValue::Long(*l),
            Some(value::Value::LongArrValue(a)) => RmiValue::LongArr(a.arr.clone()),
            Some(value::Value::AddressValue(addr)) => {
                RmiValue::Address(self.decode_addr(trace_id, addr)?)
            }
            Some(value::Value::RangeValue(rng)) => {
                RmiValue::Range(self.decode_range(trace_id, rng)?)
            }
            Some(value::Value::ByteValue(b)) => RmiValue::Int(*b),
            Some(value::Value::BytesValue(b)) => RmiValue::Bytes(b.clone()),
            Some(value::Value::NullValue(_)) => RmiValue::Null,
            Some(value::Value::ChildDesc(desc)) => RmiValue::Object(self.proxy_object_path(
                trace_id,
                desc.path.as_ref().map(|p| p.path.as_str()).unwrap_or(""),
            )),
            Some(value::Value::ChildSpec(_)) | None => {
                RmiValue::Object(self.proxy_object_path(trace_id, ""))
            }
        })
    }

    /// Mirrors the package-private `argToType(Value)`: the schema name of a wire value's type,
    /// `"OBJECT"` for object references and unset values.
    pub fn arg_to_type(&self, value: &Value) -> &'static str {
        match &value.value {
            Some(value::Value::StringValue(_)) => "STRING",
            Some(value::Value::StringArrValue(_)) => "STRING_ARR",
            Some(value::Value::BoolValue(_)) => "BOOL",
            Some(value::Value::BoolArrValue(_)) => "BOOL_ARR",
            Some(value::Value::CharValue(_)) => "CHAR",
            Some(value::Value::CharArrValue(_)) => "CHAR_ARR",
            Some(value::Value::ShortValue(_)) => "SHORT",
            Some(value::Value::ShortArrValue(_)) => "SHORT_ARR",
            Some(value::Value::IntValue(_)) => "INT",
            Some(value::Value::IntArrValue(_)) => "INT_ARR",
            Some(value::Value::LongValue(_)) => "LONG",
            Some(value::Value::LongArrValue(_)) => "LONG_ARR",
            Some(value::Value::AddressValue(_)) => "ADDRESS",
            Some(value::Value::RangeValue(_)) => "RANGE",
            Some(value::Value::ByteValue(_)) => "BYTE",
            Some(value::Value::BytesValue(_)) => "BYTE_ARR",
            Some(value::Value::NullValue(_)) => "NULL",
            Some(value::Value::ChildSpec(_)) | Some(value::Value::ChildDesc(_)) | None => "OBJECT",
        }
    }

    fn mapped_trace(&self, id: i32) -> Result<Arc<RmiTrace>, RmiClientError> {
        self.get_trace(id)
            .ok_or_else(|| RmiClientError::Invalid(format!("No trace with id {id}")))
    }

    fn decode_addr(&self, id: i32, addr: &Addr) -> Result<Address, RmiClientError> {
        let mapper = self.mapped_trace(id)?.get_memory_mapper().ok_or_else(|| {
            RmiClientError::Invalid(format!("Trace {id} has no memory mapper"))
        })?;
        Ok(mapper.gen_addr(&addr.space, addr.offset as i64))
    }

    fn decode_range(&self, id: i32, rng: &AddrRange) -> Result<AddressRange, RmiClientError> {
        let mapper = self.mapped_trace(id)?.get_memory_mapper().ok_or_else(|| {
            RmiClientError::Invalid(format!("Trace {id} has no memory mapper"))
        })?;
        let start = mapper.gen_addr(&rng.space, rng.offset as i64);
        let end = start
            .add(rng.extend as i64)
            .map_err(|e| RmiClientError::Invalid(e.to_string()))?;
        Ok(AddressRange::new(start, end))
    }

    /// Mirrors `setRegistry(RmiMethodRegistry)`.
    pub fn set_registry(&self, method_registry: Arc<RmiMethodRegistry>) {
        *self.inner.method_registry.write().unwrap_or_else(|e| e.into_inner()) =
            Some(method_registry);
    }

    fn registry(&self) -> Result<Arc<RmiMethodRegistry>, RmiClientError> {
        self.inner
            .method_registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| RmiClientError::Invalid("No method registry has been set".into()))
    }

    /// Mirrors `getMethod(String)`; `None` if the method (or the registry) is absent.
    pub fn get_method(&self, name: &str) -> Option<Arc<RmiRemoteMethod>> {
        self.registry().ok().and_then(|r| r.get_method(name))
    }

    /// Mirrors `startBatch()`: starts a batch, or joins the one in progress. Every call must be
    /// balanced by an [`RmiBatch::close`].
    pub fn start_batch(&self) -> RmiBatch {
        let mut current = self.inner.current_batch.lock().unwrap_or_else(|e| e.into_inner());
        let batch = current.get_or_insert_with(|| RmiBatch::new(self.clone())).clone();
        batch.inc();
        batch
    }

    /// Mirrors the package-private `hasBatch()`.
    pub fn has_batch(&self) -> bool {
        self.inner.current_batch.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Mirrors the package-private `endBatch(RmiBatch)`: releases one hold on the current batch
    /// and, when the last is released, ends it and waits for all of its replies. As in Java, it
    /// acts on the client's *current* batch rather than on `_batch`.
    pub fn end_batch(&self, _batch: &RmiBatch) -> Result<(), RmiException> {
        let finished = {
            let mut current = self.inner.current_batch.lock().unwrap_or_else(|e| e.into_inner());
            match current.as_ref() {
                Some(cb) if cb.dec() == 0 => current.take(),
                _ => None,
            }
        };
        if let Some(cb) = finished {
            cb.results()?;
        }
        Ok(())
    }

    /// Mirrors the static `loadSchema(String, String)`: reads the schema context in the XML file
    /// at `resource` and resolves `root_name` in it (the "ANY" primitive if it is absent).
    pub fn load_schema(
        resource: &std::path::Path,
        root_name: &str,
    ) -> Result<Box<dyn TraceObjectSchema>, XmlSchemaError> {
        let schema_context = XmlSchemaContext::deserialize_file(resource)?;
        Ok(schema_context.get_schema(&schema_context.name(root_name)))
    }

    /// Mirrors `getSchema(String)`: resolves a schema name in the context given to
    /// [`create_root_object`](Self::create_root_object). Fails if no root object was created
    /// (Java dereferences the `null` context).
    pub fn get_schema(&self, schema: &str) -> Result<Arc<dyn TraceObjectSchema>, RmiClientError> {
        let ctx = self
            .inner
            .schema_context
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| RmiClientError::Invalid("No schema context has been set".into()))?;
        Ok(Arc::from(ctx.get_schema(&SchemaName::new(schema))))
    }

    /// Mirrors `pollRequest()`: takes the oldest request still awaiting its reply. (Java takes
    /// the newest; see the module docs.)
    pub fn poll_request(&self) -> Option<RequestResult> {
        self.inner.requests.lock().unwrap_or_else(|e| e.into_inner()).pop_front()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::MemoryMapper;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use std::net::TcpListener;

    /// A connected client plus the front end's side of the socket, which tests drive by hand.
    pub(crate) struct Harness {
        pub client: RmiClient,
        pub server: ProtobufSocket<RootMessage>,
    }

    impl Harness {
        pub fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            let server = ProtobufSocket::new(
                peer,
                |m: &RootMessage| m.encode_to_vec(),
                |b: &[u8]| {
                    RootMessage::decode(b)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                },
            );
            Harness { client: RmiClient::new(stream, "test client"), server }
        }

        pub fn recv(&self) -> root_message::Msg {
            self.server.recv().unwrap().msg.expect("message with a body")
        }

        pub fn reply(&self, msg: root_message::Msg) {
            self.server.send(&root(msg)).unwrap();
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.client.close();
        }
    }

    pub(crate) fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1)
    }

    pub(crate) struct RamMapper;

    impl MemoryMapper for RamMapper {
        fn map(&self, address: &Address) -> Address {
            address.clone()
        }
        fn map_back(&self, address: &Address) -> Address {
            address.clone()
        }
        fn gen_addr(&self, _space: &str, offset: i64) -> Address {
            ram().address(offset)
        }
    }

    const WAIT: Duration = Duration::from_secs(10);

    fn x86() -> LanguageID {
        LanguageID::new("x86:LE:64:default").unwrap()
    }

    #[test]
    fn load_schema_reads_jdi_schema_resource() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../orig_src/Ghidra/Debug/Debugger-jpda/src/main/resources/ghidra/app/plugin/core/debug/client/tracermi/jdi_schema.xml",
        );
        let root = RmiClient::load_schema(&path, "Debugger").unwrap();
        assert_eq!(root.get_name(), SchemaName::new("Debugger"));
        let ifaces: Vec<String> =
            root.get_interfaces().into_iter().map(|i| i.schema_name).collect();
        assert_eq!(ifaces, vec!["EventScope", "FocusScope", "Aggregate"]);
        assert_eq!(root.get_default_element_schema(), SchemaName::new("VOID"));
        let accessible = root.get_attribute_schema("_accessible");
        assert_eq!(accessible.get_schema(), &SchemaName::new("BOOL"));
        assert!(accessible.is_required());
        assert!(root.is_hidden("_accessible"));
        // An unknown root name resolves to ANY, as in Java.
        let any = RmiClient::load_schema(&path, "NoSuchSchema").unwrap();
        assert_eq!(any.get_name(), SchemaName::new("ANY"));
        assert!(RmiClient::load_schema(std::path::Path::new("/no/such/file.xml"), "X").is_err());
    }

    #[test]
    fn create_trace_sends_expected_root_message_and_defaults_compiler() {
        let h = Harness::new();
        let trace = h.client.create_trace("/traces/demo", &x86(), None).unwrap();
        assert_eq!(trace.get_id(), 0);
        match h.recv() {
            root_message::Msg::RequestCreateTrace(req) => {
                assert_eq!(req.oid, Some(DomObjId { id: 0 }));
                assert_eq!(req.language.unwrap().id, "x86:LE:64:default");
                assert_eq!(req.compiler.unwrap().id, "default");
                assert_eq!(req.path.unwrap().path, "/traces/demo");
            }
            other => panic!("unexpected {other:?}"),
        }
        h.reply(root_message::Msg::ReplyCreateTrace(Default::default()));
        trace.check_result(WAIT).unwrap();

        let second = h
            .client
            .create_trace("/traces/two", &x86(), Some(&CompilerSpecID::new(Some("gcc"))))
            .unwrap();
        assert_eq!(second.get_id(), 1, "trace ids count up from 0");
        match h.recv() {
            root_message::Msg::RequestCreateTrace(req) => {
                assert_eq!(req.oid, Some(DomObjId { id: 1 }));
                assert_eq!(req.compiler.unwrap().id, "gcc");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn start_tx_request_matches_java_builder() {
        let h = Harness::new();
        h.client.start_tx(3, "Populate", true, 7).unwrap();
        assert_eq!(
            h.recv(),
            root_message::Msg::RequestStartTx(RequestStartTx {
                oid: Some(DomObjId { id: 3 }),
                undoable: true,
                description: "Populate".into(),
                txid: Some(TxId { id: 7 }),
            })
        );
        h.client.end_tx(3, 7, true).unwrap();
        assert_eq!(
            h.recv(),
            root_message::Msg::RequestEndTx(RequestEndTx {
                oid: Some(DomObjId { id: 3 }),
                txid: Some(TxId { id: 7 }),
                abort: true,
            })
        );
    }

    #[test]
    fn memory_requests_use_length_minus_one_but_intersecting_uses_length() {
        let h = Harness::new();
        let space = ram();
        let range = AddressRange::new(space.address(0x1000), space.address(0x10ff));
        h.client.put_bytes(0, 5, &space.address(0x1000), &[1, 2, 3]).unwrap();
        match h.recv() {
            root_message::Msg::RequestPutBytes(req) => {
                assert_eq!(req.snap, Some(Snap { snap: 5 }));
                assert_eq!(req.start, Some(Addr { space: "ram".into(), offset: 0x1000 }));
                assert_eq!(req.data, vec![1, 2, 3]);
            }
            other => panic!("unexpected {other:?}"),
        }
        h.client.set_memory_state(0, 5, &range, MemoryState::MsKnown).unwrap();
        match h.recv() {
            root_message::Msg::RequestSetMemoryState(req) => {
                assert_eq!(
                    req.range,
                    Some(AddrRange { space: "ram".into(), offset: 0x1000, extend: 0xff })
                );
                assert_eq!(req.state, MemoryState::MsKnown as i32);
            }
            other => panic!("unexpected {other:?}"),
        }
        h.client.get_values_intersecting(0, Lifespan::at(5), &range, "").unwrap();
        match h.recv() {
            root_message::Msg::RequestGetValuesIntersecting(req) => {
                let bx = req.r#box.unwrap();
                assert_eq!(bx.span, Some(Span { min: 5, max: 5 }));
                assert_eq!(bx.range.unwrap().extend, 0x100);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn put_registers_sends_name_and_mask_value_bytes() {
        let h = Harness::new();
        let reg_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let rax = Register::new("RAX", "", reg_space.address(0), 1, false, 0);
        let rv = RegisterValue::with_value(rax, 0x5a);
        h.client.put_registers(0, 2, "Threads[1].Registers", &[rv]).unwrap();
        match h.recv() {
            root_message::Msg::RequestPutRegisterValue(req) => {
                assert_eq!(req.space, "Threads[1].Registers");
                assert_eq!(req.values.len(), 1);
                assert_eq!(req.values[0].name, "RAX");
                // One-byte register: mask byte 0xff then value byte 0x5a.
                assert_eq!(req.values[0].value, vec![0xff, 0x5a]);
            }
            other => panic!("unexpected {other:?}"),
        }
        h.client.delete_registers(0, 2, "Threads[1].Registers", &["RAX", "RBX"]).unwrap();
        match h.recv() {
            root_message::Msg::RequestDeleteRegisterValue(req) => {
                assert_eq!(req.names, vec!["RAX".to_string(), "RBX".to_string()]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn set_value_resolution_is_looked_up_by_constant_name() {
        let h = Harness::new();
        let span = Lifespan::now_on(4);
        h.client
            .set_value(0, "Processes[1]", span, "_pid", &RmiValue::Long(1234), Some("RES_DENY"))
            .unwrap();
        match h.recv() {
            root_message::Msg::RequestSetValue(req) => {
                assert_eq!(req.resolution, Resolution::CrDeny as i32);
                let v = req.value.unwrap();
                assert_eq!(v.span, Some(Span { min: 4, max: i64::MAX }));
                assert_eq!(v.parent, path_spec("Processes[1]"));
                assert_eq!(v.key, "_pid");
                assert_eq!(v.value.unwrap().value, Some(value::Value::LongValue(1234)));
            }
            other => panic!("unexpected {other:?}"),
        }
        h.client
            .set_value(0, "Processes[1]", span, "_pid", &RmiValue::Long(1), None)
            .unwrap();
        match h.recv() {
            root_message::Msg::RequestSetValue(req) => {
                assert_eq!(req.resolution, Resolution::CrAdjust as i32)
            }
            other => panic!("unexpected {other:?}"),
        }
        // Java's valueOf is by constant name: the `val` string is rejected.
        let err = h
            .client
            .set_value(0, "Processes[1]", span, "_pid", &RmiValue::Null, Some("deny"))
            .unwrap_err();
        assert!(matches!(err, RmiClientError::Invalid(_)));
    }

    #[test]
    fn build_value_encodes_each_java_type() {
        let h = Harness::new();
        let space = ram();
        let c = &h.client;
        let enc = |v: RmiValue| c.build_value(&v).unwrap().value.unwrap();
        assert_eq!(enc(RmiValue::Null), value::Value::NullValue(Null {}));
        assert_eq!(enc(RmiValue::Byte(-1)), value::Value::ByteValue(-1));
        assert_eq!(enc(RmiValue::Char(0x41)), value::Value::CharValue(0x41));
        assert_eq!(enc(RmiValue::Short(-2)), value::Value::ShortValue(-2));
        assert_eq!(
            enc(RmiValue::ShortArr(vec![1, -1])),
            value::Value::ShortArrValue(ShortArr { arr: vec![1, -1] })
        );
        assert_eq!(
            enc(RmiValue::Address(space.address(0x400000))),
            value::Value::AddressValue(Addr { space: "ram".into(), offset: 0x400000 })
        );
        assert_eq!(
            enc(RmiValue::Range(AddressRange::new(space.address(0x10), space.address(0x1f)))),
            value::Value::RangeValue(AddrRange { space: "ram".into(), offset: 0x10, extend: 0xf })
        );
        assert_eq!(
            enc(RmiValue::Object(RmiTraceObject::from_path(0, "Processes[1]"))),
            value::Value::ChildSpec(ObjSpec {
                key: Some(obj_spec::Key::Path(ObjPath { path: "Processes[1]".into() }))
            })
        );
        assert!(c.build_value(&RmiValue::Object(RmiTraceObject::from_id(0, 9))).is_err());
    }

    #[test]
    fn arg_to_object_returns_java_boxed_getter_types() {
        let h = Harness::new();
        let trace = h.client.create_trace("/t", &x86(), None).unwrap();
        trace.set_memory_mapper(Arc::new(RamMapper));
        let c = &h.client;
        let dec = |v: value::Value| c.arg_to_object(0, &Value { value: Some(v) }).unwrap();
        assert!(matches!(dec(value::Value::CharValue(0x41)), RmiValue::Int(0x41)));
        assert!(matches!(dec(value::Value::ShortValue(-3)), RmiValue::Int(-3)));
        assert!(matches!(dec(value::Value::ByteValue(7)), RmiValue::Int(7)));
        match dec(value::Value::CharArrValue("hi".into())) {
            RmiValue::String(s) => assert_eq!(s, "hi"),
            other => panic!("unexpected {other:?}"),
        }
        match dec(value::Value::RangeValue(AddrRange {
            space: "ram".into(),
            offset: 0x100,
            extend: 0xf,
        })) {
            RmiValue::Range(r) => {
                assert_eq!(r.min_address().offset(), 0x100);
                assert_eq!(r.max_address().offset(), 0x10f);
            }
            other => panic!("unexpected {other:?}"),
        }
        match dec(value::Value::ChildDesc(crate::debug::rmi::proto::ObjDesc {
            id: 3,
            path: Some(ObjPath { path: "Threads[2]".into() }),
        })) {
            RmiValue::Object(o) => assert_eq!(o.get_path(), Some("Threads[2]")),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(c.arg_to_type(&Value { value: Some(value::Value::CharValue(1)) }), "CHAR");
        assert_eq!(c.arg_to_type(&Value { value: None }), "OBJECT");
    }

    #[test]
    fn replies_complete_pending_requests_in_order() {
        let h = Harness::new();
        let trace = h.client.create_trace("/t", &x86(), None).unwrap();
        let _ = h.recv();
        let obj = trace.create_object(&h.client, "Processes[1]").unwrap();
        let _ = h.recv();
        h.reply(root_message::Msg::ReplyCreateTrace(Default::default()));
        h.reply(root_message::Msg::ReplyCreateObject(crate::debug::rmi::proto::ReplyCreateObject {
            object: id_spec(42),
        }));
        trace.check_result(WAIT).unwrap();
        let pending = obj.pending_result().unwrap();
        match pending.get_timeout(WAIT).unwrap() {
            RmiReply::Long(id) => assert_eq!(id, 42),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(obj.get_id(), Some(42), "the object learns its id from the reply");
    }

    #[test]
    fn error_reply_fails_the_request() {
        let h = Harness::new();
        let trace = h.client.create_trace("/t", &x86(), None).unwrap();
        let _ = h.recv();
        h.reply(root_message::Msg::Error(crate::debug::rmi::proto::ReplyError {
            message: "no such language".into(),
        }));
        match trace.check_result(WAIT) {
            Err(RmiClientError::Remote(e)) => assert_eq!(e.message(), "no such language"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn get_timeout_times_out_without_reply() {
        let result = RequestResult::new(RootMessage::default());
        assert!(matches!(
            result.get_timeout(Duration::from_millis(10)),
            Err(RmiClientError::TimedOut)
        ));
        assert!(result.complete(RmiReply::Long(1)));
        assert!(!result.complete(RmiReply::Null), "only the first completion counts");
        assert!(matches!(result.get(), Ok(RmiReply::Long(1))));
    }

    #[test]
    fn resolution_and_value_kind_constants_match_java() {
        assert_eq!(TraceRmiResolution::value_of("RES_TRUNCATE"), Some(TraceRmiResolution::ResTruncate));
        assert_eq!(TraceRmiResolution::ResTruncate.val(), "truncate");
        assert_eq!(TraceRmiResolution::ResTruncate.description(), Resolution::CrTruncate);
        assert_eq!(TraceRmiResolution::value_of("truncate"), None);
        assert_eq!(TraceRmiValueKinds::Both.description(), ValueKinds::VkBoth);
        assert_eq!(TraceRmiValueKinds::value_of("ELEMENTS"), Some(TraceRmiValueKinds::Elements));
        assert_eq!(TraceRmiValueKinds::Attributes.val(), "attributes");
    }

    #[test]
    fn get_description_appends_remote_address() {
        let h = Harness::new();
        let desc = h.client.get_description();
        assert!(desc.starts_with("test client at 127.0.0.1:"), "{desc}");
    }
}
