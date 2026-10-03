//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiReplyHandlerThread`: the thread that
//! reads every message the front end sends an [`RmiClient`], serving method invocations and
//! completing pending requests with their replies.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::app::plugin::core::debug::client::tracermi::{
    ProtobufSocket, RequestResult, RmiClient, RmiClientError, RmiException, RmiReply,
};
use crate::debug::rmi::proto::{root_message, RootMessage, XReplyInvokeMethod, XRequestInvokeMethod};
use crate::util::msg::Msg;

const ORIGINATOR: &str = "RmiReplyHandlerThread";

/// The reply-reading thread of an [`RmiClient`].
///
/// Java's class *is* the `Thread`; here it is the handle to one. As in Java, it runs until
/// [`close`](Self::close) is called, logging (and otherwise ignoring) any error receiving or
/// processing a message, so the client must also close the socket to unblock a pending receive.
pub struct RmiReplyHandlerThread {
    client: Option<RmiClient>,
    socket: Option<Arc<ProtobufSocket<RootMessage>>>,
    terminated: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl fmt::Debug for RmiReplyHandlerThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiReplyHandlerThread")
            .field("started", &self.join.is_some())
            .field("terminated", &self.terminated.load(Ordering::SeqCst))
            .finish()
    }
}

impl RmiReplyHandlerThread {
    /// Mirrors `RmiReplyHandlerThread(RmiClient, ProtobufSocket<RootMessage>)`.
    pub fn new(client: RmiClient, socket: Arc<ProtobufSocket<RootMessage>>) -> Self {
        Self {
            client: Some(client),
            socket: Some(socket),
            terminated: Arc::new(AtomicBool::new(false)),
            join: None,
        }
    }

    /// Mirrors `Thread.start()`: spawns the thread running [`run`](Self::run)'s loop. Starting
    /// twice has no further effect.
    pub fn start(&mut self) {
        let (Some(client), Some(socket)) = (self.client.take(), self.socket.take()) else {
            return;
        };
        let terminated = self.terminated.clone();
        let handle = thread::Builder::new()
            .name("RmiReplyHandlerThread".to_string())
            .spawn(move || Self::run(&client, &socket, &terminated))
            .expect("failed to spawn RmiReplyHandlerThread");
        self.join = Some(handle);
    }

    /// Mirrors `run()`: receives and handles messages until terminated.
    pub fn run(client: &RmiClient, socket: &ProtobufSocket<RootMessage>, terminated: &AtomicBool) {
        while !terminated.load(Ordering::SeqCst) {
            let outcome = socket
                .recv()
                .map_err(RmiClientError::Io)
                .and_then(|msg| Self::handle(client, socket, msg));
            if let Err(e) = outcome {
                if !terminated.load(Ordering::SeqCst) {
                    Msg::error(ORIGINATOR, &format!("Error processing reply: {e}"));
                }
            }
        }
        Msg::info(ORIGINATOR, &"Handler exiting");
    }

    /// Mirrors `close()`: asks the thread to stop after the message it is handling.
    pub fn close(&self) {
        self.terminated.store(true, Ordering::SeqCst);
    }

    /// Mirrors `Thread.join()`: waits for the thread to exit, unless called from that thread.
    pub fn join(&mut self) {
        if let Some(handle) = self.join.take() {
            if handle.thread().id() == thread::current().id() {
                return;
            }
            let _ = handle.join();
        }
    }

    fn handle(
        client: &RmiClient,
        socket: &ProtobufSocket<RootMessage>,
        msg: RootMessage,
    ) -> Result<(), RmiClientError> {
        if let Some(root_message::Msg::XrequestInvokeMethod(req)) = &msg.msg {
            let reply = Self::invoke(client, req).unwrap_or_else(|e| {
                Msg::error(ORIGINATOR, &format!("Error handling method invocation: {e}"));
                XReplyInvokeMethod { error: e.to_string(), return_value: None }
            });
            socket.send(&RootMessage {
                msg: Some(root_message::Msg::XreplyInvokeMethod(reply)),
            })?;
            return Ok(());
        }

        let Some(result) = client.poll_request() else {
            eprintln!("REPLY without request: {msg:?}");
            return Ok(());
        };
        match Self::reply_value(client, &result, msg) {
            Ok(Some(reply)) => {
                result.complete(reply);
            }
            Ok(None) => {}
            Err(e) => {
                // Java logs and leaves the request pending forever; failing it instead keeps
                // waiters (and batches) from hanging.
                result.complete_exceptionally(RmiException::new(e.to_string()));
                return Err(e);
            }
        }
        Ok(())
    }

    fn invoke(
        client: &RmiClient,
        req: &XRequestInvokeMethod,
    ) -> Result<XReplyInvokeMethod, RmiClientError> {
        let id = req.oid.map(|o| o.id as i32).unwrap_or(0);
        let trace = client
            .get_trace(id)
            .ok_or_else(|| RmiClientError::Invalid(format!("No trace with id {id}")))?;
        trace.handle_invoke_method(client, req)
    }

    /// Computes the value `result` completes with for `msg`; `None` if `msg` failed `result`.
    ///
    /// As in Java, the trace is identified from the *request*, reading the same request kind as
    /// the reply (`getRequestCreateObject()` for `ReplyCreateObject`, and so on); a request of a
    /// different kind reads protobuf's default, trace 0.
    fn reply_value(
        client: &RmiClient,
        result: &RequestResult,
        msg: RootMessage,
    ) -> Result<Option<RmiReply>, RmiClientError> {
        use root_message::Msg;
        let request = result.request();
        let trace = |id: Option<u32>| {
            let id = id.unwrap_or(0) as i32;
            client
                .get_trace(id)
                .ok_or_else(|| RmiClientError::Invalid(format!("No trace with id {id}")))
        };
        let request_oid = |pick: fn(&Msg) -> Option<u32>| request.msg.as_ref().and_then(pick);
        Ok(Some(match msg.msg {
            Some(Msg::Error(err)) => {
                crate::util::msg::Msg::error(ORIGINATOR, &err.message);
                result.complete_exceptionally(RmiException::new(err.message));
                return Ok(None);
            }
            Some(Msg::ReplyCreateObject(reply)) => {
                let t = trace(request_oid(|m| match m {
                    Msg::RequestCreateObject(r) => r.oid.map(|o| o.id),
                    _ => None,
                }))?;
                RmiReply::Long(t.handle_create_object(&reply))
            }
            Some(Msg::ReplyCreateTrace(reply)) => {
                let t = trace(request_oid(|m| match m {
                    Msg::RequestCreateTrace(r) => r.oid.map(|o| o.id),
                    _ => None,
                }))?;
                t.handle_create_trace(&reply)
            }
            Some(Msg::ReplyGetValues(reply)) => {
                let t = trace(request_oid(|m| match m {
                    Msg::RequestGetValues(r) => r.oid.map(|o| o.id),
                    _ => None,
                }))?;
                RmiReply::Values(t.handle_get_values(client, &reply)?)
            }
            Some(Msg::ReplyDisassemble(reply)) => {
                let t = trace(request_oid(|m| match m {
                    Msg::RequestDisassemble(r) => r.oid.map(|o| o.id),
                    _ => None,
                }))?;
                RmiReply::Long(t.handle_disassemble(&reply))
            }
            _ => RmiReply::Null,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_client::tests::Harness;
    use crate::app::plugin::core::debug::client::tracermi::rmi_remote_method_parameter::tests::named;
    use crate::app::plugin::core::debug::client::tracermi::{
        RmiMethodRegistry, RmiRemoteMethod, RmiRemoteMethodParameter, RmiValue, TraceRmiMethod,
    };
    use crate::debug::rmi::proto::{
        value, DomObjId, MethodArgument, ReplyDisassemble, RequestNegotiate, Value, ValueType,
    };
    use crate::program::model::lang::LanguageID;
    use std::sync::Mutex;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(10);

    fn registry_with_echo(seen: Arc<Mutex<Vec<Vec<String>>>>) -> Arc<RmiMethodRegistry> {
        let reg = Arc::new(RmiMethodRegistry::new());
        let params = vec![
            RmiRemoteMethodParameter::new("a", named("STRING"), true, RmiValue::Null, "A", ""),
            RmiRemoteMethodParameter::new("b", named("INT"), false, RmiValue::Int(3), "B", ""),
        ];
        reg.put_method(
            "echo",
            RmiRemoteMethod::annotated(
                "echo",
                &TraceRmiMethod { action: "refresh".into(), ..Default::default() },
                named("Session"),
                params,
                Box::new(move |args| {
                    seen.lock().unwrap().push(args.iter().map(|a| format!("{a:?}")).collect());
                    match args.first() {
                        Some(RmiValue::String(s)) if s == "fail" => Err("it failed".to_string()),
                        Some(RmiValue::String(s)) => Ok(Some(RmiValue::String(s.to_uppercase()))),
                        _ => Ok(None),
                    }
                }),
            ),
        );
        reg
    }

    fn invoke_req(trace: u32, args: Vec<(&str, value::Value)>) -> root_message::Msg {
        root_message::Msg::XrequestInvokeMethod(XRequestInvokeMethod {
            oid: Some(DomObjId { id: trace }),
            name: "echo".into(),
            arguments: args
                .into_iter()
                .map(|(n, v)| MethodArgument { name: n.into(), value: Some(Value { value: Some(v) }) })
                .collect(),
        })
    }

    #[test]
    fn negotiate_advertises_registered_methods() {
        let h = Harness::new();
        h.client.set_registry(registry_with_echo(Arc::default()));
        h.client.negotiate("gdb").unwrap();
        match h.recv() {
            root_message::Msg::RequestNegotiate(RequestNegotiate { version, methods, description }) => {
                assert_eq!(version, "12.2");
                assert_eq!(description, "gdb");
                assert_eq!(methods.len(), 1);
                assert_eq!(methods[0].name, "echo");
                assert_eq!(methods[0].action, "refresh");
                let p = &methods[0].parameters;
                assert_eq!(p[0].name, "a");
                assert_eq!(p[0].r#type, Some(ValueType { name: "STRING".into() }));
                assert!(p[0].required);
                assert_eq!(
                    p[0].default_value.as_ref().unwrap().value,
                    Some(value::Value::NullValue(Default::default()))
                );
                assert_eq!(
                    p[1].default_value.as_ref().unwrap().value,
                    Some(value::Value::IntValue(3))
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn invoke_method_runs_in_a_transaction_and_replies() {
        let h = Harness::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        h.client.set_registry(registry_with_echo(seen.clone()));
        let lang = LanguageID::new("x86:LE:64:default").unwrap();
        let _trace = h.client.create_trace("/t", &lang, None).unwrap();
        let _ = h.recv();

        // Arguments arrive out of parameter order; they are placed in parameter order.
        h.reply(invoke_req(
            0,
            vec![
                ("b", value::Value::ShortValue(7)),
                ("a", value::Value::StringValue("hi".into())),
            ],
        ));
        match h.recv() {
            root_message::Msg::RequestStartTx(r) => {
                assert_eq!(r.description, "InvokeMethod");
                assert!(!r.undoable);
            }
            other => panic!("unexpected {other:?}"),
        }
        match h.recv() {
            root_message::Msg::RequestEndTx(r) => assert!(!r.abort),
            other => panic!("unexpected {other:?}"),
        }
        match h.recv() {
            root_message::Msg::XreplyInvokeMethod(r) => {
                assert_eq!(r.error, "");
                assert_eq!(
                    r.return_value.unwrap().value,
                    Some(value::Value::StringValue("HI".into()))
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(seen.lock().unwrap()[0], vec!["String(\"hi\")", "Int(7)"]);
    }

    #[test]
    fn invoke_method_errors_become_error_replies() {
        let h = Harness::new();
        h.client.set_registry(registry_with_echo(Arc::default()));
        let lang = LanguageID::new("x86:LE:64:default").unwrap();
        let _trace = h.client.create_trace("/t", &lang, None).unwrap();
        let _ = h.recv();

        h.reply(invoke_req(0, vec![("a", value::Value::StringValue("fail".into()))]));
        let _start = h.recv();
        let _end = h.recv();
        match h.recv() {
            root_message::Msg::XreplyInvokeMethod(r) => {
                assert_eq!(r.error, "it failed");
                assert!(r.return_value.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }

        // Unknown trace: no transaction, just an error reply.
        h.reply(invoke_req(9, vec![]));
        match h.recv() {
            root_message::Msg::XreplyInvokeMethod(r) => assert!(r.error.contains("9"), "{}", r.error),
            other => panic!("unexpected {other:?}"),
        }

        // A method returning nothing replies `true`.
        h.reply(invoke_req(0, vec![]));
        let _start = h.recv();
        let _end = h.recv();
        match h.recv() {
            root_message::Msg::XreplyInvokeMethod(r) => {
                assert_eq!(r.return_value.unwrap().value, Some(value::Value::BoolValue(true)))
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn disassemble_reply_routes_to_its_trace_and_request() {
        let h = Harness::new();
        let lang = LanguageID::new("x86:LE:64:default").unwrap();
        let trace = h.client.create_trace("/t", &lang, None).unwrap();
        let _ = h.recv();
        h.reply(root_message::Msg::ReplyCreateTrace(Default::default()));
        trace.check_result(WAIT).unwrap();

        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        );
        let batch = h.client.start_batch();
        trace.disassemble(&h.client, &space.address(0x1000), Some(0)).unwrap();
        h.client.save_trace(0).unwrap();
        let _ = h.recv();
        let _ = h.recv();
        h.reply(root_message::Msg::ReplyDisassemble(ReplyDisassemble { length: 16 }));
        h.reply(root_message::Msg::ReplySaveTrace(Default::default()));
        let futures = batch.futures();
        batch.close().unwrap();
        assert!(matches!(futures[0].get(), Ok(RmiReply::Long(16))));
        assert!(matches!(futures[1].get(), Ok(RmiReply::Null)));
    }

    #[test]
    fn close_stops_the_thread() {
        let h = Harness::new();
        h.client.close();
        // A second close is harmless.
        h.client.close();
    }
}
