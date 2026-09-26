//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiTransaction`.

use std::fmt;
use std::sync::Mutex;

use crate::app::plugin::core::debug::client::tracermi::{RmiClient, RmiClientError};
use crate::util::msg::Msg;

/// An open transaction on a trace, ended exactly once by [`commit`](Self::commit),
/// [`abort`](Self::abort) or [`close`](Self::close).
///
/// Java's `RmiTransaction implements AutoCloseable` is used with try-with-resources, where
/// `close()` commits; dropping an `RmiTransaction` likewise commits it if it is still open (a
/// failure to send is logged, since `Drop` cannot return it). Java reaches the client through
/// its `RmiTrace`; this holds the client handle and the trace id directly.
pub struct RmiTransaction {
    client: RmiClient,
    trace_id: i32,
    id: i32,
    closed: Mutex<bool>,
}

impl fmt::Debug for RmiTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiTransaction")
            .field("trace_id", &self.trace_id)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl RmiTransaction {
    /// Mirrors `RmiTransaction(RmiTrace, int)`.
    pub fn new(client: RmiClient, trace_id: i32, id: i32) -> Self {
        Self { client, trace_id, id, closed: Mutex::new(false) }
    }

    /// The transaction id.
    pub fn get_id(&self) -> i32 {
        self.id
    }

    /// Marks the transaction closed, returning whether it was open. Java's `closed` check under
    /// the write lock.
    fn close_once(&self) -> bool {
        let mut closed = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        !std::mem::replace(&mut *closed, true)
    }

    /// Mirrors `commit()`: ends the transaction, keeping its changes. No-op if already ended.
    pub fn commit(&self) -> Result<(), RmiClientError> {
        if !self.close_once() {
            return Ok(());
        }
        self.client.end_tx(self.trace_id, self.id, false)
    }

    /// Mirrors `abort()`: ends the transaction, discarding its changes. No-op if already ended.
    pub fn abort(&self) -> Result<(), RmiClientError> {
        if !self.close_once() {
            return Ok(());
        }
        self.client.end_tx(self.trace_id, self.id, true)
    }

    /// Mirrors `close()`, which commits.
    pub fn close(&self) -> Result<(), RmiClientError> {
        self.commit()
    }
}

impl Drop for RmiTransaction {
    fn drop(&mut self) {
        if let Err(e) = self.commit() {
            Msg::error("RmiTransaction", &format!("Failed to commit transaction {}: {e}", self.id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_client::tests::Harness;
    use crate::debug::rmi::proto::{root_message, DomObjId, RequestEndTx, TxId};

    #[test]
    fn commit_then_abort_sends_one_end() {
        let h = Harness::new();
        let tx = RmiTransaction::new(h.client.clone(), 4, 9);
        tx.commit().unwrap();
        tx.abort().unwrap();
        tx.close().unwrap();
        drop(tx);
        assert_eq!(
            h.recv(),
            root_message::Msg::RequestEndTx(RequestEndTx {
                oid: Some(DomObjId { id: 4 }),
                txid: Some(TxId { id: 9 }),
                abort: false,
            })
        );
        // Nothing else was sent: the next request we issue is the next thing received.
        h.client.save_trace(4).unwrap();
        assert!(matches!(h.recv(), root_message::Msg::RequestSaveTrace(_)));
    }

    #[test]
    fn abort_sends_abort_and_drop_after_is_silent() {
        let h = Harness::new();
        {
            let tx = RmiTransaction::new(h.client.clone(), 0, 1);
            tx.abort().unwrap();
        }
        match h.recv() {
            root_message::Msg::RequestEndTx(r) => assert!(r.abort),
            other => panic!("unexpected {other:?}"),
        }
        h.client.save_trace(0).unwrap();
        assert!(matches!(h.recv(), root_message::Msg::RequestSaveTrace(_)));
    }
}
