//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiBatch`.

use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::plugin::core::debug::client::tracermi::{
    RequestResult, RmiClient, RmiClientError, RmiException, RmiReply,
};

struct BatchInner {
    ref_count: AtomicI32,
    futures: Mutex<Vec<RequestResult>>,
}

/// Collects the results of every request sent while it is open, so they can be awaited
/// together.
///
/// [`RmiClient::start_batch`] returns the client's current batch (starting one if needed), so
/// nested users share it; each must [`close`](Self::close) it, and the last close ends the batch
/// and waits for every reply. Clones are handles to the same batch, as Java hands out the same
/// object. Java's `AutoCloseable.close()` is the explicit [`close`](Self::close) here: closing
/// waits on the network and can fail, which `Drop` could not report.
#[derive(Clone)]
pub struct RmiBatch {
    client: RmiClient,
    inner: Arc<BatchInner>,
}

impl fmt::Debug for RmiBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiBatch")
            .field("ref_count", &self.inner.ref_count.load(Ordering::SeqCst))
            .field("futures", &self.futures().len())
            .finish()
    }
}

impl RmiBatch {
    /// Mirrors `RmiBatch(RmiClient)`.
    pub fn new(client: RmiClient) -> Self {
        Self {
            client,
            inner: Arc::new(BatchInner { ref_count: AtomicI32::new(0), futures: Mutex::new(Vec::new()) }),
        }
    }

    /// Mirrors `inc()`.
    pub fn inc(&self) {
        self.inner.ref_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Mirrors `dec()`: returns the new count.
    pub fn dec(&self) -> i32 {
        self.inner.ref_count.fetch_sub(1, Ordering::SeqCst) - 1
    }

    /// Mirrors `close()`: releases this hold via [`RmiClient::end_batch`], waiting for all
    /// replies if it was the last.
    pub fn close(&self) -> Result<(), RmiClientError> {
        self.client.end_batch(self).map_err(RmiClientError::Remote)
    }

    /// Mirrors `append(RequestResult)`.
    pub fn append(&self, f: RequestResult) {
        self.inner.futures.lock().unwrap_or_else(|e| e.into_inner()).push(f);
    }

    /// Mirrors `results()`: waits for every collected request, in order, failing on the first
    /// one that failed.
    pub fn results(&self) -> Result<Vec<RmiReply>, RmiException> {
        self.futures().iter().map(RequestResult::get).collect()
    }

    /// Mirrors `futures()`: a snapshot of the collected requests.
    pub fn futures(&self) -> Vec<RequestResult> {
        self.inner.futures.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_client::tests::Harness;
    use crate::debug::rmi::proto::root_message;

    #[test]
    fn nested_batches_share_one_and_collect_requests() {
        let h = Harness::new();
        assert!(!h.client.has_batch());
        let outer = h.client.start_batch();
        let inner = h.client.start_batch();
        assert!(h.client.has_batch());
        h.client.save_trace(0).unwrap();
        h.client.save_trace(1).unwrap();
        assert_eq!(outer.futures().len(), 2);
        assert_eq!(inner.futures().len(), 2, "both handles see the same batch");

        inner.close().unwrap();
        assert!(h.client.has_batch(), "outer hold keeps the batch open");

        let _ = h.recv();
        let _ = h.recv();
        h.reply(root_message::Msg::ReplySaveTrace(Default::default()));
        h.reply(root_message::Msg::ReplySaveTrace(Default::default()));
        outer.close().unwrap();
        assert!(!h.client.has_batch());
        let replies = outer.results().unwrap();
        assert_eq!(replies.len(), 2);
        assert!(replies.iter().all(|r| matches!(r, RmiReply::Null)));
    }

    #[test]
    fn closing_batch_reports_a_failed_request() {
        let h = Harness::new();
        let batch = h.client.start_batch();
        h.client.save_trace(0).unwrap();
        let _ = h.recv();
        h.reply(root_message::Msg::Error(crate::debug::rmi::proto::ReplyError {
            message: "boom".into(),
        }));
        match batch.close() {
            Err(RmiClientError::Remote(e)) => assert_eq!(e.message(), "boom"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!h.client.has_batch());
    }

    #[test]
    fn inc_dec_count() {
        let h = Harness::new();
        let b = RmiBatch::new(h.client.clone());
        b.inc();
        b.inc();
        assert_eq!(b.dec(), 1);
        assert_eq!(b.dec(), 0);
    }
}
