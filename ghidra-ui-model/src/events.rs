//! The single Rust→renderer channel (Qt6 UI spec §3): an MPSC queue of
//! [`UiEvent`]s, coalesced per frame, plus a file-descriptor waker the Qt
//! shell watches with a `QSocketNotifier`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Something the renderer must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    /// A domain object changed over these inclusive index ranges.
    DomainChanged {
        /// Domain object id.
        object: u64,
        /// Changed inclusive ranges.
        ranges: Vec<(u64, u64)>,
    },
    /// Progress of a running task.
    TaskProgress {
        /// Task id.
        task: u64,
        /// Status message.
        message: String,
        /// Progress so far.
        progress: u64,
        /// Progress maximum (0 = indeterminate).
        maximum: u64,
    },
    /// A task finished.
    TaskDone {
        /// Task id.
        task: u64,
        /// Whether it was cancelled.
        cancelled: bool,
        /// Failure message, if it failed.
        error: Option<String>,
    },
    /// A provider was added.
    ProviderAdded(u64),
    /// A provider was removed.
    ProviderRemoved(u64),
    /// Actions or their enablement changed; rebuild menus/toolbars.
    ActionsChanged,
    /// A status-bar message (never coalesced).
    Status(String),
    /// The current location changed.
    LocationChanged {
        /// Domain object id.
        object: u64,
        /// New address.
        address: u64,
    },
}

#[derive(Default)]
struct Pending {
    events: Vec<UiEvent>,
}

/// Thread-safe event queue (cheap to clone; all clones share one queue).
#[derive(Clone)]
pub struct UiEventQueue {
    pending: Arc<Mutex<Pending>>,
    signalled: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

/// The read end the renderer watches; readable when events are pending.
pub struct WakeHandle {
    #[cfg(unix)]
    reader: std::os::unix::net::UnixStream,
}

struct Waker {
    #[cfg(unix)]
    writer: Mutex<std::os::unix::net::UnixStream>,
}

impl Waker {
    fn wake(&self) {
        #[cfg(unix)]
        {
            use std::io::Write;
            if let Ok(mut w) = self.writer.lock() {
                let _ = w.write_all(&[1]);
            }
        }
    }
}

impl WakeHandle {
    /// The raw fd to watch (Unix); readable once per drain cycle.
    #[cfg(unix)]
    pub fn raw_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.reader.as_raw_fd()
    }

    /// Consumes pending wake bytes (call before or after draining).
    pub fn clear(&self) {
        #[cfg(unix)]
        {
            use std::io::Read;
            let mut r = &self.reader;
            let _ = r.set_nonblocking(true);
            let mut buf = [0u8; 64];
            while matches!(r.read(&mut buf), Ok(n) if n > 0) {}
        }
    }

    /// A second handle on the read end (tests and diagnostics).
    #[cfg(all(unix, test))]
    pub(crate) fn reader_clone(&self) -> std::os::unix::net::UnixStream {
        self.reader.try_clone().expect("clone wake reader")
    }
}

impl UiEventQueue {
    /// A new queue and the renderer's wake handle.
    pub fn new() -> (UiEventQueue, WakeHandle) {
        #[cfg(unix)]
        let (reader, writer) = std::os::unix::net::UnixStream::pair().expect("socketpair for UI waker");
        let q = UiEventQueue {
            pending: Arc::new(Mutex::new(Pending::default())),
            signalled: Arc::new(AtomicBool::new(false)),
            waker: Arc::new(Waker {
                #[cfg(unix)]
                writer: Mutex::new(writer),
            }),
        };
        (
            q,
            WakeHandle {
                #[cfg(unix)]
                reader,
            },
        )
    }

    /// Posts an event from any thread; wakes the renderer once per drain cycle.
    pub fn post(&self, event: UiEvent) {
        if let Ok(mut p) = self.pending.lock() {
            p.events.push(event);
        }
        if !self.signalled.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// Takes all pending events, coalesced: `DomainChanged` merged per object
    /// (ranges sorted and merged), the latest `TaskProgress` per task,
    /// `ActionsChanged` once. Other events keep their order.
    pub fn drain(&self) -> Vec<UiEvent> {
        let events = match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut p.events),
            Err(_) => Vec::new(),
        };
        self.signalled.store(false, Ordering::Release);
        coalesce(events)
    }
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn coalesce(events: Vec<UiEvent>) -> Vec<UiEvent> {
    // Slot per coalescing key, in first-seen order.
    let mut out: Vec<Option<UiEvent>> = Vec::new();
    let mut domain: BTreeMap<u64, usize> = BTreeMap::new();
    let mut progress: HashMap<u64, usize> = HashMap::new();
    let mut actions_changed = false;
    for e in events {
        match e {
            UiEvent::DomainChanged { object, ranges } => match domain.get(&object) {
                Some(&i) => {
                    if let Some(UiEvent::DomainChanged { ranges: r, .. }) = &mut out[i] {
                        r.extend(ranges);
                    }
                }
                None => {
                    domain.insert(object, out.len());
                    out.push(Some(UiEvent::DomainChanged { object, ranges }));
                }
            },
            UiEvent::TaskProgress { task, .. } => match progress.get(&task) {
                Some(&i) => out[i] = Some(e),
                None => {
                    progress.insert(task, out.len());
                    out.push(Some(e));
                }
            },
            UiEvent::ActionsChanged => {
                if !actions_changed {
                    actions_changed = true;
                    out.push(Some(e));
                }
            }
            other => out.push(Some(other)),
        }
    }
    out.into_iter()
        .flatten()
        .map(|e| match e {
            UiEvent::DomainChanged { object, ranges } => UiEvent::DomainChanged { object, ranges: merge_ranges(ranges) },
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_changes_coalesce_per_object() {
        let (q, _w) = UiEventQueue::new();
        for i in 0..1000u64 {
            q.post(UiEvent::DomainChanged { object: 1, ranges: vec![(i, i)] });
        }
        q.post(UiEvent::DomainChanged { object: 2, ranges: vec![(5, 9)] });
        let ev = q.drain();
        let objs: Vec<u64> = ev
            .iter()
            .filter_map(|e| match e {
                UiEvent::DomainChanged { object, .. } => Some(*object),
                _ => None,
            })
            .collect();
        assert_eq!(objs, vec![1, 2]);
        match &ev[0] {
            UiEvent::DomainChanged { ranges, .. } => assert_eq!(ranges, &vec![(0, 999)]),
            other => panic!("unexpected {other:?}"),
        }
        assert!(q.drain().is_empty());
    }

    #[test]
    fn disjoint_ranges_stay_separate_and_sorted() {
        let (q, _w) = UiEventQueue::new();
        q.post(UiEvent::DomainChanged { object: 1, ranges: vec![(50, 60)] });
        q.post(UiEvent::DomainChanged { object: 1, ranges: vec![(1, 2), (55, 70)] });
        match &q.drain()[0] {
            UiEvent::DomainChanged { ranges, .. } => assert_eq!(ranges, &vec![(1, 2), (50, 70)]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn latest_progress_wins_and_actions_changed_once() {
        let (q, _w) = UiEventQueue::new();
        q.post(UiEvent::TaskProgress { task: 1, message: "a".into(), progress: 1, maximum: 10 });
        q.post(UiEvent::ActionsChanged);
        q.post(UiEvent::TaskProgress { task: 1, message: "b".into(), progress: 7, maximum: 10 });
        q.post(UiEvent::ActionsChanged);
        let ev = q.drain();
        assert_eq!(ev.iter().filter(|e| matches!(e, UiEvent::ActionsChanged)).count(), 1);
        assert!(ev.iter().any(|e| matches!(e, UiEvent::TaskProgress { progress: 7, .. })));
        assert!(!ev.iter().any(|e| matches!(e, UiEvent::TaskProgress { progress: 1, .. })));
    }

    #[test]
    fn task_done_is_never_dropped_and_follows_its_progress() {
        let (q, _w) = UiEventQueue::new();
        q.post(UiEvent::TaskProgress { task: 3, message: "x".into(), progress: 5, maximum: 5 });
        q.post(UiEvent::TaskDone { task: 3, cancelled: false, error: None });
        let ev = q.drain();
        let p = ev.iter().position(|e| matches!(e, UiEvent::TaskProgress { task: 3, .. })).unwrap();
        let d = ev.iter().position(|e| matches!(e, UiEvent::TaskDone { task: 3, .. })).unwrap();
        assert!(p < d);
    }

    #[test]
    fn status_messages_are_kept_in_order() {
        let (q, _w) = UiEventQueue::new();
        q.post(UiEvent::Status("a".into()));
        q.post(UiEvent::Status("a".into()));
        q.post(UiEvent::Status("b".into()));
        let st: Vec<UiEvent> = q.drain();
        assert_eq!(st, vec![UiEvent::Status("a".into()), UiEvent::Status("a".into()), UiEvent::Status("b".into())]);
    }

    #[cfg(unix)]
    #[test]
    fn waker_signals_once_per_drain_cycle() {
        use std::io::Read;
        let (q, w) = UiEventQueue::new();
        let mut r = w.reader_clone();
        r.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        assert!(r.read(&mut buf).is_err()); // nothing yet (WouldBlock)
        for _ in 0..50 {
            q.post(UiEvent::ActionsChanged);
        }
        assert_eq!(r.read(&mut buf).unwrap(), 1);
        assert!(r.read(&mut buf).is_err());
        q.drain();
        q.post(UiEvent::ActionsChanged);
        assert_eq!(r.read(&mut buf).unwrap(), 1);
    }

    #[test]
    fn post_from_other_threads() {
        let (q, _w) = UiEventQueue::new();
        let hs: Vec<_> = (0..4u64)
            .map(|t| {
                let q = q.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        q.post(UiEvent::DomainChanged { object: t, ranges: vec![(i, i)] });
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(q.drain().len(), 4);
    }
}
