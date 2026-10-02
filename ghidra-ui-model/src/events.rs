//! The single Rust→renderer channel (Qt6 UI spec §3): an MPSC queue of
//! [`UiEvent`]s, coalesced per frame, plus a file-descriptor waker the Qt
//! shell watches with a `QSocketNotifier`.

use std::collections::{BTreeMap, HashMap};
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
    /// Ask the user for a line of text; answer with
    /// [`UiEventQueue::answer_prompt`] (`None` = cancelled).
    Prompt {
        /// Prompt id to answer.
        id: u64,
        /// Dialog title.
        title: String,
        /// Field label.
        label: String,
        /// Initial text.
        initial: String,
    },
    /// Show open dialog `id` (its spec via [`UiEventQueue::dialog_spec`]).
    Dialog(u64),
    /// A provider's view state changed outside a renderer call (repaint it).
    ViewChanged(u64),
    /// A hidden provider was shown (Window menu): dock and raise it, and
    /// focus it when `focus` (the first provider an action shows).
    ProviderShown {
        /// Provider id.
        id: u64,
        /// Give it keyboard focus.
        focus: bool,
    },
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
    /// A wake byte has been written since the last take. Lives under the
    /// same lock as `events` so post and drain can't interleave between
    /// "push"/"check" and "take"/"reset" (no lost wakeup).
    signalled: bool,
}

/// Runs when a prompt is answered; an `Err` becomes a status message.
pub type PromptHandler = Box<dyn FnOnce(Option<String>) -> Result<(), String> + Send>;

#[derive(Default)]
struct Prompts {
    next_id: u64,
    handlers: HashMap<u64, PromptHandler>,
}

/// Thread-safe event queue (cheap to clone; all clones share one queue).
#[derive(Clone)]
pub struct UiEventQueue {
    pending: Arc<Mutex<Pending>>,
    prompts: Arc<Mutex<Prompts>>,
    dialogs: Arc<Mutex<crate::dialogs::Dialogs>>,
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

    /// Consumes pending wake bytes. Call it **before** draining: clearing
    /// after a drain could swallow the byte of an event posted in between.
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
        // Never block a worker thread on a full socket buffer; one pending
        // byte is all the shell needs.
        #[cfg(unix)]
        let _ = writer.set_nonblocking(true);
        let q = UiEventQueue {
            pending: Arc::new(Mutex::new(Pending::default())),
            prompts: Arc::new(Mutex::new(Prompts::default())),
            dialogs: Arc::new(Mutex::new(crate::dialogs::Dialogs::default())),
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
        let need_wake = match self.pending.lock() {
            Ok(mut p) => {
                p.events.push(event);
                !std::mem::replace(&mut p.signalled, true)
            }
            Err(_) => false,
        };
        if need_wake {
            self.waker.wake();
        }
    }

    /// Posts a [`UiEvent::Prompt`]; `handler` runs once with the answer.
    pub fn prompt(&self, title: &str, label: &str, initial: &str, handler: PromptHandler) -> u64 {
        let id = match self.prompts.lock() {
            Ok(mut p) => {
                p.next_id += 1;
                let id = p.next_id;
                p.handlers.insert(id, handler);
                id
            }
            Err(_) => return 0,
        };
        self.post(UiEvent::Prompt { id, title: title.to_owned(), label: label.to_owned(), initial: initial.to_owned() });
        id
    }

    /// Answers prompt `id`, running its handler; a handler error is posted as
    /// a status message. Unknown or already-answered ids are errors.
    pub fn answer_prompt(&self, id: u64, answer: Option<String>) -> Result<(), String> {
        // Take the handler out before running it: it may post or prompt again.
        let handler = self
            .prompts
            .lock()
            .map_err(|_| "prompt registry poisoned".to_string())?
            .handlers
            .remove(&id)
            .ok_or_else(|| format!("no pending prompt {id}"))?;
        if let Err(message) = handler(answer) {
            self.post(UiEvent::Status(message));
        }
        Ok(())
    }

    /// Opens a Rust-described dialog and asks the renderer to show it.
    pub fn open_dialog(&self, model: Box<dyn crate::dialogs::DialogModel>) -> u64 {
        let id = self.dialogs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).open(model);
        self.post(UiEvent::Dialog(id));
        id
    }

    /// The spec of open dialog `id`.
    pub fn dialog_spec(&self, id: u64) -> Result<crate::dialogs::DialogSpec, String> {
        self.dialogs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).spec(id)
    }

    /// OK on dialog `id`. The model runs outside the registry lock (it may
    /// post events or open another dialog).
    pub fn dialog_ok(&self, id: u64, text: &str, checks: &[(String, bool)]) -> Result<crate::dialogs::DialogReply, String> {
        let mut model = self
            .dialogs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(id)
            .ok_or_else(|| format!("no open dialog {id}"))?;
        let reply = model.ok(text, checks);
        if reply != crate::dialogs::DialogReply::Close {
            self.dialogs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).put_back(id, model);
        }
        Ok(reply)
    }

    /// Cancel on dialog `id`.
    pub fn dialog_cancel(&self, id: u64) -> Result<(), String> {
        let model = self.dialogs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take(id);
        let mut model = model.ok_or_else(|| format!("no open dialog {id}"))?;
        model.cancel();
        Ok(())
    }

    /// Whether no events are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.lock().map(|p| p.events.is_empty()).unwrap_or(true)
    }

    /// Takes all pending events, coalesced: `DomainChanged` merged per object
    /// (ranges sorted and merged), the latest `TaskProgress` per task,
    /// `ActionsChanged` once. Other events keep their order.
    pub fn drain(&self) -> Vec<UiEvent> {
        let events = self.take_raw();
        self.after_take();
        coalesce(events)
    }

    /// First half of [`Self::drain`]: take the raw events.
    fn take_raw(&self) -> Vec<UiEvent> {
        match self.pending.lock() {
            Ok(mut p) => {
                p.signalled = false;
                std::mem::take(&mut p.events)
            }
            Err(_) => Vec::new(),
        }
    }

    /// Second half of [`Self::drain`]; nothing left to do now that the
    /// signal is reset under the lock (kept as the test seam for the race).
    fn after_take(&self) {}
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
    fn prompt_ids(q: &UiEventQueue) -> Vec<u64> {
        q.drain()
            .into_iter()
            .filter_map(|e| match e {
                UiEvent::Prompt { id, .. } => Some(id),
                _ => None,
            })
            .collect()
    }

    /// OK opens a second dialog from inside the model (re-entrancy).
    struct Nested(UiEventQueue);
    impl crate::dialogs::DialogModel for Nested {
        fn spec(&self) -> crate::dialogs::DialogSpec {
            crate::dialogs::DialogSpec { title: "n".into(), message: String::new(), combo: None, checks: vec![], status: String::new() }
        }
        fn ok(&mut self, _text: &str, _checks: &[(String, bool)]) -> crate::dialogs::DialogReply {
            self.0.open_dialog(Box::new(Nested(self.0.clone())));
            crate::dialogs::DialogReply::Close
        }
    }

    #[test]
    fn dialogs_open_with_an_event_and_close_on_ok() {
        let (q, _w) = UiEventQueue::new();
        let id = q.open_dialog(Box::new(Nested(q.clone())));
        assert_eq!(q.drain(), vec![UiEvent::Dialog(id)]);
        assert_eq!(q.dialog_spec(id).unwrap().title, "n");
        assert_eq!(q.dialog_ok(id, "", &[]).unwrap(), crate::dialogs::DialogReply::Close);
        let second = match q.drain().as_slice() {
            [UiEvent::Dialog(n)] => *n,
            other => panic!("{other:?}"),
        };
        assert!(q.dialog_spec(id).is_err());
        q.dialog_cancel(second).unwrap();
        assert!(q.dialog_ok(second, "", &[]).is_err());
    }

    #[test]
    fn a_prompt_round_trips_its_answer_once() {
        let (q, _w) = UiEventQueue::new();
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        let id = q.prompt("Go To", "Address:", "", Box::new(move |a| {
            g.lock().unwrap().push(a);
            Ok(())
        }));
        assert_eq!(prompt_ids(&q), vec![id]);
        q.answer_prompt(id, Some("401000".into())).unwrap();
        assert_eq!(*got.lock().unwrap(), vec![Some("401000".to_string())]);
        assert!(q.answer_prompt(id, None).unwrap_err().contains(&id.to_string()));
        assert!(q.answer_prompt(999, None).is_err());
        assert_eq!(got.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_failing_prompt_handler_becomes_a_status() {
        let (q, _w) = UiEventQueue::new();
        let a = q.prompt("t", "l", "", Box::new(|_| Err("Invalid address: zz".into())));
        let b = q.prompt("t", "l", "", Box::new(|_| Ok(())));
        assert_ne!(a, b);
        q.drain();
        q.answer_prompt(a, Some("zz".into())).unwrap();
        assert_eq!(q.drain(), vec![UiEvent::Status("Invalid address: zz".into())]);
    }

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

    /// Lost-wakeup regression: whenever events are pending after producers
    /// and a concurrent drainer stop, a wake byte must be readable (otherwise
    /// the shell would never drain them, e.g. a final TaskDone).
    #[cfg(unix)]
    #[test]
    fn no_lost_wakeup_under_concurrent_post_and_drain() {
        use std::io::Read;
        for _round in 0..200 {
            let (q, w) = UiEventQueue::new();
            let mut r = w.reader_clone();
            r.set_nonblocking(true).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let drainer = {
                let (q, stop) = (q.clone(), stop.clone());
                let mut r = w.reader_clone();
                r.set_nonblocking(true).unwrap();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    while !stop.load(std::sync::atomic::Ordering::Acquire) {
                        // shell protocol: consume wake bytes, then drain
                        while matches!(r.read(&mut buf), Ok(n) if n > 0) {}
                        q.drain();
                    }
                })
            };
            let producers: Vec<_> = (0..3)
                .map(|t| {
                    let q = q.clone();
                    std::thread::spawn(move || {
                        for i in 0..200u64 {
                            q.post(UiEvent::DomainChanged { object: t, ranges: vec![(i, i)] });
                        }
                    })
                })
                .collect();
            for p in producers {
                p.join().unwrap();
            }
            stop.store(true, std::sync::atomic::Ordering::Release);
            drainer.join().unwrap();
            if !q.is_empty() {
                let mut buf = [0u8; 64];
                assert!(matches!(r.read(&mut buf), Ok(n) if n > 0), "pending events but no wake byte");
            }
        }
    }

    /// Deterministic form of the lost wakeup: a post landing between the
    /// drain's take and its signal reset must still leave a wake byte.
    #[cfg(unix)]
    #[test]
    fn post_between_take_and_reset_still_wakes() {
        use std::io::Read;
        let (q, w) = UiEventQueue::new();
        let mut r = w.reader_clone();
        r.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        q.post(UiEvent::ActionsChanged);
        let _ = r.read(&mut buf); // shell consumed the first wake byte
        let _taken = q.take_raw();
        q.post(UiEvent::Status("late".into())); // races the drain
        q.after_take();
        assert!(!q.is_empty());
        assert!(matches!(r.read(&mut buf), Ok(n) if n > 0), "late event pending but no wake byte");
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
