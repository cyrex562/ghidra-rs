use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static INSTANCES: RefCell<DbgMsgTracer> = RefCell::new(DbgMsgTracer::new());
}

pub struct DbgMsgTracer {
    stack: VecDeque<CallRecData>,
}

struct CallRecData {
    name: String,
    start: u128,
}

impl DbgMsgTracer {
    fn new() -> Self {
        DbgMsgTracer {
            stack: VecDeque::new(),
        }
    }

    pub fn rec(obj: &str, name: &str) -> CallRec {
        INSTANCES.with(|tracer_ref| {
            let mut tracer = tracer_ref.borrow_mut();
            let start = current_time_millis();
            tracer.stack.push_back(CallRecData {
                name: name.to_string(),
                start,
            });
            tracer.do_msg(obj, &format!("{}: (ENTER)", start));
            drop(tracer);
            CallRec {
                obj: obj.to_string(),
                name: name.to_string(),
                start,
            }
        })
    }

    pub fn msg(obj: &str, message: &str) {
        INSTANCES.with(|tracer_ref| {
            let tracer = tracer_ref.borrow();
            tracer.do_msg(obj, message);
        });
    }

    fn do_msg(&self, obj: &str, message: &str) {
        let thread_name = std::thread::current()
            .name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:?}", std::thread::current().id()));
        let prefix = self.prefix_stack();
        let formatted = if prefix.is_empty() {
            format!("{} {}", thread_name, message)
        } else {
            format!("{} {} {}", thread_name, prefix, message)
        };
        super::msg::Msg::info(obj, &formatted);
    }

    fn prefix_stack(&self) -> String {
        self.stack
            .iter()
            .map(|rec| rec.name.as_str())
            .collect::<Vec<_>>()
            .join(" > ")
    }
}

pub struct CallRec {
    obj: String,
    name: String,
    start: u128,
}

impl Drop for CallRec {
    fn drop(&mut self) {
        INSTANCES.with(|tracer_ref| {
            let mut tracer = tracer_ref.borrow_mut();
            let stop = current_time_millis();
            let elapsed_ms = stop - self.start;
            let extra = if elapsed_ms > 100 { " (LONG)" } else { "" };
            let elapsed_secs = elapsed_ms as f64 / 1000.0;
            tracer.do_msg(
                &self.obj,
                &format!("{}: (EXITED) after {:.3} s{}", stop, elapsed_secs, extra),
            );
            let _ = tracer.stack.pop_back();
        });
    }
}

fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn test_call_rec_basic() {
        let _rec = DbgMsgTracer::rec("test", "test_func");
        let time_before = current_time_millis();
        thread::sleep(std::time::Duration::from_millis(10));
        drop(_rec);
        let time_after = current_time_millis();
        assert!(time_after - time_before >= 10);
    }

    #[test]
    fn test_call_rec_long_duration() {
        let _rec = DbgMsgTracer::rec("test", "long_func");
        thread::sleep(std::time::Duration::from_millis(150));
    }

    #[test]
    fn test_nested_call_stack() {
        let _rec1 = DbgMsgTracer::rec("test", "outer");
        let _rec2 = DbgMsgTracer::rec("test", "middle");
        let _rec3 = DbgMsgTracer::rec("test", "inner");
        DbgMsgTracer::msg("test", "doing work");
    }

    #[test]
    fn test_thread_local_isolation() {
        let result = Arc::new(Mutex::new(Vec::new()));
        let result_clone = Arc::clone(&result);

        let handle = thread::spawn(move || {
            let _rec = DbgMsgTracer::rec("thread_test", "thread_func");
            thread::sleep(std::time::Duration::from_millis(5));
            result_clone.lock().unwrap().push("thread_done");
        });

        let _rec = DbgMsgTracer::rec("main_test", "main_func");
        thread::sleep(std::time::Duration::from_millis(5));
        result.lock().unwrap().push("main_done");

        handle.join().unwrap();

        let results = result.lock().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"thread_done"));
        assert!(results.contains(&"main_done"));
    }

    #[test]
    fn test_call_rec_drop_on_scope_exit() {
        {
            let _rec = DbgMsgTracer::rec("test", "scoped_func");
            DbgMsgTracer::msg("test", "inside scope");
        }
        DbgMsgTracer::msg("test", "after scope");
    }

    #[test]
    fn test_static_msg() {
        DbgMsgTracer::msg("test", "static message");
    }

    #[test]
    fn test_multiple_sequential_calls() {
        for i in 0..3 {
            let _rec = DbgMsgTracer::rec("test", &format!("call_{}", i));
            DbgMsgTracer::msg("test", &format!("message_{}", i));
        }
    }
}
