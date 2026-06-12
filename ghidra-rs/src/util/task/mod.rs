use crate::util::exception::CancelledException;

pub trait CancelledListener: Send + Sync {
    fn cancelled(&self);
}

pub trait TaskMonitor: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_show_progress_value(&self, show: bool);
    fn set_message(&self, message: &str);
    fn get_message(&self) -> String;
    fn set_progress(&self, value: i64);
    fn initialize(&self, max: i64);
    fn set_maximum(&self, max: i64);
    fn get_maximum(&self) -> i64;
    fn set_indeterminate(&self, indeterminate: bool);
    fn is_indeterminate(&self) -> bool;
    fn check_cancelled(&self) -> Result<(), CancelledException>;
    fn increment_progress(&self, amount: i64);
    fn get_progress(&self) -> i64;
    fn cancel(&self);
    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>);
    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener);
    fn set_cancel_enabled(&self, enabled: bool);
    fn is_cancel_enabled(&self) -> bool;
    fn clear_cancelled(&self);
}

pub struct DummyMonitor;

impl TaskMonitor for DummyMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn set_show_progress_value(&self, _show: bool) {}
    fn set_message(&self, _message: &str) {}
    fn get_message(&self) -> String {
        String::new()
    }
    fn set_progress(&self, _value: i64) {}
    fn initialize(&self, _max: i64) {}
    fn set_maximum(&self, _max: i64) {}
    fn get_maximum(&self) -> i64 {
        0
    }
    fn set_indeterminate(&self, _indeterminate: bool) {}
    fn is_indeterminate(&self) -> bool {
        false
    }
    fn check_cancelled(&self) -> Result<(), CancelledException> {
        Ok(())
    }
    fn increment_progress(&self, _amount: i64) {}
    fn get_progress(&self) -> i64 {
        -1
    }
    fn cancel(&self) {}
    fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
    fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
    fn set_cancel_enabled(&self, _enabled: bool) {}
    fn is_cancel_enabled(&self) -> bool {
        true
    }
    fn clear_cancelled(&self) {}
}
