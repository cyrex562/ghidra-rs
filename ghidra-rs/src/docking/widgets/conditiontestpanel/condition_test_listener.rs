/// Callback invoked when a set of condition tests has finished running.
///
/// Corresponds to `docking.widgets.conditiontestpanel.ConditionTestListener`.
pub trait ConditionTestListener {
    fn tests_completed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        called: u32,
    }

    impl ConditionTestListener for Recorder {
        fn tests_completed(&mut self) {
            self.called += 1;
        }
    }

    #[test]
    fn callback_is_invoked() {
        let mut r = Recorder { called: 0 };
        r.tests_completed();
        assert_eq!(r.called, 1);
    }

    #[test]
    fn callback_can_be_invoked_multiple_times() {
        let mut r = Recorder { called: 0 };
        r.tests_completed();
        r.tests_completed();
        assert_eq!(r.called, 2);
    }
}
