/// Callback invoked when a timer fires.
pub trait TimerCallback {
    fn timer_fired(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter {
        count: usize,
    }

    impl TimerCallback for Counter {
        fn timer_fired(&mut self) {
            self.count += 1;
        }
    }

    #[test]
    fn test_timer_fired_called_once() {
        let mut c = Counter { count: 0 };
        c.timer_fired();
        assert_eq!(c.count, 1);
    }

    #[test]
    fn test_timer_fired_called_multiple_times() {
        let mut c = Counter { count: 0 };
        for _ in 0..5 {
            c.timer_fired();
        }
        assert_eq!(c.count, 5);
    }

    #[test]
    fn test_timer_fired_via_trait_object() {
        let mut c = Counter { count: 0 };
        let cb: &mut dyn TimerCallback = &mut c;
        cb.timer_fired();
        assert_eq!(c.count, 1);
    }
}
