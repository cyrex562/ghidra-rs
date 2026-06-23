/// Listener for when the list of defined BSim database definitions change.
pub trait BSimServerManagerListener {
    fn server_list_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        call_count: usize,
    }

    impl BSimServerManagerListener for TestListener {
        fn server_list_changed(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn test_server_list_changed_called() {
        let mut listener = TestListener { call_count: 0 };
        listener.server_list_changed();
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn test_server_list_changed_called_multiple_times() {
        let mut listener = TestListener { call_count: 0 };
        listener.server_list_changed();
        listener.server_list_changed();
        listener.server_list_changed();
        assert_eq!(listener.call_count, 3);
    }
}
