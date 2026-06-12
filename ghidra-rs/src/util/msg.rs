use super::error_display::{ConsoleErrorDisplay, ErrorDisplay};
use super::error_logger::{DefaultErrorLogger, ErrorLogger};
use std::fmt::Display;
use std::sync::{OnceLock, RwLock};

static ERROR_LOGGER: OnceLock<RwLock<Box<dyn ErrorLogger>>> = OnceLock::new();
static ERROR_DISPLAY: OnceLock<RwLock<Box<dyn ErrorDisplay>>> = OnceLock::new();

fn get_logger() -> &'static RwLock<Box<dyn ErrorLogger>> {
    ERROR_LOGGER.get_or_init(|| RwLock::new(Box::new(DefaultErrorLogger)))
}

fn get_display() -> &'static RwLock<Box<dyn ErrorDisplay>> {
    ERROR_DISPLAY.get_or_init(|| RwLock::new(Box::new(ConsoleErrorDisplay)))
}

pub struct Msg;

impl Msg {
    pub fn set_error_logger(logger: Box<dyn ErrorLogger>) {
        if let Ok(mut lock) = get_logger().write() {
            *lock = logger;
        }
    }

    pub fn set_error_display(display: Box<dyn ErrorDisplay>) {
        if let Ok(mut lock) = get_display().write() {
            *lock = display;
        }
    }

    pub fn out(message: &dyn Display) {
        eprintln!("{}", message);
    }

    pub fn trace(originator: &str, message: &dyn Display) {
        if let Ok(logger) = get_logger().read() {
            logger.trace(originator, message);
        }
    }

    pub fn trace_with_error(
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        if let Ok(logger) = get_logger().read() {
            logger.trace_with_error(originator, message, error);
        }
    }

    pub fn debug(originator: &str, message: &dyn Display) {
        if let Ok(logger) = get_logger().read() {
            logger.debug(originator, message);
        }
    }

    pub fn debug_with_error(
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        if let Ok(logger) = get_logger().read() {
            logger.debug_with_error(originator, message, error);
        }
    }

    pub fn info(originator: &str, message: &dyn Display) {
        if let Ok(logger) = get_logger().read() {
            logger.info(originator, message);
        }
    }

    pub fn info_with_error(originator: &str, message: &dyn Display, error: &dyn std::error::Error) {
        if let Ok(logger) = get_logger().read() {
            logger.info_with_error(originator, message, error);
        }
    }

    pub fn show_info(originator: &str, title: &str, message: &dyn Display) {
        if let Ok(display) = get_display().read() {
            if let Ok(logger) = get_logger().read() {
                display.display_info_message(logger.as_ref(), originator, title, message);
            }
        }
    }

    pub fn warn(originator: &str, message: &dyn Display) {
        if let Ok(logger) = get_logger().read() {
            logger.warn(originator, message);
        }
    }

    pub fn warn_with_error(originator: &str, message: &dyn Display, error: &dyn std::error::Error) {
        if let Ok(logger) = get_logger().read() {
            logger.warn_with_error(originator, message, error);
        }
    }

    pub fn show_warn(originator: &str, title: &str, message: &dyn Display) {
        if let Ok(display) = get_display().read() {
            if let Ok(logger) = get_logger().read() {
                display.display_warning_message(logger.as_ref(), originator, title, message, None);
            }
        }
    }

    pub fn error(originator: &str, message: &dyn Display) {
        if let Ok(logger) = get_logger().read() {
            logger.error(originator, message);
        }
    }

    pub fn error_with_error(
        originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        if let Ok(logger) = get_logger().read() {
            logger.error_with_error(originator, message, error);
        }
    }

    pub fn show_error(originator: &str, title: &str, message: &dyn Display) {
        if let Ok(display) = get_display().read() {
            if let Ok(logger) = get_logger().read() {
                display.display_error_message(logger.as_ref(), originator, title, message, None);
            }
        }
    }

    pub fn show_error_with_error(
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        if let Ok(display) = get_display().read() {
            if let Ok(logger) = get_logger().read() {
                display.display_error_message(
                    logger.as_ref(),
                    originator,
                    title,
                    message,
                    Some(error),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct TestLogger {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl ErrorLogger for TestLogger {
        fn trace(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn trace_with_error(
            &self,
            _originator: &str,
            message: &dyn Display,
            _error: &dyn std::error::Error,
        ) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn debug(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn debug_with_error(
            &self,
            _originator: &str,
            message: &dyn Display,
            _error: &dyn std::error::Error,
        ) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn info(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn info_with_error(
            &self,
            _originator: &str,
            message: &dyn Display,
            _error: &dyn std::error::Error,
        ) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn warn(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn warn_with_error(
            &self,
            _originator: &str,
            message: &dyn Display,
            _error: &dyn std::error::Error,
        ) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn error(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn error_with_error(
            &self,
            _originator: &str,
            message: &dyn Display,
            _error: &dyn std::error::Error,
        ) {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    #[test]
    fn test_msg_logging() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let logger = TestLogger {
            messages: messages.clone(),
        };

        Msg::set_error_logger(Box::new(logger));

        Msg::info("test", &"Hello World");
        Msg::error("test", &"Error occurred");

        let msgs = messages.lock().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], "Hello World");
        assert_eq!(msgs[1], "Error occurred");
    }

    #[test]
    fn test_msg_show_error() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let logger = TestLogger {
            messages: messages.clone(),
        };

        Msg::set_error_logger(Box::new(logger));
        Msg::set_error_display(Box::new(ConsoleErrorDisplay));

        Msg::show_error("test", "Title", &"Message");

        let msgs = messages.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], "Title: Message");
    }
}
