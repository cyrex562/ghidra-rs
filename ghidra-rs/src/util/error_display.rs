use super::message_type::MessageType;
use super::ErrorLogger;
use std::fmt::Display;

pub trait ErrorDisplay: Send + Sync {
    fn display_info_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
    );
    fn display_error_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: Option<&dyn std::error::Error>,
    );
    fn display_warning_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: Option<&dyn std::error::Error>,
    );
}

pub struct ConsoleErrorDisplay;

impl ErrorDisplay for ConsoleErrorDisplay {
    fn display_info_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
    ) {
        self.display_message(MessageType::Info, logger, originator, title, message, None);
    }

    fn display_error_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: Option<&dyn std::error::Error>,
    ) {
        self.display_message(
            MessageType::Error,
            logger,
            originator,
            title,
            message,
            error,
        );
    }

    fn display_warning_message(
        &self,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: Option<&dyn std::error::Error>,
    ) {
        self.display_message(
            MessageType::Warning,
            logger,
            originator,
            title,
            message,
            error,
        );
    }
}

impl ConsoleErrorDisplay {
    fn display_message(
        &self,
        msg_type: MessageType,
        logger: &dyn ErrorLogger,
        originator: &str,
        title: &str,
        message: &dyn Display,
        error: Option<&dyn std::error::Error>,
    ) {
        let full_msg = format!("{}: {}", title, message);
        match (msg_type, error) {
            (MessageType::Info, _) => logger.info(originator, &full_msg),
            (MessageType::Warning, Some(e)) => logger.warn_with_error(originator, &full_msg, e),
            (MessageType::Warning, None) => logger.warn(originator, &full_msg),
            (MessageType::Error, Some(e)) => logger.error_with_error(originator, &full_msg, e),
            (MessageType::Error, None) => logger.error(originator, &full_msg),
            (MessageType::Alert, Some(e)) => logger.warn_with_error(originator, &full_msg, e),
            (MessageType::Alert, None) => logger.warn(originator, &full_msg),
        }
    }
}
