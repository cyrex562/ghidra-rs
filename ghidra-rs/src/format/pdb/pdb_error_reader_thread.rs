use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Mutex};
use std::thread;

/// Reads error stream output in a background thread and accumulates messages.
///
/// Port of `ghidra.app.util.bin.format.pdb.PdbErrorReaderThread`. Spawns a background
/// thread that reads lines from a provided input stream, accumulating them for later
/// inspection. Callers can check for the presence of "ERROR" or "WARNING" keywords
/// and retrieve the full accumulated output.
pub struct PdbErrorReaderThread {
    messages: Arc<Mutex<String>>,
}

impl PdbErrorReaderThread {
    /// Creates a new error reader that spawns a background thread to read from the given input.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read from (e.g., stderr or a pipe)
    ///
    /// # Returns
    ///
    /// A `PdbErrorReaderThread` with a spawned thread actively reading the input.
    pub fn spawn<R: Read + Send + 'static>(reader: R) -> Self {
        let messages = Arc::new(Mutex::new(String::new()));
        let messages_clone = Arc::clone(&messages);

        thread::spawn(move || {
            let buf_reader = BufReader::new(reader);
            for line in buf_reader.lines() {
                if let Ok(line) = line {
                    let mut msg = messages_clone.lock().unwrap();
                    msg.push_str(&line);
                    msg.push('\n');
                }
            }
        });

        PdbErrorReaderThread { messages }
    }

    /// Returns true if the accumulated messages contain "ERROR".
    pub fn has_errors(&self) -> bool {
        let msg = self.messages.lock().unwrap();
        !msg.is_empty() && msg.contains("ERROR")
    }

    /// Returns true if the accumulated messages contain "WARNING".
    pub fn has_warnings(&self) -> bool {
        let msg = self.messages.lock().unwrap();
        !msg.is_empty() && msg.contains("WARNING")
    }

    /// Returns the accumulated error and warning messages, or `None` if no messages were read.
    pub fn get_error_and_warning_messages(&self) -> Option<String> {
        let msg = self.messages.lock().unwrap();
        if msg.is_empty() {
            None
        } else {
            Some(msg.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn empty_stream_has_no_errors() {
        let cursor = Cursor::new("");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(!reader.has_errors());
        assert!(!reader.has_warnings());
        assert_eq!(reader.get_error_and_warning_messages(), None);
    }

    #[test]
    fn detects_error_keyword() {
        let cursor = Cursor::new("ERROR: something went wrong\n");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(reader.has_errors());
        assert!(!reader.has_warnings());
        assert!(reader.get_error_and_warning_messages().is_some());
    }

    #[test]
    fn detects_warning_keyword() {
        let cursor = Cursor::new("WARNING: be careful\n");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(!reader.has_errors());
        assert!(reader.has_warnings());
        assert!(reader.get_error_and_warning_messages().is_some());
    }

    #[test]
    fn detects_both_error_and_warning() {
        let cursor = Cursor::new("WARNING: first\nERROR: second\n");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(reader.has_errors());
        assert!(reader.has_warnings());
        assert!(reader.get_error_and_warning_messages().is_some());
    }

    #[test]
    fn message_content_preserved() {
        let input = "Line 1\nLine 2\nLine 3\n";
        let cursor = Cursor::new(input);
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        let messages = reader.get_error_and_warning_messages().unwrap();
        assert_eq!(messages, input);
    }

    #[test]
    fn partial_keywords_dont_match() {
        let cursor = Cursor::new("EEEEE RRRR OOORRR KKKS: not a match\n");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(!reader.has_errors());
        assert!(!reader.has_warnings());
        assert!(reader.get_error_and_warning_messages().is_some());
    }

    #[test]
    fn keyword_must_appear_in_non_empty_buffer() {
        let cursor = Cursor::new("");
        let reader = PdbErrorReaderThread::spawn(cursor);
        thread::sleep(Duration::from_millis(50));

        assert!(!reader.has_errors());
        assert!(!reader.has_warnings());
    }
}
