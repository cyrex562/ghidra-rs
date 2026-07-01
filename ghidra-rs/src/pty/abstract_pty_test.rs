use crate::pty::PtySession;
use std::io::{BufRead, BufReader, Read, Write};
use std::thread::{self, JoinHandle};

/// Spawns a daemon thread that pumps bytes from a reader to a writer.
///
/// Reads one byte at a time from the reader and writes it to the writer
/// until EOF is encountered or an I/O error occurs.
///
/// # Panics
///
/// Panics if an I/O error occurs during reading or writing.
pub fn pump(
    reader: Box<dyn Read + Send + 'static>,
    writer: Box<dyn Write + Send + 'static>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = reader;
        let mut writer = writer;
        let mut buf = [0u8; 1];

        loop {
            match reader.read(&mut buf) {
                Ok(0) => return,
                Ok(1) => {
                    if writer.write_all(&buf).is_err() {
                        return;
                    }
                }
                Ok(_) => unreachable!(),
                Err(e) => panic!("{}", e),
            }
        }
    })
}

/// A reader wrapper that logs each complete line to stdout.
pub struct LoggingReader {
    reader: BufReader<Box<dyn Read + Send + 'static>>,
}

impl LoggingReader {
    /// Creates a new `LoggingReader` that wraps the given reader.
    pub fn new(reader: Box<dyn Read + Send + 'static>) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }

    /// Reads a line from the underlying reader and logs it to stdout.
    pub fn read_line(&mut self) -> std::io::Result<Option<String>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line)? {
            0 => Ok(None),
            _ => {
                println!("log: {}", line.trim_end());
                Ok(Some(line))
            }
        }
    }
}

/// Spawns a daemon thread that verifies a session exits with the expected code.
///
/// Repeatedly calls `session.wait_exited()` until it succeeds (ignoring interrupts),
/// then asserts that the exit code matches the expected value.
///
/// # Panics
///
/// Panics if the exit code does not match the expected value.
pub fn run_exit_check(
    expected: i32,
    session: Box<dyn PtySession + Send + 'static>,
) -> JoinHandle<()> {
    thread::spawn(move || loop {
        match session.wait_exited() {
            Ok(code) => {
                assert_eq!(
                    code, expected,
                    "Early exit with wrong code: expected {}, got {}",
                    expected, code
                );
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                eprintln!("Exit check interrupted");
            }
            Err(e) => panic!("Unexpected error in exit check: {}", e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct VecWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pump_transfers_bytes_from_reader_to_writer() {
        let data = vec![1u8, 2, 3, 4, 5];
        let output = Arc::new(Mutex::new(Vec::new()));
        let handle = pump(
            Box::new(Cursor::new(data.clone())),
            Box::new(VecWriter(Arc::clone(&output))),
        );
        handle.join().unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }

    #[test]
    fn pump_handles_empty_input() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let handle = pump(Box::new(Cursor::new(vec![])), Box::new(VecWriter(Arc::clone(&output))));
        handle.join().unwrap();
        assert!(output.lock().unwrap().is_empty());
    }

    #[test]
    fn pump_reads_one_byte_at_a_time() {
        let data = vec![10u8, 20, 30];
        let output = Arc::new(Mutex::new(Vec::new()));
        let handle = pump(
            Box::new(Cursor::new(data.clone())),
            Box::new(VecWriter(Arc::clone(&output))),
        );
        handle.join().unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }

    #[test]
    fn logging_reader_reads_and_logs_lines() {
        let data = "hello\nworld\n";
        let reader = Box::new(Cursor::new(data.as_bytes().to_vec()));
        let mut logging_reader = LoggingReader::new(reader);

        let line1 = logging_reader.read_line().unwrap();
        assert!(line1.is_some());
        assert_eq!(line1.unwrap().trim_end(), "hello");

        let line2 = logging_reader.read_line().unwrap();
        assert!(line2.is_some());
        assert_eq!(line2.unwrap().trim_end(), "world");

        let eof = logging_reader.read_line().unwrap();
        assert!(eof.is_none());
    }

    #[test]
    fn logging_reader_handles_empty_input() {
        let reader = Box::new(Cursor::new(vec![]));
        let mut logging_reader = LoggingReader::new(reader);

        let result = logging_reader.read_line().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn logging_reader_handles_line_without_newline() {
        let data = "single line";
        let reader = Box::new(Cursor::new(data.as_bytes().to_vec()));
        let mut logging_reader = LoggingReader::new(reader);

        let line = logging_reader.read_line().unwrap();
        assert!(line.is_some());
        assert_eq!(line.unwrap(), "single line");
    }

    struct MockSession {
        exit_code: i32,
        pid: u32,
        desc: String,
    }

    impl PtySession for MockSession {
        fn wait_exited(&self) -> io::Result<i32> {
            Ok(self.exit_code)
        }

        fn wait_exited_timeout(&self, _timeout: Duration) -> io::Result<i32> {
            Ok(self.exit_code)
        }

        fn destroy_forcibly(&self) {}

        fn description(&self) -> String {
            self.desc.clone()
        }

        fn handle(&self) -> u32 {
            self.pid
        }
    }

    #[test]
    fn pump_works_with_single_byte() {
        let data = vec![42u8];
        let output = Arc::new(Mutex::new(Vec::new()));
        let handle = pump(
            Box::new(Cursor::new(data.clone())),
            Box::new(VecWriter(Arc::clone(&output))),
        );
        handle.join().unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }

    #[test]
    fn logging_reader_returns_none_on_eof() {
        let reader = Box::new(Cursor::new(vec![]));
        let mut logging_reader = LoggingReader::new(reader);

        let result = logging_reader.read_line().unwrap();
        assert!(result.is_none());

        let result2 = logging_reader.read_line().unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn exit_check_verifies_correct_exit_code() {
        let session = Box::new(MockSession {
            exit_code: 0,
            pid: 123,
            desc: "test session".to_string(),
        });

        let handle = run_exit_check(0, session);
        handle.join().unwrap();
    }

    #[test]
    fn exit_check_verifies_nonzero_exit_code() {
        let session = Box::new(MockSession {
            exit_code: 42,
            pid: 456,
            desc: "test session".to_string(),
        });

        let handle = run_exit_check(42, session);
        handle.join().unwrap();
    }

    #[test]
    #[should_panic(expected = "Early exit with wrong code")]
    fn exit_check_panics_on_mismatched_exit_code() {
        let session = Box::new(MockSession {
            exit_code: 1,
            pid: 789,
            desc: "test session".to_string(),
        });

        let handle = run_exit_check(0, session);
        handle.join().unwrap();
    }
}
