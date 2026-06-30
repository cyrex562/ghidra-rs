use std::io::{Read, Write};
use std::thread::{self, JoinHandle};

/// Pumps bytes from a reader to a writer in a background thread.
///
/// Reads up to 1024 bytes at a time from the reader and writes them to the
/// writer until EOF or an I/O error on either end. Mirrors
/// `ghidra.pty.StreamPumper`.
pub struct StreamPumper {
    reader: Box<dyn Read + Send + 'static>,
    writer: Box<dyn Write + Send + 'static>,
}

impl StreamPumper {
    /// Creates a new `StreamPumper` that will copy bytes from `reader` to `writer`.
    pub fn new(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
    ) -> Self {
        Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Spawns a background thread that pumps bytes until EOF or error.
    ///
    /// Returns a [`JoinHandle`] that resolves when the pump has finished.
    pub fn start(self) -> JoinHandle<()> {
        thread::spawn(move || {
            pump(self.reader, self.writer);
        })
    }
}

fn pump(mut reader: impl Read, mut writer: impl Write) {
    let mut buf = [0u8; 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

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

    fn make_pumper(data: Vec<u8>) -> (StreamPumper, Arc<Mutex<Vec<u8>>>) {
        let output = Arc::new(Mutex::new(Vec::new()));
        let pumper = StreamPumper::new(io::Cursor::new(data), VecWriter(Arc::clone(&output)));
        (pumper, output)
    }

    #[test]
    fn pumps_all_bytes_to_writer() {
        let data = vec![1u8, 2, 3, 4, 5];
        let (pumper, output) = make_pumper(data.clone());
        pumper.start().join().unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let (pumper, output) = make_pumper(vec![]);
        pumper.start().join().unwrap();
        assert!(output.lock().unwrap().is_empty());
    }

    #[test]
    fn pumps_large_payload_across_multiple_reads() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let (pumper, output) = make_pumper(data.clone());
        pumper.start().join().unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }

    #[test]
    fn stops_on_reader_error() {
        struct ErrorReader;
        impl Read for ErrorReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"))
            }
        }

        let output = Arc::new(Mutex::new(Vec::new()));
        let pumper = StreamPumper::new(ErrorReader, VecWriter(Arc::clone(&output)));
        pumper.start().join().unwrap();
        assert!(output.lock().unwrap().is_empty());
    }

    #[test]
    fn stops_on_writer_error() {
        struct ErrorWriter;
        impl Write for ErrorWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let pumper = StreamPumper::new(io::Cursor::new(vec![1u8, 2, 3]), ErrorWriter);
        pumper.start().join().unwrap();
    }
}
