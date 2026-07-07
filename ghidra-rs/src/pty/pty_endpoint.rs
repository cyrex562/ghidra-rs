use std::io::{Read, Write};

/// One end of a pseudo-terminal.
///
/// Provides access to the I/O streams for the local side of a pty. The
/// opposite end's output stream feeds this side's input stream (and vice
/// versa), subject to the terminal's line discipline.
pub trait PtyEndpoint {
    /// Returns the output stream for this end of the pty.
    ///
    /// Bytes written here arrive on the input stream of the opposite end,
    /// subject to the terminal's line discipline.
    ///
    /// # Errors
    ///
    /// Returns `Err` with [`std::io::ErrorKind::Unsupported`] if this end
    /// is not local.
    fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>>;

    /// Returns the input stream for this end of the pty.
    ///
    /// Bytes written to the output stream of the opposite end arrive here,
    /// subject to the terminal's line discipline.
    ///
    /// # Errors
    ///
    /// Returns `Err` with [`std::io::ErrorKind::Unsupported`] if this end
    /// is not local.
    fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, ErrorKind};

    struct LocalEndpoint {
        data: Vec<u8>,
    }

    impl PtyEndpoint for LocalEndpoint {
        fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
            Ok(Box::new(io::sink()))
        }

        fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(self.data.clone())))
        }
    }

    struct RemoteEndpoint;

    impl PtyEndpoint for RemoteEndpoint {
        fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
            Err(io::Error::new(ErrorKind::Unsupported, "not local"))
        }

        fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
            Err(io::Error::new(ErrorKind::Unsupported, "not local"))
        }
    }

    #[test]
    fn local_output_stream_is_ok() {
        let ep = LocalEndpoint { data: vec![] };
        assert!(ep.get_output_stream().is_ok());
    }

    #[test]
    fn local_input_stream_reads_data() {
        let ep = LocalEndpoint {
            data: vec![1, 2, 3],
        };
        let mut stream = ep.get_input_stream().unwrap();
        let mut buf = vec![0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3]);
    }

    #[test]
    fn local_output_stream_accepts_writes() {
        let ep = LocalEndpoint { data: vec![] };
        let mut stream = ep.get_output_stream().unwrap();
        let n = stream.write(&[0xde, 0xad]).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn remote_output_stream_is_unsupported() {
        let ep = RemoteEndpoint;
        let err = ep.get_output_stream().err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn remote_input_stream_is_unsupported() {
        let ep = RemoteEndpoint;
        let err = ep.get_input_stream().err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}
