use std::io::{self, Read};

use crate::format::seam_stubs::{DebugInfoProvider, ExternalDebugInfo};
use crate::format::dwarf::external::object_type::ObjectType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Represents an error that occurred during stream provision.
#[derive(Debug)]
pub enum StreamProviderError {
    Io(io::Error),
    Cancelled(CancelledException),
}

impl From<io::Error> for StreamProviderError {
    fn from(err: io::Error) -> Self {
        StreamProviderError::Io(err)
    }
}

impl From<CancelledException> for StreamProviderError {
    fn from(err: CancelledException) -> Self {
        StreamProviderError::Cancelled(err)
    }
}

impl std::fmt::Display for StreamProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamProviderError::Io(err) => write!(f, "IO error: {}", err),
            StreamProviderError::Cancelled(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for StreamProviderError {}

pub type StreamProviderResult<T> = Result<T, StreamProviderError>;

/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider.StreamInfo`.
/// A record containing an input stream and its content length.
pub struct StreamInfo {
    /// The input stream containing debug data.
    pub is: Box<dyn Read + Send>,
    /// The total length of the debug data in bytes.
    pub content_length: u64,
}

impl std::fmt::Debug for StreamInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamInfo")
            .field("content_length", &self.content_length)
            .finish()
    }
}

impl StreamInfo {
    /// Creates a new `StreamInfo` with the given stream and content length.
    pub fn new<R: Read + Send + 'static>(is: R, content_length: u64) -> Self {
        StreamInfo {
            is: Box::new(is),
            content_length,
        }
    }
}

/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider`.
/// A provider that returns debug objects as a stream.
pub trait DebugStreamProvider: DebugInfoProvider + Send + Sync {
    /// Returns a stream of debug information for the given external debug info.
    ///
    /// Mirrors `DebugStreamProvider.getStream(ExternalDebugInfo, TaskMonitor)`.
    fn get_stream(
        &self,
        id: &dyn ExternalDebugInfo,
        monitor: &dyn TaskMonitor,
    ) -> StreamProviderResult<StreamInfo>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn stream_info_new_creates_boxed_stream() {
        let data = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(data);
        let stream_info = StreamInfo::new(cursor, 5);

        assert_eq!(stream_info.content_length, 5);
    }

    #[test]
    fn stream_info_can_read() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cursor = Cursor::new(data);
        let mut stream_info = StreamInfo::new(cursor, 4);

        let mut buf = [0u8; 4];
        let n = stream_info.is.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn stream_provider_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        let stream_err: StreamProviderError = io_err.into();
        assert!(matches!(stream_err, StreamProviderError::Io(_)));
    }

    #[test]
    fn stream_provider_error_from_cancelled() {
        let cancelled = CancelledException::new("test");
        let stream_err: StreamProviderError = cancelled.into();
        assert!(matches!(stream_err, StreamProviderError::Cancelled(_)));
    }

    #[test]
    fn stream_provider_error_display() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        let stream_err: StreamProviderError = io_err.into();
        let display_str = stream_err.to_string();
        assert!(display_str.contains("IO error"));
    }
}
