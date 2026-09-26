// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/stream/BlockStreamServer.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use std::io;
use std::net::TcpListener;

use thiserror::Error;

use crate::framework::db::buffers::BlockStream;
use crate::server::seam_stubs::RemoteBlockStreamHandleLike;

/// Error returned by [`BlockStreamServer::register_block_stream`].
#[derive(Error, Debug)]
pub enum BlockStreamRegistrationError {
    /// Mirrors the `IllegalArgumentException` thrown when the supplied handle is not pending a
    /// connection, or its stream ID has already been registered.
    #[error("stream handle previously registered/used")]
    AlreadyRegistered,
}

/// Provides a block stream server implementation intended for integration with the RMI
/// GhidraServer implementation.
///
/// Mirrors `ghidra.server.stream.BlockStreamServer`, recast as a trait so implementations can be
/// decoupled from the concrete singleton (was selected as a dependency-cycle cut point:
/// `RemoteBlockStreamHandle` is constructed from a `BlockStreamServer` and is in turn accepted
/// back by [`register_block_stream`](Self::register_block_stream)). `RemoteBlockStreamHandle` is
/// not yet ported, so registration accepts a
/// [`RemoteBlockStreamHandleLike`](crate::server::seam_stubs::RemoteBlockStreamHandleLike)
/// placeholder instead of porting it here, which would recreate the cycle.
///
/// The server's accept loop, per-connection handler thread, and stale-registration sweep are
/// implementation details of a concrete server and are intentionally not part of this trait --
/// only the lifecycle and registration surface a caller (or `RemoteBlockStreamHandle`) actually
/// depends on is exposed here. Likewise the Java singleton accessor (`getBlockStreamServer()`) is
/// omitted; obtaining/sharing an instance is a concern for the concrete implementation and its
/// callers, not the trait.
pub trait BlockStreamServer: Send + Sync {
    /// Determine if server is running.
    fn is_running(&self) -> bool;

    /// Get the server port, `None` if server not yet started.
    fn server_port(&self) -> Option<u16>;

    /// Get the server remote access hostname, `None` if server not yet started.
    fn server_hostname(&self) -> Option<String>;

    /// Get the next available stream ID and auto-increment.
    fn next_stream_id(&self) -> u64;

    /// Register a new block stream to be serviced. A block stream registration permits the
    /// server to associate an in-bound client connection with the appropriate block stream.
    ///
    /// Returns `Ok(true)` if registration succeeded, `Ok(false)` if the server is not running, or
    /// [`BlockStreamRegistrationError::AlreadyRegistered`] if `stream_handle` is not pending a
    /// connection or its stream ID has already been registered.
    fn register_block_stream(
        &self,
        stream_handle: Box<dyn RemoteBlockStreamHandleLike>,
        block_stream: Box<dyn BlockStream>,
    ) -> Result<bool, BlockStreamRegistrationError>;

    /// Start this server instance using the given listening socket and remote access hostname.
    /// If the server has already been started, this returns an error.
    fn start_server(&self, socket: TcpListener, host: &str) -> io::Result<()>;

    /// Stop this block stream server instance.
    fn stop_server(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct MockHandle {
        stream_id: u64,
        pending: bool,
    }

    impl RemoteBlockStreamHandleLike for MockHandle {
        fn stream_id(&self) -> u64 {
            self.stream_id
        }

        fn is_pending(&self) -> bool {
            self.pending
        }
    }

    struct MockBlockStream;

    impl BlockStream for MockBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }

        fn get_block_count(&self) -> usize {
            1
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A minimal in-memory `BlockStreamServer`, mirroring the registration bookkeeping and
    /// lifecycle guards of the Java class closely enough to exercise real behavior.
    struct MockBlockStreamServer {
        running: Mutex<bool>,
        hostname: Mutex<Option<String>>,
        next_id: Mutex<u64>,
        registered: Mutex<HashSet<u64>>,
    }

    impl MockBlockStreamServer {
        fn new() -> Self {
            Self {
                running: Mutex::new(false),
                hostname: Mutex::new(None),
                next_id: Mutex::new(1),
                registered: Mutex::new(HashSet::new()),
            }
        }
    }

    impl BlockStreamServer for MockBlockStreamServer {
        fn is_running(&self) -> bool {
            *self.running.lock().unwrap()
        }

        fn server_port(&self) -> Option<u16> {
            self.is_running().then_some(4444)
        }

        fn server_hostname(&self) -> Option<String> {
            self.hostname.lock().unwrap().clone()
        }

        fn next_stream_id(&self) -> u64 {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        }

        fn register_block_stream(
            &self,
            stream_handle: Box<dyn RemoteBlockStreamHandleLike>,
            _block_stream: Box<dyn BlockStream>,
        ) -> Result<bool, BlockStreamRegistrationError> {
            if !self.is_running() {
                return Ok(false);
            }
            let mut registered = self.registered.lock().unwrap();
            if !stream_handle.is_pending() || registered.contains(&stream_handle.stream_id()) {
                return Err(BlockStreamRegistrationError::AlreadyRegistered);
            }
            registered.insert(stream_handle.stream_id());
            Ok(true)
        }

        fn start_server(&self, _socket: TcpListener, host: &str) -> io::Result<()> {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Err(io::Error::new(io::ErrorKind::Other, "server already started"));
            }
            *running = true;
            *self.hostname.lock().unwrap() = Some(host.to_string());
            Ok(())
        }

        fn stop_server(&self) {
            *self.running.lock().unwrap() = false;
        }
    }

    #[test]
    fn test_block_stream_server_lifecycle_and_registration() {
        let server: Box<dyn BlockStreamServer> = Box::new(MockBlockStreamServer::new());

        assert!(!server.is_running());
        assert!(server.server_port().is_none());
        assert!(server.server_hostname().is_none());

        // Registering before the server has started returns Ok(false), not an error.
        let early_handle = Box::new(MockHandle { stream_id: server.next_stream_id(), pending: true });
        let early_stream = Box::new(MockBlockStream);
        assert_eq!(server.register_block_stream(early_handle, early_stream).unwrap(), false);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        server.start_server(listener, "localhost").expect("start server");
        assert!(server.is_running());
        assert_eq!(server.server_port(), Some(4444));
        assert_eq!(server.server_hostname().as_deref(), Some("localhost"));

        // Starting an already-running server is an error.
        let second_listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        assert!(server.start_server(second_listener, "localhost").is_err());

        let id = server.next_stream_id();
        let handle = Box::new(MockHandle { stream_id: id, pending: true });
        let stream = Box::new(MockBlockStream);
        assert_eq!(server.register_block_stream(handle, stream).unwrap(), true);

        // Re-registering the same stream ID must fail.
        let dup_handle = Box::new(MockHandle { stream_id: id, pending: true });
        let dup_stream = Box::new(MockBlockStream);
        let dup_result = server.register_block_stream(dup_handle, dup_stream);
        assert!(matches!(dup_result, Err(BlockStreamRegistrationError::AlreadyRegistered)));

        // A handle that is no longer pending must also fail registration.
        let not_pending_handle =
            Box::new(MockHandle { stream_id: server.next_stream_id(), pending: false });
        let not_pending_stream = Box::new(MockBlockStream);
        let not_pending_result =
            server.register_block_stream(not_pending_handle, not_pending_stream);
        assert!(matches!(not_pending_result, Err(BlockStreamRegistrationError::AlreadyRegistered)));

        server.stop_server();
        assert!(!server.is_running());

        // After stopping, registration attempts return Ok(false) rather than erroring.
        let after_stop_handle =
            Box::new(MockHandle { stream_id: server.next_stream_id(), pending: true });
        let after_stop_stream = Box::new(MockBlockStream);
        assert_eq!(
            server.register_block_stream(after_stop_handle, after_stop_stream).unwrap(),
            false
        );
    }
}
