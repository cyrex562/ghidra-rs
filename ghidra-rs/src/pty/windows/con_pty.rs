//! Port of `ghidra.pty.windows.ConPty` (rule R14a-concrete-leaf -> struct).
//!
//! Owns two anonymous pipes and a pseudo-console. Java aliases one `PseudoConsoleHandle` object
//! across `ConPty`, `ConPtyParent`, and `ConPtyChild`; this port hands each a
//! [`Clone`](PseudoConsoleHandle) of the same shared, reference-counted handle instead -- see
//! [`PseudoConsoleHandle`]'s module doc for why that is safe (the real `ClosePseudoConsole` call
//! still happens exactly once).
//!
//! Java's constructor comment says "Close the child-connected ends after creating the
//! pseudoconsole" but the code that follows never actually does so -- all four pipe-end handles
//! remain open and are distributed to `parent`/`child`, exactly like this port.

use std::io;

use crate::pty::{Pty, PtyChild, PtyParent};

use super::con_pty_child::ConPtyChild;
use super::con_pty_parent::ConPtyParent;
use super::jna::console_api_native::Coord;
use super::pipe::Pipe;
use super::pseudo_console_handle::PseudoConsoleHandle;

/// A Windows pseudo-terminal, owning both ends (port of `ConPty`).
pub struct ConPty {
    pseudo_console_handle: PseudoConsoleHandle,
    closed: bool,
    parent: ConPtyParent,
    child: ConPtyChild,
}

impl ConPty {
    /// Opens a new pseudo-console of the given dimensions, mirroring the static
    /// `ConPty.openpty(short, short)` factory.
    pub fn openpty(cols: i16, rows: i16) -> io::Result<Self> {
        let pipe_to_child = Pipe::create()?;
        let pipe_from_child = Pipe::create()?;

        let h_input = pipe_to_child.read_handle().as_raw()?;
        let h_output = pipe_from_child.write_handle().as_raw()?;
        let size = Coord::new(cols, rows);

        let mut raw_pc: super::handle::RawHandle = std::ptr::null_mut();
        #[cfg(target_os = "windows")]
        {
            let hr = unsafe {
                super::jna::console_api_native::CreatePseudoConsole(
                    size, h_input, h_output, 0, &mut raw_pc,
                )
            };
            if hr < 0 {
                return Err(io::Error::from_raw_os_error(hr));
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (h_input, h_output, size);
        }

        // SAFETY: on Windows, raw_pc was just filled in by a successful CreatePseudoConsole
        // call, checked above. On non-Windows it stays null, matching every other dummy handle
        // in this module.
        let pseudo_console_handle = unsafe { PseudoConsoleHandle::new(raw_pc) };

        let (pipe_to_child_read, pipe_to_child_write) = pipe_to_child.into_handles();
        let (pipe_from_child_read, pipe_from_child_write) = pipe_from_child.into_handles();

        let parent = ConPtyParent::new(
            pipe_to_child_write,
            pipe_from_child_read,
            pseudo_console_handle.clone(),
        );
        let child = ConPtyChild::new(
            pipe_from_child_write,
            pipe_to_child_read,
            pseudo_console_handle.clone(),
        );

        Ok(ConPty {
            pseudo_console_handle,
            closed: false,
            parent,
            child,
        })
    }
}

impl Pty for ConPty {
    fn get_parent(&self) -> &dyn PtyParent {
        &self.parent
    }

    fn get_child(&self) -> &dyn PtyChild {
        &self.child
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.pseudo_console_handle.close()?;
        self.parent.close_streams()?;
        self.child.close_streams()?;
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openpty_creates_a_pty_with_working_endpoints() {
        let mut pty = ConPty::openpty(80, 24).unwrap();
        assert!(pty.get_parent().get_output_stream().is_ok());
        assert!(pty.get_child().get_output_stream().is_ok());
        pty.close().unwrap();
    }

    #[test]
    fn close_is_idempotent() {
        let mut pty = ConPty::openpty(80, 24).unwrap();
        pty.close().unwrap();
        assert!(pty.close().is_ok());
    }

    #[test]
    fn closing_invalidates_the_shared_pseudo_console_handle() {
        let mut pty = ConPty::openpty(80, 24).unwrap();
        pty.close().unwrap();
        assert!(pty.pseudo_console_handle.as_raw().is_err());
    }
}
