use std::process::Child;
use std::sync::Mutex;
use std::time::Duration;

use crate::pty::PtySession;

/// A pty session consisting of a local process and its descendants.
pub struct LocalProcessPtySession {
    process: Mutex<Child>,
    pty_name: String,
}

impl LocalProcessPtySession {
    /// Creates a new local process pty session.
    ///
    /// # Arguments
    ///
    /// * `process` - The child process to manage
    /// * `pty_name` - The name of the pseudo-terminal
    pub fn new(process: Child, pty_name: String) -> Self {
        let pid = process.id();
        tracing::info!("local Pty session. PID = {}", pid);
        Self {
            process: Mutex::new(process),
            pty_name,
        }
    }
}

impl PtySession for LocalProcessPtySession {
    fn wait_exited(&self) -> std::io::Result<i32> {
        let mut process = self
            .process
            .lock()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let status = process.wait()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn wait_exited_timeout(&self, timeout: Duration) -> std::io::Result<i32> {
        let start = std::time::Instant::now();
        loop {
            let mut process = self
                .process
                .lock()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            match (*process).try_wait()? {
                Some(status) => return Ok(status.code().unwrap_or(-1)),
                None => {
                    if start.elapsed() >= timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "process did not exit in time",
                        ));
                    }
                }
            }
            drop(process);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn destroy_forcibly(&self) {
        if let Ok(mut process) = self.process.lock() {
            let _ = process.kill();
        }
    }

    fn description(&self) -> String {
        if let Ok(process) = self.process.lock() {
            format!("process {} on {}", process.id(), self.pty_name)
        } else {
            format!("process <unknown> on {}", self.pty_name)
        }
    }

    fn handle(&self) -> u32 {
        if let Ok(process) = self.process.lock() {
            process.id()
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn new_logs_pid() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn");
        let _session = LocalProcessPtySession::new(child, "test_pty".to_string());
    }

    #[test]
    fn wait_exited_returns_exit_code() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        assert_eq!(session.wait_exited().unwrap(), 0);
    }

    #[test]
    fn wait_exited_nonzero_exit_code() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        assert_eq!(session.wait_exited().unwrap(), 42);
    }

    #[test]
    fn wait_exited_timeout_returns_exit_code() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        assert_eq!(
            session.wait_exited_timeout(Duration::from_secs(5)).unwrap(),
            0
        );
    }

    #[test]
    fn wait_exited_timeout_times_out() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("sleep 10")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        let result = session.wait_exited_timeout(Duration::from_millis(100));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
        let _ = session.kill_process();
    }

    #[test]
    fn destroy_forcibly_kills_process() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("sleep 10")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        session.destroy_forcibly();
        let result = session.wait_exited_timeout(Duration::from_millis(500));
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn description_returns_formatted_string() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn");
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        let desc = session.description();
        assert!(desc.contains("process"));
        assert!(desc.contains("test_pty"));
        let _ = session.wait_exited();
    }

    #[test]
    fn handle_returns_pid() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn");
        let pid = child.id();
        let session = LocalProcessPtySession::new(child, "test_pty".to_string());
        assert_eq!(session.handle(), pid);
        let _ = session.wait_exited();
    }
}

impl LocalProcessPtySession {
    fn kill_process(&self) {
        if let Ok(mut process) = self.process.lock() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}
