//! Offscreen smoke tests for the Qt shell (QT_QPA_PLATFORM=offscreen, no display
//! needed). Not part of the default workspace test run (spec §7).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn shell() -> Shell {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ghidra-qt"));
    c.env("QT_QPA_PLATFORM", "offscreen");
    Shell(c)
}

/// The shell binary under a hard deadline: a hang becomes a test failure
/// instead of blocking the suite.
struct Shell(Command);

const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

impl Shell {
    fn arg(mut self, a: impl AsRef<std::ffi::OsStr>) -> Self {
        self.0.arg(a);
        self
    }
    fn args<I, S>(mut self, a: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.0.args(a);
        self
    }
    fn output(mut self) -> std::io::Result<std::process::Output> {
        use std::process::Stdio;
        let mut child = self.0.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let start = std::time::Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return child.wait_with_output();
            }
            if start.elapsed() > DEADLINE {
                let _ = child.kill();
                let out = child.wait_with_output()?;
                panic!("ghidra-qt timed out after {DEADLINE:?}; stderr: {}", String::from_utf8_lossy(&out.stderr));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    fn status(self) -> std::io::Result<std::process::ExitStatus> {
        self.output().map(|o| o.status)
    }
}

fn tmp(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// Reads (width, height) from a PNG IHDR chunk.
fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
    let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    (w, h)
}

#[test]
fn offscreen_launch_writes_main_window_screenshot() {
    let out = tmp("smoke_main_window.png");
    let _ = fs::remove_file(&out);
    let status = shell()
        .args(["--quit-after-ms", "1500", "--screenshot"])
        .arg(&out)
        .status()
        .expect("spawn ghidra-qt");
    assert!(status.success(), "exit status {status:?}");
    let bytes = fs::read(&out).expect("screenshot written");
    assert_eq!(png_size(&bytes), (1200, 800));
}

#[test]
fn unwritable_screenshot_path_exits_2_with_message() {
    let out = tmp("no_such_dir/shot.png");
    let output = shell()
        .args(["--quit-after-ms", "500", "--screenshot"])
        .arg(&out)
        .output()
        .expect("spawn ghidra-qt");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write screenshot"));
}

#[test]
fn screenshot_without_quit_after_is_usage_error() {
    let output = shell().args(["--screenshot", "x.png"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --quit-after-ms"));
}

#[test]
fn version_flag_reports_crate_version() {
    let output = shell().arg("--version").output().expect("spawn");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("ghidra-qt {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_flag_is_usage_error_64_not_2() {
    let output = shell().arg("--no-such-flag").output().expect("spawn");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn malformed_number_is_usage_error_64() {
    let output = shell().args(["--quit-after-ms", "abc"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(64));
}

fn dump_docks(extra: &[&str]) -> Vec<String> {
    let out = shell().arg("--dump-docks").args(extra).output().expect("spawn");
    assert!(out.status.success(), "status {:?} stderr {}", out.status, String::from_utf8_lossy(&out.stderr));
    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(str::to_owned).collect();
    lines.sort();
    lines
}

#[test]
fn demo_docks_are_placed_by_window_position() {
    assert_eq!(
        dump_docks(&[]),
        vec![
            "Decompiler\tRight\ttext".to_string(),
            "Options\tBottom\tform".to_string(),
            "Program Tree\tLeft\ttree".to_string(),
            "Symbols\tLeft\ttable".to_string(),
        ]
    );
}

#[test]
fn garbage_geometry_falls_back_to_default_placement() {
    let f = tmp("garbage_geometry.bin");
    std::fs::write(&f, b"definitely not an ADS state blob").unwrap();
    let lines = dump_docks(&["--restore-geometry", f.to_str().unwrap()]);
    assert_eq!(lines.len(), 4);
    assert!(lines.iter().any(|l| l.starts_with("Symbols\tLeft")));
}
