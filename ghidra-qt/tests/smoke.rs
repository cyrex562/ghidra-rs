//! Offscreen smoke tests for the Qt shell (QT_QPA_PLATFORM=offscreen, no display
//! needed). Not part of the default workspace test run (spec §7).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn shell() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ghidra-qt"));
    c.env("QT_QPA_PLATFORM", "offscreen");
    c
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
