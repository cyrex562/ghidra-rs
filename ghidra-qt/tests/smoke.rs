//! Offscreen smoke tests for the Qt shell (QT_QPA_PLATFORM=offscreen, no display
//! needed). Not part of the default workspace test run (spec §7).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn shell() -> Shell {
    shell_with_config(&tmp("config-default"))
}

fn shell_with_config(dir: &std::path::Path) -> Shell {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ghidra-qt"));
    c.env("QT_QPA_PLATFORM", "offscreen");
    // never touch the user's real ~/.config during tests
    c.env("GHIDRA_RS_CONFIG_DIR", dir);
    Shell(c)
}

/// The shell binary under a hard deadline: a hang becomes a test failure
/// instead of blocking the suite.
struct Shell(Command);

const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

impl Shell {
    fn env_var(mut self, k: &str, v: &str) -> Self {
        self.0.env(k, v);
        self
    }
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
    // A fresh config: other tests save their layouts to the default one.
    let dir = tmp(&format!("config-docks-{}", extra.join("_").replace(['-', '/'], "")));
    let _ = std::fs::remove_dir_all(&dir);
    let out = shell_with_config(&dir).arg("--dump-docks").args(extra).output().expect("spawn");
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
            "Listing\tCentral\tlisting".to_string(),
            "Options\tBottom\tform".to_string(),
            "Program Tree\tLeft\ttree\ttabbed".to_string(),
            "Symbols\tLeft\ttable\ttabbed".to_string(),
        ]
    );
}

#[test]
fn garbage_geometry_falls_back_to_default_placement() {
    let f = tmp("garbage_geometry.bin");
    std::fs::write(&f, b"definitely not an ADS state blob").unwrap();
    let lines = dump_docks(&["--restore-geometry", f.to_str().unwrap()]);
    assert_eq!(lines.len(), 5);
    assert!(lines.iter().any(|l| l.starts_with("Symbols\tLeft")));
}

#[test]
fn menu_bar_is_built_in_ghidra_order() {
    let out = shell().arg("--dump-menus").output().expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let tops: Vec<&str> = text.lines().filter(|l| !l.starts_with(' ')).collect();
    assert_eq!(tops, vec!["File", "Edit", "Navigation", "Search", "Window"]);
    assert!(text.lines().any(|l| l == "  Copy\tCtrl-C"), "{text}");
    assert!(text.lines().any(|l| l == "  Find...\tCtrl-F"), "{text}");
}

fn press_status(focus: &str) -> String {
    press_status_with(focus, &[])
}

fn press_status_with(focus: &str, extra: &[&str]) -> String {
    // A fresh config: the default layout (Symbols and Program Tree tabbed),
    // not whatever an earlier test saved.
    let dir = tmp(&format!("config-press-{}", focus.replace(' ', "_")));
    let _ = std::fs::remove_dir_all(&dir);
    let out = shell_with_config(&dir)
        .args(["--press", "Ctrl-F", "--focus", focus, "--quit-after-ms", "1500"])
        .args(extra)
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn ctrl_f_runs_the_local_action_in_symbols_and_the_global_elsewhere() {
    assert!(press_status("Symbols").lines().any(|l| l == "status: Find in Table"));
    assert!(press_status("Program Tree").lines().any(|l| l == "status: Find"));
}

#[test]
fn key_bindings_work_in_a_floating_dock() {
    let out = press_status_with("Symbols", &["--float", "Symbols"]);
    assert!(out.lines().any(|l| l == "status: Find in Table"), "{out}");
}

#[test]
fn bridge_error_from_a_slot_is_reported_not_fatal() {
    let out = shell().args(["--invoke-missing-action", "--quit-after-ms", "800"]).output().expect("spawn");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no action"));
}

#[test]
fn layout_is_saved_on_exit_and_corrupt_config_is_survivable() {
    let dir = tmp("config-persist");
    let _ = fs::remove_dir_all(&dir);
    let out = shell_with_config(&dir).args(["--quit-after-ms", "600"]).output().expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    let cfg = dir.join("tools").join("Ghidra-rs.xml");
    let xml = fs::read_to_string(&cfg).expect("tool config written on exit");
    assert!(xml.contains("GEOMETRY"), "{xml}");
    assert!(xml.contains("PROVIDER:Demo.Symbols"), "{xml}");

    fs::write(&cfg, "<truncated").unwrap();
    let out = shell_with_config(&dir).arg("--dump-docks").output().expect("spawn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 5);
}

#[test]
fn saved_geometry_from_a_smaller_dock_set_does_not_hide_new_providers() {
    let dir = tmp("config-newdock");
    let _ = fs::remove_dir_all(&dir);
    // run 1: four providers; layout + ADS state saved on exit
    let out = shell_with_config(&dir).args(["--quit-after-ms", "500"]).output().expect("spawn");
    assert!(out.status.success());
    // run 2: a fifth provider exists that the saved ADS state never heard of
    let out = shell_with_config(&dir).env_var("GHIDRA_RS_DEMO_EXTRA_PROVIDER", "1").arg("--dump-docks").output().expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(text.lines().count(), 6, "{text}");
    assert!(!text.contains("closed"), "a provider was hidden by stale ADS state:\n{text}");
}

#[test]
fn edit_keys_stay_with_text_widgets() {
    let run = |focus: &str| {
        let out = shell()
            .args(["--press", "Ctrl-C", "--focus", focus, "--quit-after-ms", "1200"])
            .output()
            .expect("spawn");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    // a line edit owns Ctrl-C (Java: willBeHandledByTextComponent)
    assert!(!run("Options").lines().any(|l| l == "status: Copy"));
    // a tree view does not, so the tool's Copy action runs
    assert!(run("Program Tree").lines().any(|l| l == "status: Copy"));
}

#[test]
fn rebuilding_actions_does_not_leak_menus_or_toolbar_actions() {
    let count = |n: &str| {
        let out = shell().args(["--count-after-rebuilds", n]).output().expect("spawn");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(count("1"), count("50"));
}

#[test]
fn listing_font_change_relayouts_and_keeps_the_top_row() {
    let out = shell().arg("--listing-font-change").output().expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    let parse = |l: &str| {
        let (index, xs) = l.split_once(": ").expect("index: xs");
        (index.to_string(), xs.split(' ').map(|x| x.parse::<i32>().unwrap()).collect::<Vec<_>>())
    };
    let (before, after) = (parse(lines[0]), parse(lines[1]));
    assert_eq!(before.0, "3");
    assert_eq!(after.0, "3", "top row must survive a font change");
    assert!(after.1[1] > before.1[1], "columns must widen with the font: {text}");
}

fn listing_state(keys: &str, answer: Option<&str>) -> String {
    let mut cmd = shell().args(["--focus", "Listing", "--press", keys, "--print-listing-state", "--quit-after-ms", "2500"]);
    if let Some(a) = answer {
        cmd = cmd.args(["--prompt-answer", a]);
    }
    let out = cmd.output().expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn shift_down_selects_rows_in_the_listing() {
    let out = listing_state("Shift-Down,Shift-Down,Shift-Down", None);
    assert!(out.lines().any(|l| l.contains("cursor=00401003 selected=4")), "{out}");
}

#[test]
fn g_goes_to_an_address_and_alt_left_comes_back() {
    let out = listing_state("Down,G", Some("0x402000"));
    assert!(out.lines().any(|l| l == "dialog: Go To ..."), "{out}");
    assert!(out.lines().any(|l| l.contains("cursor=00402000")), "{out}");
    let out = listing_state("Down,G,Alt-Left", Some("402000h"));
    assert!(out.lines().any(|l| l.contains("cursor=00401001")), "{out}");
    let out = listing_state("G", Some("401800"));
    assert!(out.lines().any(|l| l == "dialog status: No results for 401800"), "{out}");
}

#[test]
fn go_to_updates_the_status_bar_location() {
    // Typed into the real dialog, so focus is in the dialog when Rust's
    // ViewChanged arrives.
    let out = listing_state("G,4,0,2,0,0,3,Return", None);
    assert!(out.lines().any(|l| l.contains("cursor=00402003") && l.ends_with("status=00402003")), "{out}");
}

#[test]
fn keys_typed_in_the_go_to_dialog_do_not_run_tool_actions() {
    // No --prompt-answer: G opens the real dialog; Ctrl-F then goes to it.
    let out = listing_state("G,Ctrl-F", None);
    assert!(!out.lines().any(|l| l.starts_with("status: Find")), "{out}");
}

#[test]
fn opening_a_non_elf_file_fails_cleanly() {
    let out = shell().arg("--open").arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).output().expect("spawn");
    assert_eq!(out.status.code(), Some(66));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not an ELF file"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn opening_bin_ls_lists_its_memory() {
    let dist = std::env::var("GHIDRA_RS_GHIDRA_DIST")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/ghidra-dist/ghidra_12.1.2_PUBLIC").to_string());
    let Ok(bytes) = std::fs::read("/bin/ls") else { return };
    if !std::path::Path::new(&dist).is_dir() || bytes.len() < 64 || bytes[..4] != *b"\x7fELF" || bytes[18] != 62 {
        return; // needs the Ghidra dist and an x86-64 /bin/ls
    }
    let out = shell().env_var("GHIDRA_RS_GHIDRA_DIST", &dist).args(["--open", "/bin/ls", "--dump-listing", "8"]).output().expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 8, "{text}");
    // the first block's `//` header, then the image's first byte at Ghidra's
    // default 64-bit image base: ELF magic
    assert_eq!(lines[0].trim(), "//", "{text}");
    assert!(lines.iter().any(|l| l.contains("ram:0000000000100000-ram:")), "{text}");
    assert!(lines.contains(&"0000000000100000  7f  ??  7Fh"), "{text}");
}

#[test]
fn go_to_bin_ls_entry_shows_its_decoded_first_instruction() {
    let dist = std::env::var("GHIDRA_RS_GHIDRA_DIST")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/ghidra-dist/ghidra_12.1.2_PUBLIC").to_string());
    let Ok(bytes) = std::fs::read("/bin/ls") else { return };
    if !std::path::Path::new(&dist).is_dir() || bytes.len() < 64 || bytes[..4] != *b"\x7fELF" || bytes[4] != 2 || bytes[18] != 62 {
        return; // needs the Ghidra dist and an x86-64 /bin/ls
    }
    let e_entry = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap());
    let entry = if u16::from_le_bytes([bytes[16], bytes[17]]) == 3 { e_entry + 0x10_0000 } else { e_entry };
    let out = shell()
        .env_var("GHIDRA_RS_GHIDRA_DIST", &dist)
        .args(["--open", "/bin/ls", "--focus", "Listing", "--press", "G,Ctrl-C", "--prompt-answer", &format!("{entry:x}")])
        .args(["--print-clipboard", "--quit-after-ms", "4000"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let line = text.lines().find(|l| l.starts_with("clipboard: ")).unwrap_or_else(|| panic!("nothing copied: {text}"));
    // the cursor row at the entry: an instruction (multi-byte, not `??`), unless a label sits there
    if line.contains(&format!("{entry:016x}")) {
        assert!(!line.contains("??"), "entry is disassembled: {line}");
    }
    if bytes.windows(4).any(|w| w == [0xf3, 0x0f, 0x1e, 0xfa]) && text.contains("f3 0f 1e fa") {
        assert!(text.contains("ENDBR64"), "{text}");
    }
}

fn options_run(dir: &std::path::Path, answer: &str) -> String {
    let out = shell_with_config(dir)
        .args(["--invoke-menu", "Tool Options", "--prompt-answer", answer, "--press", "Escape", "--quit-after-ms", "2000"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn tool_options_dialog_edits_persist_across_restarts() {
    let dir = tmp("config-options");
    let _ = std::fs::remove_dir_all(&dir);
    let first = options_run(&dir, "Tool > Max Goto Entries=4");
    assert!(first.lines().any(|l| l == "dialog: Options for Ghidra-rs"), "{first}");
    assert!(first.lines().any(|l| l == "tree: Options"), "{first}");
    assert!(first.lines().any(|l| l == "form: Max Goto Entries=10"), "{first}");
    let second = options_run(&dir, "Tool");
    assert!(second.lines().any(|l| l == "form: Max Goto Entries=4"), "{second}");
}

#[test]
fn a_key_binding_set_in_tool_options_works_after_a_restart() {
    let dir = tmp("config-keys");
    let _ = std::fs::remove_dir_all(&dir);
    let first = options_run(&dir, "Key Bindings > Go To Address/Label=ctrl J");
    assert!(first.lines().any(|l| l == "row: Go To Address/Label=G"), "{first}");
    let out = shell_with_config(&dir)
        .args(["--focus", "Listing", "--press", "Ctrl-J", "--prompt-answer", "402000", "--print-listing-state", "--quit-after-ms", "2500"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.lines().any(|l| l == "dialog: Go To ..."), "Ctrl-J opens Go To: {text}");
    assert!(text.lines().any(|l| l.contains("cursor=00402000")), "{text}");
}

#[test]
fn every_posted_key_is_dispatched_even_when_its_event_reuses_a_freed_ones_address() {
    // Synthetic key events have no timestamp; one allocated where the previous
    // (freed) event lived must not be taken for that event's propagation.
    for run in 0..5 {
        let out = shell()
            .args(["--focus", "Listing", "--press", "G,Shift-Down,Ctrl-C", "--prompt-answer", "402000", "--print-clipboard", "--quit-after-ms", "3000"])
            .output()
            .expect("spawn");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(text.lines().any(|l| l.starts_with("clipboard: 00402000")), "run {run}: {text}");
    }
}

#[test]
fn ctrl_c_copies_the_listing_selection_to_the_clipboard() {
    let out = shell()
        .args(["--focus", "Listing", "--press", "Shift-Down,Ctrl-C", "--print-clipboard", "--quit-after-ms", "2000"])
        .output()
        .expect("spawn");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("clipboard: ")).collect();
    assert_eq!(lines, vec!["clipboard: 00401000  55          ??      55h", "clipboard: 00401001  48          ??      48h"], "{text}");
}

#[test]
fn switching_to_the_dark_theme_applies_and_persists() {
    let dir = tmp("config-theme");
    let _ = std::fs::remove_dir_all(&dir);
    let run = |extra: &[&str]| {
        let out = shell_with_config(&dir).args(extra).args(["--print-palette", "--quit-after-ms", "2000"]).output().expect("spawn");
        assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let first = run(&["--invoke-menu", "Switch...", "--prompt-answer", "Flat Dark Theme", "--press", "Escape"]);
    assert!(first.lines().any(|l| l == "dialog: Change Theme"), "{first}");
    assert!(first.lines().any(|l| l == "palette: base=#2a2a2a"), "{first}");
    let second = run(&[]);
    assert!(second.lines().any(|l| l == "palette: base=#2a2a2a"), "dark after restart: {second}");
}

#[test]
fn listing_dock_renders_undefined_bytes() {
    let out = shell().args(["--dump-listing", "3"]).output().expect("spawn");
    assert!(out.status.success(), "stderr {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        vec!["00401000  55  ??  55h", "00401001  48  ??  48h", "00401002  89  ??  89h"]
    );
}
