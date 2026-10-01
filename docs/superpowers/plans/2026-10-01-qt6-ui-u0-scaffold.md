# Qt6 UI — U0 Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the three-crate UI architecture. The deliverable is a Qt6 Widgets `ghidra-qt` binary that opens an ADS-docked main window titled by the Rust `UiSession`. It has an offscreen screenshot smoke test, egui is removed from the repo, and AGENTS.md is switched to Qt6.

**Architecture:**
- `ghidra-ui-model` is a new pure-Rust crate. In U0 it holds only `UiSession`.
- `ghidra-qt` is a new binary crate. It owns a `cxx` bridge, a thin C++17 shell (`MainWindow` + ADS `CDockManager`) and a Cargo-driven `build.rs`. The build script uses `cxx-build` and `qt-build-utils` 0.10 for moc and rcc, and compiles the vendored ADS sources directly.
- `ghidra-rs` stays toolkit-free. Its two `egui::Color32` uses move to a new `util::awt::Color`.

**Tech Stack:**
- Rust 1.96 (edition 2021)
- `cxx` / `cxx-build` 1.0
- `qt-build-utils` 0.10 (default `qmake` feature)
- `cc` 1
- `clap` 4
- Qt 6.10 Widgets (dynamic, LGPL)
- Qt Advanced Docking System at commit `4f4f602c3f7b02ee041793e9bc5833bab1bdb4ab` (LGPL-2.1, git submodule)

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`. This plan covers **U0 only**. U1 (framework), U2 (listing), C1 (sleigh compiler and `.sla`) and C2 (disassembler and ELF import) each get their own plan, written when they are next.

## Global Constraints

- Toolkit is Qt6 **Widgets**. No QML, no egui, no Tauri.
- **C++ contains no domain logic.** It renders what Rust returns and forwards intents.
- Rust never calls back into C++. In U0 the only C++→Rust call is `session_title`.
- Panics never cross the bridge. Every `extern "Rust"` bridge function goes through `guard()` and returns `Result`.
- `ghidra-rs` and `ghidra-ui-model` must not depend on Qt, egui or any UI toolkit.
- The default workspace build and test (`cargo build` / `cargo test` at the root, and `cargo test --lib` in `ghidra-rs/`) must not need Qt. `ghidra-qt` is excluded from `default-members`.
- Prefix every cargo command with `CARGO_BUILD_JOBS=4`. No git worktrees, `CARGO_TARGET_DIR` or build output under `/tmp` or the scratchpad.
- Commit with explicit pathspecs only (`git commit -m "..." -- <paths>`). Never `git add -A`, never push, never force.
- Every commit message ends with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH
  ```
- **Human prerequisite** (Task 3 checks it): `sudo apt install qt6-base-dev qt6-base-private-dev` (`libxcb1-dev` is already installed). If it is missing, stop and report. Do not work around it.

## Review Focus

1. **Qt dev files or private headers missing.** `cargo build -p ghidra-qt` must fail with a message that names the packages to install, not with a cryptic compiler error. Task 3, Step 9.
2. **ADS submodule not initialized** (a fresh clone without `--recurse-submodules`). The build must fail with the exact `git submodule update --init` command. Task 3, Step 9.
3. **The default workspace build must not touch Qt.** `cargo check` at the root succeeds even with Qt unusable. Task 1, Step 6 and Task 3, Step 10.
4. **A Rust panic inside a bridge function** must become a C++ exception and an exit code, never an abort or an unwind into C++. Task 3, Step 2 (`guard` tests).
5. **Screenshot to an unwritable path** must exit with code 2 and a message, not crash. Task 4, Step 1.

---

### Task 1: `ghidra-ui-model` crate with `UiSession`

**Files:**
- Create: `ghidra-ui-model/Cargo.toml`
- Create: `ghidra-ui-model/src/lib.rs`
- Create: `ghidra-ui-model/src/session.rs`
- Modify: `Cargo.toml` (workspace root)

**Interfaces:**
- Consumes: nothing.
- Produces: `ghidra_ui_model::UiSession` with:
  - `pub fn new() -> UiSession`
  - `pub fn app_name(&self) -> &str`
  - `pub fn version(&self) -> &str`
  - `pub fn title(&self) -> String` (returns `"Ghidra-rs <version>"`)
  - `impl Default`
- Also produces: workspace `default-members` that excludes `ghidra-qt`.

- [ ] **Step 1: Create the crate manifest**

`ghidra-ui-model/Cargo.toml`:
```toml
[package]
name = "ghidra-ui-model"
version = "0.1.0"
edition = "2021"
description = "Toolkit-neutral UI model for ghidra-rs (no Qt/egui types allowed)"
license = "MIT"

[dependencies]
```

- [ ] **Step 2: Register it in the workspace**

Replace the root `Cargo.toml` workspace section with:
```toml
[workspace]
members = [
    "ghidra-rs",
    "ghidra-rs-macros",
    "ghidra-ui-model",
]
# ghidra-qt (added in Task 3) links Qt; keep it out of the default build so
# `cargo build` / `cargo test` at the root never require Qt.
default-members = [
    "ghidra-rs",
    "ghidra-rs-macros",
    "ghidra-ui-model",
]
resolver = "2"
```

- [ ] **Step 3: Write the failing tests**

`ghidra-ui-model/src/session.rs`:
```rust
//! The root UI-session object every renderer talks to.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_app_name_then_version() {
        let s = UiSession::new();
        assert_eq!(s.title(), format!("Ghidra-rs {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(UiSession::default().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(UiSession::default().app_name(), "Ghidra-rs");
    }
}
```

`ghidra-ui-model/src/lib.rs`:
```rust
//! Toolkit-neutral UI model for ghidra-rs.
//!
//! This crate is the contract between the Rust model and any renderer (the
//! `ghidra-qt` shell). It must never depend on Qt, egui or any other UI
//! toolkit. See `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`.

mod session;

pub use session::UiSession;
```

- [ ] **Step 4: Run the tests and verify they fail**

Run: `CARGO_BUILD_JOBS=4 cargo test -p ghidra-ui-model`
Expected: compile error `cannot find type UiSession in this scope`.

- [ ] **Step 5: Implement `UiSession`**

Put this above the `#[cfg(test)]` block in `ghidra-ui-model/src/session.rs`:
```rust
/// The application-wide UI session: the root object a renderer is handed at
/// startup. U1 grows this into the tool, provider and action registry.
#[derive(Debug, Clone)]
pub struct UiSession {
    app_name: String,
    version: String,
}

impl UiSession {
    /// Creates the session for this build of ghidra-rs.
    pub fn new() -> Self {
        Self {
            app_name: "Ghidra-rs".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Application name shown to users.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Application version (the crate version).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Main-window title, e.g. `"Ghidra-rs 0.1.0"`.
    pub fn title(&self) -> String {
        format!("{} {}", self.app_name, self.version)
    }
}

impl Default for UiSession {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 6: Run the tests and verify they pass; confirm the default build is Qt-free**

Run: `CARGO_BUILD_JOBS=4 cargo test -p ghidra-ui-model`
Expected: `test result: ok. 2 passed`.

Run: `CARGO_BUILD_JOBS=4 cargo metadata --format-version 1 --no-deps | python3 -c "import json,sys; m=json.load(sys.stdin); print(sorted(p['name'] for p in m['packages']))"`
Expected: `['ghidra-rs', 'ghidra-rs-macros', 'ghidra-ui-model']`.

- [ ] **Step 7: Commit**

```bash
git add ghidra-ui-model/Cargo.toml ghidra-ui-model/src/lib.rs ghidra-ui-model/src/session.rs
git commit -m "ui-model: new toolkit-neutral ghidra-ui-model crate with UiSession

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH" -- Cargo.toml Cargo.lock ghidra-ui-model
```

---

### Task 2: `util::awt::Color`, remove egui, headless `ghidra-rs` binary

**Files:**
- Create: `ghidra-rs/src/util/awt/mod.rs`
- Create: `ghidra-rs/src/util/awt/color.rs`
- Modify: `ghidra-rs/src/util/mod.rs` (add `pub mod awt;`)
- Modify: `ghidra-rs/src/script/decorating_print_writer.rs` (`egui::Color32` → `Color`)
- Modify: `ghidra-rs/src/app/plugin/core/debug/gui/model/colors_modified.rs` (`egui::Color32` → `Color`)
- Modify: `ghidra-rs/Cargo.toml` (remove `egui` and `eframe`)
- Modify: `ghidra-rs/src/main.rs` (replace the egui window with a headless entry point)

**Interfaces:**
- Consumes: nothing.
- Produces: `ghidra_rs::util::awt::Color`, a toolkit-neutral port of the `java.awt.Color` value. The full set (Font, KeyStroke, ActionTrigger, duplicate-Color consolidation) is a separate queued item that extends this module. It has:
  - `const fn from_rgb(r: u8, g: u8, b: u8) -> Color`
  - `const fn from_rgba(r: u8, g: u8, b: u8, a: u8) -> Color`
  - `const fn from_rgb_int(rgb: i32) -> Color` (Java `new Color(int)`)
  - `const fn from_argb_int(argb: i32) -> Color` (Java `new Color(int, true)`)
  - `const fn get_rgb(self) -> i32`
  - `const fn red/green/blue/alpha(self) -> u8`
  - consts `WHITE`, `BLACK`, `RED`, `GREEN`, `BLUE`

- [ ] **Step 1: Write the failing tests**

`ghidra-rs/src/util/awt/color.rs`:
```rust
//! Toolkit-neutral `java.awt.Color` value.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_constants_pack_as_java_get_rgb() {
        // java.awt.Color.RED.getRGB() == 0xFFFF0000 (as a signed int: -65536)
        assert_eq!(Color::RED.get_rgb(), 0xFFFF_0000_u32 as i32);
        assert_eq!(Color::GREEN.get_rgb(), 0xFF00_FF00_u32 as i32);
        assert_eq!(Color::BLUE.get_rgb(), 0xFF00_00FF_u32 as i32);
        assert_eq!(Color::WHITE.get_rgb(), -1);
        assert_eq!(Color::BLACK.get_rgb(), 0xFF00_0000_u32 as i32);
    }

    #[test]
    fn rgb_int_constructor_forces_opaque_alpha() {
        // new Color(0x12345678) ignores the top byte and sets alpha to 255.
        let c = Color::from_rgb_int(0x1234_5678);
        assert_eq!(c.get_rgb(), 0xFF34_5678_u32 as i32);
        assert_eq!((c.alpha(), c.red(), c.green(), c.blue()), (255, 0x34, 0x56, 0x78));
    }

    #[test]
    fn argb_int_constructor_keeps_alpha() {
        let c = Color::from_argb_int(0x8011_2233_u32 as i32);
        assert_eq!((c.alpha(), c.red(), c.green(), c.blue()), (0x80, 0x11, 0x22, 0x33));
        assert_eq!(c.get_rgb(), 0x8011_2233_u32 as i32);
    }

    #[test]
    fn rgba_components_round_trip() {
        let c = Color::from_rgba(1, 2, 3, 4);
        assert_eq!((c.red(), c.green(), c.blue(), c.alpha()), (1, 2, 3, 4));
        assert_eq!(Color::from_rgb(9, 8, 7).alpha(), 255);
    }
}
```

`ghidra-rs/src/util/awt/mod.rs`:
```rust
//! Toolkit-neutral ports of `java.awt` value types. Renderers (the
//! `ghidra-qt` shell) convert these at the UI edge; model code must never use
//! Qt or egui types. Decided 2026-10-01.

pub mod color;

pub use color::Color;
```

Add `pub mod awt;` to `ghidra-rs/src/util/mod.rs`, in alphabetical position among the existing `pub mod` lines.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo test --lib util::awt::color`
Expected: compile error `cannot find type Color in this scope` (in `color.rs` tests).

- [ ] **Step 3: Implement `Color`**

Put this above the `#[cfg(test)]` block in `color.rs`:
```rust
/// A port of the `java.awt.Color` value: sRGB components plus alpha, stored as
/// Java's packed ARGB. Only the value semantics are ported; painting belongs to
/// the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    argb: u32,
}

impl Color {
    /// `java.awt.Color.WHITE`
    pub const WHITE: Color = Color::from_rgb(255, 255, 255);
    /// `java.awt.Color.BLACK`
    pub const BLACK: Color = Color::from_rgb(0, 0, 0);
    /// `java.awt.Color.RED`
    pub const RED: Color = Color::from_rgb(255, 0, 0);
    /// `java.awt.Color.GREEN`
    pub const GREEN: Color = Color::from_rgb(0, 255, 0);
    /// `java.awt.Color.BLUE`
    pub const BLUE: Color = Color::from_rgb(0, 0, 255);

    /// Opaque color from components (`new Color(r, g, b)`).
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self::from_rgba(r, g, b, 255)
    }

    /// Color with alpha (`new Color(r, g, b, a)`).
    pub const fn from_rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self {
            argb: (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32,
        }
    }

    /// `new Color(int rgb)`: the top byte is ignored and alpha is 255.
    pub const fn from_rgb_int(rgb: i32) -> Self {
        Self {
            argb: 0xFF00_0000 | (rgb as u32 & 0x00FF_FFFF),
        }
    }

    /// `new Color(int argb, true)`: alpha taken from the top byte.
    pub const fn from_argb_int(argb: i32) -> Self {
        Self { argb: argb as u32 }
    }

    /// `getRGB()`: packed ARGB as Java's signed int.
    pub const fn get_rgb(self) -> i32 {
        self.argb as i32
    }

    /// `getRed()`
    pub const fn red(self) -> u8 {
        (self.argb >> 16) as u8
    }

    /// `getGreen()`
    pub const fn green(self) -> u8 {
        (self.argb >> 8) as u8
    }

    /// `getBlue()`
    pub const fn blue(self) -> u8 {
        self.argb as u8
    }

    /// `getAlpha()`
    pub const fn alpha(self) -> u8 {
        (self.argb >> 24) as u8
    }
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo test --lib util::awt::color`
Expected: `test result: ok. 4 passed`.

- [ ] **Step 5: Migrate the two egui users**

Edit only these two files.

In `ghidra-rs/src/script/decorating_print_writer.rs`:
- replace line 1, `use egui::Color32;`, with `use crate::util::awt::Color;`;
- replace every `Color32` token in the file with `Color`. The uses are `Color32::RED`, `Color32::GREEN` and `Color32::BLUE`, plus parameter types, all of which exist on `Color`.

In `ghidra-rs/src/app/plugin/core/debug/gui/model/colors_modified.rs`:
- replace line 1 with `use crate::util::awt::Color;`;
- replace every `Color32` token with `Color`. The uses are `Color32::from_rgb(..)`, `Color32::WHITE`, `Color32::BLACK` and type positions, all of which exist on `Color`.

Command (scoped to exactly these two files):
```bash
sed -i -e 's/^use egui::Color32;$/use crate::util::awt::Color;/' -e 's/\bColor32\b/Color/g' \
  ghidra-rs/src/script/decorating_print_writer.rs \
  ghidra-rs/src/app/plugin/core/debug/gui/model/colors_modified.rs
```
Then verify no egui reference remains in the crate:
Run: `grep -rn 'egui\|eframe' ghidra-rs/src ghidra-rs/Cargo.toml`
Expected: the `ghidra-rs/Cargo.toml` lines and `ghidra-rs/src/main.rs` only. Both are fixed in Steps 6–7.

- [ ] **Step 6: Remove the egui dependencies**

In `ghidra-rs/Cargo.toml`, delete these three lines:
```toml
# UI
egui = "0.28"
eframe = "0.28"
```

- [ ] **Step 7: Replace the egui window with a headless entry point**

Overwrite `ghidra-rs/src/main.rs` with:
```rust
//! Headless entry point for ghidra-rs. The desktop UI is the separate
//! `ghidra-qt` binary (see docs/superpowers/specs/2026-10-01-qt6-ui-design.md).

fn main() {
    println!(
        "ghidra-rs {} (headless). The desktop UI is the `ghidra-qt` binary.",
        env!("CARGO_PKG_VERSION")
    );
}
```

- [ ] **Step 8: Verify the build, tests and binary**

Run: `grep -rn 'egui\|eframe' ghidra-rs/`
Expected: no output.

Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo build --lib && CARGO_BUILD_JOBS=4 cargo test --lib 2>&1 | grep -E '^test result'`
Expected: `test result: ok. N passed; 0 failed`. N is at least 34717 plus the 4 new tests.

Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo run --bin ghidra-rs`
Expected output: `ghidra-rs 0.1.0 (headless). The desktop UI is the \`ghidra-qt\` binary.`

- [ ] **Step 9: Commit**

```bash
git add ghidra-rs/src/util/awt/mod.rs ghidra-rs/src/util/awt/color.rs
git commit -m "ui: toolkit-neutral util::awt::Color; remove egui/eframe; headless ghidra-rs main

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH" -- \
  ghidra-rs/src/util/awt ghidra-rs/src/util/mod.rs ghidra-rs/src/script/decorating_print_writer.rs \
  ghidra-rs/src/app/plugin/core/debug/gui/model/colors_modified.rs ghidra-rs/Cargo.toml \
  ghidra-rs/src/main.rs Cargo.lock
```

---

### Task 3: `ghidra-qt` shell (ADS submodule, build.rs, cxx bridge, MainWindow)

**Files:**
- Create: `.gitmodules` (via `git submodule add`)
- Create: `ghidra-qt/third_party/ads` (submodule, pinned)
- Create: `THIRD_PARTY_NOTICES.md`
- Create: `ghidra-qt/Cargo.toml`
- Create: `ghidra-qt/build.rs`
- Create: `ghidra-qt/src/main.rs`
- Create: `ghidra-qt/src/bridge.rs`
- Create: `ghidra-qt/src/guard.rs`
- Create: `ghidra-qt/src/cli.rs`
- Create: `ghidra-qt/cpp/app.h`
- Create: `ghidra-qt/cpp/app.cpp`
- Create: `ghidra-qt/cpp/main_window.h`
- Create: `ghidra-qt/cpp/main_window.cpp`
- Modify: `Cargo.toml` (add `ghidra-qt` to `members` only, not to `default-members`)

**Interfaces:**
- Consumes: `ghidra_ui_model::UiSession::{new, title}` (Task 1).
- Produces:
  - Binary `ghidra-qt` with flags `--screenshot <PNG>` and `--quit-after-ms <N>`. Exit codes:
    - 0 = ok
    - 2 = screenshot write failed
    - 3 = bridge error
    - 64 = usage error
  - `guard::guard<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String>`, the panic boundary every later bridge function must use.
  - `cli::Args` and `cli::validate(&Args) -> Result<(), String>`.
  - C++ `ghidra_qt::run_app(const UiSession&, const AppOptions&) -> int32_t`.
  - C++ `MainWindow(const QString& title)`, a 1200×800 window owning an `ads::CDockManager` with one `"Welcome"` dock widget.

- [ ] **Step 1: Check the human prerequisite (stop if missing)**

Run:
```bash
(command -v qmake6 || ls /usr/lib/qt6/bin/qmake 2>/dev/null) && \
ls /usr/include/x86_64-linux-gnu/qt6/QtGui/$(qtpaths6 --query QT_VERSION)/QtGui/qpa/qplatformnativeinterface.h
```
Expected: a qmake path and the header path, both printed.

If either is missing, **stop this task**. Report: "Human prerequisite missing: run `sudo apt install qt6-base-dev qt6-base-private-dev`". Do not continue and do not work around it.

- [ ] **Step 2: Write the failing tests for the panic guard and CLI validation**

`ghidra-qt/src/guard.rs`:
```rust
//! Panic boundary for every `extern "Rust"` bridge function: a panic must
//! never unwind into C++ (cxx would abort). The message is extracted at catch
//! time (see memory note on panic-payload eager extraction).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_value_passes_through() {
        assert_eq!(guard("f", || 7), Ok(7));
    }

    #[test]
    fn str_panic_becomes_err_with_context() {
        let r: Result<(), String> = guard("session_title", || panic!("boom"));
        assert_eq!(r, Err("session_title panicked: boom".to_owned()));
    }

    #[test]
    fn string_panic_becomes_err_with_context() {
        let r: Result<(), String> = guard("x", || panic!("{}", String::from("formatted 42")));
        assert_eq!(r, Err("x panicked: formatted 42".to_owned()));
    }
}
```

`ghidra-qt/src/cli.rs`:
```rust
//! Command-line options for the `ghidra-qt` binary.

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn interactive_launch_is_valid() {
        let a = Args::parse_from(["ghidra-qt"]);
        assert_eq!(validate(&a), Ok(()));
    }

    #[test]
    fn screenshot_requires_quit_after() {
        let a = Args::parse_from(["ghidra-qt", "--screenshot", "out.png"]);
        assert_eq!(
            validate(&a),
            Err("--screenshot requires --quit-after-ms > 0".to_owned())
        );
    }

    #[test]
    fn screenshot_with_quit_after_is_valid() {
        let a = Args::parse_from(["ghidra-qt", "--screenshot", "o.png", "--quit-after-ms", "500"]);
        assert_eq!(validate(&a), Ok(()));
    }
}
```

The crate cannot compile until Steps 4–8 exist. Step 9 runs these 6 tests. Until Step 5 adds `guard` and `validate`, they fail with `cannot find function`.

- [ ] **Step 3: Add the ADS submodule (pinned) and the notices file**

```bash
git submodule add https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System.git ghidra-qt/third_party/ads
git -C ghidra-qt/third_party/ads checkout 4f4f602c3f7b02ee041793e9bc5833bab1bdb4ab
```

Create `THIRD_PARTY_NOTICES.md`:
```markdown
# Third-party notices

## Qt 6 (https://www.qt.io)
The `ghidra-qt` binary links the Qt 6 libraries dynamically under the GNU LGPL v3.
Qt is not distributed in this repository.

## Qt Advanced Docking System (https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System)
Vendored as a git submodule at `ghidra-qt/third_party/ads` (commit 4f4f602c3f7b02ee041793e9bc5833bab1bdb4ab)
and compiled into `ghidra-qt`. Licensed under the GNU LGPL v2.1; its complete source is
the submodule, so users can modify and relink it.
```

- [ ] **Step 4: Crate manifest and workspace membership**

`ghidra-qt/Cargo.toml`:
```toml
[package]
name = "ghidra-qt"
version = "0.1.0"
edition = "2021"
description = "Qt6 Widgets desktop shell for ghidra-rs"
license = "MIT"
build = "build.rs"

[[bin]]
name = "ghidra-qt"
path = "src/main.rs"

[dependencies]
ghidra-ui-model = { path = "../ghidra-ui-model" }
cxx = "1.0"
clap = { version = "4.5", features = ["derive"] }

[build-dependencies]
cxx-build = "1.0"
cc = "1"
qt-build-utils = "0.10"
```

In the root `Cargo.toml`, add `"ghidra-qt",` to `members` only, after `"ghidra-ui-model",`. **Do not** add it to `default-members`.

- [ ] **Step 5: Implement `guard` and `cli`**

Put this above the tests in `ghidra-qt/src/guard.rs`:
```rust
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Runs `f`, converting a panic into `Err("<what> panicked: <message>")`.
/// Every `extern "Rust"` bridge function must return through this.
pub fn guard<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_owned()
        };
        format!("{what} panicked: {msg}")
    })
}
```

Put this above the tests in `ghidra-qt/src/cli.rs`:
```rust
use std::path::PathBuf;

use clap::Parser;

/// `ghidra-qt` command line.
#[derive(Debug, Parser)]
#[command(name = "ghidra-qt", version, about = "Ghidra-rs desktop UI (Qt6)")]
pub struct Args {
    /// Save a PNG of the main window just before quitting (needs --quit-after-ms).
    #[arg(long, value_name = "PNG")]
    pub screenshot: Option<PathBuf>,

    /// Quit automatically after this many milliseconds (0 = run interactively).
    #[arg(long, value_name = "MS", default_value_t = 0)]
    pub quit_after_ms: u32,
}

/// Rejects option combinations the shell cannot honour.
pub fn validate(args: &Args) -> Result<(), String> {
    if args.screenshot.is_some() && args.quit_after_ms == 0 {
        return Err("--screenshot requires --quit-after-ms > 0".to_owned());
    }
    Ok(())
}
```

- [ ] **Step 6: The cxx bridge and `main`**

`ghidra-qt/src/bridge.rs`:
```rust
//! The cxx bridge between the C++ Qt shell and the Rust UI model.
//! Rules (spec §3): C++ calls Rust for data only; Rust never calls back into
//! C++ widgets; every `extern "Rust"` function returns through `guard`.

use ghidra_ui_model::UiSession;

use crate::guard::guard;

#[cxx::bridge(namespace = "ghidra_qt")]
pub mod ffi {
    /// Startup options passed from `main` to the C++ shell.
    pub struct AppOptions {
        /// PNG path for the auto-quit screenshot; empty = none.
        pub screenshot_path: String,
        /// Auto-quit delay in ms; 0 = interactive.
        pub quit_after_ms: u32,
    }

    extern "Rust" {
        type UiSession;
        fn session_title(session: &UiSession) -> Result<String>;
    }

    unsafe extern "C++" {
        include!("ghidra-qt/cpp/app.h");
        fn run_app(session: &UiSession, options: &AppOptions) -> i32;
    }
}

fn session_title(session: &UiSession) -> Result<String, String> {
    guard("session_title", || session.title())
}
```

`ghidra-qt/src/main.rs`:
```rust
//! `ghidra-qt`: the Qt6 Widgets desktop shell for ghidra-rs.

mod bridge;
mod cli;
mod guard;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    if let Err(msg) = cli::validate(&args) {
        eprintln!("ghidra-qt: {msg}");
        std::process::exit(64);
    }
    let session = ghidra_ui_model::UiSession::new();
    let options = bridge::ffi::AppOptions {
        screenshot_path: args
            .screenshot
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        quit_after_ms: args.quit_after_ms,
    };
    std::process::exit(bridge::ffi::run_app(&session, &options));
}
```

- [ ] **Step 7: The C++ shell**

`ghidra-qt/cpp/app.h`:
```cpp
#pragma once
#include "rust/cxx.h"
#include <cstdint>

namespace ghidra_qt {
struct UiSession;
struct AppOptions;

// Creates the QApplication and main window and runs the event loop. Returns the
// process exit code: 0 ok, 2 screenshot write failed, 3 bridge error.
int32_t run_app(const UiSession& session, const AppOptions& options);
}  // namespace ghidra_qt
```

`ghidra-qt/cpp/main_window.h`:
```cpp
#pragma once
#include <QMainWindow>
#include <QString>

namespace ads {
class CDockManager;
}

namespace ghidra_qt {

// Top-level tool window. Owns the ADS dock manager; U1 populates it from the
// Rust DockLayout. Contains no domain logic.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString& title, QWidget* parent = nullptr);
    ads::CDockManager* dockManager() const { return m_dockManager; }

private:
    ads::CDockManager* m_dockManager;
};

}  // namespace ghidra_qt
```

`ghidra-qt/cpp/main_window.cpp`:
```cpp
#include "ghidra-qt/cpp/main_window.h"

#include <QLabel>

#include "DockManager.h"
#include "DockWidget.h"

namespace ghidra_qt {

MainWindow::MainWindow(const QString& title, QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(title);
    resize(1200, 800);
    // Config flags must be set before the dock manager is created.
    ads::CDockManager::setConfigFlag(ads::CDockManager::OpaqueSplitterResize, true);
    m_dockManager = new ads::CDockManager(this);

    auto* label = new QLabel(QStringLiteral("%1 — Qt shell scaffold").arg(title));
    label->setAlignment(Qt::AlignCenter);
    auto* dock = new ads::CDockWidget(m_dockManager, QStringLiteral("Welcome"));
    dock->setWidget(label);
    m_dockManager->addDockWidget(ads::CenterDockWidgetArea, dock);
}

}  // namespace ghidra_qt
```

`ghidra-qt/cpp/app.cpp`:
```cpp
#include "ghidra-qt/cpp/app.h"

#include <QApplication>
#include <QPixmap>
#include <QString>
#include <QTimer>
#include <cstdio>

#include "ghidra-qt/cpp/main_window.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString toQString(const rust::String& s) {
    return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size()));
}
}  // namespace

int32_t run_app(const UiSession& session, const AppOptions& options) {
    static int argc = 1;
    static char arg0[] = "ghidra-qt";
    static char* argv[] = {arg0, nullptr};
    QApplication app(argc, argv);

    QString title;
    try {
        title = toQString(session_title(session));
    } catch (const rust::Error& e) {
        std::fprintf(stderr, "ghidra-qt: %s\n", e.what());
        return 3;
    }

    MainWindow window(title);
    window.show();

    if (options.quit_after_ms > 0) {
        const QString shot = toQString(options.screenshot_path);
        QTimer::singleShot(static_cast<int>(options.quit_after_ms), &app, [&app, &window, shot]() {
            if (!shot.isEmpty() && !window.grab().save(shot, "PNG")) {
                std::fprintf(stderr, "ghidra-qt: could not write screenshot to %s\n",
                             shot.toUtf8().constData());
                app.exit(2);
                return;
            }
            app.exit(0);
        });
    }
    return app.exec();
}

}  // namespace ghidra_qt
```

- [ ] **Step 8: `build.rs`**

`ghidra-qt/build.rs`:
```rust
//! Builds the C++ Qt shell: cxx bridge + vendored ADS + moc/rcc, linked
//! against Qt6 Core/Gui/Widgets (dynamic, LGPL). See spec §2.

use std::env;
use std::path::{Path, PathBuf};

const QT_MODULES: [&str; 3] = ["Core", "Gui", "Widgets"];

/// ADS translation units (src/*.cpp at the pinned commit).
const ADS_SOURCES: &[&str] = &[
    "AutoHideDockContainer.cpp", "AutoHideSideBar.cpp", "AutoHideTab.cpp",
    "DockAreaTabBar.cpp", "DockAreaTitleBar.cpp", "DockAreaWidget.cpp",
    "DockComponentsFactory.cpp", "DockContainerWidget.cpp", "DockFocusController.cpp",
    "DockManager.cpp", "DockOverlay.cpp", "DockSplitter.cpp", "DockWidget.cpp",
    "DockWidgetTab.cpp", "DockingStateReader.cpp", "ElidingLabel.cpp",
    "FloatingDockContainer.cpp", "FloatingDragPreview.cpp", "IconProvider.cpp",
    "PushButton.cpp", "ResizeHandle.cpp", "ads_globals.cpp",
];

/// ADS headers declaring Q_OBJECT classes (need moc).
const ADS_MOC_HEADERS: &[&str] = &[
    "AutoHideDockContainer.h", "AutoHideSideBar.h", "AutoHideTab.h", "DockAreaTabBar.h",
    "DockAreaTitleBar.h", "DockAreaTitleBar_p.h", "DockAreaWidget.h", "DockContainerWidget.h",
    "DockFocusController.h", "DockManager.h", "DockOverlay.h", "DockSplitter.h", "DockWidget.h",
    "DockWidgetTab.h", "ElidingLabel.h", "FloatingDockContainer.h", "FloatingDragPreview.h",
    "PushButton.h", "ResizeHandle.h",
];

fn main() {
    let ads = env::var_os("GHIDRA_QT_ADS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("third_party/ads/src"));
    if !ads.join("DockManager.h").exists() {
        panic!(
            "ghidra-qt: ADS sources not found at {}. Run `git submodule update --init ghidra-qt/third_party/ads`.",
            ads.display()
        );
    }
    let linux = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");

    let mut qt = qt_build_utils::QtBuild::new(QT_MODULES.iter().map(|m| m.to_string()).collect())
        .unwrap_or_else(|e| {
            panic!(
                "ghidra-qt: Qt6 development files not found ({e}). Install them with \
                 `sudo apt install qt6-base-dev qt6-base-private-dev` (spec §8)."
            )
        });
    let version = qt.version();
    if version.major != 6 {
        panic!("ghidra-qt: Qt 6 is required, found Qt {version}");
    }

    let mut includes = qt.include_paths();
    // ADS includes <qpa/qplatformnativeinterface.h>, a QtGui private header.
    let headers = qt_headers_dir(&includes);
    for module in ["QtCore", "QtGui"] {
        let versioned = headers.join(module).join(version.to_string());
        let private_root = versioned.join(module);
        if !private_root.join("private").exists() {
            panic!(
                "ghidra-qt: Qt private headers missing at {}. Install `qt6-base-private-dev`.",
                private_root.display()
            );
        }
        includes.push(versioned);
        includes.push(private_root);
    }
    includes.push(ads.clone());

    let moc_args = || qt_build_utils::MocArguments::default().include_paths(includes.clone());
    let mut moc_cpp = Vec::new();
    for header in ADS_MOC_HEADERS {
        moc_cpp.push(qt.moc().compile(ads.join(header), moc_args()).cpp);
    }
    if linux {
        moc_cpp.push(qt.moc().compile(ads.join("linux/FloatingWidgetTitleBar.h"), moc_args()).cpp);
    }
    moc_cpp.push(qt.moc().compile("cpp/main_window.h", moc_args()).cpp);
    let resources = qt.rcc().compile(ads.join("ads.qrc"));

    let mut build = cxx_build::bridge("src/bridge.rs");
    build
        .std("c++17")
        .define("ADS_STATIC", None)
        .includes(&includes)
        .files(ADS_SOURCES.iter().map(|f| ads.join(f)))
        .files(&moc_cpp)
        .files(resources.file.iter())
        .file("cpp/app.cpp")
        .file("cpp/main_window.cpp")
        .warnings(false); // third-party ADS; our own files are reviewed instead
    if linux {
        build.file(ads.join("linux/FloatingWidgetTitleBar.cpp"));
        println!("cargo:rustc-link-lib=xcb");
    }
    qt.cargo_link_libraries(&mut build);
    build.compile("ghidra_qt_shell");

    for path in ["src/bridge.rs", "cpp", "build.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed={}", ads.display());
    println!("cargo:rerun-if-env-changed=GHIDRA_QT_ADS_DIR");
}

/// The directory containing `QtCore/`, `QtGui/`, ... (parent of the QtCore include path).
fn qt_headers_dir(includes: &[PathBuf]) -> PathBuf {
    includes
        .iter()
        .find(|p| p.ends_with("QtCore"))
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .expect("ghidra-qt: could not locate the Qt headers directory (no QtCore include path)")
}
```

- [ ] **Step 9: Build, run the unit tests, and check the failure messages (Review Focus 1–2, 4)**

Run: `CARGO_BUILD_JOBS=4 cargo build -p ghidra-qt 2>&1 | tail -3`
Expected: `Finished`. If moc reports a header with no Q_OBJECT, remove it from `ADS_MOC_HEADERS`. If the linker reports a missing `moc_*` symbol, add that header. The list above was derived from `grep -l Q_OBJECT src/*.h` at the pinned commit.

Run: `CARGO_BUILD_JOBS=4 cargo test -p ghidra-qt --bins`
Expected: `test result: ok. 6 passed` (3 `guard`, 3 `cli`).

Run: `GHIDRA_QT_ADS_DIR=/nonexistent CARGO_BUILD_JOBS=4 cargo build -p ghidra-qt 2>&1 | grep -o 'Run `git submodule update --init ghidra-qt/third_party/ads`'`
Expected: that line is printed.

Run: `QMAKE=/nonexistent/qmake CARGO_BUILD_JOBS=4 cargo build -p ghidra-qt 2>&1 | grep -o 'sudo apt install qt6-base-dev qt6-base-private-dev'`
Expected: that line is printed.

After both negative checks, run `CARGO_BUILD_JOBS=4 cargo build -p ghidra-qt` again so the build script's cached state is clean.

- [ ] **Step 10: Confirm the default workspace build is still Qt-free (Review Focus 3)**

Run: `QMAKE=/nonexistent/qmake CARGO_BUILD_JOBS=4 cargo check 2>&1 | tail -1`
Expected: `Finished` (ghidra-qt is not in `default-members`).

- [ ] **Step 11: Interactive sanity check (if a display is available; otherwise skip and say so)**

Run: `CARGO_BUILD_JOBS=4 cargo run -p ghidra-qt`
Expected: a 1200×800 window titled "Ghidra-rs 0.1.0" with a docked "Welcome" tab. Close it; the exit code is 0.

- [ ] **Step 12: Commit**

```bash
git add .gitmodules ghidra-qt/third_party/ads THIRD_PARTY_NOTICES.md ghidra-qt/Cargo.toml ghidra-qt/build.rs \
  ghidra-qt/src ghidra-qt/cpp
git commit -m "ghidra-qt: Qt6 Widgets shell with ADS docking, cxx bridge and panic guard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH" -- \
  .gitmodules ghidra-qt THIRD_PARTY_NOTICES.md Cargo.toml Cargo.lock
```

---

### Task 4: Offscreen smoke tests

**Files:**
- Create: `ghidra-qt/tests/smoke.rs`

**Interfaces:**
- Consumes: the `ghidra-qt` binary and its exit codes (Task 3).
- Produces: `cargo test -p ghidra-qt --test smoke`, the harness that later milestones extend with dock, scroll and screenshot scenarios.

- [ ] **Step 1: Write the tests**

`ghidra-qt/tests/smoke.rs`:
```rust
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
```

- [ ] **Step 2: Run the tests**

Run: `CARGO_BUILD_JOBS=4 cargo test -p ghidra-qt --test smoke`
Expected: `test result: ok. 4 passed`.

These tests exercise behaviour Task 3 already implemented, so they pass immediately. To prove they detect a regression, temporarily change `resize(1200, 800)` to `resize(1000, 800)` in `main_window.cpp` and re-run. `offscreen_launch_writes_main_window_screenshot` must FAIL with `(1000, 800)`. Then revert the change and re-run until green.

- [ ] **Step 3: Save the screenshot for the human review gate**

Run: `ls -la target/tmp/smoke_main_window.png` (the `CARGO_TARGET_TMPDIR` path).
Expected: the file exists. Cite its path in the task report.

- [ ] **Step 4: Commit**

```bash
git add ghidra-qt/tests/smoke.rs
git commit -m "ghidra-qt: offscreen smoke tests (screenshot, exit codes, version)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH" -- ghidra-qt/tests/smoke.rs
```

---

### Task 5: Switch AGENTS.md and the brief to Qt6

**Files:**
- Modify: `AGENTS.md`: the "Project Objectives" UI bullet, the "UI / Swing rule" section, and the "Current Porting State" UI line
- Modify: `.claude/descent_batch_brief.md` (append a short "Qt6 UI" note)

**Interfaces:**
- Consumes: the spec path and the crate names from Tasks 1–3.
- Produces: repo guidance that later UI plans (U1, U2) rely on.

- [ ] **Step 1: Edit AGENTS.md**

Replace the objectives bullet `- Use \`egui\` for the UI, with native and WASM support.` with:
```markdown
- Desktop UI in **Qt6 Widgets**: a thin C++17 shell (`ghidra-qt/`) over a toolkit-neutral Rust UI
  model (`ghidra-ui-model/`), joined by a `cxx` bridge. Desktop only (Linux, Windows, macOS); WASM
  remains a target for scripts/plugins, not the UI. Design: `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`.
```

Replace the whole `### UI / Swing rule` section body with:
```markdown
Swing→Qt is a redesign, not a mechanical port. The architecture is fixed by
`docs/superpowers/specs/2026-10-01-qt6-ui-design.md`:
- Plugins stay pure Rust and describe panes through `ghidra-ui-model` view-model traits
  (table/tree/text/form/listing/custom). C++ in `ghidra-qt/` contains no domain logic.
- `ghidra-rs` and `ghidra-ui-model` must never depend on Qt, egui or any toolkit; `java.awt`
  values use `ghidra_rs::util::awt` types.
- UI work is agent-executable **within an approved UI plan** (`docs/superpowers/plans/`). Park
  (`needs-attention`, label `ui`) for: a new `ViewKind`, any UX deviation from Ghidra's layout/
  actions/keybindings, or a Swing class with no plan covering it.
- `ghidra-qt` is excluded from `default-members`; build/test it with `cargo build -p ghidra-qt` /
  `cargo test -p ghidra-qt` (needs `qt6-base-dev qt6-base-private-dev`).
```

In "Current Porting State", replace `The UI shell exists but Swing→egui work is human-directed (see UI rule).` with `The Qt6 UI shell lives in ghidra-qt/ (see UI rule).`

- [ ] **Step 2: Verify the edits**

Run: `grep -n 'egui' AGENTS.md`
Expected: matches only inside the new "must never depend on Qt, egui" rule line.

Run: `grep -c 'qt6-ui-design.md' AGENTS.md`
Expected: `2`.

- [ ] **Step 3: Append the brief note**

Append to `.claude/descent_batch_brief.md`:
```markdown

## Qt6 UI (2026-10-01)
UI toolkit is Qt6 Widgets (spec docs/superpowers/specs/2026-10-01-qt6-ui-design.md). Never add
egui/Qt types to ghidra-rs or ghidra-ui-model; java.awt values use ghidra_rs::util::awt. Swing-heavy
classes still park with `ui` unless a UI plan in docs/superpowers/plans/ covers them.
```
(`.claude/` is untracked, so this file is not committed.)

- [ ] **Step 4: Commit**

```bash
git commit -m "docs: AGENTS.md switches the UI to Qt6 (ghidra-qt + ghidra-ui-model)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01W5P7Tt86T5UaoJCxC5WjYH" -- AGENTS.md
```

---

## Milestone gate (after Task 5)

Human review:
1. The offscreen screenshot `target/tmp/smoke_main_window.png`.
2. On a desktop: `cargo run -p ghidra-qt`. Check that the "Welcome" dock tab can be undocked into a floating window and re-docked, and that the window title reads "Ghidra-rs 0.1.0".
3. Approve U0. Then the **U1 (framework) plan** is written, against the spec §3–4.
