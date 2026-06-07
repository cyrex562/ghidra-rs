# Ghidra to Rust Port Todo List

## Foundation & Setup
- [x] Initial workspace and crate setup
- [x] Agent instruction files (GEMINI.md)
- [x] Sync check script (scripts/sync_check.py)
- [x] Initial Git repository setup
- [ ] Implement basic egui application shell
- [ ] Set up PyO3 integration for Python scripts
- [ ] Set up Wasmer integration for WASM plugins

## Phase 1: Core Framework (Ghidra/Framework)
- [ ] **Utility** (Ghidra/Framework/Utility)
- [ ] **Generic** (Ghidra/Framework/Generic)
- [ ] **SoftwareModeling** (Ghidra/Framework/SoftwareModeling)
- [ ] **DB** (Ghidra/Framework/DB)

## Phase 2: Core Features
- [ ] **ProgramDB** (Ghidra/Framework/Project)
- [ ] **Disassembler**
- [ ] **Decompiler** (Ghidra/Features/Decompiler)

## Phase 3: UI & Plugins
- [ ] Port Docking framework components
- [ ] Python plugin loader
- [ ] Rust plugin loader
- [ ] WASM plugin loader

## Maintenance
- [ ] Update `scripts/sync_check.py` to compare Java vs Rust progress
- [ ] Expand unit test coverage for each ported module
