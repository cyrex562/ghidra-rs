# Ghidra to Rust Port Todo List

## Foundation & Setup

- [x] Initial workspace and crate setup
- [x] Agent instruction file (AGENTS.md)
- [x] Sync check script (scripts/sync_check.py)
- [x] Initial Git repository setup
- [x] Implement basic egui application shell
- [x] Set up PyO3 integration for Python scripts
- [x] Set up Wasmer integration for WASM plugins

## Phase 1: Core Framework (Ghidra/Framework)

### Utility (Ghidra/Framework/Utility)

- [x] `OperatingSystem` (os.rs)
- [x] `ApplicationVersion` (version.rs)
- [x] **Low-Dependency Essentials**
  - [x] `Msg` (Logging/Messaging)
  - [x] `ErrorLogger` / `DefaultErrorLogger`
  - [x] `ErrorDisplay` / `ConsoleErrorDisplay`
  - [x] `MessageType`
  - [x] `SystemUtilities`
  - [x] `PluggableServiceRegistry`
- [x] **Data Structures & Exceptions**
  - [x] `Duo` (Pair)
  - [x] `Range`
  - [x] `UsrException` / `AssertException` / `CancelledException`
- [x] **IO & Files**
  - [x] `BoundedInputStream`
  - [x] `NullOutputStream`
  - [x] `HashingOutputStream`
  - [x] `Resource` / `FileResource` / `ResourceFile` (Standard file support; JAR support TODO)
- [x] **Concurrency & Execution**
  - [x] `Callback` / `Dummy` / `Exceptional*`
  - [x] `NamedDaemonThreadFactory` (Implemented via `rayon::ThreadPoolBuilder`)
  - [x] `GThreadPool` (Implemented via `rayon`)

### Generic (Ghidra/Framework/Generic)

- [x] **Foundational Types**
  - [x] `CRC64` (algorithms/crc64.rs)
  - [x] `Complex` (complex/mod.rs)
  - [x] `Factory` (cache/mod.rs)
  - [x] `ConcurrentListenerSet` (concurrent/listener_set.rs)
- [x] **Algorithms & Cache**
  - [x] `Lcs` (Longest Common Subsequence)
  - [x] `WordDiffer`
  - [x] `CachingPool`
  - [x] `WeakReferenceCache`
- [x] **Concurrency**
  - [x] `ConcurrentQ`
  - [x] `ProgressTracker`

### SoftwareModeling (Ghidra/Framework/SoftwareModeling)

  - [x] **Foundational Modeling Types**
  - [x] `AddressFormatException` (program/model/address/address_format_exception.rs)
  - [x] `AddressLabelPair` (program/model/symbol/address_label_pair.rs)
  - [x] `AddressSpace` (program/model/address/mod.rs)
  - [x] `Address` (program/model/address/mod.rs)
  - [x] `EquateReference` (program/model/symbol/equate_reference.rs)
  - [x] `ExternalPath` (program/model/symbol/external_path.rs)
  - [x] `IllegalCharCppTransformer` (program/model/symbol/illegal_char_cpp_transformer.rs)
  - [x] `IdentityNameTransformer` / `NameTransformer` (program/model/symbol/name_transformer.rs)
  - [x] `InvalidAddressException` (program/model/mem/invalid_address_exception.rs)
  - [x] `LabelHistory` (program/model/symbol/label_history.rs)
  - [x] `MemoryConstants` (program/model/mem/memory_constants.rs)
  - [x] `MemoryBlockException` (program/model/mem/memory_block_exception.rs)
  - [x] `MemoryBlockListener` (program/model/mem/memory_block_listener.rs)
  - [x] `MemoryBlockStub` (program/model/mem/memory_block_stub.rs)
  - [x] `MemoryBlockType` (program/model/mem/memory_block_type.rs)
  - [x] `MemoryConflictException` (program/model/mem/memory_conflict_exception.rs)
  - [x] `SegmentMismatchException` (program/model/address/segment_mismatch_exception.rs)
  - [x] `SymbolIterator` / `SymbolIteratorAdapter` (program/model/symbol/symbol_iterator.rs)
  - [x] `Varnode` (program/model/pcode/mod.rs)
  - [x] `PcodeOp` (program/model/pcode/mod.rs)
- [ ] **SLA Loading**
  - [x] `PackedDecode` (Low-level parser)
  - [x] `SleighLanguage` (Loader and high-level structure)
  - [x] Instruction Decision Tree (Parsing/Decoding)
  - [x] Instruction Resolution Logic (`resolve`)

### DB (Ghidra/Framework/DB)

- [x] `Field` types and serialization (field.rs)
- [x] `Buffer` and `DataBuffer` (buffer.rs)
- [x] `ChainedBuffer` (chained_buffer.rs)
- [x] `Schema` (schema.rs)
- [x] `DBRecord` (record.rs)
- [x] `DBHandle` (High-level database management)
- [x] `Table` and `Index` implementation (B-Tree nodes, splitting, etc.)

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

## Future

- [ ] SQlite Database
- [ ] Standard file formats for SLA, etc
- [ ] YARA signatures?
- [ ] MCP support?
- [ ] Simplification
- [ ] Reduce/Eliminate use of Unwrap
