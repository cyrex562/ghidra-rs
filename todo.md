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
  - [x] `AddressCollectors` (program/model/address/address_collectors.rs)
  - [x] `AddressFormatException` (program/model/address/address_format_exception.rs)
  - [x] `AddressFactory` / `DefaultAddressFactory` (program/model/address/factory.rs)
  - [x] `AddressIterator` / `AddressIteratorAdapter` / `EmptyAddressIterator` (program/model/address/iterator.rs)
  - [x] `AddressLabelPair` (program/model/symbol/address_label_pair.rs)
  - [x] `AddressMapImpl` (program/model/address/address_map_impl.rs)
  - [x] `AddressObjectMap` (program/model/address/address_object_map.rs)
  - [x] `AddressSetMapping` (program/model/address/address_set_mapping.rs)
  - [x] `AddressOutOfBoundsException` (program/model/address/address_out_of_bounds_exception.rs)
  - [x] `AddressOverflowException` (program/model/address/address_overflow_exception.rs)
  - [x] `AddressRange` intersection/comparison/iteration methods (program/model/address/range.rs)
  - [x] `AddressRangeIterator` / `EmptyAddressRangeIterator` (program/model/address/iterator.rs)
  - [x] `AddressRangeToAddressComparator` (program/model/address/address_range_to_address_comparator.rs)
  - [x] `AddressSet` / `AddressSetView` (program/model/address/address_set.rs)
  - [x] `AddressSetCollection` / `SingleAddressSetCollection` (program/model/address/address_set_collection.rs)
  - [x] `AddressSetViewAdapter` (program/model/address/address_set_view_adapter.rs)
  - [x] `AddressRangeChunker` / `AddressRangeSplitter` (program/model/address/range_splitter.rs)
  - [x] `AddressSpace` (program/model/address/mod.rs)
  - [x] `Address` (program/model/address/mod.rs)
  - [x] `GenericAddress` / `GenericAddressSpace` behavior (program/model/address/mod.rs)
  - [x] `GlobalNamespace` / `GlobalSymbol` (program/model/address/global_namespace.rs)
  - [x] `EntryPointReference` (program/model/symbol/entry_point_reference.rs)
  - [x] `Equate` (program/model/symbol/equate.rs)
  - [x] `EquateReference` (program/model/symbol/equate_reference.rs)
  - [x] `EquateTable` (program/model/symbol/equate_table.rs)
  - [x] `ExternalPath` (program/model/symbol/external_path.rs)
  - [x] `IllegalCharCppTransformer` (program/model/symbol/illegal_char_cpp_transformer.rs)
  - [x] `IdentityNameTransformer` / `NameTransformer` (program/model/symbol/name_transformer.rs)
  - [x] `InvalidAddressException` (program/model/mem/invalid_address_exception.rs)
  - [x] `ImmutableAddressSet` (program/model/address/immutable_address_set.rs)
  - [x] `KeyRange` (program/model/address/key_range.rs)
  - [x] `LabelHistory` (program/model/symbol/label_history.rs)
  - [x] `MemReferenceImpl` (program/model/symbol/mem_reference_impl.rs)
  - [x] `MemoryConstants` (program/model/mem/memory_constants.rs)
  - [x] `MemoryBlockException` (program/model/mem/memory_block_exception.rs)
  - [x] `MemoryBlockListener` (program/model/mem/memory_block_listener.rs)
  - [x] `MemoryBlockStub` (program/model/mem/memory_block_stub.rs)
  - [x] `MemoryBlockType` (program/model/mem/memory_block_type.rs)
  - [x] `MemoryConflictException` (program/model/mem/memory_conflict_exception.rs)
  - [x] `OffsetReference` (program/model/symbol/offset_reference.rs)
  - [x] `OldGenericNamespaceAddress` (program/model/address/old_generic_namespace_address.rs)
  - [x] `OverlayAddressSpace` (program/model/address/overlay_address_space.rs)
  - [x] `RefType` / `DataRefType` / `FlowType` (program/model/symbol/ref_type.rs)
  - [x] `RefTypeFactory` static lookup and type groups (program/model/symbol/ref_type_factory.rs)
  - [x] `Reference` / `DynamicReference` (program/model/symbol/reference.rs)
  - [x] `ReferenceIterator` / `ReferenceIteratorAdapter` (program/model/symbol/reference_iterator.rs)
  - [x] `ReferenceListener` (program/model/symbol/reference_listener.rs)
  - [x] `SegmentMismatchException` (program/model/address/segment_mismatch_exception.rs)
  - [x] `SegmentedAddress` / `SegmentedAddressSpace` / `ProtectedAddressSpace` (program/model/address/segmented_address.rs)
  - [x] `SpecialAddress` (program/model/address/special_address.rs)
  - [x] `ShiftedReference` (program/model/symbol/shifted_reference.rs)
  - [x] `SourceType` (program/model/symbol/source_type.rs)
  - [x] `StackReference` (program/model/symbol/stack_reference.rs)
  - [x] `SymbolIterator` / `SymbolIteratorAdapter` (program/model/symbol/symbol_iterator.rs)
  - [x] `SymbolTableListener` (program/model/symbol/symbol_table_listener.rs)
  - [x] `SymbolType` (program/model/symbol/symbol_type.rs)
  - [x] `SymbolUtilities` name/address utilities (program/model/symbol/symbol_utilities.rs)
  - [x] `ThunkReference` (program/model/symbol/thunk_reference.rs)
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

## Post-Port: native Rust equivalents (NOT direct ports)

These Java areas are intentionally excluded from the automated porting queue (absent
from `scripts/port_layout.tsv`). Rather than translating them, build Rust-native
equivalents once the core port is complete. Each is a topic, not a 1:1 port.

- [ ] **Test infrastructure** — a Rust-native test harness/fixtures replacing
  `ghidra.test`, `ghidra.project.test` (don't port JUnit scaffolding).
- [ ] **Example programs & scripts** — re-create representative samples for
  `ghidra.examples`/`examples2`, `skeleton`, `ghidraclass`, `experiments`, and the
  demo `ghidra_scripts/*.java` as idiomatic Rust/Python examples.
- [ ] **Developer tooling / launchers** — Rust-appropriate replacements for
  `ghidradev` (Eclipse plugin), `ghidra.launch`, `ghidra.macosx`, `ghidra.lifecycle`.
- [ ] **Docs & help system** — regenerate `help` / screenshots from Rust docs
  tooling instead of porting the Java help framework.
- [ ] **Javadoc doclets** — replace `ghidra.doclets` with rustdoc-based generation.
