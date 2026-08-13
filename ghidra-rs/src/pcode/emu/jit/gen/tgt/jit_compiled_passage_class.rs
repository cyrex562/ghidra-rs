//! Port of `ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass`.
//!
//! A compiled passage that is not yet bound/instantiated to a thread.
//!
//! This is the output of `JitCompiler::compilePassage(Lookup, JitPassage)`, and it will be cached
//! (indirectly) by `JitPcodeEmulator`. The emulator actually caches the various entry points
//! returned by [`get_block_entries`](JitCompiledPassageClass::get_block_entries). Each of those
//! retains a reference to this object. An `EntryPointPrototype` pairs this with an entry block id.
//! That prototype can then be instantiated/bound to a thread, producing an `EntryPoint`. That
//! bound entry point is produced by invoking
//! [`create_instance`](JitCompiledPassageClass::create_instance) and just copying the block id.
//!
//! # Deviation from Java
//!
//! Java's record wraps three JVM reflection handles -- a `Lookup`, a `Class<? extends
//! JitCompiledPassage>`, and a `MethodHandle` -- and uses them to reflectively load a dynamically
//! generated classfile (`Lookup.defineHiddenClass`), find its constructor
//! (`Lookup.findConstructor`), and read its static `ENTRIES` field
//! (`Lookup.findStaticGetter`). This crate has no JVM and no bytecode loader (see
//! [`crate::pcode::seam_stubs::MethodVisitor`], which *records* emitted bytecode rather than
//! running it), so there is no classfile to reflect over. Instead, this port takes the
//! constructor and entry list directly -- the same information the real class would have
//! extracted reflectively -- as a typed closure and a `Vec` respectively. The closure's Rust type
//! already encodes what Java's `CONSTRUCTOR_TYPE` (`MethodType.methodType(void.class,
//! JitPcodeThread.class)`) exists to check at reflection time, so no analog of that constant is
//! needed here.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::seam_stubs::{AddrCtx, EntryPointPrototype, JitCompiledPassage, JitPcodeThread};

/// A compiled passage class: the generated constructor for binding a passage to a thread, plus
/// its block-indexed entry targets.
///
/// Port of `ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass`.
#[derive(Clone)]
pub struct JitCompiledPassageClass {
    /// Constructs a bound instance of the generated passage for the given thread. Stands in for
    /// Java's `constructor: MethodHandle`, invoked reflectively with a single `JitPcodeThread`
    /// argument.
    constructor: Arc<dyn Fn(&JitPcodeThread) -> Box<dyn JitCompiledPassage> + Send + Sync>,
    /// The passage's entry targets. The position of each target in this list corresponds to the
    /// block id accepted by the generated `JitCompiledPassage::run(int)` method. Stands in for
    /// the reflected static `ENTRIES` field Java's [`get_block_entries`](Self::get_block_entries)
    /// reads via `lookup`/`cls`.
    entries: Vec<AddrCtx>,
}

impl JitCompiledPassageClass {
    /// Wrap an already-produced constructor and entry list.
    ///
    /// Stands in for the static factory `JitCompiledPassageClass.load(Lookup, byte[])`, which
    /// reflectively defines a hidden class from `bytes` and extracts its constructor. This port
    /// has no bytecode to define a class from, so it takes the constructor (and the entry list
    /// Java would later reflect off the loaded class) directly.
    pub fn new(
        constructor: Arc<dyn Fn(&JitPcodeThread) -> Box<dyn JitCompiledPassage> + Send + Sync>,
        entries: Vec<AddrCtx>,
    ) -> Self {
        Self { constructor, entries }
    }

    /// Create an instance bound to the given thread.
    ///
    /// Port of `JitCompiledPassageClass.createInstance(JitPcodeThread)`.
    pub fn create_instance(&self, thread: &JitPcodeThread) -> Box<dyn JitCompiledPassage> {
        (self.constructor)(thread)
    }

    /// Get the entry points for this compiled passage.
    ///
    /// This processes the entry list, which is just a list of targets. The position of each
    /// target in the list corresponds to the block id accepted by the generated
    /// `JitCompiledPassage::run(int)` method.
    ///
    /// Port of `JitCompiledPassageClass.getBlockEntries()`.
    pub fn get_block_entries(&self) -> HashMap<AddrCtx, EntryPointPrototype> {
        self.entries
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, target)| (target, EntryPointPrototype::new(self.clone(), i as i32)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::instruction_decoder::InstructionDecoder;
    use crate::pcode::exec::pcode_userop_library::{
        ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn ram(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct DummyDecoder;
    impl InstructionDecoder for DummyDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn crate::pcode::seam_stubs::RegisterValue>,
        ) -> Result<Box<dyn crate::pcode::seam_stubs::PseudoInstruction>, Box<dyn std::error::Error>>
        {
            unimplemented!("not exercised by these tests")
        }

        fn branched(&mut self, _address: &Address) {
            unimplemented!("not exercised by these tests")
        }

        fn get_last_instruction(
            &self,
        ) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            unimplemented!("not exercised by these tests")
        }

        fn get_last_length_with_delays(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockUseropLibrary {
        userops: UseropMap<Vec<u8>>,
    }
    impl ErasedPcodeUseropLibrary for MockUseropLibrary {}
    impl PcodeUseropLibrary<Vec<u8>> for MockUseropLibrary {
        fn get_userops(&self) -> &UseropMap<Vec<u8>> {
            &self.userops
        }
    }

    fn mock_thread() -> JitPcodeThread {
        JitPcodeThread::new(
            Arc::new(Mutex::new(DummyDecoder)),
            None,
            Arc::new(MockUseropLibrary { userops: UseropMap::new() }),
        )
    }

    struct FakePassage;
    impl JitCompiledPassage for FakePassage {}

    /// Port of `JitCompiledPassageClassTest`-style behavior: `createInstance` invokes the wrapped
    /// constructor exactly once, passing along the given thread.
    #[test]
    fn create_instance_invokes_constructor() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_closure = Arc::clone(&calls);
        let cls = JitCompiledPassageClass::new(
            Arc::new(move |_thread: &JitPcodeThread| {
                calls_in_closure.fetch_add(1, Ordering::SeqCst);
                Box::new(FakePassage) as Box<dyn JitCompiledPassage>
            }),
            vec![],
        );

        let thread = mock_thread();
        let _passage = cls.create_instance(&thread);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Port of `JitCompiledPassageClassTest.testGetBlockEntries`: each entry's position in the
    /// list becomes its block id, and the map is keyed by the entry's `AddrCtx`.
    #[test]
    fn get_block_entries_indexes_by_position() {
        let targets = vec![ram(0x1000), ram(0x2000), ram(0x3000)];
        let entries: Vec<AddrCtx> =
            targets.iter().map(|addr| AddrCtx::new(None, addr.clone())).collect();
        let cls = JitCompiledPassageClass::new(
            Arc::new(|_thread: &JitPcodeThread| {
                Box::new(FakePassage) as Box<dyn JitCompiledPassage>
            }),
            entries.clone(),
        );

        let block_entries = cls.get_block_entries();
        assert_eq!(block_entries.len(), 3);
        for (i, addr_ctx) in entries.iter().enumerate() {
            let proto = block_entries.get(addr_ctx).expect("entry should be present");
            assert_eq!(proto.block_id, i as i32);
        }
    }
}
