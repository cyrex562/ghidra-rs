//! A symbolic value tailored for stack unwind analysis.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.Sym` (a Java `sealed interface`, so a Rust
//! `enum`: the set of alternatives is closed by construction).

use std::rc::Rc;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, SpecialAddress};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::register::RegisterRef;

/// A symbolic value tailored for stack unwind analysis.
///
/// The goals of stack unwind analysis are 1) to figure the stack depth at a particular
/// instruction, 2) to figure the locations of saved registers on the stack, 3) to figure the
/// location of the return address, whether in a register or on the stack, and 4) to figure the
/// change in stack depth from calling the function. Not surprisingly, these are the fields of
/// `UnwindInfo`. To these ends, symbols may have only one of the following forms:
///
/// * An opaque value: [`Sym::Opaque`], to represent expressions too complex.
/// * A constant: [`Sym::Const`], to fold constants and use as offsets.
/// * A register: [`Sym::Register`], to detect saved registers and to generate stack offsets.
/// * A stack offset, i.e., `SP + c`: [`Sym::StackOffset`], to fold offsets, detect stack depth,
///   and to generate stack dereferences.
/// * A dereference of a stack offset, i.e., `*(SP + c)`: [`Sym::StackDeref`], to detect
///   restored registers and return address location.
///
/// The rules are fairly straightforward:
///
/// * `a:Opaque + b:Any => Opaque()`
/// * `a:Const + b:Const => Const(val=a.val + b.val)`
/// * `a:Const + b:Register(reg==SP) => Offset(offset=a.val)`
/// * `a:Offset + b:Const => Offset(offset=a.offset + b.val)`
/// * `*a:Offset => Deref(offset=a.offset)`
/// * `*a:Register(reg==SP) => Deref(offset=0)`
///
/// Some minute operations are omitted for clarity. Any other operation results in `Opaque()`.
/// There is a small fault in that `Register(reg=SP)` and `Offset(offset=0)` represent the same
/// thing, but with some extra bookkeeping, it's not too terrible. By interpreting p-code and
/// then examining the symbolic machine state, simple movement of data between registers and the
/// stack can be summarized.
#[derive(Clone, Debug, PartialEq)]
pub enum Sym {
    /// The opaque symbol, representing an expression too complex to analyze.
    ///
    /// Java equivalent: the `OpaqueSym.OPAQUE` singleton.
    Opaque,
    /// A constant symbol, of the given size in bytes.
    Const { value: i64, size: i32 },
    /// A register symbol, with the bits retained so far by masking.
    Register { register: RegisterRef, mask: i64 },
    /// A stack offset symbol, representing a value of the form `SP + offset`.
    StackOffset { offset: i64 },
    /// A dereferenced [`Sym::StackOffset`] (or the dereferenced stack pointer register, which
    /// is treated as a stack offset of 0), with the bits retained so far by masking.
    StackDeref { offset: i64, mask: i64, size: i32 },
}

impl Sym {
    /// Get the opaque symbol.
    pub fn opaque() -> Sym {
        Sym::Opaque
    }

    /// Get a constant symbol (with size 8 bytes).
    pub fn constant(value: i64) -> Sym {
        Sym::Const { value, size: 8 }
    }

    /// Add this and another symbol with the given compiler for context.
    pub fn add(&self, c_spec: &dyn CompilerSpec, in2: &Sym) -> Sym {
        match self {
            Sym::Opaque => Sym::Opaque,
            Sym::Const { value, size } => match in2 {
                Sym::Const { value: value2, .. } => Sym::Const {
                    value: value.wrapping_add(*value2),
                    size: *size,
                },
                Sym::Register { register, .. } if is_stack_pointer(register, c_spec) => {
                    Sym::StackOffset { offset: *value }
                }
                Sym::StackOffset { offset: offset2 } => Sym::StackOffset {
                    offset: value.wrapping_add(*offset2),
                },
                _ => Sym::opaque(),
            },
            // Register, stack offset, and stack deref symbols only fold with a constant, and
            // they do so by deferring to the constant's own rules.
            Sym::Register { .. } | Sym::StackOffset { .. } | Sym::StackDeref { .. } => match in2 {
                Sym::Const { .. } => in2.add(c_spec, self),
                _ => Sym::opaque(),
            },
        }
    }

    /// Subtract another symbol from this with the given compiler for context.
    pub fn sub(&self, c_spec: &dyn CompilerSpec, in2: &Sym) -> Sym {
        self.add(c_spec, &in2.twos_comp())
    }

    /// Negate this symbol.
    pub fn twos_comp(&self) -> Sym {
        match self {
            Sym::Const { value, size } => Sym::Const {
                value: value.wrapping_neg(),
                size: *size,
            },
            _ => Sym::opaque(),
        }
    }

    /// Logical bitwise and this and another symbol with the given compiler context.
    pub fn and(&self, c_spec: &dyn CompilerSpec, in2: &Sym) -> Sym {
        match self {
            Sym::Opaque => Sym::Opaque,
            Sym::Const { value, size } => match in2 {
                Sym::Const { value: value2, .. } => Sym::Const {
                    value: value & value2,
                    size: *size,
                },
                Sym::Register { .. } | Sym::StackDeref { .. } => in2.with_applied_mask(*value),
                _ => Sym::opaque(),
            },
            Sym::Register { .. } | Sym::StackOffset { .. } | Sym::StackDeref { .. } => match in2 {
                Sym::Const { .. } => in2.and(c_spec, self),
                _ => Sym::opaque(),
            },
        }
    }

    /// Retain only the bits of this symbol selected by `mask`.
    ///
    /// Java defines `withAppliedMask` only on the two mask-carrying records, and only calls it
    /// from `ConstSym.and`, whose remaining alternatives fold to the opaque symbol; hence the
    /// other variants mask to [`Sym::Opaque`] here.
    pub fn with_applied_mask(&self, mask: i64) -> Sym {
        match self {
            Sym::Register {
                register,
                mask: this_mask,
            } => Sym::Register {
                register: Rc::clone(register),
                mask: this_mask & mask,
            },
            Sym::StackDeref {
                offset,
                mask: this_mask,
                size,
            } => Sym::StackDeref {
                offset: *offset,
                mask: this_mask & mask,
                size: *size,
            },
            _ => Sym::opaque(),
        }
    }

    /// Get the size of this symbol, in bytes, with the given compiler for context.
    ///
    /// # Panics
    ///
    /// Panics for [`Sym::Opaque`], which has no size (Java throws
    /// `UnsupportedOperationException`), and for [`Sym::StackOffset`] when the compiler
    /// specification declares no stack pointer.
    pub fn size_of(&self, c_spec: &dyn CompilerSpec) -> i64 {
        match self {
            Sym::Opaque => panic!("UnsupportedOperationException: size_of on the opaque symbol"),
            Sym::Const { size, .. } => *size as i64,
            Sym::Register { register, .. } => register.borrow().minimum_byte_size() as i64,
            Sym::StackOffset { .. } => c_spec
                .get_stack_pointer()
                .expect("compiler spec has no stack pointer")
                .borrow()
                .minimum_byte_size() as i64,
            Sym::StackDeref { size, .. } => *size as i64,
        }
    }

    /// When this symbol is used as the offset in a given address space, translate it to the
    /// address if possible.
    ///
    /// The address will be used by the state to retrieve the appropriate (symbolic) value,
    /// possibly generating a fresh symbol. If the address is [`SpecialAddress::no_address`],
    /// then the state will yield the opaque symbol. For sets, the state will store the given
    /// symbolic value at the address. If it is [`SpecialAddress::no_address`], then the value
    /// is ignored.
    pub fn address_in(&self, space: &Arc<AddressSpace>, c_spec: &dyn CompilerSpec) -> Address {
        match self {
            Sym::Opaque | Sym::StackDeref { .. } => SpecialAddress::no_address(),
            Sym::Const { value, .. } => match space.space_type() {
                AddressSpaceType::Constant
                | AddressSpaceType::Register
                | AddressSpaceType::Unique => space.address(*value),
                _ => SpecialAddress::no_address(),
            },
            Sym::Register { register, .. } => {
                if !is_stack_pointer(register, c_spec) || **space != *c_spec.get_stack_base_space()
                {
                    return SpecialAddress::no_address();
                }
                c_spec.get_stack_space().address(0)
            }
            Sym::StackOffset { offset } => {
                if **space != *c_spec.get_stack_base_space() {
                    return SpecialAddress::no_address();
                }
                c_spec.get_stack_space().address(*offset)
            }
        }
    }
}

/// Java compares the register against `cSpec.getStackPointer()` by reference; registers are
/// shared through the language, so pointer identity is checked first, falling back to the
/// register's own equality (name, size, and location).
fn is_stack_pointer(register: &RegisterRef, c_spec: &dyn CompilerSpec) -> bool {
    match c_spec.get_stack_pointer() {
        None => false,
        Some(sp) => Rc::ptr_eq(register, &sp) || *register.borrow() == *sp.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::PcodeInjectLibrary;
    use std::collections::HashSet;

    struct TestCompilerSpec {
        register_space: Arc<AddressSpace>,
        stack_space: Arc<AddressSpace>,
        stack_base_space: Arc<AddressSpace>,
        stack_pointer: RegisterRef,
    }

    impl TestCompilerSpec {
        fn new() -> Self {
            let register_space =
                AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
            let stack_space = AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 2);
            let stack_base_space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 3);
            let stack_pointer = Register::new(
                "SP",
                "stack pointer",
                register_space.address(0x10),
                8,
                true,
                Register::TYPE_SP,
            );
            Self {
                register_space,
                stack_space,
                stack_base_space,
                stack_pointer,
            }
        }

        fn other_register(&self) -> RegisterRef {
            Register::new(
                "RBX",
                "callee saved",
                self.register_space.address(0x20),
                8,
                true,
                Register::TYPE_NONE,
            )
        }
    }

    impl CompilerSpec for TestCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!()
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!()
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            unimplemented!()
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            Some(Rc::clone(&self.stack_pointer))
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.stack_space)
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.stack_base_space)
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            unimplemented!()
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!()
        }
        fn is_global(&self, _addr: &Address) -> bool {
            false
        }
        fn get_data_organization(
            &self,
        ) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!()
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!()
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!()
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            unimplemented!()
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    #[test]
    fn constant_has_size_eight() {
        let c_spec = TestCompilerSpec::new();
        let c = Sym::constant(0x1234);

        assert_eq!(c, Sym::Const { value: 0x1234, size: 8 });
        assert_eq!(c.size_of(&c_spec), 8);
    }

    #[test]
    fn const_plus_const_folds_and_keeps_receiver_size() {
        let c_spec = TestCompilerSpec::new();
        let a = Sym::Const { value: 10, size: 4 };
        let b = Sym::Const { value: -3, size: 8 };

        assert_eq!(a.add(&c_spec, &b), Sym::Const { value: 7, size: 4 });
        // sub is add of the two's complement: 10 - (-3) == 13
        assert_eq!(a.sub(&c_spec, &b), Sym::Const { value: 13, size: 4 });
    }

    #[test]
    fn const_plus_stack_pointer_becomes_stack_offset_either_way() {
        let c_spec = TestCompilerSpec::new();
        let c = Sym::Const { value: -0x20, size: 8 };
        let sp = Sym::Register {
            register: c_spec.get_stack_pointer().unwrap(),
            mask: -1,
        };

        assert_eq!(c.add(&c_spec, &sp), Sym::StackOffset { offset: -0x20 });
        assert_eq!(sp.add(&c_spec, &c), Sym::StackOffset { offset: -0x20 });
    }

    #[test]
    fn const_plus_other_register_is_opaque() {
        let c_spec = TestCompilerSpec::new();
        let c = Sym::Const { value: 8, size: 8 };
        let rbx = Sym::Register {
            register: c_spec.other_register(),
            mask: -1,
        };

        assert_eq!(c.add(&c_spec, &rbx), Sym::Opaque);
        assert_eq!(rbx.add(&c_spec, &rbx), Sym::Opaque);
    }

    #[test]
    fn stack_offset_folds_with_constants_and_sizes_as_stack_pointer() {
        let c_spec = TestCompilerSpec::new();
        let off = Sym::StackOffset { offset: -0x20 };
        let c = Sym::Const { value: 8, size: 8 };

        assert_eq!(off.add(&c_spec, &c), Sym::StackOffset { offset: -0x18 });
        assert_eq!(off.sub(&c_spec, &c), Sym::StackOffset { offset: -0x28 });
        assert_eq!(off.size_of(&c_spec), 8);
        // Only constants fold; anything else is opaque, and negation is never representable.
        assert_eq!(off.add(&c_spec, &off), Sym::Opaque);
        assert_eq!(off.twos_comp(), Sym::Opaque);
    }

    #[test]
    fn and_applies_mask_to_register_and_deref() {
        let c_spec = TestCompilerSpec::new();
        let mask = Sym::Const { value: 0xffff, size: 8 };
        let sp = c_spec.get_stack_pointer().unwrap();
        let reg = Sym::Register {
            register: Rc::clone(&sp),
            mask: -1,
        };
        let deref = Sym::StackDeref { offset: -8, mask: -1, size: 8 };

        assert_eq!(
            mask.and(&c_spec, &reg),
            Sym::Register { register: sp, mask: 0xffff }
        );
        assert_eq!(
            reg.and(&c_spec, &mask),
            mask.and(&c_spec, &reg),
            "and is symmetric: the non-constant defers to the constant"
        );
        assert_eq!(
            mask.and(&c_spec, &deref),
            Sym::StackDeref { offset: -8, mask: 0xffff, size: 8 }
        );
        assert_eq!(
            mask.and(&c_spec, &Sym::Const { value: 0xff00ff, size: 4 }),
            Sym::Const { value: 0xff, size: 8 }
        );
        assert_eq!(mask.and(&c_spec, &Sym::StackOffset { offset: 0 }), Sym::Opaque);
    }

    #[test]
    fn opaque_absorbs_everything() {
        let c_spec = TestCompilerSpec::new();
        let c = Sym::constant(4);

        assert_eq!(Sym::opaque().add(&c_spec, &c), Sym::Opaque);
        assert_eq!(Sym::opaque().and(&c_spec, &c), Sym::Opaque);
        assert_eq!(Sym::opaque().twos_comp(), Sym::Opaque);
        assert_eq!(c.add(&c_spec, &Sym::opaque()), Sym::Opaque);
    }

    #[test]
    fn address_in_translates_only_where_java_does() {
        let c_spec = TestCompilerSpec::new();
        let no_address = SpecialAddress::no_address();

        // A constant addresses the constant, register, and unique spaces directly.
        let c = Sym::Const { value: 0x40, size: 8 };
        assert_eq!(
            c.address_in(&c_spec.register_space, &c_spec),
            c_spec.register_space.address(0x40)
        );
        assert_eq!(c.address_in(&c_spec.stack_base_space, &c_spec), no_address);

        // The stack pointer register dereferences to stack offset 0.
        let sp = Sym::Register {
            register: c_spec.get_stack_pointer().unwrap(),
            mask: -1,
        };
        assert_eq!(
            sp.address_in(&c_spec.stack_base_space, &c_spec),
            c_spec.stack_space.address(0)
        );
        assert_eq!(sp.address_in(&c_spec.register_space, &c_spec), no_address);

        // Another register never yields an address.
        let rbx = Sym::Register {
            register: c_spec.other_register(),
            mask: -1,
        };
        assert_eq!(rbx.address_in(&c_spec.stack_base_space, &c_spec), no_address);

        // A stack offset dereferences into the stack space at that offset.
        let off = Sym::StackOffset { offset: -0x18 };
        assert_eq!(
            off.address_in(&c_spec.stack_base_space, &c_spec),
            c_spec.stack_space.address(-0x18)
        );
        assert_eq!(off.address_in(&c_spec.register_space, &c_spec), no_address);

        // Opaque and already-dereferenced symbols never yield an address.
        assert_eq!(
            Sym::opaque().address_in(&c_spec.stack_base_space, &c_spec),
            no_address
        );
        assert_eq!(
            Sym::StackDeref { offset: 0, mask: -1, size: 8 }
                .address_in(&c_spec.stack_base_space, &c_spec),
            no_address
        );
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn opaque_has_no_size() {
        let c_spec = TestCompilerSpec::new();
        Sym::opaque().size_of(&c_spec);
    }
}
