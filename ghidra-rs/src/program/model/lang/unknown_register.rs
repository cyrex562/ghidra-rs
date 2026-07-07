use crate::program::model::address::Address;
use super::register::{Register, RegisterRef};

/// A register used when a register is requested in the register space for an undefined location.
///
/// This is a semantic wrapper around [`RegisterRef`] that indicates the register was created
/// to represent an unknown/undefined register location, rather than a real processor register.
#[derive(Clone)]
pub struct UnknownRegister(RegisterRef);

impl UnknownRegister {
    /// Creates a new `UnknownRegister` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the register
    /// * `description` - A human-readable description of the register
    /// * `address` - The address where the register is located
    /// * `num_bytes` - The number of bytes this register occupies
    /// * `big_endian` - Whether the register uses big-endian byte order
    /// * `type_flags` - Type flags for this register
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> Self {
        let register = Register::new(name, description, address, num_bytes, big_endian, type_flags);
        UnknownRegister(register)
    }

    /// Returns a reference to the underlying [`RegisterRef`].
    pub fn register(&self) -> &RegisterRef {
        &self.0
    }

    /// Consumes this `UnknownRegister` and returns the underlying [`RegisterRef`].
    pub fn into_register(self) -> RegisterRef {
        self.0
    }

    /// Returns a clone of the underlying [`RegisterRef`].
    pub fn register_ref(&self) -> RegisterRef {
        self.0.clone()
    }
}

impl std::ops::Deref for UnknownRegister {
    type Target = RegisterRef;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<RegisterRef> for UnknownRegister {
    fn from(register: RegisterRef) -> Self {
        UnknownRegister(register)
    }
}

impl From<UnknownRegister> for RegisterRef {
    fn from(unknown: UnknownRegister) -> Self {
        unknown.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::SpecialAddress;

    #[test]
    fn new_creates_unknown_register() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new("test_reg", "Test Register", addr, 4, true, 0);

        let reg_ref = unknown.register();
        let reg = reg_ref.borrow();
        assert_eq!(reg.name(), "test_reg");
        assert_eq!(reg.description(), "Test Register");
        assert_eq!(reg.num_bytes(), 4);
        assert!(reg.is_big_endian());
    }

    #[test]
    fn new_with_type_flags() {
        let addr = SpecialAddress::no_address();
        let type_flags = Register::TYPE_SP | Register::TYPE_PC;
        let unknown = UnknownRegister::new("sp_pc", "Stack Pointer", addr, 8, false, type_flags);

        let reg_ref = unknown.register();
        let reg = reg_ref.borrow();
        assert!(reg.is_default_frame_pointer() == false); // TYPE_SP is 2, not TYPE_FP
        assert_eq!(reg.type_flags(), type_flags);
    }

    #[test]
    fn clone_creates_independent_reference() {
        let addr = SpecialAddress::no_address();
        let unknown1 = UnknownRegister::new("reg1", "Register 1", addr, 4, true, 0);
        let unknown2 = unknown1.clone();

        let reg1_ref = unknown1.register();
        let reg2_ref = unknown2.register();

        // Both should refer to the same underlying register
        assert_eq!(reg1_ref.borrow().name(), reg2_ref.borrow().name());
    }

    #[test]
    fn register_ref_clone() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new("test", "Test Reg", addr, 2, false, Register::TYPE_CONTEXT);

        let reg_ref1 = unknown.register_ref();
        let reg_ref2 = unknown.register_ref();

        assert_eq!(reg_ref1.borrow().name(), reg_ref2.borrow().name());
    }

    #[test]
    fn into_register() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new("temp", "Temporary", addr, 1, true, 0);
        let name = unknown.register().borrow().name().to_string();

        let register_ref = unknown.into_register();
        assert_eq!(register_ref.borrow().name(), &name);
    }

    #[test]
    fn from_register_ref() {
        let addr = SpecialAddress::no_address();
        let register_ref = Register::new("original", "Original Reg", addr, 4, true, 0);
        let unknown = UnknownRegister::from(register_ref.clone());

        assert_eq!(unknown.register().borrow().name(), "original");
    }

    #[test]
    fn into_register_ref_from_unknown() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new("src", "Source", addr, 8, false, 0);
        let name = unknown.register().borrow().name().to_string();

        let register_ref: RegisterRef = unknown.into();
        assert_eq!(register_ref.borrow().name(), &name);
    }

    #[test]
    fn deref_provides_register_ref() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new("deref_test", "Deref Test", addr, 4, true, 0);

        // Through Deref, we can call RegisterRef methods
        let borrowed = unknown.borrow();
        assert_eq!(borrowed.name(), "deref_test");
    }

    #[test]
    fn multiple_parameters() {
        let addr = SpecialAddress::no_address();
        let unknown = UnknownRegister::new(
            "complex",
            "A complex register",
            addr,
            16,
            false,
            Register::TYPE_VECTOR | Register::TYPE_HIDDEN,
        );

        let reg = unknown.register().borrow();
        assert_eq!(reg.name(), "complex");
        assert_eq!(reg.description(), "A complex register");
        assert_eq!(reg.num_bytes(), 16);
        assert!(!reg.is_big_endian());
        assert!(reg.is_vector_register());
        assert!(reg.is_hidden());
    }
}
