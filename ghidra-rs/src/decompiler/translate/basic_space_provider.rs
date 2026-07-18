/// Models `ghidra.pcodeCPort.translate.BasicSpaceProvider`.

use crate::decompiler::space::AddrSpace;

/// Provides access to the fundamental address spaces used by a processor.
///
/// Most processors have a main address bus on which the bulk of the processor's RAM is mapped.
/// Everything referenced with this address bus should be modeled in pcode with a single address
/// space, referred to as the default space.
///
/// Pcode also represents constant values within an operation as offsets within a special
/// constant address space. This trait abstracts access to these two fundamental spaces.
pub trait BasicSpaceProvider: Send + Sync {
    /// Returns a reference to the processor's default address space.
    ///
    /// The default space is the main address bus on which the bulk of the processor's RAM is
    /// mapped. Everything referenced with this address bus should be modeled in pcode with
    /// this single address space.
    fn get_default_space(&self) -> &dyn AddrSpace;

    /// Returns a reference to the constant address space.
    ///
    /// Pcode represents constant values within an operation as offsets within this special
    /// constant address space.
    fn get_constant_space(&self) -> &dyn AddrSpace;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe() {
        fn _accepts_dyn_trait(_: &dyn BasicSpaceProvider) {}
    }

    #[test]
    fn trait_requires_send_sync() {
        const fn _requires_send_sync<T: Send + Sync>() {}
        const fn _check() {
            _requires_send_sync::<Box<dyn BasicSpaceProvider>>();
        }
    }
}
