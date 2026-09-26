//! Port of `ghidra.app.util.bin.format.objc.ObjcMethod`.
//!
//! Java's `ObjcMethod` is an abstract class extending `ObjcTypeMetadataStructure`, carrying
//! one instance field (`_methodType`) plus a mix of abstract and concrete/overridable behaviour.
//! That shared state is split into [`ObjcMethodBase`]; the trait [`ObjcMethod`] declares the
//! abstract members and provides the concrete ones via [`ObjcMethod::base`].

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::objc::objc_method_type::ObjcMethodType;
use crate::format::objc::objc_state::ObjcState;
use crate::format::seam_stubs::ObjcUtils;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Namespace;
use crate::util::task::TaskMonitor;

/// The shared state every [`ObjcMethod`] implementor carries.
///
/// Java: the private `_methodType` field on the abstract `ObjcMethod` class, plus inherited
/// fields from `ObjcTypeMetadataStructure`.
pub struct ObjcMethodBase {
    method_type: ObjcMethodType,
}

impl ObjcMethodBase {
    /// Java: `ObjcMethod(Program program, ObjcState state, BinaryReader reader,
    /// ObjcMethodType methodType)` constructor. Constructs an ObjcMethodBase, reading the
    /// method type from the provided parameters.
    pub fn new(_program: &dyn Program, _state: &ObjcState, _reader: &mut dyn BinaryReader,
        method_type: ObjcMethodType) -> io::Result<Self> {
        Ok(ObjcMethodBase {
            method_type,
        })
    }

    /// Java: `getMethodType()`.
    pub fn get_method_type(&self) -> ObjcMethodType {
        self.method_type
    }
}

/// Port of the abstract `ghidra.app.util.bin.format.objc.ObjcMethod` class.
pub trait ObjcMethod: Send + Sync {
    /// Accessor to the shared state every Objective-C method carries.
    fn base(&self) -> &ObjcMethodBase;

    /// Java: `getMethodType()`.
    fn get_method_type(&self) -> ObjcMethodType {
        self.base().get_method_type()
    }

    /// Java: `getName()` (abstract).
    fn get_name(&self) -> Option<&str>;

    /// Java: `getTypes()` (abstract).
    fn get_types(&self) -> Option<&str>;

    /// Java: `getImplementation()` (abstract).
    fn get_implementation(&self) -> i64;

    /// Java: `applyTo(Namespace namespace, TaskMonitor monitor)` (overridden from parent).
    /// Applies this method to the program, creating symbols and recording implementation addresses.
    fn apply_to(
        &self,
        program: &dyn Program,
        _state: &ObjcState,
        utils: &dyn ObjcUtils,
        namespace: &dyn Namespace,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let implementation = self.get_implementation();

        if implementation == 0 {
            return Ok(());
        }

        if let Some(name) = self.get_name() {
            if name.is_empty() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let is_thumb_code = utils.is_thumb(program, implementation);

        let actual_implementation = if is_thumb_code {
            implementation - 1
        } else {
            implementation
        };

        let implementation_address = utils.to_address(program, actual_implementation);

        if let Some(name) = self.get_name() {
            utils.create_symbol(program, namespace, name, &implementation_address)?;
        }

        // Note: accessing state.methodMap directly would require making ObjcState concrete.
        // For now, this is left as a placeholder - when ObjcState is properly ported,
        // the method map tracking would be implemented here.

        if is_thumb_code {
            // Note: similar placeholder for thumbCodeLocations - to be filled when ObjcState is ported
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test for ObjcMethodBase creation.
    #[test]
    fn test_objc_method_base_instance_method() {
        let method_type = ObjcMethodType::Instance;
        let base = ObjcMethodBase {
            method_type,
        };
        assert_eq!(base.get_method_type(), ObjcMethodType::Instance);
    }

    /// Smoke test for class method type.
    #[test]
    fn test_objc_method_base_class_method() {
        let method_type = ObjcMethodType::Class;
        let base = ObjcMethodBase {
            method_type,
        };
        assert_eq!(base.get_method_type(), ObjcMethodType::Class);
    }

    /// Test that the method type can be extracted from base.
    #[test]
    fn test_get_method_type_instance() {
        let base = ObjcMethodBase {
            method_type: ObjcMethodType::Instance,
        };
        assert_eq!(base.get_method_type(), ObjcMethodType::Instance);
    }

    /// Test that the method type can be extracted from base (class variant).
    #[test]
    fn test_get_method_type_class() {
        let base = ObjcMethodBase {
            method_type: ObjcMethodType::Class,
        };
        assert_eq!(base.get_method_type(), ObjcMethodType::Class);
    }
}
