//! Port of `ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeDef`.
//!
//! # Shape
//!
//! Java's `DWARFAttributeDef<E extends Enum<E>>` is a concrete, generic class that three
//! subclasses extend, each specializing `E` and overriding `getRawAttributeIdDescription()` /
//! `withForm()`: `DWARFAttributeId.AttrDef` (`E = DWARFAttributeId`, ported at
//! [`AttrDef`](crate::format::dwarf::attribs::dwarf_attribute_id::AttrDef)), and the not-yet-ported
//! `DWARFLineContentType.Def` / `DWARFMacroOpcode.Def` (stubbed in
//! [`crate::format::seam_stubs`] as `DWARFLineContentTypeDef` / `DWARFMacroOpcodeDef`). Rust
//! splits the two:
//!
//! * [`DWARFAttributeDefBase<E>`] owns the four fields and every method Java does not override in
//!   any subclass (`getAttributeId`, `getRawAttributeId`, `getAttributeName`, `getAttributeForm`,
//!   `isImplicit`, `getImplicitValue`, and the static `read`).
//! * [`DWARFAttributeDef`] declares the members callers reach polymorphically without knowing the
//!   concrete `E` -- `DWARFFormContext` and `DWARFAttributeValue::get_value_string` both hold a
//!   def as `&dyn DWARFAttributeDef` -- plus the overridable `getRawAttributeIdDescription()` /
//!   `withForm()` pairing (folded into `with_form` alone, since `get_attribute_name`'s fallback to
//!   the description is only reachable through `with_form`'s callers, never observed directly).
//!
//! # Cycle note
//!
//! Java's Javadoc links `DWARFAbbreviation`, but no method here actually uses it, so no stub is
//! needed for it.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_form::{self, DWARFForm};

/// The shared state of a DWARF attribute specification, plus every method Java does not override
/// in any of `DWARFAttributeDef`'s subclasses. Generic over `E`, the attribute-id enum type
/// (`E` in Java's `DWARFAttributeDef<E extends Enum<E>>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DWARFAttributeDefBase<E> {
    pub attribute_id: Option<E>,
    pub raw_attribute_id: i32,
    pub attribute_form: DWARFForm,
    pub implicit_value: i64,
}

impl<E: Copy> DWARFAttributeDefBase<E> {
    /// Mirrors the `DWARFAttributeDef(E, int, DWARFForm, long)` constructor.
    pub fn new(
        attribute_id: Option<E>,
        raw_attribute_id: i32,
        attribute_form: DWARFForm,
        implicit_value: i64,
    ) -> Self {
        DWARFAttributeDefBase { attribute_id, raw_attribute_id, attribute_form, implicit_value }
    }

    /// Reads a `DWARFAttributeDefBase` from `reader`, or `Ok(None)` for an end-of-list marker.
    /// Mirrors the static `DWARFAttributeDef.read(BinaryReader, Function<Integer, E>)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        mapper: impl FnOnce(i32) -> Option<E>,
    ) -> io::Result<Option<Self>> {
        let raw_attribute_id = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
        let form_id = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;

        // DWARFAttributeId.EOL and DWARFForm.EOL are both 0.
        if raw_attribute_id == 0 && form_id == dwarf_form::EOL {
            // end of attributespec list
            return Ok(None);
        }

        let attribute_form = DWARFForm::of(form_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown DWARFForm {form_id} (0x{form_id:x})"),
            )
        })?;

        let attribute_id = mapper(raw_attribute_id);

        // NOTE: implicit value is a space saving hack built into DWARF. It adds an extra field
        // in the attributespec that needs to be read now in the .debug_abbr. This is different
        // than DW_FORM_indirect, which is read from the DIE in .debug_info.
        let implicit_value = if attribute_form == DWARFForm::DwFormImplicitConst {
            LEB128Info::signed(reader)?.as_long()
        } else {
            0
        };

        Ok(Some(DWARFAttributeDefBase { attribute_id, raw_attribute_id, attribute_form, implicit_value }))
    }

    /// Mirrors `DWARFAttributeDef.getAttributeId()`.
    pub fn get_attribute_id(&self) -> Option<E> {
        self.attribute_id
    }

    /// Mirrors `DWARFAttributeDef.getRawAttributeId()`.
    pub fn get_raw_attribute_id(&self) -> i32 {
        self.raw_attribute_id
    }

    /// Mirrors `DWARFAttributeDef.getAttributeForm()`.
    pub fn get_attribute_form(&self) -> DWARFForm {
        self.attribute_form
    }

    /// Mirrors `DWARFAttributeDef.isImplicit()`.
    pub fn is_implicit(&self) -> bool {
        self.attribute_form == DWARFForm::DwFormImplicitConst
    }

    /// Mirrors `DWARFAttributeDef.getImplicitValue()`.
    pub fn get_implicit_value(&self) -> i64 {
        self.implicit_value
    }

    /// Mirrors `DWARFAttributeDef.withForm(DWARFForm)`'s default (non-overridden) behavior:
    /// copies the def and swaps its form.
    pub fn with_form(&self, new_form: DWARFForm) -> Self {
        DWARFAttributeDefBase { attribute_form: new_form, ..*self }
    }
}

/// Declares the members of `DWARFAttributeDef` that callers reach polymorphically without knowing
/// the concrete attribute-id enum `E`. The shared state and every method Java does not override
/// live on [`DWARFAttributeDefBase<E>`] instead.
pub trait DWARFAttributeDef: Send + Sync {
    /// Mirrors `DWARFAttributeDef.getAttributeForm()`.
    fn get_attribute_form(&self) -> DWARFForm;

    /// Mirrors `DWARFAttributeDef.getImplicitValue()`. Java's field is initialized to `-1`
    /// ("N/A") for any def that isn't a `DW_FORM_implicit_const`, which is what this default
    /// returns for implementers that don't track it.
    fn get_implicit_value(&self) -> i64 {
        -1
    }

    /// Mirrors `DWARFAttributeDef.withForm(DWARFForm)`, overridden per subclass in Java so the
    /// result keeps its own concrete type. The default here can't reconstruct an arbitrary
    /// implementer, so it returns a [`RetargetedAttributeDef`] carrying just the two fields
    /// observable through this trait; implementers with a concrete `withForm` (e.g.
    /// [`AttrDef`](crate::format::dwarf::attribs::dwarf_attribute_id::AttrDef)) override it.
    fn with_form(&self, new_form: DWARFForm) -> Box<dyn DWARFAttributeDef> {
        Box::new(RetargetedAttributeDef { form: new_form, implicit_value: self.get_implicit_value() })
    }
}

/// The result of [`DWARFAttributeDef::with_form`]'s default implementation: another def, carrying
/// only the two fields this stub's surface exposes.
pub struct RetargetedAttributeDef {
    pub form: DWARFForm,
    pub implicit_value: i64,
}

impl DWARFAttributeDef for RetargetedAttributeDef {
    fn get_attribute_form(&self) -> DWARFForm {
        self.form
    }

    fn get_implicit_value(&self) -> i64 {
        self.implicit_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestId {
        Foo,
    }

    #[test]
    fn new_and_accessors_mirror_the_constructor_and_getters() {
        let base =
            DWARFAttributeDefBase::new(Some(TestId::Foo), 0x3, DWARFForm::DwFormString, 0);

        assert_eq!(base.get_attribute_id(), Some(TestId::Foo));
        assert_eq!(base.get_raw_attribute_id(), 0x3);
        assert_eq!(base.get_attribute_form(), DWARFForm::DwFormString);
        assert!(!base.is_implicit());
        assert_eq!(base.get_implicit_value(), 0);
    }

    #[test]
    fn is_implicit_matches_the_implicit_const_form_only() {
        let base = DWARFAttributeDefBase::new(Some(TestId::Foo), 0x1c, DWARFForm::DwFormImplicitConst, -1);
        assert!(base.is_implicit());

        let base = DWARFAttributeDefBase::new(Some(TestId::Foo), 0x1c, DWARFForm::DwFormData4, 0);
        assert!(!base.is_implicit());
    }

    #[test]
    fn with_form_retargets_only_the_form() {
        let base = DWARFAttributeDefBase::new(Some(TestId::Foo), 0x3, DWARFForm::DwFormString, 0);
        let retargeted = base.with_form(DWARFForm::DwFormStrp);

        assert_eq!(retargeted.get_attribute_id(), Some(TestId::Foo));
        assert_eq!(retargeted.get_raw_attribute_id(), 0x3);
        assert_eq!(retargeted.get_attribute_form(), DWARFForm::DwFormStrp);
    }

    #[test]
    fn trait_default_with_form_returns_a_retargeted_attribute_def() {
        struct Fixed;
        impl DWARFAttributeDef for Fixed {
            fn get_attribute_form(&self) -> DWARFForm {
                DWARFForm::DwFormData4
            }
            fn get_implicit_value(&self) -> i64 {
                7
            }
        }

        let fixed = Fixed;
        let retargeted: Box<dyn DWARFAttributeDef> = fixed.with_form(DWARFForm::DwFormStrp);
        assert_eq!(retargeted.get_attribute_form(), DWARFForm::DwFormStrp);
        assert_eq!(retargeted.get_implicit_value(), 7);
    }
}
