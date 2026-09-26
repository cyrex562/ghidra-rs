//! Port of `ghidra.app.plugin.processors.generic.VarnodeTemplate`.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::plugin::processors::generic::constant_template::ConstantTemplate;
use crate::app::plugin::processors::generic::handle::Handle;
use crate::app::plugin::processors::generic::operand::{OperandId, OperandTable};
use crate::app::plugin::processors::generic::position::Position;
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::pcode::Varnode;

/// A p-code varnode template: space, offset and size [`ConstantTemplate`]s resolved into a
/// [`Varnode`] per instruction, optionally replaced by an operand's already-computed handle.
///
/// Port of `ghidra.app.plugin.processors.generic.VarnodeTemplate`.
///
/// # Deviations from Java
///
/// * The replacing operand is an [`OperandId`]; resolution takes the constructor's
///   [`OperandTable`] (see [`Offset`](super::offset::Offset) for why).
/// * `setDef(OpTemplate)` is not ported: its body is commented out in Java (the `def` field it
///   would set is too), so it has no effect.
/// * An unknown space ID is an error where Java would throw a `NullPointerException`.
/// * `equals`/`hashCode` are [`PartialEq`]/[`Hash`] with Java's semantics: the hash (which counts
///   `oneuse`) and the three templates are compared; `loadomit` and the replacement are not.
///   Java's `Serializable` marker is not modeled.
#[derive(Clone)]
pub struct VarnodeTemplate {
    loadomit: bool,
    replace: Option<OperandId>,
    address_factory: Arc<dyn AddressFactory>,
    hash_code: i32,
    space: ConstantTemplate,
    offset: ConstantTemplate,
    size: ConstantTemplate,
    oneuse: bool,
}

impl VarnodeTemplate {
    /// Java: `VarnodeTemplate(ConstantTemplate space, ConstantTemplate offset, ConstantTemplate
    /// size, AddressFactory addressFactory, boolean ou)`.
    pub fn new(
        space: ConstantTemplate,
        offset: ConstantTemplate,
        size: ConstantTemplate,
        address_factory: Arc<dyn AddressFactory>,
        oneuse: bool,
    ) -> Self {
        let mut hash_code = space
            .hash_code()
            .wrapping_add(offset.hash_code())
            .wrapping_add(size.hash_code());
        if oneuse {
            hash_code = hash_code.wrapping_add(1);
        }
        VarnodeTemplate {
            loadomit: false,
            replace: None,
            address_factory,
            hash_code,
            space,
            offset,
            size,
            oneuse,
        }
    }

    /// Java: `resolve(HashMap<Object, Handle> handles, Position position, int bufoff)`.
    ///
    /// If a replacing operand is set and its recorded handle is not dynamic, the varnode is that
    /// handle's space, pointer offset and size; otherwise the three templates are resolved against
    /// `handles`.
    pub fn resolve_with_handles(
        &self,
        operands: &OperandTable,
        handles: &HashMap<OperandId, Handle>,
        position: &Position,
        bufoff: i32,
    ) -> Result<Varnode, SledException> {
        let (space_id, off, sz);
        match self.replace.map(|id| operands.get(id)) {
            Some(replace) if !replace.dynamic() => {
                let h = replace.get_cached_handle().ok_or_else(|| {
                    SledException::with_message(format!(
                        "operand '{}' has no computed handle",
                        replace.name()
                    ))
                })?;
                space_id = h.get_long(Handle::SPACE, 0) as i32;
                off = h.get_long(Handle::OFFSET, Handle::OFFSET);
                sz = h.get_long(Handle::SIZE, 0) as i32;
            }
            _ => {
                space_id =
                    self.space.resolve_with_handles(operands, handles, position, bufoff)? as i32;
                off = self.offset.resolve_with_handles(operands, handles, position, bufoff)?;
                sz = self.size.resolve_with_handles(operands, handles, position, bufoff)? as i32;
            }
        }
        Ok(Varnode::new(self.get_masked_addr(space_id, off)?, sz))
    }

    /// Java: `resolve(Position position, int bufoff)`: resolves the three templates, ignoring any
    /// replacement. The result only contains an address and size.
    pub fn resolve(
        &self,
        operands: &OperandTable,
        position: &Position,
        bufoff: i32,
    ) -> Result<Varnode, SledException> {
        let space_id = self.space.resolve(operands, position, bufoff)? as i32;
        let off = self.offset.resolve(operands, position, bufoff)?;
        let sz = self.size.resolve(operands, position, bufoff)? as i32;
        Ok(Varnode::new(self.get_masked_addr(space_id, off)?, sz))
    }

    /// The address `off` in space `space_id`, truncated to the space
    /// (`getTruncatedAddress(off, false)`).
    fn get_masked_addr(&self, space_id: i32, off: i64) -> Result<Address, SledException> {
        let my_space = self
            .address_factory
            .get_address_space_by_id(space_id)
            .ok_or_else(|| {
                SledException::with_message(format!("unknown address space id {space_id}"))
            })?;
        let truncated = my_space.truncate_offset(off);
        Ok(my_space.address(truncated))
    }

    /// Java: `oneuse()`.
    pub fn oneuse(&self) -> bool {
        self.oneuse
    }

    /// Java: `space()`.
    pub fn space(&self) -> &ConstantTemplate {
        &self.space
    }

    /// Java: `offset()`.
    pub fn offset(&self) -> &ConstantTemplate {
        &self.offset
    }

    /// Java: `size()`.
    pub fn size(&self) -> &ConstantTemplate {
        &self.size
    }

    /// Java: `setReplace(Operand op, boolean load)`: resolve to `op`'s recorded handle when it is
    /// not dynamic. `load` sets [`VarnodeTemplate::loadomit`] (it is never cleared).
    pub fn set_replace(&mut self, op: OperandId, load: bool) {
        self.replace = Some(op);
        if load {
            self.loadomit = true;
        }
    }

    /// The replacing operand, if set.
    pub fn replace(&self) -> Option<OperandId> {
        self.replace
    }

    /// Java: `loadomit()`.
    pub fn loadomit(&self) -> bool {
        self.loadomit
    }

    /// Java: `hashCode()`.
    pub fn hash_code(&self) -> i32 {
        self.hash_code
    }
}

impl std::fmt::Debug for VarnodeTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VarnodeTemplate")
            .field("loadomit", &self.loadomit)
            .field("replace", &self.replace)
            .field("space", &self.space)
            .field("offset", &self.offset)
            .field("size", &self.size)
            .field("oneuse", &self.oneuse)
            .finish_non_exhaustive()
    }
}

impl PartialEq for VarnodeTemplate {
    /// Java: `equals(Object)`.
    fn eq(&self, vt: &Self) -> bool {
        vt.hash_code == self.hash_code
            && vt.space == self.space
            && vt.offset == self.offset
            && vt.size == self.size
    }
}

impl Eq for VarnodeTemplate {}

impl Hash for VarnodeTemplate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::binary_expression::BinaryExpression;
    use crate::app::plugin::processors::generic::constant::Constant;
    use crate::app::plugin::processors::generic::expression_term::{
        ExpressionTerm, ExpressionTermValue,
    };
    use crate::app::plugin::processors::generic::offset::Offset;
    use crate::app::plugin::processors::generic::operand::Operand;
    use crate::app::plugin::processors::generic::test_support::{
        const_space, make_position, ram_space,
    };
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 16, 1, AddressSpaceType::Register, 0)
    }

    fn factory() -> Arc<dyn AddressFactory> {
        Arc::new(DefaultAddressFactory::new(vec![
            ram_space(),
            register_space(),
            const_space(),
        ]))
    }

    fn real(v: i64) -> ConstantTemplate {
        ConstantTemplate::real(v)
    }

    /// An operand whose handle points at `register:value` (size 2).
    fn table_with_register_operand(value: i64) -> (OperandTable, OperandId) {
        let term = |v| {
            ExpressionTerm::new(
                ExpressionTermValue::Constant(Constant::new(v)),
                Offset::new(0, "").unwrap(),
            )
        };
        let mut bin =
            BinaryExpression::new(BinaryExpression::ADD, term(value), term(0), &const_space())
                .unwrap();
        bin.set_space(&register_space());
        let mut table = OperandTable::new();
        let id = table.add(Operand::new("reg", bin, Offset::new(0, "").unwrap()));
        (table, id)
    }

    #[test]
    fn resolves_templates_and_truncates_the_offset() {
        let table = OperandTable::new();
        let position = make_position(0x1000, 4);
        let vt = VarnodeTemplate::new(
            real(ram_space().space_id() as i64),
            real(0x1_0000_0010),
            real(4),
            factory(),
            false,
        );
        let vn = vt.resolve(&table, &position, 0).unwrap();
        assert_eq!(vn.get_space_id(), ram_space().space_id());
        // 32-bit space: 0x1_0000_0010 truncates to 0x10.
        assert_eq!(vn.get_offset(), 0x10);
        assert_eq!(vn.get_size(), 4);
        let via_map = vt
            .resolve_with_handles(&table, &HashMap::new(), &position, 0)
            .unwrap();
        assert_eq!(via_map, vn);
    }

    #[test]
    fn unknown_space_is_an_error() {
        let vt = VarnodeTemplate::new(real(0x7fff), real(0), real(1), factory(), false);
        assert!(vt.resolve(&OperandTable::new(), &make_position(0, 1), 0).is_err());
    }

    #[test]
    fn handle_templates_read_the_handle_map() {
        let (table, id) = table_with_register_operand(0x20);
        let position = make_position(0, 4);
        let mut handles = HashMap::new();
        handles.insert(
            id,
            Handle::new(
                Varnode::new(Address::new(const_space(), 0x30), 2),
                register_space().space_id(),
                2,
            ),
        );
        let vt = VarnodeTemplate::new(
            ConstantTemplate::handle(id, Handle::SPACE, 0),
            ConstantTemplate::handle(id, Handle::OFFSET, Handle::OFFSET),
            ConstantTemplate::handle(id, Handle::SIZE, 0),
            factory(),
            false,
        );
        let vn = vt.resolve_with_handles(&table, &handles, &position, 0).unwrap();
        assert_eq!(vn.get_space_id(), register_space().space_id());
        assert_eq!(vn.get_offset(), 0x30);
        assert_eq!(vn.get_size(), 2);
        // Without the map, the operand itself is evaluated.
        let vn = vt.resolve(&table, &position, 0).unwrap();
        assert_eq!(vn.get_offset(), 0x20);
    }

    #[test]
    fn non_dynamic_replacement_uses_the_recorded_handle() {
        let (mut table, id) = table_with_register_operand(0x20);
        let position = make_position(0, 4);
        let mut vt = VarnodeTemplate::new(
            real(ram_space().space_id() as i64),
            real(0x99),
            real(4),
            factory(),
            false,
        );
        vt.set_replace(id, false);
        assert!(!vt.loadomit());
        assert_eq!(vt.replace(), Some(id));

        // No handle recorded yet (and so not dynamic): Java would dereference null.
        assert!(vt
            .resolve_with_handles(&table, &HashMap::new(), &position, 0)
            .is_err());

        table
            .get_handle_with_pcode(id, &mut Vec::new(), &position, 0)
            .unwrap();
        let vn = vt
            .resolve_with_handles(&table, &HashMap::new(), &position, 0)
            .unwrap();
        assert_eq!(vn.get_space_id(), register_space().space_id());
        assert_eq!(vn.get_offset(), 0x20);
        assert_eq!(vn.get_size(), 2);

        // The position-only overload ignores the replacement.
        assert_eq!(vt.resolve(&table, &position, 0).unwrap().get_offset(), 0x99);

        vt.set_replace(id, true);
        assert!(vt.loadomit());
    }

    #[test]
    fn equality_and_hash_follow_java() {
        let a = VarnodeTemplate::new(real(1), real(2), real(3), factory(), false);
        let b = VarnodeTemplate::new(real(1), real(2), real(3), factory(), false);
        let c = VarnodeTemplate::new(real(1), real(2), real(3), factory(), true);
        assert_eq!(a.hash_code(), 6);
        assert_eq!(c.hash_code(), 7);
        assert!(c.oneuse());
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Same hash, different templates.
        let d = VarnodeTemplate::new(real(3), real(2), real(1), factory(), false);
        assert_eq!(d.hash_code(), a.hash_code());
        assert_ne!(a, d);
        assert_eq!(a.space(), &real(1));
        assert_eq!(a.offset(), &real(2));
        assert_eq!(a.size(), &real(3));
    }
}
