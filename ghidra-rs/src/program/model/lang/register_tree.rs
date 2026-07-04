use std::cell::RefCell;
use std::cmp::Ordering;
use std::rc::{Rc, Weak};

use crate::program::model::lang::register::RegisterRef;

const SEPARATOR: &str = ".";

/// Shared, mutable reference to a [`RegisterTree`].
pub type RegisterTreeRef = Rc<RefCell<RegisterTree>>;

/// Non-owning reference to a [`RegisterTree`], used for parent back-links.
pub type WeakRegisterTreeRef = Weak<RefCell<RegisterTree>>;

/// Builds and represents relationships between registers. Any register that "breaks down" into
/// smaller registers can be represented by a `RegisterTree`. The largest register will be at
/// the root and the registers that make it up will be its children trees. The children are
/// `RegisterTree`s as well and can have children trees of their own. The root of a
/// `RegisterTree` may not have an associated register, which means that its children are
/// unrelated. This way all the registers of a processor can be represented as a single
/// `RegisterTree`.
pub struct RegisterTree {
    self_ref: WeakRegisterTreeRef,
    name: String,
    register: Option<RegisterRef>,
    parent: Option<WeakRegisterTreeRef>,
    children: Vec<RegisterTreeRef>,
}

impl RegisterTree {
    /// Constructs a `RegisterTree` rooted at `reg`, recursively building children trees for
    /// each of `reg`'s child registers.
    pub fn new(reg: &RegisterRef) -> RegisterTreeRef {
        let name = reg.borrow().name().to_string();
        let register_children = reg.borrow().child_registers();

        Rc::new_cyclic(|weak| {
            let children: Vec<RegisterTreeRef> = register_children
                .iter()
                .map(|child_reg| {
                    let child_tree = RegisterTree::new(child_reg);
                    child_tree.borrow_mut().parent = Some(weak.clone());
                    child_tree
                })
                .collect();

            RefCell::new(RegisterTree {
                self_ref: weak.clone(),
                name,
                register: Some(Rc::clone(reg)),
                parent: None,
                children,
            })
        })
    }

    /// Constructs a `RegisterTree` with the given name and set of registers. Only base
    /// registers among `regs` become children of the new tree.
    pub fn with_registers(name: impl Into<String>, regs: &[RegisterRef]) -> RegisterTreeRef {
        let name = name.into();

        Rc::new_cyclic(|weak| {
            let children: Vec<RegisterTreeRef> = regs
                .iter()
                .filter(|reg| reg.borrow().is_base_register())
                .map(|reg| {
                    let child_tree = RegisterTree::new(reg);
                    child_tree.borrow_mut().parent = Some(weak.clone());
                    child_tree
                })
                .collect();

            RefCell::new(RegisterTree {
                self_ref: weak.clone(),
                name,
                register: None,
                parent: None,
                children,
            })
        })
    }

    /// Constructs a `RegisterTree` with one `RegisterTree` child.
    pub fn with_child(name: impl Into<String>, tree: RegisterTreeRef) -> RegisterTreeRef {
        Rc::new_cyclic(|weak| {
            RefCell::new(RegisterTree {
                self_ref: weak.clone(),
                name: name.into(),
                register: None,
                parent: None,
                children: vec![tree],
            })
        })
    }

    /// Returns the name of this register tree.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds a `RegisterTree` to this tree.
    pub fn add(&mut self, tree: RegisterTreeRef) {
        tree.borrow_mut().parent = Some(self.self_ref.clone());
        self.children.push(tree);
    }

    /// Returns the `RegisterTree`s that are the children of this `RegisterTree`.
    pub fn get_components(&self) -> Vec<RegisterTreeRef> {
        self.children.clone()
    }

    /// Returns the register associated with this tree. This may be `None`, which indicates the
    /// children register trees are unrelated to each other.
    pub fn register(&self) -> Option<RegisterRef> {
        self.register.clone()
    }

    /// Returns the parent `RegisterTree`.
    pub fn parent(&self) -> Option<RegisterTreeRef> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    /// The parent path of this `RegisterTree` if it exists, or `None` if this tree has no
    /// parent or no parent with a register.
    pub fn parent_register_path(&self) -> Option<String> {
        let parent_tree = self.parent()?;
        let has_register = parent_tree.borrow().register.is_some();
        if !has_register {
            return None;
        }
        let path = parent_tree.borrow().register_path();
        Some(path)
    }

    /// The path of this register, which includes the parent path of this `RegisterTree` if this
    /// `RegisterTree` has a parent.
    pub fn register_path(&self) -> String {
        let register_name = self
            .register
            .as_ref()
            .expect("register_path requires an associated register")
            .borrow()
            .name()
            .to_string();

        match self.parent_register_path() {
            Some(parent_path) => format!("{parent_path}{SEPARATOR}{register_name}"),
            None => register_name,
        }
    }

    /// Returns the `RegisterTree` for the given register if one exists in this `RegisterTree`.
    pub fn get_register_tree(&self, register: &RegisterRef) -> Option<RegisterTreeRef> {
        if let Some(this_register) = &self.register {
            if Rc::ptr_eq(this_register, register) {
                return self.self_ref.upgrade();
            }
        }
        for child in &self.children {
            if let Some(found) = child.borrow().get_register_tree(register) {
                return Some(found);
            }
        }
        None
    }

    /// Removes the register from the children.
    pub fn remove(&self, reg: &RegisterRef) {
        let Some(tree) = self.get_register_tree(reg) else {
            return;
        };
        let Some(parent) = tree.borrow().parent() else {
            return;
        };
        parent
            .borrow_mut()
            .children
            .retain(|child| !Rc::ptr_eq(child, &tree));
    }
}

impl PartialEq for RegisterTree {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for RegisterTree {}

impl PartialOrd for RegisterTree {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegisterTree {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl std::fmt::Display for RegisterTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}[", self.name)?;
        for child in &self.children {
            write!(f, "{},", child.borrow())?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;

    fn register_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    #[test]
    fn new_from_register_builds_children_recursively() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ax = Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);
        eax.borrow_mut().set_child_registers(vec![Rc::clone(&ax)]);

        let tree = RegisterTree::new(&eax);
        let tree = tree.borrow();
        assert_eq!(tree.name(), "EAX");
        assert!(Rc::ptr_eq(tree.register().as_ref().unwrap(), &eax));

        let components = tree.get_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].borrow().name(), "AX");
        assert!(Rc::ptr_eq(
            components[0].borrow().register().as_ref().unwrap(),
            &ax
        ));

        let child_parent = components[0].borrow().parent().expect("parent set");
        assert_eq!(child_parent.borrow().name(), "EAX");
    }

    #[test]
    fn with_registers_only_includes_base_registers() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ax = Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);
        eax.borrow_mut().set_child_registers(vec![Rc::clone(&ax)]);

        let tree = RegisterTree::with_registers("root", &[Rc::clone(&eax), Rc::clone(&ax)]);
        let tree = tree.borrow();
        assert_eq!(tree.name(), "root");
        assert!(tree.register().is_none());

        let components = tree.get_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].borrow().name(), "EAX");
    }

    #[test]
    fn with_child_does_not_set_parent_link() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let child = RegisterTree::new(&eax);

        let root = RegisterTree::with_child("root", Rc::clone(&child));
        assert_eq!(root.borrow().get_components().len(), 1);
        assert!(child.borrow().parent().is_none());
    }

    #[test]
    fn add_wires_parent_link() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ebx = Register::new("EBX", "", space.address(0x4), 4, false, Register::TYPE_NONE);

        let root = RegisterTree::with_registers("root", &[Rc::clone(&eax)]);
        let ebx_tree = RegisterTree::new(&ebx);
        root.borrow_mut().add(Rc::clone(&ebx_tree));

        assert_eq!(root.borrow().get_components().len(), 2);
        let parent = ebx_tree.borrow().parent().expect("parent set");
        assert_eq!(parent.borrow().name(), "root");
    }

    #[test]
    fn register_path_includes_ancestor_registers() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ax = Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);
        let al = Register::new("AL", "", space.address(0x0), 1, false, Register::TYPE_NONE);
        ax.borrow_mut().set_child_registers(vec![Rc::clone(&al)]);
        eax.borrow_mut().set_child_registers(vec![Rc::clone(&ax)]);

        let tree = RegisterTree::new(&eax);
        let tree = tree.borrow();
        let ax_tree = tree.get_register_tree(&ax).expect("ax tree found");
        let al_tree = tree.get_register_tree(&al).expect("al tree found");

        assert_eq!(ax_tree.borrow().register_path(), "EAX.AX");
        assert_eq!(al_tree.borrow().register_path(), "EAX.AX.AL");
        assert!(tree.parent_register_path().is_none());
        assert_eq!(
            al_tree.borrow().parent_register_path().unwrap(),
            "EAX.AX"
        );
    }

    #[test]
    fn get_register_tree_returns_none_for_unknown_register() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let unrelated = Register::new(
            "EBX",
            "",
            space.address(0x4),
            4,
            false,
            Register::TYPE_NONE,
        );

        let tree = RegisterTree::new(&eax);
        assert!(tree.borrow().get_register_tree(&unrelated).is_none());
    }

    #[test]
    fn remove_detaches_register_subtree_from_parent() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ax = Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);
        eax.borrow_mut().set_child_registers(vec![Rc::clone(&ax)]);

        let tree = RegisterTree::new(&eax);
        assert_eq!(tree.borrow().get_components().len(), 1);

        tree.borrow().remove(&ax);

        assert_eq!(tree.borrow().get_components().len(), 0);
        assert!(tree.borrow().get_register_tree(&ax).is_none());
    }

    #[test]
    fn remove_on_root_with_no_parent_is_a_no_op() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let tree = RegisterTree::new(&eax);

        tree.borrow().remove(&eax);
        assert!(tree.borrow().get_register_tree(&eax).is_some());
    }

    #[test]
    fn ordering_and_display_match_name() {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ebx = Register::new("EBX", "", space.address(0x4), 4, false, Register::TYPE_NONE);

        let a = RegisterTree::new(&eax);
        let b = RegisterTree::new(&ebx);
        assert!(a.borrow().cmp(&b.borrow()) == Ordering::Less);
        assert_eq!(format!("{}", a.borrow()), "EAX[]");
    }
}
