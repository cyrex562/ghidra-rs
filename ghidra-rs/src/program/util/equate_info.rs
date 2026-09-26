use std::fmt;

use crate::program::model::address::Address;

/// Holds information about an Equate; used in a `ProgramChangeRecord` when an
/// equate is created and when references to the Equate are updated.
///
/// Port of `ghidra.program.util.EquateInfo`.
pub struct EquateInfo {
    name: String,
    value: i64,
    ref_addr: Option<Address>,
    op_index: i32,
    dynamic_hash: i64,
}

impl EquateInfo {
    /// Construct a new EquateInfo.
    ///
    /// # Arguments
    /// * `name` - equate name
    /// * `value` - equate value
    /// * `ref_addr` - reference address (may be `None` for some event types)
    /// * `op_index` - operand index for the reference; useful only if `ref_addr`
    ///   is not `None`. May be -1 if only `dynamic_hash` applies.
    /// * `dynamic_hash` - dynamic hash. May be 0 if only `op_index` applies.
    ///
    /// Note: matching the original Java source, `dynamic_hash` is accepted but
    /// never stored, so `dynamic_hash()` always returns 0.
    pub fn new(
        name: impl Into<String>,
        value: i64,
        ref_addr: Option<Address>,
        op_index: i32,
        _dynamic_hash: i64,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            ref_addr,
            op_index,
            dynamic_hash: 0,
        }
    }

    /// Get the equate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the equate value.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Get the reference address.
    pub fn reference_address(&self) -> Option<&Address> {
        self.ref_addr.as_ref()
    }

    /// Get the operand index of where the equate was placed. This value is
    /// meaningful only if the reference address is not `None`, and may be -1
    /// if only the dynamic hash applies.
    pub fn operand_index(&self) -> i32 {
        self.op_index
    }

    /// Get the varnode dynamic hash of where the equate was placed. This value
    /// is meaningful only if the reference address is not `None`, and may be 0
    /// if only the operand index applies.
    pub fn dynamic_hash(&self) -> i64 {
        self.dynamic_hash
    }
}

impl fmt::Display for EquateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name={}", self.name)?;
        write!(f, ",value={}", self.value)?;
        match &self.ref_addr {
            Some(addr) => write!(f, ", RefAddr={}", addr)?,
            None => write!(f, ", RefAddr=null")?,
        }
        write!(f, ", opIndex={}", self.op_index)?;
        write!(f, ", dynamicHash=0x{:x}", self.dynamic_hash)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_name_value_and_op_index() {
        let info = EquateInfo::new("FOO", 42, None, 1, 0);
        assert_eq!(info.name(), "FOO");
        assert_eq!(info.value(), 42);
        assert_eq!(info.operand_index(), 1);
    }

    #[test]
    fn reference_address_defaults_to_none() {
        let info = EquateInfo::new("FOO", 42, None, -1, 0);
        assert!(info.reference_address().is_none());
    }

    #[test]
    fn dynamic_hash_is_always_zero_matching_java_behavior() {
        // The original Java constructor never assigns its dynamicHash parameter
        // to the field, so getDynamicHash() always returns 0. Preserved here.
        let info = EquateInfo::new("FOO", 42, None, -1, 0xdead_beef);
        assert_eq!(info.dynamic_hash(), 0);
    }

    #[test]
    fn display_without_ref_addr_uses_null() {
        let info = EquateInfo::new("BAR", 7, None, -1, 0);
        let s = format!("{}", info);
        assert_eq!(s, "Name=BAR,value=7, RefAddr=null, opIndex=-1, dynamicHash=0x0");
    }

    #[test]
    fn new_accepts_owned_string_name() {
        let name = String::from("BAZ");
        let info = EquateInfo::new(name, 1, None, 0, 0);
        assert_eq!(info.name(), "BAZ");
    }
}
