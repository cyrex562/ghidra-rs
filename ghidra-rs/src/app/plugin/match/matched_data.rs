use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::{Data, Program};

/// Holds matched data from two programs.
///
/// This is a data container holding match information between data elements in two programs,
/// including the addresses, data objects, and a reason for the match.
///
/// Ported from `ghidra.app.plugin.match.MatchedData`.
#[derive(Clone)]
pub struct MatchedData {
    a_prog: Arc<dyn Program>,
    b_prog: Arc<dyn Program>,
    a_addr: Address,
    b_addr: Address,
    a_data: Arc<dyn Data>,
    b_data: Arc<dyn Data>,
    a_match_num: i32,
    b_match_num: i32,
    reason: String,
}

impl MatchedData {
    /// Creates a new matched data container.
    ///
    /// # Arguments
    ///
    /// * `a_prog` - The first program
    /// * `b_prog` - The second program
    /// * `a_addr` - The address in the first program
    /// * `b_addr` - The address in the second program
    /// * `a_data` - The data in the first program
    /// * `b_data` - The data in the second program
    /// * `a_match_num` - Match number in the first program
    /// * `b_match_num` - Match number in the second program
    /// * `reason` - Reason for the match
    pub fn new(
        a_prog: Arc<dyn Program>,
        b_prog: Arc<dyn Program>,
        a_addr: Address,
        b_addr: Address,
        a_data: Arc<dyn Data>,
        b_data: Arc<dyn Data>,
        a_match_num: i32,
        b_match_num: i32,
        reason: impl Into<String>,
    ) -> Self {
        MatchedData {
            a_prog,
            b_prog,
            a_addr,
            b_addr,
            a_data,
            b_data,
            a_match_num,
            b_match_num,
            reason: reason.into(),
        }
    }

    /// Returns the first program.
    pub fn get_a_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.a_prog)
    }

    /// Returns the second program.
    pub fn get_b_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.b_prog)
    }

    /// Returns the address in the first program.
    pub fn get_a_data_address(&self) -> Address {
        self.a_addr.clone()
    }

    /// Returns the address in the second program.
    pub fn get_b_data_address(&self) -> Address {
        self.b_addr.clone()
    }

    /// Returns the data in the first program.
    pub fn get_a_data(&self) -> Arc<dyn Data> {
        Arc::clone(&self.a_data)
    }

    /// Returns the data in the second program.
    pub fn get_b_data(&self) -> Arc<dyn Data> {
        Arc::clone(&self.b_data)
    }

    /// Returns the match number in the first program.
    pub fn get_a_match_num(&self) -> i32 {
        self.a_match_num
    }

    /// Returns the match number in the second program.
    pub fn get_b_match_num(&self) -> i32 {
        self.b_match_num
    }

    /// Returns the reason for the match.
    pub fn get_reason(&self) -> &str {
        &self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;
    impl Program for MockProgram {}

    struct MockData;
    impl Data for MockData {}

    fn create_test_data() -> (Arc<dyn Program>, Arc<dyn Program>, Arc<dyn Data>, Arc<dyn Data>) {
        (
            Arc::new(MockProgram),
            Arc::new(MockProgram),
            Arc::new(MockData),
            Arc::new(MockData),
        )
    }

    #[test]
    fn test_new() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x1000);
        let b_addr = Address::new(space, 0x2000);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            1,
            2,
            "test reason",
        );

        assert_eq!(matched.get_a_match_num(), 1);
        assert_eq!(matched.get_b_match_num(), 2);
        assert_eq!(matched.get_reason(), "test reason");
        assert_eq!(matched.get_a_data_address(), a_addr);
        assert_eq!(matched.get_b_data_address(), b_addr);
    }

    #[test]
    fn test_getters() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x100);
        let b_addr = Address::new(space, 0x200);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            5,
            10,
            "another reason",
        );

        assert_eq!(matched.get_a_match_num(), 5);
        assert_eq!(matched.get_b_match_num(), 10);
        assert_eq!(matched.get_reason(), "another reason");
    }

    #[test]
    fn test_clone() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x1000);
        let b_addr = Address::new(space, 0x2000);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            1,
            2,
            "test",
        );

        let cloned = matched.clone();
        assert_eq!(cloned.get_a_match_num(), matched.get_a_match_num());
        assert_eq!(cloned.get_b_match_num(), matched.get_b_match_num());
        assert_eq!(cloned.get_reason(), matched.get_reason());
    }
}
