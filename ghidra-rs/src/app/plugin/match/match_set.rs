use std::collections::HashSet;

use super::Match;

/// A collection of matches between two programs.
///
/// Port of `ghidra.app.plugin.match.MatchSet`.
pub struct MatchSet {
    pub this_name: String,
    pub other_name: String,
    matches: HashSet<Match>,
}

impl MatchSet {
    /// Creates a new empty MatchSet.
    ///
    /// # Arguments
    /// * `this_program_name` - Name of the program from which the matching was initiated.
    /// * `other_program_name` - Name of the program being matched.
    pub fn new(this_program_name: String, other_program_name: String) -> Self {
        MatchSet {
            this_name: this_program_name,
            other_name: other_program_name,
            matches: HashSet::new(),
        }
    }

    /// Adds a match to this set.
    pub fn add(&mut self, m: Match) {
        self.matches.insert(m);
    }

    /// Returns the matches as a sorted array.
    pub fn get_matches(&self) -> Vec<Match> {
        let mut matches: Vec<Match> = self.matches.iter().cloned().collect();
        matches.sort();
        matches
    }

    /// Returns the number of matches in this set.
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    /// Checks if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Returns a representation of the match as an array of values.
    ///
    /// The array contains:
    /// - [0]: this_beginning address (as u64 offset)
    /// - [1]: this_name (String)
    /// - [2]: other_beginning address (as u64 offset)
    /// - [3]: other_name (String)
    /// - [4]: match length (as usize)
    pub fn get_results_array(&self, m: &Match) -> (u64, String, u64, String, usize) {
        (
            m.get_this_beginning().unsigned_offset(),
            self.this_name.clone(),
            m.get_other_beginning().unsigned_offset(),
            self.other_name.clone(),
            m.length(),
        )
    }

    /// Returns an iterator over the matches.
    pub fn iter(&self) -> impl Iterator<Item = &Match> {
        self.matches.iter()
    }

    /// Clears all matches from this set.
    pub fn clear(&mut self) {
        self.matches.clear();
    }
}

impl Clone for MatchSet {
    fn clone(&self) -> Self {
        MatchSet {
            this_name: self.this_name.clone(),
            other_name: self.other_name.clone(),
            matches: self.matches.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn test_new() {
        let match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        assert_eq!(match_set.this_name, "prog1");
        assert_eq!(match_set.other_name, "prog2");
        assert!(match_set.is_empty());
        assert_eq!(match_set.len(), 0);
    }

    #[test]
    fn test_add_and_len() {
        let mut match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        let m = Match::new_from_bytes(&addr(0x1000), &addr(0x2000), b"\x90\x90", 2);
        match_set.add(m);
        assert_eq!(match_set.len(), 1);
        assert!(!match_set.is_empty());
    }

    #[test]
    fn test_get_matches_sorted() {
        let mut match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        let m1 = Match::new_from_bytes(&addr(0x3000), &addr(0x4000), b"\x90", 1);
        let m2 = Match::new_from_bytes(&addr(0x1000), &addr(0x2000), b"\x90\x90", 2);
        match_set.add(m1);
        match_set.add(m2);

        let matches = match_set.get_matches();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].get_this_beginning().offset(), 0x1000);
        assert_eq!(matches[1].get_this_beginning().offset(), 0x3000);
    }

    #[test]
    fn test_get_results_array() {
        let match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        let m = Match::new_from_bytes(&addr(0x1000), &addr(0x2000), b"\x90\x90", 2);
        let (this_addr, this_name, other_addr, other_name, length) = match_set.get_results_array(&m);

        assert_eq!(this_addr, 0x1000);
        assert_eq!(this_name, "prog1");
        assert_eq!(other_addr, 0x2000);
        assert_eq!(other_name, "prog2");
        assert_eq!(length, 2);
    }

    #[test]
    fn test_clear() {
        let mut match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        let m = Match::new_from_bytes(&addr(0x1000), &addr(0x2000), b"\x90\x90", 2);
        match_set.add(m);
        assert_eq!(match_set.len(), 1);

        match_set.clear();
        assert_eq!(match_set.len(), 0);
        assert!(match_set.is_empty());
    }

    #[test]
    fn test_clone() {
        let mut match_set = MatchSet::new("prog1".to_string(), "prog2".to_string());
        let m = Match::new_from_bytes(&addr(0x1000), &addr(0x2000), b"\x90\x90", 2);
        match_set.add(m);

        let cloned = match_set.clone();
        assert_eq!(cloned.this_name, "prog1");
        assert_eq!(cloned.other_name, "prog2");
        assert_eq!(cloned.len(), 1);
    }
}
