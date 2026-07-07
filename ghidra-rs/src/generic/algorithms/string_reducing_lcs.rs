use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::reducing_lcs::{ReducingLcs, ReducingLcsOps};

struct StringOps;

impl ReducingLcsOps<String, char> for StringOps {
    fn reduce(&self, s: &String, start: usize, end: usize) -> String {
        s.chars().skip(start).take(end - start).collect()
    }

    fn length_of(&self, s: &String) -> usize {
        s.chars().count()
    }

    fn value_of(&self, s: &String, offset: usize) -> char {
        s.chars().nth(offset).unwrap()
    }

    fn matches(&self, x: &char, y: &char) -> bool {
        x == y
    }
}

/// An implementation of [`ReducingLcs`] that works on Strings, comparing character by character.
pub struct StringReducingLcs {
    lcs: ReducingLcs<String, char, StringOps>,
}

impl StringReducingLcs {
    /// Creates a new instance with two input strings.
    pub fn new(x: String, y: String) -> Self {
        Self {
            lcs: ReducingLcs::new(StringOps, x, y),
        }
    }

    /// Returns the longest common subsequence, re-attaching the shared prefix/suffix
    /// that were trimmed away before computing the reduced LCS.
    pub fn get_lcs(&self, monitor: &dyn TaskMonitor) -> Result<String, CancelledException> {
        self.lcs.get_lcs(monitor).map(|chars| chars.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn test_identical() {
        let lcs = StringReducingLcs::new("DEADBEEF".to_string(), "DEADBEEF".to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), "DEADBEEF");
    }

    #[test]
    fn test_similar() {
        let lcs = StringReducingLcs::new("DEADBEEF".to_string(), "DEEDBEAD".to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), "DEDBE");
    }

    #[test]
    fn test_different() {
        let lcs = StringReducingLcs::new("DEAD".to_string(), "CANND".to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), "AD");

        let lcs = StringReducingLcs::new("DEADBEEFISGOOD".to_string(), "CANNDBEEFISBAD".to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), "ADBEEFISD");

        let lcs = StringReducingLcs::new("this here is one string".to_string(), "here a different string is".to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), "here in string");
    }

    #[test]
    fn test_insert_only() {
        let x = "Line not modified";
        let y = "Line not not modified";
        let lcs = StringReducingLcs::new(x.to_string(), y.to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), x);
    }

    #[test]
    fn test_removal_only() {
        let x = "Line not modified";
        let y = "Line modified";
        let lcs = StringReducingLcs::new(x.to_string(), y.to_string());
        assert_eq!(lcs.get_lcs(&DummyMonitor).unwrap(), y);
    }
}
