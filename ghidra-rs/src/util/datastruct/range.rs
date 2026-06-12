use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    pub min: i32,
    pub max: i32,
}

impl Range {
    pub fn new(min: i32, max: i32) -> Self {
        if max < min {
            panic!("Range max ({}) cannot be less than min ({}).", max, min);
        }
        Self { min, max }
    }

    pub fn contains(&self, value: i32) -> bool {
        value >= self.min && value <= self.max
    }

    pub fn size(&self) -> i64 {
        (self.max as i64) - (self.min as i64) + 1
    }

    pub fn iter(&self) -> std::ops::RangeInclusive<i32> {
        self.min..=self.max
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.min, self.max)
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Range {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.min.cmp(&other.min)
    }
}

impl IntoIterator for Range {
    type Item = i32;
    type IntoIter = std::ops::RangeInclusive<i32>;

    fn into_iter(self) -> Self::IntoIter {
        self.min..=self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range() {
        let r = Range::new(1, 10);
        assert_eq!(r.size(), 10);
        assert!(r.contains(5));
        assert!(!r.contains(11));

        let vals: Vec<i32> = r.into_iter().collect();
        assert_eq!(vals.len(), 10);
        assert_eq!(vals[0], 1);
        assert_eq!(vals[9], 10);
    }

    #[test]
    #[should_panic]
    fn test_invalid_range() {
        Range::new(10, 1);
    }
}
