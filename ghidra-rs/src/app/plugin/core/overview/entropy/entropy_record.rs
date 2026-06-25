/// A record containing entropy information for various types found in a program.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyRecord {
    pub name: &'static str,
    pub center: f64,
    pub width: f64,
}

impl EntropyRecord {
    /// Creates a new entropy record.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the entropy record
    /// * `center` - The center point of the entropy range
    /// * `width` - The width of the entropy range
    pub fn new(name: &'static str, center: f64, width: f64) -> Self {
        EntropyRecord { name, center, width }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_record_creation() {
        let record = EntropyRecord::new("x86", 5.94, 0.4);
        assert_eq!(record.name, "x86");
        assert_eq!(record.center, 5.94);
        assert_eq!(record.width, 0.4);
    }

    #[test]
    fn test_entropy_record_clone() {
        let record = EntropyRecord::new("arm", 5.1252, 0.51);
        let cloned = record;
        assert_eq!(record, cloned);
    }
}
