use crate::sleigh::grammar::Location;
use std::fmt;

/// Represents field metadata for SLEIGH language constructs.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.FieldQuality`.
pub struct FieldQuality {
    pub location: Location,
    pub name: String,
    pub low: i32,
    pub high: i32,
    pub signext: bool,
    pub flow: bool,
    pub hex: bool,
}

impl FieldQuality {
    pub fn new(name: String, location: Location, low: i64, high: i64) -> Self {
        Self {
            location,
            name,
            low: low as i32,
            high: high as i32,
            signext: false,
            flow: true,
            hex: true,
        }
    }
}

impl fmt::Display for FieldQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fq:{{{},{},{},{},{}}}",
            self.name, self.low, self.high, self.signext, self.hex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction() {
        let loc = Location::new("test.sleigh", 10);
        let fq = FieldQuality::new("field1".to_string(), loc, 0, 31);

        assert_eq!(fq.name, "field1");
        assert_eq!(fq.low, 0);
        assert_eq!(fq.high, 31);
        assert!(!fq.signext);
        assert!(fq.flow);
        assert!(fq.hex);
    }

    #[test]
    fn test_construction_with_long_values() {
        let loc = Location::new("test.sleigh", 20);
        let fq = FieldQuality::new("field2".to_string(), loc, 100i64, 200i64);

        assert_eq!(fq.low, 100);
        assert_eq!(fq.high, 200);
    }

    #[test]
    fn test_display_format() {
        let loc = Location::new("test.sleigh", 30);
        let mut fq = FieldQuality::new("test".to_string(), loc, 0, 15);
        fq.signext = true;

        let display = fq.to_string();
        assert_eq!(display, "fq:{test,0,15,true,true}");
    }

    #[test]
    fn test_display_with_defaults() {
        let loc = Location::new("test.sleigh", 40);
        let fq = FieldQuality::new("field".to_string(), loc, 5, 10);

        let display = fq.to_string();
        assert_eq!(display, "fq:{field,5,10,false,true}");
    }

    #[test]
    fn test_fields_can_be_modified() {
        let loc = Location::new("test.sleigh", 50);
        let mut fq = FieldQuality::new("mod".to_string(), loc, 1, 2);

        fq.signext = true;
        fq.flow = false;
        fq.hex = false;

        assert!(fq.signext);
        assert!(!fq.flow);
        assert!(!fq.hex);
    }
}
