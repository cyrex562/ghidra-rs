use std::fmt;

/// Stores information about the instruction and mask.
#[derive(Debug, Clone)]
pub struct MaskValue {
    mask: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
    text_representation: Option<String>,
}

impl MaskValue {
    pub fn new(mask: Vec<u8>, value: Vec<u8>) -> Self {
        Self { mask: Some(mask), value: Some(value), text_representation: None }
    }

    pub fn with_text(mask: Vec<u8>, value: Vec<u8>, text_representation: String) -> Self {
        Self { mask: Some(mask), value: Some(value), text_representation: Some(text_representation) }
    }

    /// Performs a bitwise OR on the stored mask and `other`. Clears the mask if lengths differ.
    pub fn or_mask(&mut self, other: &[u8]) {
        if let Some(mask) = &self.mask {
            self.mask = byte_array_or(mask, other);
        }
    }

    /// Performs a bitwise OR on the stored value and `other`. Clears the value if lengths differ.
    pub fn or_value(&mut self, other: &[u8]) {
        if let Some(value) = &self.value {
            self.value = byte_array_or(value, other);
        }
    }

    pub fn set_mask(&mut self, mask: Option<Vec<u8>>) {
        self.mask = mask;
    }

    pub fn set_value(&mut self, value: Option<Vec<u8>>) {
        self.value = value;
    }

    pub fn get_mask(&self) -> Option<&[u8]> {
        self.mask.as_deref()
    }

    pub fn get_value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// Returns the element-wise OR of two equal-length slices, or `None` if lengths differ.
fn byte_array_or(arr1: &[u8], arr2: &[u8]) -> Option<Vec<u8>> {
    if arr1.len() != arr2.len() {
        return None;
    }
    Some(arr1.iter().zip(arr2.iter()).map(|(a, b)| a | b).collect())
}

fn format_byte_array(arr: &Option<Vec<u8>>) -> String {
    match arr {
        None => "null".to_string(),
        Some(v) if v.is_empty() => "[]".to_string(),
        Some(v) => {
            let items: Vec<String> = v.iter().map(|b| (*b as i8).to_string()).collect();
            format!("[{}]", items.join(", "))
        }
    }
}

impl fmt::Display for MaskValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rep = self.text_representation.as_deref().unwrap_or("");
        write!(
            f,
            "MaskValue - {} [mask={}, value={}]",
            rep,
            format_byte_array(&self.mask),
            format_byte_array(&self.value)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_mask_and_value() {
        let mv = MaskValue::new(vec![0xFF, 0x00], vec![0xAB, 0xCD]);
        assert_eq!(mv.get_mask(), Some([0xFF, 0x00].as_ref()));
        assert_eq!(mv.get_value(), Some([0xAB, 0xCD].as_ref()));
    }

    #[test]
    fn with_text_stores_text_representation() {
        let mv = MaskValue::with_text(vec![0x01], vec![0x02], "ADD".to_string());
        assert!(mv.to_string().contains("ADD"));
    }

    #[test]
    fn or_mask_applies_bitwise_or() {
        let mut mv = MaskValue::new(vec![0b1010, 0b0000], vec![0x00, 0x00]);
        mv.or_mask(&[0b0101, 0b1111]);
        assert_eq!(mv.get_mask(), Some([0b1111, 0b1111].as_ref()));
    }

    #[test]
    fn or_value_applies_bitwise_or() {
        let mut mv = MaskValue::new(vec![0x00, 0x00], vec![0b1100, 0b0000]);
        mv.or_value(&[0b0011, 0b1010]);
        assert_eq!(mv.get_value(), Some([0b1111, 0b1010].as_ref()));
    }

    #[test]
    fn or_mask_clears_mask_on_length_mismatch() {
        let mut mv = MaskValue::new(vec![0xFF, 0xFF], vec![0x00]);
        mv.or_mask(&[0x01]); // length 1 vs 2
        assert_eq!(mv.get_mask(), None);
    }

    #[test]
    fn or_value_clears_value_on_length_mismatch() {
        let mut mv = MaskValue::new(vec![0x00], vec![0xFF, 0xFF]);
        mv.or_value(&[0x01]); // length 1 vs 2
        assert_eq!(mv.get_value(), None);
    }

    #[test]
    fn or_mask_is_noop_when_mask_is_none() {
        let mut mv = MaskValue::new(vec![0x00], vec![0x00]);
        mv.set_mask(None);
        mv.or_mask(&[0xFF]);
        assert_eq!(mv.get_mask(), None);
    }

    #[test]
    fn or_value_is_noop_when_value_is_none() {
        let mut mv = MaskValue::new(vec![0x00], vec![0x00]);
        mv.set_value(None);
        mv.or_value(&[0xFF]);
        assert_eq!(mv.get_value(), None);
    }

    #[test]
    fn set_mask_and_set_value_replace_fields() {
        let mut mv = MaskValue::new(vec![0x00], vec![0x00]);
        mv.set_mask(Some(vec![0xAB]));
        mv.set_value(Some(vec![0xCD]));
        assert_eq!(mv.get_mask(), Some([0xAB].as_ref()));
        assert_eq!(mv.get_value(), Some([0xCD].as_ref()));
    }

    #[test]
    fn display_without_text_representation() {
        let mv = MaskValue::new(vec![0x01, 0x02], vec![0x03, 0x04]);
        let s = mv.to_string();
        assert!(s.starts_with("MaskValue - "));
        assert!(s.contains("[mask=[1, 2], value=[3, 4]]"));
    }

    #[test]
    fn display_with_text_representation() {
        let mv = MaskValue::with_text(vec![0xFF], vec![0x00], "MOV".to_string());
        let s = mv.to_string();
        assert!(s.contains("MOV"));
        assert!(s.contains("[mask=[-1], value=[0]]"));
    }

    #[test]
    fn display_signed_byte_formatting() {
        // 0xFF as i8 is -1
        let mv = MaskValue::new(vec![0xFF, 0x80, 0x7F], vec![]);
        let s = mv.to_string();
        assert!(s.contains("[-1, -128, 127]"));
    }

    #[test]
    fn display_null_mask_shows_null() {
        let mut mv = MaskValue::new(vec![], vec![]);
        mv.set_mask(None);
        assert!(mv.to_string().contains("mask=null"));
    }

    #[test]
    fn display_empty_array_shows_brackets() {
        let mv = MaskValue::new(vec![], vec![]);
        let s = mv.to_string();
        assert!(s.contains("mask=[]"));
        assert!(s.contains("value=[]"));
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mv = MaskValue::new(vec![0x01], vec![0x02]);
        let mut clone = mv.clone();
        clone.or_mask(&[0xFF]);
        // original unchanged
        assert_eq!(mv.get_mask(), Some([0x01].as_ref()));
    }
}
