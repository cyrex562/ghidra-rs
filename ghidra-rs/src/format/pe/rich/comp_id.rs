use crate::format::pe::rich::ms_product_type::MsProductType;
use crate::format::seam_stubs::RichHeaderUtils;

/// Mirrors `ghidra.app.util.bin.format.pe.rich.CompId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompId {
    id: i32,
    product_id: i32,
    build_number: i32,
}

impl CompId {
    pub fn new(id: i32) -> Self {
        let product_id = id >> 16;
        let build_number = id & 0x0000FFFF;
        CompId {
            id,
            product_id,
            build_number,
        }
    }

    pub fn value(&self) -> i32 {
        self.id
    }

    pub fn product_id(&self) -> i32 {
        self.product_id
    }

    pub fn build_number(&self) -> i32 {
        self.build_number
    }

    pub fn product_description(&self, rich_header_utils: &dyn RichHeaderUtils) -> String {
        let prod = rich_header_utils.get_product(self.product_id);

        let prod_version = prod
            .as_ref()
            .map(|p| p.get_product_version())
            .unwrap_or_else(|| format!("Unknown Product ({})", format!("{:x}", self.product_id)));

        let prod_type = prod
            .as_ref()
            .map(|p| p.get_product_type())
            .unwrap_or(MsProductType::Unknown);

        let mut result = String::new();
        if prod_type != MsProductType::Unknown {
            result.push_str(&prod_type.to_string());
            result.push_str(" from ");
            result.push_str(&prod_version);
        } else {
            result.push_str(&prod_version);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::RichProduct;

    struct MockRichHeaderUtils;

    impl RichHeaderUtils for MockRichHeaderUtils {
        fn get_product(&self, _id: i32) -> Option<Box<dyn RichProduct>> {
            None
        }
    }

    #[test]
    fn test_new() {
        let comp_id = CompId::new(0x12340042);
        assert_eq!(comp_id.value(), 0x12340042);
        assert_eq!(comp_id.product_id(), 0x1234);
        assert_eq!(comp_id.build_number(), 0x0042);
    }

    #[test]
    fn test_build_number_masked() {
        let comp_id = CompId::new(-1i32);
        assert_eq!(comp_id.build_number(), 0xFFFF);
    }

    #[test]
    fn test_product_id_shift() {
        let comp_id = CompId::new(0x00010002);
        assert_eq!(comp_id.product_id(), 0x0001);
        assert_eq!(comp_id.build_number(), 0x0002);
    }

    #[test]
    fn test_product_description_without_product() {
        let comp_id = CompId::new(0x12345678);
        let utils = MockRichHeaderUtils;
        let desc = comp_id.product_description(&utils);
        assert!(desc.contains("Unknown Product"));
        assert!(desc.contains("1234"));
    }
}
