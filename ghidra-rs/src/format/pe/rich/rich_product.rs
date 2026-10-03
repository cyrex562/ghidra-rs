//! Port of `ghidra.app.util.bin.format.pe.rich.RichProduct`.

use std::fmt;

use crate::format::pe::rich::comp_id::CompId;
use crate::format::pe::rich::ms_product_type::MsProductType;

/// A single decoded entry from a PE Rich header: the tool (compiler/linker/etc.) that produced an
/// object, together with its version and product-type classification.
///
/// Port of `ghidra.app.util.bin.format.pe.rich.RichProduct`. Previously modeled in this crate as
/// the placeholder trait `crate::format::seam_stubs::RichProduct` (referenced by
/// [`CompId::product_description`](crate::format::pe::rich::comp_id::CompId::product_description)/
/// [`RichHeaderUtils`](crate::format::seam_stubs::RichHeaderUtils) before this real class was
/// ported); that placeholder is retired below in favor of this concrete struct, mirroring how
/// `RichHeaderRecord`'s own placeholder was retired once it was ported for real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichProduct {
    compid: CompId,
    product_version: String,
    product_type: MsProductType,
}

impl RichProduct {
    /// Port of `RichProduct(int compid, String version, MSProductType type)`.
    pub fn new(compid: i32, version: impl Into<String>, product_type: MsProductType) -> Self {
        RichProduct { compid: CompId::new(compid), product_version: version.into(), product_type }
    }

    /// Port of `RichProduct.getCompid()`.
    pub fn get_compid(&self) -> CompId {
        self.compid
    }

    /// Port of `RichProduct.getProductVersion()`.
    pub fn get_product_version(&self) -> &str {
        &self.product_version
    }

    /// Port of `RichProduct.getProductType()`.
    pub fn get_product_type(&self) -> MsProductType {
        self.product_type
    }
}

impl fmt::Display for RichProduct {
    /// Port of `RichProduct.toString()`: `getProductVersion() + " -- " + getProductType()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -- {}", self.product_version, self.product_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_derives_comp_id_from_the_raw_value() {
        let product = RichProduct::new(0x0009_0042, "19.20.27508", MsProductType::CCompiler);
        assert_eq!(product.get_compid().value(), 0x0009_0042);
        assert_eq!(product.get_compid().product_id(), 0x0009);
    }

    #[test]
    fn accessors_return_constructor_arguments() {
        let product = RichProduct::new(0x1234_5678, "1.0", MsProductType::Linker);
        assert_eq!(product.get_product_version(), "1.0");
        assert_eq!(product.get_product_type(), MsProductType::Linker);
    }

    #[test]
    fn to_string_matches_java_format() {
        let product = RichProduct::new(0x1234_5678, "19.20.27508", MsProductType::CxxCompiler);
        assert_eq!(product.to_string(), "19.20.27508 -- C++ Compiler");
    }

    #[test]
    fn equality_is_structural() {
        let a = RichProduct::new(1, "v", MsProductType::Assembler);
        let b = RichProduct::new(1, "v", MsProductType::Assembler);
        let c = RichProduct::new(2, "v", MsProductType::Assembler);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
