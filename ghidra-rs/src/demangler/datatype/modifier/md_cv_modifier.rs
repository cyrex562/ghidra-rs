/// Const/Volatile modifier of a modifier type within a Microsoft mangled symbol.
///
/// Port of `mdemangler.datatype.modifier.MDCVModifier`.
///
/// The original Java source has all implementation commented out; this struct
/// preserves the type identity as the code is progressively re-enabled.
pub struct MdCvModifier;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_construct() {
        let _ = MdCvModifier;
    }
}
