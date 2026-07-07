/// Info header for Apple iBootIm image files.
///
/// Mirrors `ghidra.file.formats.ios.ibootim.iBootImInfoHeader`.
pub struct IBootImInfoHeader;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_construct() {
        let _ = IBootImInfoHeader;
    }
}
