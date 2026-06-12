pub mod sleigh;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    pub fn is_big_endian(&self) -> bool {
        matches!(self, Self::Big)
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Big => "big",
            Self::Little => "little",
        }
    }
}
