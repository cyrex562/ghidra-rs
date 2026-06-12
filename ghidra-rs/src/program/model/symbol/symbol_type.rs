#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    Label = 0,
    Library = 1,
    Namespace = 3,
    Class = 4,
    Function = 5,
    Parameter = 6,
    LocalVar = 7,
    GlobalVar = 8,
    Global = -1,
}

impl SymbolType {
    pub fn get_id(&self) -> i32 {
        *self as i32
    }

    pub fn from_id(id: i32) -> Option<Self> {
        match id {
            0 => Some(SymbolType::Label),
            1 => Some(SymbolType::Library),
            3 => Some(SymbolType::Namespace),
            4 => Some(SymbolType::Class),
            5 => Some(SymbolType::Function),
            6 => Some(SymbolType::Parameter),
            7 => Some(SymbolType::LocalVar),
            8 => Some(SymbolType::GlobalVar),
            -1 => Some(SymbolType::Global),
            _ => None,
        }
    }

    pub fn is_namespace(&self) -> bool {
        matches!(
            self,
            SymbolType::Library
                | SymbolType::Namespace
                | SymbolType::Class
                | SymbolType::Function
                | SymbolType::Global
        )
    }

    pub fn allows_duplicates(&self) -> bool {
        matches!(self, SymbolType::Label | SymbolType::Function)
    }
}
