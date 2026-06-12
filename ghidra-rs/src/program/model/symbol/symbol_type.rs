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
    pub fn display_name(&self) -> &'static str {
        match self {
            SymbolType::Label => "Label",
            SymbolType::Library => "Library",
            SymbolType::Namespace => "Namespace",
            SymbolType::Class => "Class",
            SymbolType::Function => "Function",
            SymbolType::Parameter => "Parameter",
            SymbolType::LocalVar => "Local Var",
            SymbolType::GlobalVar => "Global Register Var",
            SymbolType::Global => "Global",
        }
    }

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

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_java_values() {
        assert_eq!(SymbolType::Label.get_id(), 0);
        assert_eq!(SymbolType::Library.get_id(), 1);
        assert_eq!(SymbolType::Namespace.get_id(), 3);
        assert_eq!(SymbolType::Class.get_id(), 4);
        assert_eq!(SymbolType::Function.get_id(), 5);
        assert_eq!(SymbolType::Parameter.get_id(), 6);
        assert_eq!(SymbolType::LocalVar.get_id(), 7);
        assert_eq!(SymbolType::GlobalVar.get_id(), 8);
        assert_eq!(SymbolType::Global.get_id(), -1);

        assert_eq!(SymbolType::from_id(0), Some(SymbolType::Label));
        assert_eq!(SymbolType::from_id(1), Some(SymbolType::Library));
        assert_eq!(SymbolType::from_id(2), None);
        assert_eq!(SymbolType::from_id(3), Some(SymbolType::Namespace));
        assert_eq!(SymbolType::from_id(8), Some(SymbolType::GlobalVar));
        assert_eq!(SymbolType::from_id(-1), Some(SymbolType::Global));
        assert_eq!(SymbolType::from_id(9), None);
    }

    #[test]
    fn display_names_match_java() {
        assert_eq!(SymbolType::Label.to_string(), "Label");
        assert_eq!(SymbolType::Library.to_string(), "Library");
        assert_eq!(SymbolType::Namespace.to_string(), "Namespace");
        assert_eq!(SymbolType::Class.to_string(), "Class");
        assert_eq!(SymbolType::Function.to_string(), "Function");
        assert_eq!(SymbolType::Parameter.to_string(), "Parameter");
        assert_eq!(SymbolType::LocalVar.to_string(), "Local Var");
        assert_eq!(SymbolType::GlobalVar.to_string(), "Global Register Var");
        assert_eq!(SymbolType::Global.to_string(), "Global");
    }

    #[test]
    fn namespace_and_duplicate_flags_match_java_defaults() {
        assert!(!SymbolType::Label.is_namespace());
        assert!(SymbolType::Library.is_namespace());
        assert!(SymbolType::Namespace.is_namespace());
        assert!(SymbolType::Class.is_namespace());
        assert!(SymbolType::Function.is_namespace());
        assert!(!SymbolType::Parameter.is_namespace());
        assert!(!SymbolType::LocalVar.is_namespace());
        assert!(!SymbolType::GlobalVar.is_namespace());
        assert!(SymbolType::Global.is_namespace());

        assert!(SymbolType::Label.allows_duplicates());
        assert!(SymbolType::Function.allows_duplicates());
        assert!(!SymbolType::Namespace.allows_duplicates());
    }
}
