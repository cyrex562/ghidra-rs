//! Ported from `ghidra.app.util.demangler.swift.SwiftDemangledNodeKind`.
//!
//! Kinds of Swift demangling [`crate::demangler::swift::nodes::swift_node::SwiftNode`]s.
//!
//! See <https://github.com/swiftlang/swift/blob/main/include/swift/Demangling/DemangleNodes.def>.

/// Mirrors `SwiftDemangledNodeKind`, a closed enum of Swift demangle node kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum SwiftDemangledNodeKind {
    Allocator,
    AnonymousDescriptor,
    ArgumentTuple,
    BoundGenericStructure,
    BuiltinTypeName,
    Class,
    Constructor,
    Deallocator,
    DefaultArgumentInitializer,
    DependentGenericParamType,
    DependentGenericType,
    Destructor,
    DispatchThunk,
    Enum,
    Extension,
    FirstElementMarker,
    Function,
    FunctionType,
    GenericSpecialization,
    Getter,
    Global,
    GlobalVariableOnceDeclList,
    GlobalVariableOnceFunction,
    Identifier,
    InfixOperator,
    Initializer,
    InOut,
    LabelList,
    LazyProtocolWitnessTableAccessor,
    LocalDeclName,
    MergedFunction,
    MethodDescriptor,
    ModifyAccessor,
    Module,
    ModuleDescriptor,
    NominalTypeDescriptor,
    Number,
    ObjCAttribute,
    OutlinedConsume,
    OutlinedCopy,
    Owned,
    PrivateDeclName,
    Protocol,
    ProtocolConformance,
    ProtocolConformanceDescriptor,
    ProtocolDescriptor,
    ProtocolWitness,
    ReflectionMetadataBuiltinDescriptor,
    ReflectionMetadataFieldDescriptor,
    ReturnType,
    Setter,
    Static,
    Structure,
    Subscript,
    Suffix,
    Tuple,
    TupleElement,
    TupleElementName,
    Type,
    TypeAlias,
    TypeList,
    TypeMetadataAccessFunction,
    UnsafeMutableAddressor,
    Unsupported,
    Variable,
}

impl SwiftDemangledNodeKind {
    /// Returns the constant's Java name.
    ///
    /// Mirrors `Enum.name()` / `Enum.toString()`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Allocator => "Allocator",
            Self::AnonymousDescriptor => "AnonymousDescriptor",
            Self::ArgumentTuple => "ArgumentTuple",
            Self::BoundGenericStructure => "BoundGenericStructure",
            Self::BuiltinTypeName => "BuiltinTypeName",
            Self::Class => "Class",
            Self::Constructor => "Constructor",
            Self::Deallocator => "Deallocator",
            Self::DefaultArgumentInitializer => "DefaultArgumentInitializer",
            Self::DependentGenericParamType => "DependentGenericParamType",
            Self::DependentGenericType => "DependentGenericType",
            Self::Destructor => "Destructor",
            Self::DispatchThunk => "DispatchThunk",
            Self::Enum => "Enum",
            Self::Extension => "Extension",
            Self::FirstElementMarker => "FirstElementMarker",
            Self::Function => "Function",
            Self::FunctionType => "FunctionType",
            Self::GenericSpecialization => "GenericSpecialization",
            Self::Getter => "Getter",
            Self::Global => "Global",
            Self::GlobalVariableOnceDeclList => "GlobalVariableOnceDeclList",
            Self::GlobalVariableOnceFunction => "GlobalVariableOnceFunction",
            Self::Identifier => "Identifier",
            Self::InfixOperator => "InfixOperator",
            Self::Initializer => "Initializer",
            Self::InOut => "InOut",
            Self::LabelList => "LabelList",
            Self::LazyProtocolWitnessTableAccessor => "LazyProtocolWitnessTableAccessor",
            Self::LocalDeclName => "LocalDeclName",
            Self::MergedFunction => "MergedFunction",
            Self::MethodDescriptor => "MethodDescriptor",
            Self::ModifyAccessor => "ModifyAccessor",
            Self::Module => "Module",
            Self::ModuleDescriptor => "ModuleDescriptor",
            Self::NominalTypeDescriptor => "NominalTypeDescriptor",
            Self::Number => "Number",
            Self::ObjCAttribute => "ObjCAttribute",
            Self::OutlinedConsume => "OutlinedConsume",
            Self::OutlinedCopy => "OutlinedCopy",
            Self::Owned => "Owned",
            Self::PrivateDeclName => "PrivateDeclName",
            Self::Protocol => "Protocol",
            Self::ProtocolConformance => "ProtocolConformance",
            Self::ProtocolConformanceDescriptor => "ProtocolConformanceDescriptor",
            Self::ProtocolDescriptor => "ProtocolDescriptor",
            Self::ProtocolWitness => "ProtocolWitness",
            Self::ReflectionMetadataBuiltinDescriptor => "ReflectionMetadataBuiltinDescriptor",
            Self::ReflectionMetadataFieldDescriptor => "ReflectionMetadataFieldDescriptor",
            Self::ReturnType => "ReturnType",
            Self::Setter => "Setter",
            Self::Static => "Static",
            Self::Structure => "Structure",
            Self::Subscript => "Subscript",
            Self::Suffix => "Suffix",
            Self::Tuple => "Tuple",
            Self::TupleElement => "TupleElement",
            Self::TupleElementName => "TupleElementName",
            Self::Type => "Type",
            Self::TypeAlias => "TypeAlias",
            Self::TypeList => "TypeList",
            Self::TypeMetadataAccessFunction => "TypeMetadataAccessFunction",
            Self::UnsafeMutableAddressor => "UnsafeMutableAddressor",
            Self::Unsupported => "Unsupported",
            Self::Variable => "Variable",
        }
    }

    /// Parses a constant by its Java name.
    ///
    /// Mirrors `Enum.valueOf(SwiftDemangledNodeKind.class, name)`; returns `None` where the Java
    /// call would throw `IllegalArgumentException` for an unrecognized name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Allocator" => Some(Self::Allocator),
            "AnonymousDescriptor" => Some(Self::AnonymousDescriptor),
            "ArgumentTuple" => Some(Self::ArgumentTuple),
            "BoundGenericStructure" => Some(Self::BoundGenericStructure),
            "BuiltinTypeName" => Some(Self::BuiltinTypeName),
            "Class" => Some(Self::Class),
            "Constructor" => Some(Self::Constructor),
            "Deallocator" => Some(Self::Deallocator),
            "DefaultArgumentInitializer" => Some(Self::DefaultArgumentInitializer),
            "DependentGenericParamType" => Some(Self::DependentGenericParamType),
            "DependentGenericType" => Some(Self::DependentGenericType),
            "Destructor" => Some(Self::Destructor),
            "DispatchThunk" => Some(Self::DispatchThunk),
            "Enum" => Some(Self::Enum),
            "Extension" => Some(Self::Extension),
            "FirstElementMarker" => Some(Self::FirstElementMarker),
            "Function" => Some(Self::Function),
            "FunctionType" => Some(Self::FunctionType),
            "GenericSpecialization" => Some(Self::GenericSpecialization),
            "Getter" => Some(Self::Getter),
            "Global" => Some(Self::Global),
            "GlobalVariableOnceDeclList" => Some(Self::GlobalVariableOnceDeclList),
            "GlobalVariableOnceFunction" => Some(Self::GlobalVariableOnceFunction),
            "Identifier" => Some(Self::Identifier),
            "InfixOperator" => Some(Self::InfixOperator),
            "Initializer" => Some(Self::Initializer),
            "InOut" => Some(Self::InOut),
            "LabelList" => Some(Self::LabelList),
            "LazyProtocolWitnessTableAccessor" => Some(Self::LazyProtocolWitnessTableAccessor),
            "LocalDeclName" => Some(Self::LocalDeclName),
            "MergedFunction" => Some(Self::MergedFunction),
            "MethodDescriptor" => Some(Self::MethodDescriptor),
            "ModifyAccessor" => Some(Self::ModifyAccessor),
            "Module" => Some(Self::Module),
            "ModuleDescriptor" => Some(Self::ModuleDescriptor),
            "NominalTypeDescriptor" => Some(Self::NominalTypeDescriptor),
            "Number" => Some(Self::Number),
            "ObjCAttribute" => Some(Self::ObjCAttribute),
            "OutlinedConsume" => Some(Self::OutlinedConsume),
            "OutlinedCopy" => Some(Self::OutlinedCopy),
            "Owned" => Some(Self::Owned),
            "PrivateDeclName" => Some(Self::PrivateDeclName),
            "Protocol" => Some(Self::Protocol),
            "ProtocolConformance" => Some(Self::ProtocolConformance),
            "ProtocolConformanceDescriptor" => Some(Self::ProtocolConformanceDescriptor),
            "ProtocolDescriptor" => Some(Self::ProtocolDescriptor),
            "ProtocolWitness" => Some(Self::ProtocolWitness),
            "ReflectionMetadataBuiltinDescriptor" => Some(Self::ReflectionMetadataBuiltinDescriptor),
            "ReflectionMetadataFieldDescriptor" => Some(Self::ReflectionMetadataFieldDescriptor),
            "ReturnType" => Some(Self::ReturnType),
            "Setter" => Some(Self::Setter),
            "Static" => Some(Self::Static),
            "Structure" => Some(Self::Structure),
            "Subscript" => Some(Self::Subscript),
            "Suffix" => Some(Self::Suffix),
            "Tuple" => Some(Self::Tuple),
            "TupleElement" => Some(Self::TupleElement),
            "TupleElementName" => Some(Self::TupleElementName),
            "Type" => Some(Self::Type),
            "TypeAlias" => Some(Self::TypeAlias),
            "TypeList" => Some(Self::TypeList),
            "TypeMetadataAccessFunction" => Some(Self::TypeMetadataAccessFunction),
            "UnsafeMutableAddressor" => Some(Self::UnsafeMutableAddressor),
            "Unsupported" => Some(Self::Unsupported),
            "Variable" => Some(Self::Variable),
            _ => None,
        }
    }
}

impl std::fmt::Display for SwiftDemangledNodeKind {
    /// Mirrors `Enum.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matches_java_constant() {
        assert_eq!(SwiftDemangledNodeKind::Global.name(), "Global");
        assert_eq!(SwiftDemangledNodeKind::InOut.name(), "InOut");
        assert_eq!(SwiftDemangledNodeKind::Variable.name(), "Variable");
    }

    #[test]
    fn display_matches_name() {
        assert_eq!(format!("{}", SwiftDemangledNodeKind::Structure), "Structure");
    }

    #[test]
    fn from_name_round_trips_and_rejects_unknown_names() {
        assert_eq!(SwiftDemangledNodeKind::from_name("Global"), Some(SwiftDemangledNodeKind::Global));
        assert_eq!(SwiftDemangledNodeKind::from_name("InOut"), Some(SwiftDemangledNodeKind::InOut));
        assert_eq!(SwiftDemangledNodeKind::from_name("VariadicMarker"), None);
        assert_eq!(SwiftDemangledNodeKind::from_name(""), None);
    }

    #[test]
    fn all_65_java_constants_present() {
        let all = [
            SwiftDemangledNodeKind::Allocator,
            SwiftDemangledNodeKind::AnonymousDescriptor,
            SwiftDemangledNodeKind::ArgumentTuple,
            SwiftDemangledNodeKind::BoundGenericStructure,
            SwiftDemangledNodeKind::BuiltinTypeName,
            SwiftDemangledNodeKind::Class,
            SwiftDemangledNodeKind::Constructor,
            SwiftDemangledNodeKind::Deallocator,
            SwiftDemangledNodeKind::DefaultArgumentInitializer,
            SwiftDemangledNodeKind::DependentGenericParamType,
            SwiftDemangledNodeKind::DependentGenericType,
            SwiftDemangledNodeKind::Destructor,
            SwiftDemangledNodeKind::DispatchThunk,
            SwiftDemangledNodeKind::Enum,
            SwiftDemangledNodeKind::Extension,
            SwiftDemangledNodeKind::FirstElementMarker,
            SwiftDemangledNodeKind::Function,
            SwiftDemangledNodeKind::FunctionType,
            SwiftDemangledNodeKind::GenericSpecialization,
            SwiftDemangledNodeKind::Getter,
            SwiftDemangledNodeKind::Global,
            SwiftDemangledNodeKind::GlobalVariableOnceDeclList,
            SwiftDemangledNodeKind::GlobalVariableOnceFunction,
            SwiftDemangledNodeKind::Identifier,
            SwiftDemangledNodeKind::InfixOperator,
            SwiftDemangledNodeKind::Initializer,
            SwiftDemangledNodeKind::InOut,
            SwiftDemangledNodeKind::LabelList,
            SwiftDemangledNodeKind::LazyProtocolWitnessTableAccessor,
            SwiftDemangledNodeKind::LocalDeclName,
            SwiftDemangledNodeKind::MergedFunction,
            SwiftDemangledNodeKind::MethodDescriptor,
            SwiftDemangledNodeKind::ModifyAccessor,
            SwiftDemangledNodeKind::Module,
            SwiftDemangledNodeKind::ModuleDescriptor,
            SwiftDemangledNodeKind::NominalTypeDescriptor,
            SwiftDemangledNodeKind::Number,
            SwiftDemangledNodeKind::ObjCAttribute,
            SwiftDemangledNodeKind::OutlinedConsume,
            SwiftDemangledNodeKind::OutlinedCopy,
            SwiftDemangledNodeKind::Owned,
            SwiftDemangledNodeKind::PrivateDeclName,
            SwiftDemangledNodeKind::Protocol,
            SwiftDemangledNodeKind::ProtocolConformance,
            SwiftDemangledNodeKind::ProtocolConformanceDescriptor,
            SwiftDemangledNodeKind::ProtocolDescriptor,
            SwiftDemangledNodeKind::ProtocolWitness,
            SwiftDemangledNodeKind::ReflectionMetadataBuiltinDescriptor,
            SwiftDemangledNodeKind::ReflectionMetadataFieldDescriptor,
            SwiftDemangledNodeKind::ReturnType,
            SwiftDemangledNodeKind::Setter,
            SwiftDemangledNodeKind::Static,
            SwiftDemangledNodeKind::Structure,
            SwiftDemangledNodeKind::Subscript,
            SwiftDemangledNodeKind::Suffix,
            SwiftDemangledNodeKind::Tuple,
            SwiftDemangledNodeKind::TupleElement,
            SwiftDemangledNodeKind::TupleElementName,
            SwiftDemangledNodeKind::Type,
            SwiftDemangledNodeKind::TypeAlias,
            SwiftDemangledNodeKind::TypeList,
            SwiftDemangledNodeKind::TypeMetadataAccessFunction,
            SwiftDemangledNodeKind::UnsafeMutableAddressor,
            SwiftDemangledNodeKind::Unsupported,
            SwiftDemangledNodeKind::Variable,
        ];
        assert_eq!(all.len(), 65);
    }
}
