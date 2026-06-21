/// A snap-selected reference space within a trace database.
///
/// Corresponds to `ghidra.trace.database.symbol.DBTraceSnapSelectedReferenceSpace`.
pub struct DBTraceSnapSelectedReferenceSpace {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instantiate() {
        let _ = DBTraceSnapSelectedReferenceSpace {};
    }
}
