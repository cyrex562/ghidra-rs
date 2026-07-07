use super::counter::Counter;

/// Formats a human-readable XML import/export summary from a [`Counter`].
///
/// Mirrors the static `ghidra.util.xml.XmlSummary.getSummary`.
///
/// The counter is mutated: all named buckets are consumed via
/// `get_count_and_remove` and `clear` is called before returning.
/// The "References" line concatenates three individual counts as strings,
/// matching the Java source's left-to-right `+` evaluation.
pub(crate) fn get_summary(counter: &mut Counter) -> String {
    let mut buf = String::with_capacity(256);
    let orig_total = counter.get_total_count();

    buf.push('\n');
    buf.push_str("\nXML Program Summary:");
    buf.push_str("\n--------------------------");
    buf.push_str(&format!("\nMemory Sections:       {}", counter.get_count_and_remove("MEMORY_SECTION")));
    buf.push_str(&format!("\nMemory Contents:       {}", counter.get_count_and_remove("MEMORY_CONTENTS")));
    buf.push_str(&format!("\nCode Blocks:           {}", counter.get_count_and_remove("CODE_BLOCK")));
    buf.push_str(&format!("\nDefined Data:          {}", counter.get_count_and_remove("DEFINED_DATA")));
    buf.push_str(&format!("\nStructures:            {}", counter.get_count_and_remove("STRUCTURE")));
    buf.push_str(&format!("\nUnions:                {}", counter.get_count_and_remove("UNION")));
    buf.push_str(&format!("\nTypedefs:              {}", counter.get_count_and_remove("TYPE_DEF")));
    buf.push_str(&format!("\nEnums:                 {}", counter.get_count_and_remove("ENUM")));
    buf.push_str(&format!("\nSymbols:               {}", counter.get_count_and_remove("SYMBOL")));
    buf.push_str(&format!("\nEntry Points:          {}", counter.get_count_and_remove("PROGRAM_ENTRY_POINT")));
    buf.push_str(&format!("\nEquates:               {}", counter.get_count_and_remove("EQUATE")));
    buf.push_str(&format!("\n    References:        {}", counter.get_count_and_remove("EQUATE_REFERENCE")));
    buf.push_str(&format!("\nComments:              {}", counter.get_count_and_remove("COMMENT")));
    buf.push_str(&format!("\nBookmarks:             {}", counter.get_count_and_remove("BOOKMARK")));
    buf.push_str(&format!("\nProperties:            {}", counter.get_count_and_remove("PROPERTY")));
    buf.push_str(&format!("\nProgram Trees:         {}", counter.get_count_and_remove("TREE")));
    buf.push_str(&format!("\n    Folders:           {}", counter.get_count_and_remove("FOLDER")));
    buf.push_str(&format!("\n    Fragments:         {}", counter.get_count_and_remove("FRAGMENT")));
    buf.push_str(&format!("\nFunction Signatures:   {}", counter.get_count_and_remove("FUNCTION_DEF")));
    buf.push_str(&format!("\n    Parameters:        {}", counter.get_count_and_remove("PARAMETER")));
    buf.push_str(&format!("\nFunctions:             {}", counter.get_count_and_remove("FUNCTION")));
    buf.push_str(&format!("\n    Stack Frames:      {}", counter.get_count_and_remove("STACK_FRAME")));
    buf.push_str(&format!("\n    Stack Vars:        {}", counter.get_count_and_remove("STACK_VAR")));
    buf.push_str(&format!("\n    Register Vars:     {}", counter.get_count_and_remove("REGISTER_VAR")));
    // Java concatenates three int-to-string conversions (not numeric addition):
    // "prefix" + int + int + int  →  "prefix" + "N" + "M" + "L" = "prefixNML"
    buf.push_str(&format!(
        "\nReferences:            {}{}{}",
        counter.get_count_and_remove("MEMORY_REFERENCE"),
        counter.get_count_and_remove("STACK_REFERENCE"),
        counter.get_count_and_remove("EXT_LIBRARY_REFERENCE"),
    ));
    buf.push_str(&format!("\nRelocations:           {}", counter.get_count_and_remove("RELOCATION")));
    buf.push('\n');

    counter.get_count_and_remove("MEMBER"); // consumed to exclude from overhead

    buf.push_str("\n--------------------------");
    buf.push_str(&format!("\nTotal XML Elements:    {}", orig_total));
    buf.push_str(&format!("\n    Processed:         {}", orig_total - counter.get_total_count()));
    buf.push_str(&format!("\n    Overhead:          {}", counter.get_total_count()));
    buf.push('\n');

    counter.clear();

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_counter() -> Counter {
        let mut c = Counter::new();
        c.increment("MEMORY_SECTION");
        c.increment("MEMORY_CONTENTS");
        c.increment("CODE_BLOCK");
        c.increment("CODE_BLOCK");
        c.increment("FUNCTION");
        c.increment("FUNCTION");
        c.increment("FUNCTION");
        c.increment("MEMBER"); // overhead only, not displayed
        c
    }

    #[test]
    fn summary_contains_header() {
        let mut c = Counter::new();
        let s = get_summary(&mut c);
        assert!(s.contains("XML Program Summary:"));
        assert!(s.contains("--------------------------"));
    }

    #[test]
    fn summary_shows_correct_counts() {
        let mut c = make_counter();
        let s = get_summary(&mut c);
        assert!(s.contains("Memory Sections:       1"));
        assert!(s.contains("Memory Contents:       1"));
        assert!(s.contains("Code Blocks:           2"));
        assert!(s.contains("Functions:             3"));
    }

    #[test]
    fn summary_shows_zero_for_absent_keys() {
        let mut c = Counter::new();
        let s = get_summary(&mut c);
        assert!(s.contains("Memory Sections:       0"));
        assert!(s.contains("Functions:             0"));
    }

    #[test]
    fn summary_totals_are_correct() {
        let mut c = make_counter();
        // Total: 8 entries (1+1+2+3+1 MEMBER); MEMBER removed as overhead (1)
        // Processed: 8 - 1 overhead remaining = 7
        // (remaining after removing the displayed keys and MEMBER is 0, so overhead=0)
        let s = get_summary(&mut c);
        assert!(s.contains("Total XML Elements:    8"));
    }

    #[test]
    fn counter_is_cleared_after_summary() {
        let mut c = make_counter();
        get_summary(&mut c);
        assert_eq!(c.get_total_count(), 0);
    }

    #[test]
    fn references_line_concatenates_three_values() {
        let mut c = Counter::new();
        c.increment("MEMORY_REFERENCE");
        c.increment("MEMORY_REFERENCE");
        c.increment("STACK_REFERENCE");
        // EXT_LIBRARY_REFERENCE absent → 0
        let s = get_summary(&mut c);
        // Java concatenation: "210" not "3"
        assert!(s.contains("References:            210"));
    }

    #[test]
    fn member_not_shown_in_output() {
        let mut c = Counter::new();
        c.increment("MEMBER");
        c.increment("MEMBER");
        let s = get_summary(&mut c);
        // MEMBER should not appear as a labelled line
        assert!(!s.contains("MEMBER"));
    }

    #[test]
    fn overhead_accounts_for_unrecognised_keys() {
        let mut c = Counter::new();
        c.increment("FUNCTION");
        c.increment("UNKNOWN_KEY"); // not consumed by get_summary
        let s = get_summary(&mut c);
        assert!(s.contains("Total XML Elements:    2"));
        assert!(s.contains("    Overhead:          1"));
        assert!(s.contains("    Processed:         1"));
    }
}
