use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use super::java_source_line::JavaSourceLine;

/// A parsed Java source file that tracks per-line edits and can locate/remove whole
/// Java statements that may span multiple lines.
///
/// Port of `ghidra.util.JavaSourceFile`.
pub struct JavaSourceFile {
    filename: String,
    lines_list: Vec<JavaSourceLine>,
    initial_line_count: usize,
}

impl JavaSourceFile {
    /// Loads the file at `filename`, one [`JavaSourceLine`] per line of text.
    ///
    /// Matches the Java constructor's behavior of logging and continuing (rather than
    /// propagating an error) when the file cannot be read.
    pub fn new(filename: impl Into<String>) -> Self {
        let filename = filename.into();
        let lines_list = Self::load_file(&filename);
        let initial_line_count = lines_list.len();
        Self { filename, lines_list, initial_line_count }
    }

    fn with_lines(filename: String, lines_list: Vec<JavaSourceLine>) -> Self {
        let initial_line_count = lines_list.len();
        Self { filename, lines_list, initial_line_count }
    }

    fn load_file(filename: &str) -> Vec<JavaSourceLine> {
        let mut lines_list = Vec::new();
        let file = match File::open(filename) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{}", e);
                return lines_list;
            }
        };

        let newline = if cfg!(windows) { "\r\n" } else { "\n" };
        let reader = BufReader::new(file);
        let mut line_number = 0;
        for line_result in reader.lines() {
            match line_result {
                Ok(line) => {
                    line_number += 1;
                    lines_list.push(JavaSourceLine::new(format!("{}{}", line, newline), line_number));
                }
                Err(e) => {
                    eprintln!("{}", e);
                    break;
                }
            }
        }

        lines_list
    }

    /// Returns `true` if any line was added/removed or edited since this file was loaded.
    pub fn has_changes(&self) -> bool {
        self.initial_line_count != self.lines_list.len() || self.has_line_changes()
    }

    fn has_line_changes(&self) -> bool {
        self.lines_list.iter().any(|line| line.has_changes())
    }

    /// Returns the 1-based line number of the first `import` statement, or `-1` if none.
    pub fn get_import_section_start_line_number(&self) -> i32 {
        for line in &self.lines_list {
            if line.text().trim().starts_with("import") {
                return line.line_number();
            }
        }
        -1
    }

    /// Returns the line number immediately following the Java statement that starts at
    /// or contains `line_number`.
    pub fn get_line_number_after_statement_at_line(&self, line_number: i32) -> i32 {
        let start_line_number = self.get_statement_start_for_line(line_number);
        if self.get_line(start_line_number).text().trim().ends_with(';') {
            return line_number + 1;
        }

        let statement_lines =
            self.get_remaining_lines_for_statement(start_line_number, start_line_number + 1);
        let last_line_number = *statement_lines.last().unwrap();
        last_line_number + 1
    }

    /// Removes the entire Java statement that starts at or contains `line_number`,
    /// deleting every line the statement spans.
    pub fn remove_java_statement(&mut self, line_number: i32) {
        let start_line_number = self.get_statement_start_for_line(line_number);
        if self.get_line(start_line_number).text().trim().ends_with(';') {
            // statement is all on one line, nothing more to do
            self.get_line_mut(start_line_number).delete();
            return;
        }

        let mut lines_to_clear =
            self.get_remaining_lines_for_statement(start_line_number, start_line_number + 1);
        lines_to_clear.insert(0, start_line_number);

        let size = lines_to_clear.len();
        for &line_number in &lines_to_clear[..size - 1] {
            self.get_line_mut(line_number).delete();
        }

        // do the last line special
        let last_line_number = lines_to_clear[size - 1];
        let text = self.get_line(last_line_number).text().to_string();
        let count = text.matches(';').count();
        if count == 1 {
            // normal line
            self.get_line_mut(last_line_number).delete();
            return;
        }

        // remove all text up to the first semicolon
        let remaining = text[text.find(';').unwrap() + 1..].to_string();
        self.get_line_mut(last_line_number).set_text(remaining);
    }

    /// Returns the line numbers, starting at `start_line_number`, that make up the rest
    /// of the statement begun on `statement_start_line_number` (inclusive of the line on
    /// which the statement's closing `;` is found).
    fn get_remaining_lines_for_statement(
        &self,
        statement_start_line_number: i32,
        start_line_number: i32,
    ) -> Vec<i32> {
        let mut paren_matcher = TokenPairMatcher::new('(', ')');
        let mut brace_matcher = TokenPairMatcher::new('{', '}');
        let text = self.get_line(statement_start_line_number).text().to_string();
        paren_matcher.scan_line(&text);
        brace_matcher.scan_line(&text);

        let mut list = Vec::new();
        let start_index = (start_line_number - 1) as usize; // internally zero-based
        for source_line in &self.lines_list[start_index..] {
            list.push(source_line.line_number());
            if Self::is_valid_end_of_statement(&mut paren_matcher, &mut brace_matcher, source_line) {
                break; // found the end!
            }
        }
        list
    }

    fn is_valid_end_of_statement(
        paren_matcher: &mut TokenPairMatcher,
        brace_matcher: &mut TokenPairMatcher,
        source_line: &JavaSourceLine,
    ) -> bool {
        let text = source_line.text();
        paren_matcher.scan_line(text);
        brace_matcher.scan_line(text);

        if !paren_matcher.is_balanced() || !brace_matcher.is_balanced() {
            return false;
        }

        text.trim().ends_with(';')
    }

    /// Returns the line on which the statement containing `line_number` begins.
    pub fn get_line_containting_statement_start(&self, line_number: i32) -> &JavaSourceLine {
        let start_line_number = self.get_statement_start_for_line(line_number);
        self.get_line(start_line_number)
    }

    /// Returns the full text of the Java statement starting at `first_use_line_number`,
    /// joining continuation lines (with their leading/trailing whitespace trimmed) when
    /// the statement spans multiple lines.
    pub fn get_java_statement_starting_at_line(&self, first_use_line_number: i32) -> String {
        let start_line_number = self.get_statement_start_for_line(first_use_line_number);
        let line_text = self.get_line(start_line_number).text().to_string();
        if line_text.trim().ends_with(';') {
            return line_text;
        }

        let mut buffy = line_text;
        let statement_lines =
            self.get_remaining_lines_for_statement(start_line_number, start_line_number + 1);
        for statement_line_number in statement_lines {
            buffy.push_str(self.get_line(statement_line_number).text().trim());
        }
        buffy
    }

    fn get_statement_start_for_line(&self, line_number: i32) -> i32 {
        if let Some(backwards_line_number) = self.get_statement_from_next_semicolon(line_number) {
            return backwards_line_number;
        }

        let mut current_line_number = line_number;
        let mut semicolon_matcher = TokenMatcher::new(';');
        let mut equals_matcher = TokenMatcher::new('=');

        let text = self.get_line(current_line_number).text().to_string();
        equals_matcher.scan_line(&text);
        if equals_matcher.found_token() {
            return current_line_number; // our line contains an assignment
        }

        // start looking backwards until we hit an equals or semicolon
        current_line_number -= 1;
        let mut text = self.get_line(current_line_number).text().to_string();
        loop {
            equals_matcher.scan_line(&text);
            if equals_matcher.found_token() {
                return current_line_number; // an assignment means the start of a line
            }

            semicolon_matcher.scan_line(&text);
            if semicolon_matcher.found_token() {
                // found an end-of-statement for a previous statement
                return self.find_next_non_blank_line(current_line_number + 1);
            }

            current_line_number -= 1;
            text = self.get_line(current_line_number).text().to_string();
        }
    }

    fn get_statement_from_next_semicolon(&self, line_number: i32) -> Option<i32> {
        // see if we are at the end of a line and can walk backwards to find the entire statement
        let last_line_number = self.find_end_of_unknown_line(line_number);

        if self.is_valid_statement(last_line_number) {
            return Some(last_line_number);
        }

        let mut paren_matcher = TokenPairMatcher::new('(', ')');
        let mut brace_matcher = TokenPairMatcher::new('{', '}');

        let mut last_line_seen_from_statement: Option<i32> = None;
        let start_offset = last_line_number;
        let mut search_line_offset = start_offset;
        loop {
            let search_line_number = search_line_offset;
            search_line_offset -= 1;

            let text = self.get_line(search_line_number).text().to_string();
            paren_matcher.scan_line(&text);
            brace_matcher.scan_line(&text);

            // ignore special cases
            if !text.contains("serialVersion") {
                let mut semicolon_matcher = TokenMatcher::new(';');
                semicolon_matcher.scan_line(&text);
                if semicolon_matcher.found_token()
                    && start_offset != search_line_number + 1
                    && last_line_seen_from_statement.is_some()
                {
                    return Some(
                        self.find_next_non_blank_line(last_line_seen_from_statement.unwrap()),
                    );
                }

                let mut equals_matcher = TokenMatcher::new('=');
                equals_matcher.scan_line(&text);
                if equals_matcher.found_token() && self.contains_action_assignment(&text) {
                    return Some(search_line_number);
                }

                if text.contains('(') || text.contains('.') {
                    last_line_seen_from_statement = Some(search_line_number);
                }
            }

            if search_line_offset <= 0 {
                break;
            }
        }

        None // shouldn't get here
    }

    fn is_valid_statement(&self, line_number: i32) -> bool {
        let text = self.get_line(line_number).text().trim().to_string();
        if !text.ends_with(';') {
            return false;
        }

        let mut paren_matcher = TokenPairMatcher::new('(', ')');
        let mut brace_matcher = TokenPairMatcher::new('{', '}');
        paren_matcher.scan_line(&text);
        brace_matcher.scan_line(&text);
        paren_matcher.is_balanced() && brace_matcher.is_balanced()
    }

    fn contains_action_assignment(&self, text: &str) -> bool {
        let mut equals_parts = text.split('=');
        let left_hand_side = equals_parts.next().unwrap_or("");
        let name_and_maybe_declaration: Vec<&str> =
            left_hand_side.trim().split(|c: char| c.is_whitespace()).collect();
        if name_and_maybe_declaration.len() == 2 {
            return name_and_maybe_declaration[0].ends_with("Action");
        }
        name_and_maybe_declaration[0].to_lowercase().contains("action")
    }

    fn find_end_of_unknown_line(&self, line_number: i32) -> i32 {
        let current_text = self.get_line(line_number).text().to_string();
        if current_text.trim().ends_with(';') {
            return line_number;
        }

        let start_index = line_number as usize; // one past the current (zero-based) line
        let mut last_line_number = line_number;
        for source_line in &self.lines_list[start_index..] {
            last_line_number = source_line.line_number();
            if source_line.text().trim().ends_with(';') {
                break; // found the end!
            }
        }

        last_line_number
    }

    fn find_next_non_blank_line(&self, line_number: i32) -> i32 {
        let mut current_line_number = line_number;
        loop {
            let line = self.get_line(current_line_number);
            if !line.text().trim().is_empty() {
                return current_line_number;
            }
            current_line_number += 1;
        }
    }

    /// Returns the line at `one_based_line_number`.
    ///
    /// # Panics
    ///
    /// Panics if `one_based_line_number` is out of range.
    pub fn get_line(&self, one_based_line_number: i32) -> &JavaSourceLine {
        if one_based_line_number <= 0 || one_based_line_number as usize > self.lines_list.len() {
            panic!("File does not contain line number: {}", one_based_line_number);
        }

        &self.lines_list[(one_based_line_number - 1) as usize]
    }

    fn get_line_mut(&mut self, one_based_line_number: i32) -> &mut JavaSourceLine {
        if one_based_line_number <= 0 || one_based_line_number as usize > self.lines_list.len() {
            panic!("File does not contain line number: {}", one_based_line_number);
        }

        &mut self.lines_list[(one_based_line_number - 1) as usize]
    }

    /// Writes the current lines back to `filename`, if there are any changes to save.
    ///
    /// Matches the Java method's behavior of logging and swallowing an I/O error rather
    /// than propagating one.
    pub fn save(&self) {
        eprintln!("save on file: {}", self.filename);

        if !self.has_changes() {
            eprintln!("\tno changes to: {}", self.filename);
            return;
        }

        match File::create(&self.filename) {
            Ok(mut file) => {
                for line in &self.lines_list {
                    if let Err(e) = file.write_all(line.text().as_bytes()) {
                        eprintln!("{}", e);
                        return;
                    }
                }
                let _ = file.flush();
            }
            Err(e) => eprintln!("{}", e),
        }
    }

    /// Returns a copy of this file whose lines all reflect their original, unmodified text.
    pub fn get_original_source_file_copy(&self) -> Self {
        Self::with_lines(self.filename.clone(), self.copy_original_lines())
    }

    fn copy_original_lines(&self) -> Vec<JavaSourceLine> {
        self.lines_list.iter().map(JavaSourceLine::create_original_clone).collect()
    }
}

impl std::fmt::Display for JavaSourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.filename)
    }
}

//==================================================================================================
// Helper types (ports of JavaSourceFile's private inner classes)
//==================================================================================================

struct TokenMatcher {
    token: char,
    found_token: bool,
}

impl TokenMatcher {
    fn new(token: char) -> Self {
        Self { token, found_token: false }
    }

    fn scan_line(&mut self, line: &str) {
        if self.found_token {
            return;
        }

        if line.contains(self.token) {
            self.found_token = true;
        }
    }

    fn found_token(&self) -> bool {
        self.found_token
    }
}

struct TokenPairMatcher {
    running_token_count: i32, // can be negative
    left_token: char,
    right_token: char,
}

impl TokenPairMatcher {
    fn new(left_token: char, right_token: char) -> Self {
        Self { running_token_count: 0, left_token, right_token }
    }

    fn scan_line(&mut self, line: &str) {
        for c in line.chars() {
            if c == self.left_token {
                self.running_token_count += 1;
            }
            else if c == self.right_token {
                self.running_token_count -= 1;
            }
        }
    }

    fn is_balanced(&self) -> bool {
        self.running_token_count == 0
    }
}

impl std::fmt::Display for TokenPairMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TokenMatcher: [{}, {}] - count: {}",
            self.left_token, self.right_token, self.running_token_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST_FILE_ID: AtomicUsize = AtomicUsize::new(0);

    fn write_temp_file(contents: &str) -> std::path::PathBuf {
        let id = NEXT_TEST_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("java_source_file_test_{}_{}.java", std::process::id(), id));
        let mut file = File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_lines_from_file() {
        let path = write_temp_file("package foo;\nimport bar.Baz;\n\nclass Foo {}\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.get_line(1).text().trim_end(), "package foo;");
        assert_eq!(source.get_line(2).text().trim_end(), "import bar.Baz;");
        assert!(!source.has_changes());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn missing_file_logs_and_yields_empty_lines() {
        let source = JavaSourceFile::new("/nonexistent/path/does-not-exist.java");
        assert!(!source.has_changes());
        assert_eq!(source.get_import_section_start_line_number(), -1);
    }

    #[test]
    fn get_import_section_start_line_number_finds_first_import() {
        let path = write_temp_file("package foo;\n\nimport java.util.List;\nimport java.util.Map;\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.get_import_section_start_line_number(), 3);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_import_section_start_line_number_absent_returns_negative_one() {
        let path = write_temp_file("package foo;\nclass Foo {}\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.get_import_section_start_line_number(), -1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_line_out_of_bounds_panics() {
        let path = write_temp_file("class Foo {}\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        let result = std::panic::catch_unwind(|| source.get_line(99));
        assert!(result.is_err());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn remove_java_statement_single_line_deletes_line() {
        let path = write_temp_file("int x = 1;\nint y = 2;\n");
        let mut source = JavaSourceFile::new(path.to_str().unwrap());
        source.remove_java_statement(1);
        assert!(source.get_line(1).is_deleted());
        assert_eq!(source.get_line(1).text(), "");
        assert_eq!(source.get_line(2).text().trim_end(), "int y = 2;");
        assert!(source.has_changes());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn remove_java_statement_multi_line_deletes_all_spanned_lines() {
        let path = write_temp_file("int x = foo(\n    1,\n    2\n);\nint y = 2;\n");
        let mut source = JavaSourceFile::new(path.to_str().unwrap());
        source.remove_java_statement(1);
        assert!(source.get_line(1).is_deleted());
        assert!(source.get_line(2).is_deleted());
        assert!(source.get_line(3).is_deleted());
        assert!(source.get_line(4).is_deleted());
        assert_eq!(source.get_line(5).text().trim_end(), "int y = 2;");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_line_number_after_statement_at_line_single_line() {
        let path = write_temp_file("int x = 1;\nint y = 2;\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.get_line_number_after_statement_at_line(1), 2);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_line_number_after_statement_at_line_multi_line() {
        let path = write_temp_file("int x = foo(\n    1,\n    2\n);\nint y = 2;\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.get_line_number_after_statement_at_line(1), 5);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_java_statement_starting_at_line_joins_continuation_lines() {
        let path = write_temp_file("int x = foo(\n    1,\n    2\n);\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        let statement = source.get_java_statement_starting_at_line(1);
        assert!(statement.starts_with("int x = foo("));
        assert!(statement.contains("1,"));
        assert!(statement.trim_end().ends_with(");"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_line_containting_statement_start_returns_start_line() {
        let path = write_temp_file("int x = foo(\n    1,\n    2\n);\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        let start = source.get_line_containting_statement_start(3);
        assert_eq!(start.line_number(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn has_changes_true_after_line_edit() {
        let path = write_temp_file("int x = 1;\n");
        let mut source = JavaSourceFile::new(path.to_str().unwrap());
        assert!(!source.has_changes());
        source.get_line_mut(1).set_text("int x = 2;\n");
        assert!(source.has_changes());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn get_original_source_file_copy_is_independent_of_edits() {
        let path = write_temp_file("int x = 1;\n");
        let mut source = JavaSourceFile::new(path.to_str().unwrap());
        let original_copy = source.get_original_source_file_copy();
        source.get_line_mut(1).set_text("int x = 2;\n");
        assert_eq!(original_copy.get_line(1).text(), "int x = 1;\n");
        assert!(source.has_changes());
        assert!(!original_copy.has_changes());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn display_shows_filename() {
        let path = write_temp_file("class Foo {}\n");
        let source = JavaSourceFile::new(path.to_str().unwrap());
        assert_eq!(source.to_string(), path.to_str().unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn token_pair_matcher_tracks_balance() {
        let mut matcher = TokenPairMatcher::new('(', ')');
        matcher.scan_line("foo(bar(");
        assert!(!matcher.is_balanced());
        matcher.scan_line("baz))");
        assert!(matcher.is_balanced());
    }

    #[test]
    fn token_matcher_finds_token_once() {
        let mut matcher = TokenMatcher::new(';');
        assert!(!matcher.found_token());
        matcher.scan_line("no semicolon here");
        assert!(!matcher.found_token());
        matcher.scan_line("here it is;");
        assert!(matcher.found_token());
    }
}
