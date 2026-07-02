use std::fmt;
use std::io::{self, BufRead, Write};

use super::LineArrayListWriter;

/// ANTLR token type marking a synthetic "step down" into a node's children
/// when a tree is flattened into a node stream.
const DOWN_TOKEN_TYPE: i32 = 2;
/// ANTLR token type marking a synthetic "step up" out of a node's children
/// when a tree is flattened into a node stream.
const UP_TOKEN_TYPE: i32 = 3;

/// Mirrors the slice of `org.antlr.runtime.tree.CommonTree` consulted by
/// [`AntlrUtil::debug_node_stream`]: a node's own display text plus its
/// optional token type/line/column. A `None` token type mirrors a `null`
/// `Token` field on the Java node.
pub trait DebugStreamNode: fmt::Display {
    fn token_type(&self) -> Option<i32>;
    fn line(&self) -> i32;
    fn char_position_in_line(&self) -> i32;
}

/// Mirrors the slice of `org.antlr.runtime.tree.Tree` walked by
/// [`AntlrUtil::debug_tree`]: a node's own display text, its optional token
/// position, and access to its children.
pub trait DebugTreeNode: fmt::Display {
    fn line(&self) -> Option<i32>;
    fn char_position_in_line(&self) -> i32;
    fn child_count(&self) -> usize;
    fn child(&self, index: usize) -> &Self;
}

/// Debug-printing and error-position helpers for the Sleigh/ANTLR parsing
/// infrastructure.
///
/// Mirrors `ghidra.sleigh.grammar.ANTLRUtil`.
pub struct AntlrUtil;

impl AntlrUtil {
    fn indent(n: usize) -> String {
        "    ".repeat(n)
    }

    /// Prints one line per non-synthetic node in `nodes`, indented to match
    /// tree depth; DOWN/UP marker nodes adjust the indent instead of being
    /// printed.
    ///
    /// Mirrors `debugNodeStream(BufferedTreeNodeStream, PrintStream)`.
    pub fn debug_node_stream<N: DebugStreamNode>(
        nodes: &[N],
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let mut indent = 0usize;
        for node in nodes {
            match node.token_type() {
                Some(DOWN_TOKEN_TYPE) => {
                    indent += 1;
                    continue;
                }
                Some(UP_TOKEN_TYPE) => {
                    indent = indent.saturating_sub(1);
                    continue;
                }
                _ => {}
            }
            let pos = match node.token_type() {
                Some(_) => format!("{}:{}", node.line(), node.char_position_in_line()),
                None => "no pos".to_string(),
            };
            writeln!(out, "{}'{}'     ({})", Self::indent(indent), node, pos)?;
        }
        Ok(())
    }

    /// Prints each token in `tokens` with its index in the stream.
    ///
    /// Mirrors `debugTokenStream(CommonTokenStream, PrintStream)`.
    pub fn debug_token_stream<T: fmt::Display>(
        tokens: &[T],
        out: &mut dyn Write,
    ) -> io::Result<()> {
        for (index, token) in tokens.iter().enumerate() {
            writeln!(out, "{}     ({})", token, index)?;
        }
        Ok(())
    }

    /// Prints a depth-first dump of `tree`, one line per node, indented to
    /// match tree depth. Produces the same output as flattening the tree
    /// into a node stream (via `BufferedTreeNodeStream`) and passing it to
    /// [`Self::debug_node_stream`].
    ///
    /// Mirrors `debugTree(Tree, PrintStream)`.
    pub fn debug_tree<N: DebugTreeNode>(tree: &N, out: &mut dyn Write) -> io::Result<()> {
        Self::debug_tree_node(tree, 0, out)
    }

    fn debug_tree_node<N: DebugTreeNode>(
        node: &N,
        indent: usize,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let pos = match node.line() {
            Some(line) => format!("{}:{}", line, node.char_position_in_line()),
            None => "no pos".to_string(),
        };
        writeln!(out, "{}'{}'     ({})", Self::indent(indent), node, pos)?;
        for i in 0..node.child_count() {
            Self::debug_tree_node(node.child(i), indent + 1, out)?;
        }
        Ok(())
    }

    /// Reads `reader` up through line `lineno` (1-based) and returns that
    /// line, or `None` if the reader has fewer lines.
    ///
    /// Mirrors `getLine(Reader, int)`.
    pub fn get_line_from_reader<R: BufRead>(
        reader: R,
        mut lineno: i32,
    ) -> io::Result<Option<String>> {
        let mut lines = reader.lines();
        let mut line = None;
        while lineno > 0 {
            line = lines.next().transpose()?;
            lineno -= 1;
        }
        Ok(line)
    }

    /// Returns line `lineno` (1-based) from `writer`. Negative or
    /// out-of-range indices wrap relative to the end of the buffer.
    ///
    /// Mirrors `getLine(LineArrayListWriter, int)`.
    pub fn get_line_from_writer(writer: &LineArrayListWriter, lineno: i32) -> String {
        let lines = writer.get_lines();
        let size = lines.len() as i32;
        let mut line = (size - 1).min(lineno - 1);
        while line < 0 {
            line += size;
        }
        lines[line as usize].clone()
    }

    /// Builds a `"----^"`-style arrow pointing at `char_position_in_line`.
    ///
    /// Mirrors `generateArrow(int)`.
    pub fn generate_arrow(char_position_in_line: i32) -> String {
        let dashes = char_position_in_line.max(0) as usize;
        let mut arrow = "-".repeat(dashes);
        arrow.push('^');
        arrow
    }

    /// Converts a character offset into `line` to a column position with
    /// tabs expanded to the next multiple of 8.
    ///
    /// Mirrors `tabCompensate(String, int)`.
    pub fn tab_compensate(line: &str, char_position_in_line: i32) -> i32 {
        if char_position_in_line < 0 {
            return char_position_in_line;
        }
        let mut pos: i32 = 0;
        for c in line.chars().take(char_position_in_line as usize) {
            if c == '\t' {
                pos = (pos + 8) / 8 * 8;
            } else {
                pos += 1;
            }
        }
        pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct SimpleStreamNode {
        text: &'static str,
        token_type: Option<i32>,
        line: i32,
        char_position_in_line: i32,
    }

    impl fmt::Display for SimpleStreamNode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl DebugStreamNode for SimpleStreamNode {
        fn token_type(&self) -> Option<i32> {
            self.token_type
        }
        fn line(&self) -> i32 {
            self.line
        }
        fn char_position_in_line(&self) -> i32 {
            self.char_position_in_line
        }
    }

    fn node(text: &'static str, token_type: Option<i32>, line: i32, col: i32) -> SimpleStreamNode {
        SimpleStreamNode {
            text,
            token_type,
            line,
            char_position_in_line: col,
        }
    }

    struct SimpleTreeNode {
        text: &'static str,
        line: Option<i32>,
        char_position_in_line: i32,
        children: Vec<SimpleTreeNode>,
    }

    impl fmt::Display for SimpleTreeNode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl DebugTreeNode for SimpleTreeNode {
        fn line(&self) -> Option<i32> {
            self.line
        }
        fn char_position_in_line(&self) -> i32 {
            self.char_position_in_line
        }
        fn child_count(&self) -> usize {
            self.children.len()
        }
        fn child(&self, index: usize) -> &Self {
            &self.children[index]
        }
    }

    fn out_to_string(out: Vec<u8>) -> String {
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn debug_node_stream_prints_position_and_skips_down_up_markers() {
        let nodes = vec![
            node("root", Some(1), 1, 0),
            node("DOWN", Some(DOWN_TOKEN_TYPE), 0, 0),
            node("child", Some(1), 2, 4),
            node("UP", Some(UP_TOKEN_TYPE), 0, 0),
        ];
        let mut out = Vec::new();
        AntlrUtil::debug_node_stream(&nodes, &mut out).unwrap();
        let text = out_to_string(out);
        assert_eq!(text, "'root'     (1:0)\n    'child'     (2:4)\n");
    }

    #[test]
    fn debug_node_stream_prints_no_pos_for_null_token() {
        let nodes = vec![node("orphan", None, 0, 0)];
        let mut out = Vec::new();
        AntlrUtil::debug_node_stream(&nodes, &mut out).unwrap();
        assert_eq!(out_to_string(out), "'orphan'     (no pos)\n");
    }

    #[test]
    fn debug_token_stream_prints_tokens_with_index() {
        let tokens = vec!["alpha".to_string(), "beta".to_string()];
        let mut out = Vec::new();
        AntlrUtil::debug_token_stream(&tokens, &mut out).unwrap();
        assert_eq!(out_to_string(out), "alpha     (0)\nbeta     (1)\n");
    }

    #[test]
    fn debug_tree_walks_children_with_increasing_indent() {
        let tree = SimpleTreeNode {
            text: "root",
            line: Some(1),
            char_position_in_line: 0,
            children: vec![
                SimpleTreeNode {
                    text: "child1",
                    line: Some(2),
                    char_position_in_line: 1,
                    children: vec![],
                },
                SimpleTreeNode {
                    text: "child2",
                    line: None,
                    char_position_in_line: 0,
                    children: vec![],
                },
            ],
        };
        let mut out = Vec::new();
        AntlrUtil::debug_tree(&tree, &mut out).unwrap();
        assert_eq!(
            out_to_string(out),
            "'root'     (1:0)\n    'child1'     (2:1)\n    'child2'     (no pos)\n"
        );
    }

    #[test]
    fn debug_tree_indents_nested_children() {
        let tree = SimpleTreeNode {
            text: "root",
            line: Some(1),
            char_position_in_line: 0,
            children: vec![SimpleTreeNode {
                text: "mid",
                line: Some(2),
                char_position_in_line: 0,
                children: vec![SimpleTreeNode {
                    text: "leaf",
                    line: Some(3),
                    char_position_in_line: 0,
                    children: vec![],
                }],
            }],
        };
        let mut out = Vec::new();
        AntlrUtil::debug_tree(&tree, &mut out).unwrap();
        assert_eq!(
            out_to_string(out),
            "'root'     (1:0)\n    'mid'     (2:0)\n        'leaf'     (3:0)\n"
        );
    }

    #[test]
    fn get_line_from_reader_returns_requested_line() {
        let reader = Cursor::new("first\nsecond\nthird\n");
        let line = AntlrUtil::get_line_from_reader(reader, 2).unwrap();
        assert_eq!(line, Some("second".to_string()));
    }

    #[test]
    fn get_line_from_reader_returns_none_past_end() {
        let reader = Cursor::new("only\n");
        let line = AntlrUtil::get_line_from_reader(reader, 5).unwrap();
        assert_eq!(line, None);
    }

    #[test]
    fn get_line_from_reader_returns_none_for_zero_lineno() {
        let reader = Cursor::new("only\n");
        let line = AntlrUtil::get_line_from_reader(reader, 0).unwrap();
        assert_eq!(line, None);
    }

    #[test]
    fn get_line_from_writer_returns_requested_line() {
        let mut writer = LineArrayListWriter::new();
        writer.write("first");
        writer.new_line();
        writer.write("second");
        assert_eq!(AntlrUtil::get_line_from_writer(&writer, 1), "first");
        assert_eq!(AntlrUtil::get_line_from_writer(&writer, 2), "second");
    }

    #[test]
    fn get_line_from_writer_clamps_lineno_past_end() {
        let mut writer = LineArrayListWriter::new();
        writer.write("only");
        assert_eq!(AntlrUtil::get_line_from_writer(&writer, 99), "only");
    }

    #[test]
    fn get_line_from_writer_wraps_negative_lineno() {
        let mut writer = LineArrayListWriter::new();
        writer.write("first");
        writer.new_line();
        writer.write("second");
        // lineno - 1 = -1, which wraps to size - 1 (the last line).
        assert_eq!(AntlrUtil::get_line_from_writer(&writer, 0), "second");
    }

    #[test]
    fn generate_arrow_pads_with_dashes() {
        assert_eq!(AntlrUtil::generate_arrow(0), "^");
        assert_eq!(AntlrUtil::generate_arrow(3), "---^");
    }

    #[test]
    fn generate_arrow_clamps_negative_position() {
        assert_eq!(AntlrUtil::generate_arrow(-5), "^");
    }

    #[test]
    fn tab_compensate_counts_plain_characters() {
        assert_eq!(AntlrUtil::tab_compensate("hello", 3), 3);
    }

    #[test]
    fn tab_compensate_expands_tabs_to_next_multiple_of_eight() {
        assert_eq!(AntlrUtil::tab_compensate("\t", 1), 8);
        assert_eq!(AntlrUtil::tab_compensate("a\t", 2), 8);
        assert_eq!(AntlrUtil::tab_compensate("\t\t", 2), 16);
    }

    #[test]
    fn tab_compensate_returns_negative_position_unchanged() {
        assert_eq!(AntlrUtil::tab_compensate("anything", -1), -1);
    }
}
