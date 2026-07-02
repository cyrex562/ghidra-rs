use regex::Regex;
use std::sync::OnceLock;

/// Error type for ANSI parser operations.
#[derive(Debug, Clone)]
pub struct AnsiParserError {
    pub message: String,
}

impl std::fmt::Display for AnsiParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AnsiParserError {}

/// A text stream processor that invokes callbacks for ANSI escape codes.
///
/// The general pattern is:
/// 1. Implement [`AnsiParserHandler`]
/// 2. Construct a parser, passing in your handler
/// 3. Invoke [`AnsiParser::process_string`] as needed
///
/// The parser keeps an internal buffer so that input text can be streamed incrementally.
pub struct AnsiParser<H: AnsiParserHandler> {
    buffer: String,
    handler: H,
}

/// The interface for parser callbacks.
///
/// See [ANSI escape code](https://en.wikipedia.org/wiki/ANSI_escape_code) on Wikipedia.
pub trait AnsiParserHandler {
    /// Callback for a portion of text
    fn handle_string(&mut self, text: &str) -> Result<(), AnsiParserError> {
        let _ = text;
        Ok(())
    }

    /// Callback for an ANSI Control Sequence Introducer sequence
    ///
    /// # Arguments
    /// * `param` - zero or more parameter bytes (0-9:;<=>?)
    /// * `inter` - zero or more intermediate bytes (space !"#$%&'()*+,-,./)
    /// * `final_char` - the final byte (@A-Z[\]^_`a-z{|}~)
    fn handle_csi(&mut self, param: &str, inter: &str, final_char: &str) -> Result<(), AnsiParserError> {
        let _ = (param, inter, final_char);
        Ok(())
    }

    /// Callback for an ANSI Operating System Command sequence
    ///
    /// # Arguments
    /// * `param` - zero or more parameter bytes in the ASCII printable range
    fn handle_osc(&mut self, param: &str) -> Result<(), AnsiParserError> {
        let _ = param;
        Ok(())
    }
}

fn get_csi_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // A 7-bit CSI sequence consists of ESC [, followed by any number of parameter characters in the
        // range 0x30-0x3f, followed by any number of intermediate characters in the range 0x20-0x2f,
        // followed by a single final character in the range 0x40-0x7e.
        let csi_param_expr = "[\\x30-\\x3F]*";
        let csi_inter_expr = "[\\x20-\\x2F]*";
        let csi_final_expr = "[\\x40-\\x7E]";
        let csi_match_expr = format!(
            "\\x1b\\[(?P<CSIPARAM>{})(?P<CSIINTER>{})(?P<CSIFINAL>{})",
            csi_param_expr, csi_inter_expr, csi_final_expr
        );

        // A 7-bit OSC sequence consists of ESC ], followed by any number of non-control parameter
        // characters, followed by a BEL character \x07 or the ST sequence ESC \
        let osc_param_expr = "[\\x20-\\x7F]*";
        let osc_match_expr = format!(
            "\\x1b\\](?P<OSCPARAM>{})(?:\\x07|\\x1b\\\\)",
            osc_param_expr
        );

        let combined = format!(
            "(?P<CSI>{})|(?P<OSC>{})|(?P<NUL>\\x00)",
            csi_match_expr, osc_match_expr
        );

        Regex::new(&combined).unwrap()
    })
}

fn get_ctrl_tail_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // A regex to match an unfinished CSI sequence at the end of the input
        let csi_param_expr = "[\\x30-\\x3F]*";
        let csi_inter_expr = "[\\x20-\\x2F]*";
        let csi_tail_expr = format!(
            "\\x1b(?:\\[(?:{}(?:{})?)?)?\\z",
            csi_param_expr, csi_inter_expr
        );

        // A regex to match an unfinished OSC sequence at the end of the input
        let osc_param_expr = "[\\x20-\\x7F]*";
        let osc_tail_expr = format!(
            "\\x1b(?:\\](?:{}(?:\\x1b)?)?)?\\z",
            osc_param_expr
        );

        let combined = format!("{}|{}", csi_tail_expr, osc_tail_expr);
        Regex::new(&combined).unwrap()
    })
}

impl<H: AnsiParserHandler> AnsiParser<H> {
    /// Construct a parser with the given handler
    pub fn new(handler: H) -> Self {
        AnsiParser {
            buffer: String::new(),
            handler,
        }
    }

    /// Process a portion of input text
    pub fn process_string(&mut self, text: &str) -> Result<(), AnsiParserError> {
        self.buffer.push_str(text);

        let ctrl_seq = get_csi_regex();
        let mut last_pos = 0;

        for m in ctrl_seq.captures_iter(self.buffer.clone().as_str()) {
            let m_start = m.get(0).unwrap().start();
            let m_end = m.get(0).unwrap().end();

            if m_start > last_pos {
                self.handler.handle_string(&self.buffer[last_pos..m_start])?;
            }

            if m.name("CSI").is_some() {
                let param = m.name("CSIPARAM").map(|m| m.as_str()).unwrap_or("");
                let inter = m.name("CSIINTER").map(|m| m.as_str()).unwrap_or("");
                let final_char = m.name("CSIFINAL").map(|m| m.as_str()).unwrap_or("");
                self.handler.handle_csi(param, inter, final_char)?;
            } else if m.name("OSC").is_some() {
                let param = m.name("OSCPARAM").map(|m| m.as_str()).unwrap_or("");
                self.handler.handle_osc(param)?;
            } else if m.name("NUL").is_some() {
                // Suppress NUL bytes from the output.
                // TTY commands, such as "clear", that see TERM=vt100
                // may append NUL padding to their output, which a real vt100 would need.
            }

            last_pos = m_end;
        }

        let ctrl_tail = get_ctrl_tail_regex();
        if let Some(m) = ctrl_tail.find_at(&self.buffer, last_pos) {
            if last_pos < m.start() {
                self.handler.handle_string(&self.buffer[last_pos..m.start()])?;
            }
            self.buffer.drain(0..m.start());
        } else {
            if last_pos < self.buffer.len() {
                self.handler.handle_string(&self.buffer[last_pos..])?;
            }
            self.buffer.clear();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct TestHandler {
        strings: Rc<RefCell<Vec<String>>>,
        csi_calls: Rc<RefCell<Vec<(String, String, String)>>>,
        osc_calls: Rc<RefCell<Vec<String>>>,
    }

    impl TestHandler {
        fn new() -> Self {
            TestHandler {
                strings: Rc::new(RefCell::new(Vec::new())),
                csi_calls: Rc::new(RefCell::new(Vec::new())),
                osc_calls: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl AnsiParserHandler for TestHandler {
        fn handle_string(&mut self, text: &str) -> Result<(), AnsiParserError> {
            self.strings.borrow_mut().push(text.to_string());
            Ok(())
        }

        fn handle_csi(&mut self, param: &str, inter: &str, final_char: &str) -> Result<(), AnsiParserError> {
            self.csi_calls.borrow_mut().push((param.to_string(), inter.to_string(), final_char.to_string()));
            Ok(())
        }

        fn handle_osc(&mut self, param: &str) -> Result<(), AnsiParserError> {
            self.osc_calls.borrow_mut().push(param.to_string());
            Ok(())
        }
    }

    #[test]
    fn test_plain_string() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        parser.process_string("hello").unwrap();

        assert_eq!(handler.strings.borrow().len(), 1);
        assert_eq!(handler.strings.borrow()[0], "hello");
    }

    #[test]
    fn test_csi_sequence() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // ESC[31m - red text
        parser.process_string("\x1b[31m").unwrap();

        assert_eq!(handler.csi_calls.borrow().len(), 1);
        let (param, inter, final_char) = &handler.csi_calls.borrow()[0];
        assert_eq!(param, "31");
        assert_eq!(inter, "");
        assert_eq!(final_char, "m");
    }

    #[test]
    fn test_osc_sequence() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // OSC with BEL terminator
        parser.process_string("\x1b]test\x07").unwrap();

        assert_eq!(handler.osc_calls.borrow().len(), 1);
        assert_eq!(handler.osc_calls.borrow()[0], "test");
    }

    #[test]
    fn test_osc_sequence_st_terminator() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // OSC with ST terminator
        parser.process_string("\x1b]test\x1b\\").unwrap();

        assert_eq!(handler.osc_calls.borrow().len(), 1);
        assert_eq!(handler.osc_calls.borrow()[0], "test");
    }

    #[test]
    fn test_nul_suppression() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        parser.process_string("hello\x00world").unwrap();

        // NUL should be suppressed from output
        assert_eq!(handler.strings.borrow().len(), 2);
        assert_eq!(handler.strings.borrow()[0], "hello");
        assert_eq!(handler.strings.borrow()[1], "world");
    }

    #[test]
    fn test_partial_csi_buffering() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        parser.process_string("text\x1b[").unwrap();

        // Partial sequence should be buffered, not emitted yet
        assert_eq!(handler.strings.borrow().len(), 1);
        assert_eq!(handler.strings.borrow()[0], "text");
        assert_eq!(handler.csi_calls.borrow().len(), 0);

        // Complete the sequence
        parser.process_string("31m").unwrap();
        assert_eq!(handler.csi_calls.borrow().len(), 1);
    }

    #[test]
    fn test_partial_osc_buffering() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        parser.process_string("text\x1b]").unwrap();

        assert_eq!(handler.strings.borrow().len(), 1);
        assert_eq!(handler.strings.borrow()[0], "text");
        assert_eq!(handler.osc_calls.borrow().len(), 0);

        // Complete the sequence with BEL
        parser.process_string("data\x07").unwrap();
        assert_eq!(handler.osc_calls.borrow().len(), 1);
        assert_eq!(handler.osc_calls.borrow()[0], "data");
    }

    #[test]
    fn test_multiple_sequences() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        parser.process_string("normal\x1b[31mred\x1b[0mplain").unwrap();

        assert_eq!(handler.strings.borrow().len(), 3);
        assert_eq!(handler.strings.borrow()[0], "normal");
        assert_eq!(handler.strings.borrow()[1], "red");
        assert_eq!(handler.strings.borrow()[2], "plain");
        assert_eq!(handler.csi_calls.borrow().len(), 2);
    }

    #[test]
    fn test_csi_with_parameters() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // CSI with multiple parameters
        parser.process_string("\x1b[1;31mtext").unwrap();

        assert_eq!(handler.csi_calls.borrow().len(), 1);
        let (param, _, _) = &handler.csi_calls.borrow()[0];
        assert_eq!(param, "1;31");
    }

    #[test]
    fn test_streamed_input() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());

        parser.process_string("hel").unwrap();
        parser.process_string("lo\x1b[").unwrap();
        parser.process_string("31m").unwrap();
        parser.process_string("world").unwrap();

        // The parser emits text eagerly per call and only buffers an unfinished
        // control sequence at the tail; it does not merge text across calls. So
        // "hel" is emitted on the first call, then "lo" (before the buffered
        // "\x1b[" tail) on the second, then "world" on the last.
        assert_eq!(handler.strings.borrow().len(), 3);
        assert_eq!(handler.strings.borrow()[0], "hel");
        assert_eq!(handler.strings.borrow()[1], "lo");
        assert_eq!(handler.strings.borrow()[2], "world");
        assert_eq!(handler.csi_calls.borrow().len(), 1);
    }

    #[test]
    fn test_empty_csi_param() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // CSI with no parameters
        parser.process_string("\x1b[m").unwrap();

        assert_eq!(handler.csi_calls.borrow().len(), 1);
        let (param, inter, final_char) = &handler.csi_calls.borrow()[0];
        assert_eq!(param, "");
        assert_eq!(inter, "");
        assert_eq!(final_char, "m");
    }

    #[test]
    fn test_csi_with_intermediate() {
        let handler = TestHandler::new();
        let mut parser = AnsiParser::new(handler.clone());
        // CSI with intermediate bytes. Note: '?', '2', '5' are all in the
        // parameter range (0x30-0x3F), so they are all parameter bytes; 'h'
        // (0x68) is the final byte. There are no intermediate bytes here.
        parser.process_string("\x1b[?25h").unwrap();

        assert_eq!(handler.csi_calls.borrow().len(), 1);
        let (param, inter, final_char) = &handler.csi_calls.borrow()[0];
        assert_eq!(param, "?25");
        assert_eq!(inter, "");
        assert_eq!(final_char, "h");
    }
}
