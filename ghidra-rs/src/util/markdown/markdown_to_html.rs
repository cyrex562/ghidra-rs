//! Port of `ghidra.markdown.MarkdownToHtml`
//! (orig_src/GhidraBuild/MarkdownSupport/src/main/java/ghidra/markdown/MarkdownToHtml.java).
//!
//! The Java program converts a Markdown file to an HTML file. It configures the
//! CommonMark library with the tables, footnotes and heading-anchor extensions
//! and installs a set of attribute providers that:
//!
//! * add inline table styling to `<table>`/`<td>` elements,
//! * add a bottom border to level 1/2 headings,
//! * add styling to fenced code blocks, inline code, and indented code blocks,
//! * rewrite links to Markdown files (`*.md`) to point at the generated HTML
//!   (`*.html`), leaving anchors and absolute `http(s)` URLs alone, and
//!   applying the known repository/release path fixups.
//!
//! This Rust port preserves that observable behavior on top of the
//! [`pulldown_cmark`] CommonMark renderer, and wraps the rendered body in a
//! faithful HTML document skeleton (doctype/head/body).

use std::io;
use std::path::Path;

use pulldown_cmark::{html, Event, Options, Parser, Tag};

/// Static utility for converting Markdown to a complete HTML document.
pub struct MarkdownToHtml;

impl MarkdownToHtml {
    /// Converts Markdown source text into a complete HTML document string.
    ///
    /// The rendered CommonMark body is wrapped in a `<!DOCTYPE html>` skeleton
    /// with a `<head>` (containing a UTF-8 charset and the given `title`) and a
    /// `<body>` containing the rendered markup.
    ///
    /// Tables, footnotes and heading attributes are enabled, matching the
    /// extension set used by the Java program. Table cells/blocks, level 1-2
    /// headings, and code elements receive the same inline styling as the Java
    /// attribute providers, and `.md` links are rewritten to `.html` (with the
    /// same anchor/URL exclusions and repository-path fixups).
    pub fn convert(markdown: &str, title: &str) -> String {
        let body = render_body(markdown);
        wrap_html(&body, title)
    }

    /// Converts Markdown source text into just the rendered HTML body (no
    /// document skeleton). Exposed as the `&str` -> `String` core used by
    /// [`MarkdownToHtml::convert`].
    pub fn convert_body(markdown: &str) -> String {
        render_body(markdown)
    }

    /// Reads a Markdown file at `in_path` and returns a complete HTML document.
    ///
    /// The document `<title>` is derived from the input file's stem (file name
    /// without extension); if that cannot be determined, `"Document"` is used.
    ///
    /// # Errors
    /// Returns any I/O error encountered while reading the input file.
    pub fn convert_file<P: AsRef<Path>>(in_path: P) -> io::Result<String> {
        let in_path = in_path.as_ref();
        let markdown = std::fs::read_to_string(in_path)?;
        let title = in_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Document");
        Ok(Self::convert(&markdown, title))
    }

    /// Reads the Markdown file at `in_path`, converts it to a complete HTML
    /// document, and writes the result to `out_path`.
    ///
    /// This mirrors the Java `main` entry point (minus the two-argument CLI
    /// validation): any missing parent directories of `out_path` are created.
    ///
    /// # Errors
    /// Returns an error if `in_path` does not have a `.md` extension
    /// (case-insensitive), or on any I/O failure while reading, creating
    /// directories, or writing the output.
    pub fn convert_file_to_file<P: AsRef<Path>, Q: AsRef<Path>>(
        in_path: P,
        out_path: Q,
    ) -> io::Result<()> {
        let in_path = in_path.as_ref();
        let out_path = out_path.as_ref();

        let ends_with_md = in_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("md"))
            .unwrap_or(false);
        if !ends_with_md {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "First argument doesn't not end with .md",
            ));
        }

        let html = Self::convert_file(in_path)?;

        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(out_path, html)
    }
}

/// Inline style applied to table blocks and cells, matching
/// `TableAttributeProvider`.
const TABLE_STYLE: &str = "border: 1px solid black; border-collapse: collapse; padding: 5px;";

/// Inline style applied to level 1/2 headings, matching
/// `HeadingAttributeProvider`.
const HEADING_STYLE: &str =
    "border-bottom: solid 1px; border-bottom-color: #cccccc; padding-bottom: 8px;";

/// Inline style applied to fenced code block `<pre>` elements, matching
/// `CodeAttributeProvider`.
const PRE_STYLE: &str = "background: #f4f4f4;border: 1px solid #ddd;border-left: 3px solid #f36d33;\
color: #666;display: block;font-family: monospace;line-height: 1.6;margin-bottom: 1.6em;\
max-width: 100%;overflow: auto;padding: 1em 1.5em;page-break-inside: avoid;word-wrap: break-word;";

/// Inline style applied to inline `<code>` and indented code blocks, matching
/// `CodeAttributeProvider`.
const CODE_STYLE: &str = "background: #f4f4f4;font-family: monospace;";

/// Renders CommonMark `markdown` to an HTML body fragment, applying the same
/// extensions, inline styling and link fixups as the Java attribute providers.
fn render_body(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_HEADING_ATTRIBUTES);

    let parser = Parser::new_ext(markdown, options).map(transform_event);

    let mut html_out = String::new();
    html::push_html(&mut html_out, parser);
    html_out
}

/// Applies the Java attribute-provider behavior to a single parse event by
/// injecting inline styles and rewriting link destinations.
fn transform_event(event: Event<'_>) -> Event<'_> {
    // Note: table/heading/code styling is applied post-render in `apply_styles`,
    // since pulldown-cmark exposes no per-node attribute hook. Only link
    // destinations require rewriting at the event level.
    match event {
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let new_dest = fixup_link(dest_url.as_ref());
            Event::Start(Tag::Link {
                link_type,
                dest_url: new_dest.into(),
                title,
                id,
            })
        }
        other => other,
    }
}

/// Rewrites a single link destination following the Java `fixupLinks` logic.
///
/// * Local anchors (`#...`) and absolute `http(s)` URLs are returned unchanged.
/// * A trailing `.md` (case-insensitive) is converted to `.html`.
/// * `src/main/py` is rewritten to `pypkg`.
/// * Destinations containing `src/main/java` are dropped (rendered as empty).
fn fixup_link(href: &str) -> String {
    if href.is_empty() || href.starts_with('#') {
        return href.to_string();
    }

    let lower = href.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return href.to_string();
    }

    let mut result = href.to_string();
    if lower.ends_with(".md") {
        let len = result.len();
        result.truncate(len - 2);
        result.push_str("html");
    }

    if result.contains("src/main/py") {
        result = result.replace("src/main/py", "pypkg");
    } else if result.contains("src/main/java") {
        // Java maps this case to `null`, which removes the href entirely.
        return String::new();
    }

    result
}

/// Post-processes rendered HTML to inject inline styles onto table, heading and
/// code elements, matching the Java attribute providers. pulldown-cmark has no
/// per-node attribute hook, so styling is applied via targeted tag rewrites.
fn apply_styles(html_fragment: &str) -> String {
    let mut out = html_fragment.to_string();

    // Table blocks and cells.
    out = out.replace("<table>", &format!("<table style=\"{}\">", TABLE_STYLE));
    out = out.replace("<td>", &format!("<td style=\"{}\">", TABLE_STYLE));
    out = out.replace(
        "<td align=",
        &format!("<td style=\"{}\" align=", TABLE_STYLE),
    );

    // Level 1/2 headings. Plain headings render as `<h1>`; headings carrying
    // attributes (from ENABLE_HEADING_ATTRIBUTES) render as `<h1 id=...>`.
    for level in ['1', '2'] {
        out = out.replace(
            &format!("<h{level}>"),
            &format!("<h{level} style=\"{HEADING_STYLE}\">"),
        );
        out = out.replace(
            &format!("<h{level} "),
            &format!("<h{level} style=\"{HEADING_STYLE}\" "),
        );
    }

    // Fenced code blocks render as `<pre><code ...>`.
    out = out.replace("<pre>", &format!("<pre style=\"{}\">", PRE_STYLE));

    // Inline code and indented code blocks.
    out = out.replace("<code>", &format!("<code style=\"{}\">", CODE_STYLE));

    out
}

/// Wraps a rendered HTML `body` fragment in a complete HTML document skeleton.
fn wrap_html(body: &str, title: &str) -> String {
    let styled_body = apply_styles(body);
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{}</title>\n</head>\n<body>\n{}</body>\n</html>\n",
        escape_html_text(title),
        styled_body
    )
}

/// Minimal HTML text escaping for the document `<title>`.
fn escape_html_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heading_in_body() {
        let html = MarkdownToHtml::convert("# Title", "T");
        assert!(html.contains("<h1"), "missing <h1>: {html}");
        assert!(html.contains(">Title</h1>"), "missing heading text: {html}");
    }

    #[test]
    fn test_paragraph() {
        let html = MarkdownToHtml::convert("Hello world.", "T");
        assert!(
            html.contains("<p>Hello world.</p>"),
            "missing paragraph: {html}"
        );
    }

    #[test]
    fn test_unordered_list() {
        let html = MarkdownToHtml::convert("- one\n- two\n", "T");
        assert!(html.contains("<ul>"), "missing <ul>: {html}");
        assert!(html.contains("<li>one</li>"), "missing list item: {html}");
        assert!(html.contains("<li>two</li>"), "missing list item: {html}");
    }

    #[test]
    fn test_inline_code_span() {
        let html = MarkdownToHtml::convert("Use `foo()` here.", "T");
        assert!(html.contains("<code"), "missing <code>: {html}");
        assert!(html.contains("foo()"), "missing code content: {html}");
        assert!(
            html.contains(CODE_STYLE),
            "inline code style not applied: {html}"
        );
    }

    #[test]
    fn test_fenced_code_block() {
        let md = "```\nlet x = 1;\n```\n";
        let html = MarkdownToHtml::convert(md, "T");
        assert!(html.contains("<pre"), "missing <pre>: {html}");
        assert!(html.contains("let x = 1;"), "missing code content: {html}");
        assert!(
            html.contains(PRE_STYLE),
            "pre style not applied: {html}"
        );
    }

    #[test]
    fn test_document_wrapper_present() {
        let html = MarkdownToHtml::convert("# Hi", "My Title");
        assert!(html.starts_with("<!DOCTYPE html>"), "missing doctype: {html}");
        assert!(html.contains("<html>"), "missing <html>: {html}");
        assert!(html.contains("</html>"), "missing </html>: {html}");
        assert!(html.contains("<body>"), "missing <body>: {html}");
        assert!(html.contains("</body>"), "missing </body>: {html}");
        assert!(
            html.contains("<title>My Title</title>"),
            "missing title: {html}"
        );
    }

    #[test]
    fn test_body_core_has_no_wrapper() {
        let body = MarkdownToHtml::convert_body("# Hi");
        assert!(!body.contains("<!DOCTYPE html>"));
        assert!(!body.contains("<body>"));
        assert!(body.contains("Hi"));
    }

    #[test]
    fn test_table_styling() {
        let md = "| a | b |\n|---|---|\n| 1 | 2 |\n";
        let html = MarkdownToHtml::convert(md, "T");
        assert!(html.contains("<table"), "missing <table>: {html}");
        assert!(
            html.contains(TABLE_STYLE),
            "table style not applied: {html}"
        );
    }

    #[test]
    fn test_heading_styling_h1_h2() {
        let html = MarkdownToHtml::convert("# A\n\n## B\n", "T");
        assert!(html.contains(HEADING_STYLE), "heading style missing: {html}");
    }

    #[test]
    fn test_link_md_to_html() {
        let html = MarkdownToHtml::convert("[doc](other.md)", "T");
        assert!(
            html.contains("href=\"other.html\""),
            "md link not rewritten: {html}"
        );
    }

    #[test]
    fn test_link_anchor_unchanged() {
        assert_eq!(fixup_link("#section"), "#section");
    }

    #[test]
    fn test_link_http_unchanged() {
        assert_eq!(fixup_link("https://example.com/x.md"), "https://example.com/x.md");
        assert_eq!(fixup_link("http://example.com/x.md"), "http://example.com/x.md");
    }

    #[test]
    fn test_link_py_fixup() {
        assert_eq!(fixup_link("a/src/main/py/b.md"), "a/pypkg/b.html");
    }

    #[test]
    fn test_link_java_dropped() {
        assert_eq!(fixup_link("a/src/main/java/B.md"), "");
    }

    #[test]
    fn test_convert_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("md_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("input.md");
        let out_path = dir.join("nested/out.html");
        std::fs::write(&in_path, "# File Title\n\nBody text.\n").unwrap();

        MarkdownToHtml::convert_file_to_file(&in_path, &out_path).unwrap();
        let written = std::fs::read_to_string(&out_path).unwrap();
        assert!(written.starts_with("<!DOCTYPE html>"));
        assert!(written.contains("<title>input</title>"));
        assert!(written.contains(">File Title</h1>"));
        assert!(written.contains("<p>Body text.</p>"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_convert_file_rejects_non_md() {
        let dir = std::env::temp_dir().join(format!("md_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("input.txt");
        std::fs::write(&in_path, "hi").unwrap();
        let err =
            MarkdownToHtml::convert_file_to_file(&in_path, dir.join("out.html")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
