use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use serde_json::Value;

use crate::util::msg::Msg;

use super::elastic_exception::ElasticException;

/// HTTP method name for POST requests.
pub const POST: &str = "POST";
/// HTTP method name for PUT requests.
pub const PUT: &str = "PUT";
/// HTTP method name for GET requests.
pub const GET: &str = "GET";
/// HTTP method name for DELETE requests.
pub const DELETE: &str = "DELETE";

/// The response to a single HTTP request, as needed by [`ElasticConnection`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason_phrase: String,
    pub body: String,
}

/// Abstracts the transport `ElasticConnection` uses to talk to the elasticsearch server.
///
/// In the Java source this role is played by `java.net.HttpURLConnection`, whose
/// concrete protocol handling (including transparent TLS for `https://` URLs) is
/// supplied by the JDK. This workspace has no equivalent HTTP client crate, so the
/// default implementation, [`TcpHttpTransport`], speaks HTTP/1.1 directly over a
/// plain `std::net::TcpStream`. The trait seam lets a TLS-capable transport be
/// substituted later (or a mock substituted in tests) without changing
/// `ElasticConnection`'s public API.
pub trait HttpTransport {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> io::Result<HttpResponse>;
}

/// Default [`HttpTransport`] that speaks HTTP/1.1 over a plain TCP socket.
///
/// Only `http://` URLs are supported; `https://` and other schemes fail with an
/// [`io::Error`] since no TLS client transport is wired into this workspace yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpHttpTransport;

impl HttpTransport for TcpHttpTransport {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> io::Result<HttpResponse> {
        let parsed = ParsedUrl::parse(url)?;

        let mut request = format!("{} {} HTTP/1.1\r\n", method, parsed.path);
        request.push_str(&format!("Host: {}\r\n", parsed.host));
        request.push_str("Connection: close\r\n");
        if let Some(content_type) = content_type {
            request.push_str(&format!("Content-Type: {}\r\n", content_type));
        }
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("\r\n");
        request.push_str(body);

        let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))?;
        stream.write_all(request.as_bytes())?;
        read_http_response(stream)
    }
}

#[derive(Debug)]
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> io::Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Malformed URL: {url}"))
        })?;
        if scheme != "http" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported URL scheme (only http:// is supported): {scheme}"),
            ));
        }
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Bad port in URL: {url}"))
                })?;
                (h.to_string(), port)
            }
            None => (authority.to_string(), 80),
        };
        Ok(Self { host, port, path })
    }
}

fn read_http_response<S: Read>(stream: S) -> io::Result<HttpResponse> {
    let mut reader = BufReader::new(stream);

    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let mut parts = status_line.trim_end().splitn(3, ' ');
    parts.next(); // HTTP version
    let status_code: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Malformed HTTP status line"))?;
    let reason_phrase = parts.next().unwrap_or("").to_string();

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.parse().ok(),
                "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
                _ => {}
            }
        }
    }

    let body = if chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        buf
    };

    Ok(HttpResponse { status_code, reason_phrase, body })
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size_str = size_line.trim_end_matches(['\r', '\n']);
        let size_str = size_str.split(';').next().unwrap_or("0").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                reader.read_line(&mut trailer)?;
                if trailer.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// A connection to an elasticsearch server backing a BSim database.
///
/// Mirrors `ghidra.features.bsim.query.elastic.ElasticConnection`. Generic over the
/// [`HttpTransport`] used to actually talk to the server, defaulting to
/// [`TcpHttpTransport`]; tests substitute a mock transport instead.
pub struct ElasticConnection<T = TcpHttpTransport> {
    /// Main server URL, e.g. `http://hostname:port`.
    host_url: String,
    /// Main URL to elasticsearch, i.e. `host_url` plus `/<repo>_`.
    http_url_base: String,
    last_response_code: i32,
    transport: T,
}

impl ElasticConnection<TcpHttpTransport> {
    pub fn new(url: impl Into<String>, repo: &str) -> Self {
        Self::with_transport(url, repo, TcpHttpTransport)
    }
}

impl<T: HttpTransport> ElasticConnection<T> {
    pub fn with_transport(url: impl Into<String>, repo: &str, transport: T) -> Self {
        let host_url = url.into();
        let http_url_base = format!("{}/{}_", host_url, repo);
        Self { host_url, http_url_base, last_response_code: 0, transport }
    }

    pub fn host_url(&self) -> &str {
        &self.host_url
    }

    pub fn http_url_base(&self) -> &str {
        &self.http_url_base
    }

    pub fn last_request_successful(&self) -> bool {
        (200..300).contains(&self.last_response_code)
    }

    /// Send a raw request to the server that is not specific to the repository.
    /// Intended for general configuration or security commands.
    pub fn execute_raw_statement(
        &mut self,
        command: &str,
        path: &str,
        body: &str,
    ) -> Result<Value, ElasticException> {
        let url = format!("{}{}", self.host_url, path);
        self.execute(command, &url, Some("application/json"), body, true)
    }

    /// Execute an elasticsearch command where we are not expecting a response.
    pub fn execute_statement_no_response(
        &mut self,
        command: &str,
        path: &str,
        body: &str,
    ) -> Result<(), ElasticException> {
        let url = format!("{}{}", self.http_url_base, path);
        self.execute(command, &url, Some("application/json"), body, true)?;
        Ok(())
    }

    /// Execute an elastic search statement and return the JSON response to user.
    pub fn execute_statement(
        &mut self,
        command: &str,
        path: &str,
        body: &str,
    ) -> Result<Value, ElasticException> {
        let url = format!("{}{}", self.http_url_base, path);
        self.execute(command, &url, Some("application/json"), body, true)
    }

    /// Execute an elastic search statement and return the JSON response to user.
    /// Do not fail on a non-2xx response, just return the (possibly error) response.
    pub fn execute_statement_expect_failure(
        &mut self,
        command: &str,
        path: &str,
        body: &str,
    ) -> Result<Value, ElasticException> {
        let url = format!("{}{}", self.http_url_base, path);
        self.execute(command, &url, Some("application/json"), body, false)
    }

    /// Send a bulk request to the elasticsearch server. This is a special format for
    /// combining multiple commands and is structured slightly differently from other
    /// commands.
    pub fn execute_bulk(&mut self, path: &str, body: &str) -> Result<Value, ElasticException> {
        let url = format!("{}{}", self.host_url, path);
        self.execute(POST, &url, Some("application/x-ndjson"), body, true)
    }

    pub fn execute_uri_only(
        &mut self,
        command: &str,
        path: &str,
    ) -> Result<Value, ElasticException> {
        let url = format!("{}{}", self.http_url_base, path);
        self.execute(command, &url, None, "", true)
    }

    fn execute(
        &mut self,
        command: &str,
        url: &str,
        content_type: Option<&str>,
        body: &str,
        fail_on_error: bool,
    ) -> Result<Value, ElasticException> {
        let response = self
            .transport
            .send(command, url, content_type, body)
            .map_err(|e| ElasticException::new(format!("Error sending request: {}", e)))?;
        self.last_response_code = response.status_code as i32;
        let resp = grab_response(&response)?;
        if fail_on_error && !self.last_request_successful() {
            return Err(ElasticException::new(parse_error_json(&resp)));
        }
        Ok(resp)
    }
}

/// Assuming the response status code and body have been captured, parse the body into
/// a `JsonObject`.
///
/// Mirrors `grabResponse`. Java distinguishes `getInputStream()` (success) from
/// `getErrorStream()` (failure) but treats a `null` stream identically in both cases
/// (an `IOException` naming `connection.getResponseMessage()`); here that collapses to
/// an empty response body, regardless of `status_code`.
fn grab_response(response: &HttpResponse) -> Result<Value, ElasticException> {
    if response.body.is_empty() {
        return Err(ElasticException::new(format!(
            "Error sending request: {}",
            response.reason_phrase
        )));
    }
    let value: Value = serde_json::from_str(&response.body)
        .map_err(|e| ElasticException::new(format!("Error parsing response: {}", e)))?;
    if !value.is_object() {
        // Java's JsonElement.getAsJsonObject() throws an unchecked IllegalStateException
        // here, which is not caught by ElasticConnection's callers. Returning an
        // ElasticException instead avoids panicking on a malformed response body.
        return Err(ElasticException::new(
            "Error parsing response: expected a JSON object".to_string(),
        ));
    }
    Ok(value)
}

/// Elastic search sends a JSON document in the Http error stream for any error. Pull
/// out relevant info from the document and construct an exception message.
fn parse_error_json(resp: &Value) -> String {
    // Java also checks `errorObj instanceof String`, but `resp.get("error")` always
    // returns a JsonElement (never a raw String), so that branch is unreachable and is
    // omitted here.
    let err = match resp.get("error").and_then(Value::as_object) {
        Some(err) => err,
        None => return "Unknown error format".to_string(),
    };

    let type_string = convert_to_string_or(err.get("type"), "Unknown Error");
    if type_string.ends_with("_exception") {
        let error_detail = parse_error_cause(err);
        if !error_detail.is_empty() {
            Msg::error(
                "ElasticConnection",
                &format!("Elasticsearch exception: {}", error_detail),
            );
        }
    }

    let reason_string = convert_to_string_or(err.get("reason"), "Unknown Reason");
    format!("{} : {}", type_string, reason_string)
}

fn conditional_new_line(buf: &mut String) {
    if !buf.is_empty() {
        buf.push('\n');
    }
}

fn parse_error_cause(error: &serde_json::Map<String, Value>) -> String {
    let mut buf = String::new();

    let reason = error.get("reason");

    if let Some(type_string) = convert_to_string(error.get("type")) {
        // "reason" is a string when "type" is present.
        let reason_string = convert_to_string(reason).unwrap_or_else(|| "null".to_string());
        conditional_new_line(&mut buf);
        buf.push_str(&format!("{} : {}", type_string, reason_string));
    }

    if let Some(Value::Array(script_stack)) = error.get("script_stack") {
        for e in script_stack {
            conditional_new_line(&mut buf);
            buf.push_str("   ");
            buf.push_str(&convert_to_string(Some(e)).unwrap_or_else(|| "null".to_string()));
        }
    }

    if let Some(Value::Object(caused_by)) = error.get("caused_by") {
        conditional_new_line(&mut buf);
        buf.push_str("   ");
        buf.push_str(&parse_error_cause(caused_by));
    }

    if let Some(Value::Array(failed_shards)) = error.get("failed_shards") {
        for failed_shard_element in failed_shards {
            // Java casts unconditionally, throwing an unchecked ClassCastException for a
            // non-object entry; skipping non-objects here avoids that panic.
            if let Value::Object(failed_shard) = failed_shard_element {
                let index_str =
                    convert_to_string(failed_shard.get("index")).unwrap_or_else(|| "null".to_string());
                conditional_new_line(&mut buf);
                buf.push_str("   Failed shard index: ");
                buf.push_str(&index_str);
                conditional_new_line(&mut buf);
                buf.push_str("   ");
                buf.push_str(&parse_error_cause(failed_shard));
            }
        }
    }

    if let Some(Value::Object(reason_object)) = reason {
        conditional_new_line(&mut buf);
        buf.push_str(&parse_error_cause(reason_object));
    }

    buf
}

/// Get the string held by a JsonElement, allowing for a null (missing) or JSON-null element.
fn convert_to_string(element: Option<&Value>) -> Option<String> {
    if is_null(element) {
        return None;
    }
    Some(json_primitive_to_string(element.unwrap()))
}

/// Get the string held by a JsonElement, falling back to `default_str` if null.
fn convert_to_string_or(element: Option<&Value>, default_str: &str) -> String {
    convert_to_string(element).unwrap_or_else(|| default_str.to_string())
}

/// Check an element for a missing or JSON-null value.
fn is_null(element: Option<&Value>) -> bool {
    element.map_or(true, Value::is_null)
}

/// Mirrors Gson's `JsonElement.getAsString()` for primitive values.
fn json_primitive_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;

    #[derive(Default)]
    struct MockTransport {
        responses: VecDeque<io::Result<HttpResponse>>,
        calls: Vec<(String, String, Option<String>, String)>,
    }

    impl MockTransport {
        fn push_ok(&mut self, status_code: u16, reason_phrase: &str, body: &str) {
            self.responses.push_back(Ok(HttpResponse {
                status_code,
                reason_phrase: reason_phrase.to_string(),
                body: body.to_string(),
            }));
        }

        fn push_err(&mut self, message: &str) {
            self.responses
                .push_back(Err(io::Error::new(io::ErrorKind::Other, message)));
        }
    }

    impl HttpTransport for MockTransport {
        fn send(
            &mut self,
            method: &str,
            url: &str,
            content_type: Option<&str>,
            body: &str,
        ) -> io::Result<HttpResponse> {
            self.calls.push((
                method.to_string(),
                url.to_string(),
                content_type.map(|s| s.to_string()),
                body.to_string(),
            ));
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::Other, "no mock response queued")))
        }
    }

    fn conn(transport: MockTransport) -> ElasticConnection<MockTransport> {
        ElasticConnection::with_transport("http://localhost:9200", "myrepo", transport)
    }

    #[test]
    fn test_new_builds_urls() {
        let c = ElasticConnection::new("http://localhost:9200", "myrepo");
        assert_eq!(c.host_url(), "http://localhost:9200");
        assert_eq!(c.http_url_base(), "http://localhost:9200/myrepo_");
    }

    #[test]
    fn test_last_request_successful_boundaries() {
        let mut c = conn(MockTransport::default());
        assert!(!c.last_request_successful(), "default (0) is not successful");
        c.last_response_code = 200;
        assert!(c.last_request_successful());
        c.last_response_code = 299;
        assert!(c.last_request_successful());
        c.last_response_code = 300;
        assert!(!c.last_request_successful());
        c.last_response_code = 199;
        assert!(!c.last_request_successful());
    }

    #[test]
    fn test_execute_statement_success() {
        let mut t = MockTransport::default();
        t.push_ok(200, "OK", r#"{"acknowledged":true}"#);
        let mut c = conn(t);
        let resp = c.execute_statement(GET, "myindex/_doc/1", "{}").unwrap();
        assert_eq!(resp["acknowledged"], Value::Bool(true));
        assert!(c.last_request_successful());
        assert_eq!(
            c.transport.calls[0],
            (
                GET.to_string(),
                "http://localhost:9200/myrepo_myindex/_doc/1".to_string(),
                Some("application/json".to_string()),
                "{}".to_string(),
            )
        );
    }

    #[test]
    fn test_execute_statement_failure_builds_error_message() {
        let mut t = MockTransport::default();
        t.push_ok(
            404,
            "Not Found",
            r#"{"error":{"type":"index_not_found_exception","reason":"no such index"}}"#,
        );
        let mut c = conn(t);
        let err = c.execute_statement(GET, "missing", "{}").unwrap_err();
        assert_eq!(err.message(), "index_not_found_exception : no such index");
        assert!(!c.last_request_successful());
    }

    #[test]
    fn test_execute_statement_expect_failure_does_not_error() {
        let mut t = MockTransport::default();
        t.push_ok(500, "Server Error", r#"{"error":{"type":"x","reason":"y"}}"#);
        let mut c = conn(t);
        let resp = c.execute_statement_expect_failure(GET, "path", "{}").unwrap();
        assert_eq!(resp["error"]["type"], Value::String("x".to_string()));
        assert!(!c.last_request_successful());
    }

    #[test]
    fn test_execute_raw_statement_uses_host_url() {
        let mut t = MockTransport::default();
        t.push_ok(200, "OK", "{}");
        let mut c = conn(t);
        c.execute_raw_statement(PUT, "/_security/role/foo", "{}").unwrap();
        assert_eq!(c.transport.calls[0].1, "http://localhost:9200/_security/role/foo");
    }

    #[test]
    fn test_execute_bulk_uses_ndjson_content_type_and_post() {
        let mut t = MockTransport::default();
        t.push_ok(200, "OK", "{}");
        let mut c = conn(t);
        c.execute_bulk("/_bulk", "{}\n{}\n").unwrap();
        let (method, url, content_type, body) = &c.transport.calls[0];
        assert_eq!(method, POST);
        assert_eq!(url, "http://localhost:9200/_bulk");
        assert_eq!(content_type.as_deref(), Some("application/x-ndjson"));
        assert_eq!(body, "{}\n{}\n");
    }

    #[test]
    fn test_execute_uri_only_sends_no_content_type_or_body() {
        let mut t = MockTransport::default();
        t.push_ok(200, "OK", "{}");
        let mut c = conn(t);
        c.execute_uri_only(DELETE, "myindex").unwrap();
        let (method, url, content_type, body) = &c.transport.calls[0];
        assert_eq!(method, DELETE);
        assert_eq!(url, "http://localhost:9200/myrepo_myindex");
        assert_eq!(content_type, &None);
        assert_eq!(body, "");
    }

    #[test]
    fn test_execute_statement_no_response_returns_unit() {
        let mut t = MockTransport::default();
        t.push_ok(200, "OK", r#"{"result":"created"}"#);
        let mut c = conn(t);
        assert_eq!(c.execute_statement_no_response(PUT, "doc/1", "{}"), Ok(()));
    }

    #[test]
    fn test_execute_wraps_transport_io_error() {
        let mut t = MockTransport::default();
        t.push_err("connection refused");
        let mut c = conn(t);
        let err = c.execute_statement(GET, "path", "{}").unwrap_err();
        assert_eq!(err.message(), "Error sending request: connection refused");
    }

    #[test]
    fn test_grab_response_empty_body_is_error() {
        let response = HttpResponse {
            status_code: 502,
            reason_phrase: "Bad Gateway".to_string(),
            body: String::new(),
        };
        let err = grab_response(&response).unwrap_err();
        assert_eq!(err.message(), "Error sending request: Bad Gateway");
    }

    #[test]
    fn test_grab_response_invalid_json_is_error() {
        let response = HttpResponse {
            status_code: 200,
            reason_phrase: "OK".to_string(),
            body: "not json".to_string(),
        };
        let err = grab_response(&response).unwrap_err();
        assert!(err.message().starts_with("Error parsing response:"));
    }

    #[test]
    fn test_grab_response_non_object_json_is_error() {
        let response = HttpResponse {
            status_code: 200,
            reason_phrase: "OK".to_string(),
            body: "[1,2,3]".to_string(),
        };
        assert!(grab_response(&response).is_err());
    }

    #[test]
    fn test_convert_to_string_variants() {
        assert_eq!(convert_to_string(None), None);
        assert_eq!(convert_to_string(Some(&Value::Null)), None);
        assert_eq!(
            convert_to_string(Some(&Value::String("hi".to_string()))),
            Some("hi".to_string())
        );
        assert_eq!(
            convert_to_string(Some(&Value::from(42))),
            Some("42".to_string())
        );
        assert_eq!(
            convert_to_string(Some(&Value::Bool(true))),
            Some("true".to_string())
        );
    }

    #[test]
    fn test_convert_to_string_or_default() {
        assert_eq!(convert_to_string_or(None, "fallback"), "fallback");
        assert_eq!(
            convert_to_string_or(Some(&Value::String("x".to_string())), "fallback"),
            "x"
        );
    }

    #[test]
    fn test_parse_error_json_unknown_format() {
        let resp: Value = serde_json::from_str(r#"{"no_error_field":true}"#).unwrap();
        assert_eq!(parse_error_json(&resp), "Unknown error format");
    }

    #[test]
    fn test_parse_error_json_missing_fields_use_defaults() {
        let resp: Value = serde_json::from_str(r#"{"error":{}}"#).unwrap();
        assert_eq!(parse_error_json(&resp), "Unknown Error : Unknown Reason");
    }

    #[test]
    fn test_parse_error_cause_nested_caused_by() {
        let error: Value = serde_json::from_str(
            r#"{
                "type": "search_phase_execution_exception",
                "reason": "all shards failed",
                "caused_by": {
                    "type": "parse_exception",
                    "reason": "bad query"
                }
            }"#,
        )
        .unwrap();
        let obj = error.as_object().unwrap();
        let cause = parse_error_cause(obj);
        assert_eq!(
            cause,
            "search_phase_execution_exception : all shards failed\n   parse_exception : bad query"
        );
    }

    #[test]
    fn test_parse_error_cause_script_stack_and_failed_shards() {
        let error: Value = serde_json::from_str(
            r#"{
                "type": "script_exception",
                "reason": "bad script",
                "script_stack": ["line1", "line2"],
                "failed_shards": [
                    {"index": "myindex", "type": "x", "reason": "y"}
                ]
            }"#,
        )
        .unwrap();
        let obj = error.as_object().unwrap();
        let cause = parse_error_cause(obj);
        assert_eq!(
            cause,
            "script_exception : bad script\n   line1\n   line2\n   Failed shard index: myindex\n   x : y"
        );
    }

    #[test]
    fn test_conditional_new_line() {
        let mut buf = String::new();
        conditional_new_line(&mut buf);
        assert_eq!(buf, "");
        buf.push_str("hello");
        conditional_new_line(&mut buf);
        assert_eq!(buf, "hello\n");
    }

    #[test]
    fn test_parsed_url_default_port_and_path() {
        let url = ParsedUrl::parse("http://example.com/foo/bar").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/foo/bar");
    }

    #[test]
    fn test_parsed_url_explicit_port_and_no_path() {
        let url = ParsedUrl::parse("http://example.com:9200").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 9200);
        assert_eq!(url.path, "/");
    }

    #[test]
    fn test_parsed_url_rejects_https() {
        let err = ParsedUrl::parse("https://example.com").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parsed_url_rejects_malformed() {
        assert!(ParsedUrl::parse("not-a-url").is_err());
    }

    #[test]
    fn test_read_http_response_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\r\n";
        let resp = read_http_response(Cursor::new(&raw[..])).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason_phrase, "OK");
        assert_eq!(resp.body, "{\"ok\":true}\r\n");
    }

    #[test]
    fn test_read_http_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n5\r\n12345\r\n0\r\n\r\n";
        let resp = read_http_response(Cursor::new(&raw[..])).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, "test12345");
    }

    #[test]
    fn test_read_http_response_error_status_and_reason() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
        let resp = read_http_response(Cursor::new(&raw[..])).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason_phrase, "Not Found");
        assert_eq!(resp.body, "{}");
    }

    #[test]
    fn test_read_http_response_no_content_length_reads_to_eof() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nhello world";
        let resp = read_http_response(Cursor::new(&raw[..])).unwrap();
        assert_eq!(resp.body, "hello world");
    }
}
