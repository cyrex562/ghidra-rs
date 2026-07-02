use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Key used to order and de-duplicate [`ConnectLine`] entries.
///
/// Mirrors the fields compared by `ConnectLine.compareTo` in the Java source
/// (`database`, `user`, `address`); `type`, `method`, `options`, and the matched flag
/// are intentionally excluded, matching Java's `TreeSet` semantics.
type ConnectKey = (String, String, Option<String>);

fn connect_line_key(line: &ConnectLine) -> ConnectKey {
    (line.database.clone(), line.user.clone(), line.address.clone())
}

fn is_java_identifier_part(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Class for modifying the PostgreSQL configuration files describing
///   the main server settings (postgresql.conf)
///   the connection settings  (pg_hba.conf)
///   the identification map   (pg_ident.conf)
///
/// Port of `ghidra.features.bsim.query.ServerConfig`.
#[derive(Debug, Default)]
pub struct ServerConfig {
    /// Values we want set in the configuration file.
    key_value: BTreeMap<String, String>,
    /// Entries we want in the connection file, keyed by (database, user, address).
    connect_set: BTreeMap<ConnectKey, ConnectLine>,
}

/// Holds a single configuration option from the PostgreSQL configuration file.
#[derive(Debug, Default)]
struct ConfigLine {
    /// Configuration key.
    key: Option<String>,
    /// Value assigned to the key.
    value: Option<String>,
    /// Any associated comment on the same line as the key/value.
    comment: Option<String>,
    /// 0 if the line does not contain a controlled key.
    /// 1 if the line contains a controlled key that is uncommented.
    /// 2 if the line contains a controlled key that is commented.
    status: i32,

    sz: usize,
    pos: usize,
    commented_key: bool,
}

impl ConfigLine {
    fn parse_upto_key(&mut self, line: &str) {
        let chars: Vec<char> = line.chars().collect();
        self.key = None;
        self.value = None;
        self.comment = None;
        self.status = 0;
        self.sz = chars.len();
        self.pos = 0;
        self.commented_key = false;
        self.pos = Self::skip_white_space(&chars, self.pos);
        if self.pos >= self.sz {
            return;
        }
        if chars[self.pos] == '#' {
            self.pos += 1;
            self.commented_key = true;
            self.pos = Self::skip_white_space(&chars, self.pos);
            if self.pos >= self.sz {
                return;
            }
        }
        let tokend = Self::scan_token(&chars, self.pos);
        if tokend == self.pos {
            return; // No characters in token
        }
        self.key = Some(chars[self.pos..tokend].iter().collect());
        self.pos = tokend;
    }

    fn skip_value_parse_comment(&mut self, line: &str) {
        let chars: Vec<char> = line.chars().collect();
        self.pos = Self::skip_white_space(&chars, self.pos);
        if self.pos >= self.sz {
            return;
        }
        if chars[self.pos] != '=' {
            return;
        }
        self.pos += 1;
        self.comment = Some(String::new());

        while self.pos < self.sz {
            if chars[self.pos] == '#' {
                self.comment = Some(chars[self.pos..].iter().collect());
                break;
            }
            self.pos += 1;
        }
        self.status = if self.commented_key { 2 } else { 1 };
    }

    fn parse_value(&mut self, line: &str) {
        let chars: Vec<char> = line.chars().collect();
        self.pos = Self::skip_white_space(&chars, self.pos);
        if self.pos >= self.sz {
            return;
        }
        if chars[self.pos] != '=' {
            return;
        }
        self.pos += 1;
        self.comment = Some(String::new());
        let valstart = self.pos;
        while self.pos < self.sz {
            if chars[self.pos] == '#' {
                self.comment = Some(chars[self.pos..].iter().collect());
                break;
            }
            self.pos += 1;
        }
        let value: String = chars[valstart..self.pos].iter().collect();
        self.value = Some(value.trim().to_string());
        self.status = if self.commented_key { 2 } else { 1 };
    }

    fn scan_token(chars: &[char], mut pos: usize) -> usize {
        while pos < chars.len() && is_java_identifier_part(chars[pos]) {
            pos += 1;
        }
        pos
    }

    fn skip_white_space(chars: &[char], mut pos: usize) -> usize {
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        pos
    }
}

/// Holds an entry from the PostgreSQL connection configuration file.
#[derive(Debug, Clone, Default)]
struct ConnectLine {
    /// Type of connection: local, host, hostssl, etc.
    conn_type: String,
    /// Name of database associated with entry or the reserved word 'all'.
    database: String,
    /// Name of user associated with entry (or 'all').
    user: String,
    /// IPv4 or IPv6 address.
    address: Option<String>,
    /// Authentication method to use: trust, cert, ...
    method: String,
    /// Additional options.
    options: Option<String>,
    /// Set to true if we have seen this entry in the connection file.
    is_matched: bool,
}

impl ConnectLine {
    /// Determines if the connection is coming either from UNIX socket or "localhost".
    fn is_local(&self) -> bool {
        if self.conn_type == "local" {
            return true; // UNIX socket
        }
        if let Some(ref address) = self.address {
            if address == "127.0.0.1/32" {
                return true; // IPv4 localhost
            }
            if address == "::1/128" {
                return true; // IPv6 localhost
            }
        }
        false
    }

    /// Parses the fields out of a line of the connection file.
    fn parse(&mut self, line: &str) -> io::Result<()> {
        let split: Vec<&str> = line.split(' ').filter(|s| !s.is_empty()).collect();
        if split.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Parsing error"));
        }
        self.conn_type = split[0].to_string();
        self.database = split[1].to_string();
        self.user = split[2].to_string();
        let mut next_pos = 3;
        if self.conn_type == "local" {
            // "local" type has no address
            self.address = None;
        } else {
            self.address = Some(split[3].to_string());
            next_pos = 4;
        }
        if next_pos >= split.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Parsing error"));
        }
        self.method = split[next_pos].to_string();
        next_pos += 1;
        if next_pos >= split.len() {
            self.options = None;
            return Ok(());
        }
        let mut buffer = String::new();
        buffer.push_str(split[next_pos]);
        next_pos += 1;
        while next_pos < split.len() {
            buffer.push(' ');
            buffer.push_str(split[next_pos]);
            next_pos += 1;
        }
        self.options = Some(buffer);
        Ok(())
    }

    /// Restores a connection entry from an XML tag.
    fn restore_xml(&mut self, el: &impl XmlElement) {
        self.conn_type = el.get_attribute("type").unwrap_or_default();
        self.database = el.get_attribute("db").unwrap_or_default();
        self.user = el.get_attribute("user").unwrap_or_default();
        self.address = el.get_attribute("addr");
        self.method = el.get_attribute("method").unwrap_or_default();
        self.options = el.get_attribute("options");
    }

    /// Emits the line, formatted as it should appear in the connection file.
    fn emit(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(writer, "{}", self.conn_type)?;
        for _ in self.conn_type.chars().count()..8 {
            write!(writer, " ")?;
        }
        write!(writer, "{}", self.database)?;
        for _ in self.database.chars().count()..16 {
            write!(writer, " ")?;
        }
        write!(writer, "{}", self.user)?;
        for _ in self.user.chars().count()..16 {
            write!(writer, " ")?;
        }
        let addr_len = self.address.as_ref().map(|a| a.chars().count()).unwrap_or(0);
        if let Some(ref address) = self.address {
            write!(writer, "{}", address)?;
        }
        for _ in addr_len..24 {
            write!(writer, " ")?;
        }
        write!(writer, "{}", self.method)?;
        if let Some(ref options) = self.options {
            write!(writer, " {}", options)?;
        }
        Ok(())
    }
}

/// Holds a single entry from the PostgreSQL identification map file (pg_ident.conf).
#[derive(Debug, Default)]
struct IdentLine {
    /// Map the entry belongs to.
    map_name: String,
    /// Name reported by the system.
    system_name: String,
    system_name_is_quoted: bool,
    /// Database role to map to.
    role_name: String,
    role_name_is_quoted: bool,
}

impl IdentLine {
    fn new(map_name: &str, system_name: &str, role_name: &str) -> Self {
        Self {
            map_name: map_name.to_string(),
            system_name: system_name.to_string(),
            system_name_is_quoted: Self::needs_double_quotes(system_name),
            role_name: role_name.to_string(),
            role_name_is_quoted: Self::needs_double_quotes(role_name),
        }
    }

    fn set_system_name(&mut self, system_name: &str) {
        self.system_name = system_name.to_string();
        self.system_name_is_quoted = Self::needs_double_quotes(system_name);
    }

    fn match_role(&self, map_name: &str, role_name: &str) -> bool {
        self.map_name == map_name && self.role_name == role_name
    }

    fn needs_double_quotes(name: &str) -> bool {
        name.chars().any(|c| !c.is_alphanumeric())
    }

    fn skip_white_space(pos: usize, chars: &[char]) -> usize {
        let mut pos = pos;
        while pos < chars.len() {
            let c = chars[pos];
            if c != ' ' && c != '\t' {
                break;
            }
            pos += 1;
        }
        pos
    }

    fn parse_field(pos: usize, chars: &[char]) -> usize {
        let mut pos = pos;
        while pos < chars.len() {
            let c = chars[pos];
            if c == ' ' || c == '\t' {
                break;
            }
            pos += 1;
        }
        pos
    }

    fn parse_double_quote(pos: usize, chars: &[char]) -> usize {
        let mut pos = pos + 1; // Skip the initial quote character
        while pos < chars.len() {
            let c = chars[pos];
            if c == '"' {
                pos += 1;
                break;
            }
            pos += 1;
        }
        pos
    }

    /// Parses a single line from the pg_ident.conf file and recovers the
    /// map name, system name, and role.
    ///
    /// Returns `Ok(true)` if the line is an ident entry, `Ok(false)` if it is a comment.
    fn parse(&mut self, line: &str) -> io::Result<bool> {
        let chars: Vec<char> = line.chars().collect();
        let mut pos = Self::skip_white_space(0, &chars);
        if pos >= chars.len() {
            return Ok(false); // Blank line, treat as comment
        }
        if chars[pos] == '"' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Bad map field in pg_ident.conf entry",
            ));
        }
        if chars[pos] == '#' {
            return Ok(false); // Indicate comment
        }
        let mut endpos = Self::parse_field(pos, &chars);
        self.map_name = chars[pos..endpos].iter().collect();

        pos = Self::skip_white_space(endpos, &chars);
        if pos >= chars.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing system-name in pg_ident.conf entry",
            ));
        } else if chars[pos] == '"' {
            self.system_name_is_quoted = true;
            endpos = Self::parse_double_quote(pos, &chars);
            if chars[endpos - 1] != '"' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Entry missing ending quote in pg_ident.conf",
                ));
            }
            self.system_name = chars[pos + 1..endpos - 1].iter().collect(); // Strip quotes
        } else {
            self.system_name_is_quoted = false;
            endpos = Self::parse_field(pos, &chars);
            self.system_name = chars[pos..endpos].iter().collect();
        }

        pos = Self::skip_white_space(endpos, &chars);
        if pos >= chars.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing role in pg_ident.conf entry",
            ));
        } else if chars[pos] == '"' {
            self.role_name_is_quoted = true;
            endpos = Self::parse_double_quote(pos, &chars);
            if chars[endpos - 1] != '"' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Entry missing ending quote in pg_ident.conf",
                ));
            }
            self.role_name = chars[pos + 1..endpos - 1].iter().collect(); // Strip quotes
        } else {
            self.role_name_is_quoted = false;
            endpos = Self::parse_field(pos, &chars);
            self.role_name = chars[pos..endpos].iter().collect();
        }
        Ok(true)
    }

    fn emit(&self, writer: &mut impl Write) -> io::Result<()> {
        write!(writer, "{}", self.map_name)?;
        for _ in self.map_name.chars().count()..15 {
            write!(writer, " ")?;
        }
        write!(writer, " ")?;
        if self.system_name_is_quoted {
            write!(writer, "\"")?;
        }
        write!(writer, "{}", self.system_name)?;
        if self.system_name_is_quoted {
            write!(writer, "\"")?;
        }
        let sys_len =
            self.system_name.chars().count() + if self.system_name_is_quoted { 2 } else { 0 };
        for _ in sys_len..23 {
            write!(writer, " ")?;
        }
        write!(writer, " ")?;
        if self.role_name_is_quoted {
            write!(writer, "\"")?;
        }
        write!(writer, "{}", self.role_name)?;
        if self.role_name_is_quoted {
            write!(writer, "\"")?;
        }
        Ok(())
    }
}

/// Strips any trailing comment from a connection-file line.
///
/// Returns `None` if the line only contains whitespace and/or a comment.
fn strip_connect_comment(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    let pos = chars.iter().position(|&c| c == '#').unwrap_or(chars.len());
    for (i, &c) in chars.iter().enumerate().take(pos) {
        if c != ' ' && c != '\t' {
            return Some(chars[i..pos].iter().collect());
        }
    }
    None
}

impl ServerConfig {
    /// Creates a new, empty `ServerConfig`.
    pub fn new() -> Self {
        Self::default()
    }

    fn add_connect_line(&mut self, line: ConnectLine) {
        let key = connect_line_key(&line);
        self.connect_set.entry(key).or_insert(line);
    }

    /// Reads a set of key/value pairs and connection entries to use for patching, from an
    /// XML file.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<(), XmlException> {
        parser.start(&["serverconfig"])?;
        while parser.peek().is_start() {
            let el = parser.start(&[])?;
            if el.get_name() == "config" {
                let key = el.get_attribute("key").unwrap_or_default();
                let val = parser.end()?.get_text().to_string();
                self.key_value.insert(key, val);
            } else if el.get_name() == "connect" {
                let mut conn_line = ConnectLine::default();
                conn_line.is_matched = false;
                conn_line.restore_xml(&el);
                self.add_connect_line(conn_line);
                parser.end_matching(&el)?;
            } else {
                parser.discard_sub_tree_element(&el);
            }
        }
        parser.end()?;
        Ok(())
    }

    /// Given a set of key/value pairs, established via `restore_xml` or manually entered via
    /// `add_key`, reads in an existing configuration file, and writes out an altered form, where:
    ///   1) Keys matching something in the keyValue map have their value altered to match the map
    ///   2) Keys that don't match anything in the map, are output unaltered
    ///   3) Comments, both entire line and those coming after key/value pairs, are preserved
    pub fn patch_config(&self, in_file: &Path, out_file: &Path) -> io::Result<()> {
        let mut already_emitted: BTreeSet<String> = BTreeSet::new();
        let mut parse = ConfigLine::default();

        let reader = BufReader::new(File::open(in_file)?);
        let mut writer = File::create(out_file)?;

        for line in reader.lines() {
            let mut line = line?;
            if !line.is_empty() {
                parse.parse_upto_key(&line);
                if let Some(ref key) = parse.key {
                    parse.value = self.key_value.get(key).cloned(); // Check if this is a key we control
                }
                if parse.value.is_some() {
                    parse.skip_value_parse_comment(&line); // Discard original value, preserve comment
                }
                if parse.status > 0 {
                    // A controlled key
                    let key = parse.key.clone().unwrap();
                    if !already_emitted.contains(&key) {
                        // Have not emitted yet
                        let mut new_line =
                            format!("{} = {}", key, parse.value.clone().unwrap_or_default());
                        if let Some(ref comment) = parse.comment {
                            if !comment.is_empty() {
                                new_line.push_str("          ");
                                new_line.push_str(comment);
                            }
                        }
                        line = new_line;
                        already_emitted.insert(key);
                    } else if parse.status == 1 {
                        // Have already emitted before
                        line = format!("#{}", line);
                    }
                }
            }
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\n")?;
        }

        for (key, value) in &self.key_value {
            if !already_emitted.contains(key) {
                writer.write_all(format!("{} = {}", key, value).as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }

        Ok(())
    }

    /// Reads in a connection file and writes out an altered version of the file where:
    ///   1) Any entry that matches something in connectSet, has its authentication method altered
    ///   2) Any entry that does not match into connectSet is commented out in the output
    ///   3) Entire line comments are preserved
    pub fn patch_connect(&mut self, in_file: &Path, out_file: &Path) -> io::Result<()> {
        let reader = BufReader::new(File::open(in_file)?);
        let mut writer = File::create(out_file)?;

        for line in reader.lines() {
            let line = line?;
            match strip_connect_comment(&line) {
                None => {
                    // This line only contained a comment; output the original line
                    writer.write_all(line.as_bytes())?;
                }
                Some(stripped) => {
                    let mut conn_line = ConnectLine::default();
                    conn_line.parse(&stripped)?;
                    let key = connect_line_key(&conn_line);
                    match self.connect_set.get_mut(&key) {
                        Some(match_line) => {
                            match_line.emit(&mut writer)?;
                            match_line.is_matched = true;
                        }
                        None => {
                            writer.write_all(b"#")?; // Comment out the line
                            conn_line.emit(&mut writer)?;
                        }
                    }
                }
            }
            writer.write_all(b"\n")?;
        }

        // Append any entries we didn't match
        for conn_line in self.connect_set.values() {
            if conn_line.is_matched {
                continue;
            }
            conn_line.emit(&mut writer)?;
            writer.write_all(b"\n")?;
        }

        Ok(())
    }

    /// Adds/removes an identity entry to pg_ident.conf.
    ///
    /// * `in_file` is a copy of pg_ident.conf to modify
    /// * `out_file` becomes the modified copy of pg_ident.conf
    /// * `map_name` is the map being modified
    /// * `system_name` is the system name (map from)
    /// * `role_name` is the database role (map to)
    /// * `add_user` is true if the map entry is to be added, false if the entry should be removed
    pub fn patch_ident(
        in_file: &Path,
        out_file: &Path,
        map_name: &str,
        system_name: &str,
        role_name: &str,
        add_user: bool,
    ) -> io::Result<()> {
        let reader = BufReader::new(File::open(in_file)?);
        let mut writer = File::create(out_file)?;

        let mut entry_is_matched = !add_user;
        for line in reader.lines() {
            let line = line?;
            let mut ident_line = IdentLine::default();
            if ident_line.parse(&line)? {
                if ident_line.match_role(map_name, role_name) {
                    // Found old entry
                    if !add_user {
                        // If we are supposed to drop the entry, skip the emit below
                        continue;
                    }
                    ident_line.set_system_name(system_name); // Update to new role
                    entry_is_matched = true;
                }
                ident_line.emit(&mut writer)?;
                writer.write_all(b"\n")?;
            } else {
                // Read a comment; keep line as is
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }
        if !entry_is_matched {
            let ident_line = IdentLine::new(map_name, system_name, role_name);
            ident_line.emit(&mut writer)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Adds a key/value pair directly into the configuration file.
    pub fn add_key(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.key_value.insert(key.into(), value.into());
    }

    /// Retrieves the value associated with a particular key from a (parsed) configuration file.
    pub fn get_value(&self, key: &str) -> Option<String> {
        self.key_value.get(key).cloned()
    }

    /// Parses a configuration file.
    pub fn scan_config(&mut self, in_file: &Path) -> io::Result<()> {
        let reader = BufReader::new(File::open(in_file)?);
        let mut parse = ConfigLine::default();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            parse.parse_upto_key(&line);
            let key = match parse.key.clone() {
                Some(key) => key,
                None => continue,
            };
            // Check if this is a key we want to find
            if let Some(curval) = self.key_value.get(&key).cloned() {
                // If this line is setting a value we control
                if !curval.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Multiple settings for: {}", key),
                    ));
                }
                parse.parse_value(&line); // Discard original value, preserve comment
                if parse.status == 1 {
                    // We have an uncommented controlled key
                    self.key_value.insert(key, parse.value.clone().unwrap_or_default());
                }
            }
        }
        Ok(())
    }

    /// Reads in all the entries of the connection file.
    pub fn scan_connect(&mut self, in_file: &Path) -> io::Result<()> {
        let reader = BufReader::new(File::open(in_file)?);
        for line in reader.lines() {
            let line = line?;
            if let Some(stripped) = strip_connect_comment(&line) {
                let mut conn_line = ConnectLine::default();
                conn_line.parse(&stripped)?;
                self.add_connect_line(conn_line);
            }
        }
        Ok(())
    }

    pub fn get_local_authentication(&self) -> Option<String> {
        self.connect_set
            .values()
            .find(|conn_line| conn_line.is_local())
            .map(|conn_line| conn_line.method.clone())
    }

    pub fn set_local_authentication(&mut self, val: impl Into<String>, options: Option<String>) {
        let val = val.into();
        for conn_line in self.connect_set.values_mut() {
            if conn_line.is_local() {
                conn_line.method = val.clone();
                conn_line.options = options.clone();
            }
        }
    }

    pub fn get_host_authentication(&self) -> Option<String> {
        self.connect_set
            .values()
            .find(|conn_line| conn_line.conn_type == "hostssl" && !conn_line.is_local())
            .map(|conn_line| conn_line.method.clone())
    }

    pub fn set_host_authentication(&mut self, val: impl Into<String>, options: Option<String>) {
        let val = val.into();
        for conn_line in self.connect_set.values_mut() {
            if conn_line.conn_type == "hostssl" && !conn_line.is_local() {
                conn_line.method = val.clone();
                conn_line.options = options.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn add_key_and_get_value_round_trip() {
        let mut cfg = ServerConfig::new();
        cfg.add_key("max_connections", "100");
        assert_eq!(cfg.get_value("max_connections"), Some("100".to_string()));
        assert_eq!(cfg.get_value("missing"), None);
    }

    #[test]
    fn is_local_true_for_unix_socket() {
        let mut line = ConnectLine::default();
        line.parse("local all all trust").unwrap();
        assert!(line.is_local());
        assert_eq!(line.address, None);
    }

    #[test]
    fn is_local_true_for_ipv4_and_ipv6_loopback() {
        let mut ipv4 = ConnectLine::default();
        ipv4.parse("host all all 127.0.0.1/32 trust").unwrap();
        assert!(ipv4.is_local());

        let mut ipv6 = ConnectLine::default();
        ipv6.parse("host all all ::1/128 trust").unwrap();
        assert!(ipv6.is_local());
    }

    #[test]
    fn is_local_false_for_remote_host() {
        let mut line = ConnectLine::default();
        line.parse("host all all 10.0.0.5/32 trust").unwrap();
        assert!(!line.is_local());
    }

    #[test]
    fn connect_line_parse_with_options() {
        let mut line = ConnectLine::default();
        line.parse("hostssl mydb myuser 10.0.0.0/24 md5 clientcert=1").unwrap();
        assert_eq!(line.conn_type, "hostssl");
        assert_eq!(line.database, "mydb");
        assert_eq!(line.user, "myuser");
        assert_eq!(line.address.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(line.method, "md5");
        assert_eq!(line.options.as_deref(), Some("clientcert=1"));
    }

    #[test]
    fn connect_line_parse_too_few_fields_errors() {
        let mut line = ConnectLine::default();
        assert!(line.parse("host all all").is_err());
    }

    #[test]
    fn strip_connect_comment_drops_full_comment_line() {
        assert_eq!(strip_connect_comment("   # just a comment"), None);
        assert_eq!(strip_connect_comment(""), None);
    }

    #[test]
    fn strip_connect_comment_keeps_content_and_strips_trailing_comment() {
        assert_eq!(
            strip_connect_comment("local all all trust # comment").as_deref(),
            Some("local all all trust ")
        );
    }

    #[test]
    fn set_and_get_local_authentication() {
        let mut cfg = ServerConfig::new();
        cfg.scan_connect_lines_for_test(&["local all all trust"]);
        assert_eq!(cfg.get_local_authentication().as_deref(), Some("trust"));
        cfg.set_local_authentication("md5", Some("clientcert=1".to_string()));
        assert_eq!(cfg.get_local_authentication().as_deref(), Some("md5"));
    }

    #[test]
    fn set_and_get_host_authentication() {
        let mut cfg = ServerConfig::new();
        cfg.scan_connect_lines_for_test(&["hostssl all all 0.0.0.0/0 cert"]);
        assert_eq!(cfg.get_host_authentication().as_deref(), Some("cert"));
        cfg.set_host_authentication("md5", None);
        assert_eq!(cfg.get_host_authentication().as_deref(), Some("md5"));
    }

    impl ServerConfig {
        fn scan_connect_lines_for_test(&mut self, lines: &[&str]) {
            for line in lines {
                let mut conn_line = ConnectLine::default();
                conn_line.parse(line).unwrap();
                self.add_connect_line(conn_line);
            }
        }
    }

    #[test]
    fn patch_config_updates_controlled_keys_and_preserves_others() {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("postgresql.conf");
        let out_path = dir.path().join("postgresql.out.conf");
        std::fs::write(
            &in_path,
            "shared_buffers = 128MB   # default\nunrelated = keepme\n#max_connections = 50\n",
        )
        .unwrap();

        let mut cfg = ServerConfig::new();
        cfg.add_key("shared_buffers", "256MB");
        cfg.add_key("max_connections", "100");
        cfg.patch_config(&in_path, &out_path).unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("shared_buffers = 256MB"));
        assert!(contents.contains("shared_buffers = 256MB          # default"));
        assert!(contents.contains("unrelated = keepme"));
        assert!(contents.contains("#max_connections = 50"));
        assert!(contents.contains("max_connections = 100"));
    }

    #[test]
    fn scan_config_recovers_uncommented_values() {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("postgresql.conf");
        std::fs::write(&in_path, "shared_buffers = 256MB   # comment\n").unwrap();

        let mut cfg = ServerConfig::new();
        cfg.add_key("shared_buffers", "");
        cfg.scan_config(&in_path).unwrap();
        assert_eq!(cfg.get_value("shared_buffers"), Some("256MB".to_string()));
    }

    #[test]
    fn patch_connect_comments_out_unmatched_and_updates_matched() {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("pg_hba.conf");
        let out_path = dir.path().join("pg_hba.out.conf");
        std::fs::write(
            &in_path,
            "# a comment\nlocal all all trust\nhost all all 10.0.0.0/24 md5\n",
        )
        .unwrap();

        let mut cfg = ServerConfig::new();
        cfg.scan_connect_lines_for_test(&["local all all peer"]);
        cfg.patch_connect(&in_path, &out_path).unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("# a comment"));
        assert!(contents.contains("local   all             all             "));
        assert!(contents.contains("peer"));
        assert!(contents.contains("#host"));
    }

    #[test]
    fn patch_ident_adds_new_entry_when_missing() {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("pg_ident.conf");
        let out_path = dir.path().join("pg_ident.out.conf");
        std::fs::write(&in_path, "# comment line\n").unwrap();

        ServerConfig::patch_ident(&in_path, &out_path, "mymap", "alice", "alice_db", true)
            .unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("# comment line"));
        assert!(contents.contains("mymap"));
        assert!(contents.contains("alice"));
        assert!(contents.contains("alice_db"));
    }

    #[test]
    fn patch_ident_removes_entry_when_requested() {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("pg_ident.conf");
        let out_path = dir.path().join("pg_ident.out.conf");
        std::fs::write(&in_path, "mymap alice alice_db\n").unwrap();

        ServerConfig::patch_ident(&in_path, &out_path, "mymap", "alice", "alice_db", false)
            .unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(!contents.contains("alice_db"));
    }

    #[test]
    fn ident_line_needs_double_quotes_for_non_alphanumeric() {
        let line = IdentLine::new("map", "user-name", "role");
        assert!(line.system_name_is_quoted);
        assert!(!line.role_name_is_quoted);
    }
}
