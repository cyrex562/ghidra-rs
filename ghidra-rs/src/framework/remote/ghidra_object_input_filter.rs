/// Default limit on the number of elements in a deserialized array, mirroring
/// `GhidraObjectInputFilter.MAXARRAY_DEFAULT`.
pub const MAXARRAY_DEFAULT: i64 = 200_000;
/// Default limit on the number of object references in a single deserialization stream, mirroring
/// `GhidraObjectInputFilter.MAXREFS_DEFAULT`.
pub const MAXREFS_DEFAULT: i64 = 10_000;
/// Default limit on object graph depth, mirroring `GhidraObjectInputFilter.MAXDEPTH_DEFAULT`.
pub const MAXDEPTH_DEFAULT: i64 = 50;
/// Default limit on the number of bytes consumed from the input stream, mirroring
/// `GhidraObjectInputFilter.MAXBYTES_DEFAULT` (32MB).
pub const MAXBYTES_DEFAULT: i64 = 32 * 1024 * 1024;

const MAXARRAY: &str = "maxarray";
const MAXREFS: &str = "maxrefs";
const MAXDEPTH: &str = "maxdepth";
const MAXBYTES: &str = "maxbytes";
const REMOTE_INTERFACE: &str = "remoteIf";

/// Path (relative to an application installation) of the documentation referenced by rejection
/// messages, mirroring `GhidraObjectInputFilter.README_PATH`.
pub const README_PATH: &str = "Ghidra/Framework/FileSystem/data/serialFilterREADME.md";

/// Outcome of a single serialization-filter decision, mirroring `java.io.ObjectInputFilter.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterStatus {
    /// The class is allowed to be deserialized.
    Allowed,
    /// The class is rejected and deserialization will throw an exception.
    Rejected,
    /// The class is neither allowed nor rejected by this filter; later filters (or the JVM's own
    /// checks) decide.
    Undecided,
}

/// Snapshot of information about a candidate object graph node being filtered, mirroring
/// `java.io.ObjectInputFilter.FilterInfo`.
///
/// Java's `FilterInfo.serialClass()` returns a reflective `Class<?>`; Rust has no equivalent, so
/// this carries the fully-qualified class name instead (`None` matches `serialClass()`'s
/// documented `null` case for non-class stream elements). The `Class<?>` queries
/// `checkInput`'s default implementation performs on that class (`isArray()`,
/// `getComponentType().isPrimitive()`, `getPackageName()`, `Proxy.isProxyClass()`,
/// `getInterfaces()`) are likewise precomputed into plain fields rather than derived from a live
/// class object.
#[derive(Debug, Clone, Default)]
pub struct FilterInfo {
    /// Fully-qualified name of the class being deserialized, or `None` for non-class stream
    /// elements (e.g. primitive values), mirroring `FilterInfo.serialClass()`.
    pub serial_class_name: Option<String>,
    /// Whether `serial_class_name` names an array type, mirroring `Class.isArray()`.
    pub is_array: bool,
    /// Whether an array class's component type is a primitive, mirroring
    /// `Class.getComponentType().isPrimitive()`.
    pub component_type_is_primitive: bool,
    /// Whether `serial_class_name` names a dynamic proxy class, mirroring
    /// `Proxy.isProxyClass(Class)`.
    pub is_proxy_class: bool,
    /// The package name of `serial_class_name`, mirroring `Class.getPackageName()`.
    pub package_name: String,
    /// The names of the interfaces implemented by a proxy class, mirroring
    /// `Class.getInterfaces()`.
    pub interface_names: Vec<String>,
    /// The array length if `serial_class_name` names an array type, mirroring
    /// `FilterInfo.arrayLength()`.
    pub array_length: i64,
    /// Current depth of the object graph, mirroring `FilterInfo.depth()`.
    pub depth: i64,
    /// Number of object references already read from the stream, mirroring
    /// `FilterInfo.references()`.
    pub references: i64,
    /// Number of bytes already read from the stream, mirroring `FilterInfo.streamBytes()`.
    pub stream_bytes: i64,
}

/// Provides the global serial input filter for use with the Ghidra server and client
/// applications.
///
/// Mirrors `ghidra.framework.remote.GhidraObjectInputFilter`, which `implements
/// java.io.ObjectInputFilter`. This filter primarily targets RMI deserialization, however as a
/// global filter it impacts all deserialization cases which may need to be considered when
/// specifying filters.
///
/// This type was flagged as a package-cycle cut-point, so it is ported to an object-safe trait:
/// callers depend on `Box<dyn GhidraObjectInputFilter>`/`Arc<dyn GhidraObjectInputFilter>` rather
/// than a single concrete implementation. [`check_input`](Self::check_input) reproduces
/// `checkInput(FilterInfo)`'s full decision logic as a default method over a handful of abstract
/// accessors, so a conforming implementation only needs to supply its configured limits, its
/// allow-listed remote interfaces, and a delegate pattern filter.
///
/// The Java class's `TRACKER_ENABLED` class-deserialization tracking (gated by a hardcoded
/// `false` constant documented "must be set to 'false' when committed to source control") is
/// omitted: it is unreachable in normal operation and reproducing it would require file/shutdown
/// -hook side effects and `Class.getModule()` reflection with no Rust equivalent.
///
/// The static factory installers `configureServerSerialFilter`/`configureClientSerialFilter`
/// (which build a filter from `*.serial.filter` files and install it as the process-wide
/// deserialization filter via `GhidraSerialFilterFactory`/
/// `ObjectInputFilter.Config.setSerialFilterFactory`) are also omitted from the trait: like
/// `Application`'s `initializeApplication`, they establish process-wide singleton state rather
/// than querying an already-configured instance, so they don't fit an object-safe accessor trait.
/// The filter-file text parsing they perform (`readFilterEntries`/`consumeSpecialValue`/
/// `parseLong`) is pure text-processing logic independent of that singleton wiring, and is
/// reproduced as the free function [`parse_serial_filter_text`] so implementations can still
/// build their configuration from `*.serial.filter` file contents.
pub trait GhidraObjectInputFilter {
    /// Maximum number of elements permitted in a deserialized array.
    fn max_array(&self) -> i64;
    /// Maximum number of object references permitted in a single deserialization stream.
    fn max_refs(&self) -> i64;
    /// Maximum object graph depth permitted.
    fn max_depth(&self) -> i64;
    /// Maximum number of bytes permitted to be consumed from the input stream.
    fn max_bytes(&self) -> i64;

    /// Returns whether `interface_name` is an allow-listed RMI `Remote` interface for dynamic
    /// proxy classes, mirroring `allowedRemoteInterfaces.contains(iface)`.
    fn is_allowed_remote_interface(&self, interface_name: &str) -> bool;

    /// Returns whether the delegate pattern filter has been initialized, mirroring the `null`
    /// check on `patternFilterRef.get()`. `check_input` returns
    /// [`FilterStatus::Undecided`](FilterStatus::Undecided) unconditionally while this is `false`,
    /// to facilitate lazy initialization (documented in the Java source as required to
    /// accommodate Gradle testing frameworks' use of serialization before this filter has been
    /// configured).
    fn pattern_filter_initialized(&self) -> bool;

    /// Delegates to the configured pattern filter (built from `*.serial.filter` file syntax),
    /// mirroring `patternFilter.checkInput(info)`. Only called once
    /// [`pattern_filter_initialized`](Self::pattern_filter_initialized) returns `true`.
    fn pattern_filter_check(&self, info: &FilterInfo) -> FilterStatus;

    /// Gets the class serialization source, mirroring `GhidraObjectInputFilter.getSourceName()`.
    /// Returns `None` by default, matching the Java method's behavior when no source-name
    /// supplier has been set.
    fn source_name(&self) -> Option<String> {
        None
    }

    /// Called whenever a rejection message has been built for a class serialization, mirroring
    /// the `log().error(...)` call inside `serialReject`. No-op by default; implementations may
    /// override to route the message to their own logger.
    fn log_rejection(&self, _message: &str) {}

    /// Builds the rejection message for a class serialization, mirroring the `StringBuilder`
    /// construction inside `GhidraObjectInputFilter.serialReject(FilterInfo, String)`.
    fn rejection_message(&self, info: &FilterInfo, reason: &str) -> String {
        let mut message = String::from("Rejected class serialization");
        if let Some(source) = self.source_name() {
            message.push_str(" from ");
            message.push_str(&source);
        }
        message.push('(');
        message.push_str(reason);
        message.push(')');

        if let Some(class_name) = &info.serial_class_name {
            message.push_str(": ");
            message.push_str(class_name);
            message.push(' ');
            if info.is_array {
                message.push_str(&format!("(array-length={})", info.array_length));
            }
        }

        message.push_str(&format!(" (see {README_PATH})"));
        message
    }

    /// Logs and returns a rejection, mirroring `GhidraObjectInputFilter.serialReject(FilterInfo,
    /// String)`.
    fn reject(&self, info: &FilterInfo, reason: &str) -> FilterStatus {
        self.log_rejection(&self.rejection_message(info, reason));
        FilterStatus::Rejected
    }

    /// Determines whether the given candidate object graph node should be allowed, rejected, or
    /// left undecided, mirroring `GhidraObjectInputFilter.checkInput(FilterInfo)`.
    fn check_input(&self, info: &FilterInfo) -> FilterStatus {
        if !self.pattern_filter_initialized() {
            // Uninitialized filter state.
            // NOTE: This mode is required to facilitate lazy initialization due to
            // Gradle testing frameworks use of serialization.
            return FilterStatus::Undecided;
        }

        if info.references > self.max_refs() {
            return self.reject(info, &format!("maxrefs exceeded: {}", info.references));
        }

        if info.depth > self.max_depth() {
            return self.reject(info, &format!("maxdepth exceeded: {}", info.depth));
        }

        if info.stream_bytes > self.max_bytes() {
            return self.reject(info, &format!("maxbytes exceeded: {}", info.stream_bytes));
        }

        let has_class = info.serial_class_name.is_some();
        if has_class {
            // Allow all primitive arrays
            if info.is_array {
                if info.array_length > self.max_array() {
                    return self.reject(info, &format!("maxarray exceeded: {}", info.array_length));
                }
                if info.component_type_is_primitive {
                    return FilterStatus::Allowed; // allow all primitive arrays
                }
            }
            // Check for allowed RMI Remote Proxies
            else if info.package_name.starts_with("jdk.proxy") && info.is_proxy_class {
                for iface in &info.interface_names {
                    if self.is_allowed_remote_interface(iface) {
                        return FilterStatus::Allowed;
                    }
                }
                return self.reject(info, "unknown proxy");
            }
        }

        // Give serial filter patterns first shot
        let status = self.pattern_filter_check(info);
        if status == FilterStatus::Allowed {
            return status;
        }

        if !has_class {
            return FilterStatus::Undecided;
        }

        self.reject(info, "not allowed")
    }
}

/// Result of parsing `*.serial.filter` file text, mirroring the accumulated state
/// `GhidraObjectInputFilter.initializeFilter`/`readSerialFilterFiles`/`readFilterEntries`/
/// `consumeSpecialValue` build up from one or more filter files before a
/// [`GhidraObjectInputFilter`] is configured.
#[derive(Debug, Clone, Default)]
pub struct ParsedSerialFilter {
    /// The accumulated, deduplicated filter pattern text (each entry newline-free and
    /// semicolon-terminated), suitable for a `java.io.ObjectInputFilter.Config#createFilter`
    /// -equivalent parser, mirroring `readSerialFilterFiles`'s joined `LinkedHashSet<String>`
    /// (plus any default limit entries appended by `initializeFilter`).
    pub pattern_text: String,
    /// Maximum number of elements permitted in a deserialized array.
    pub max_array: i64,
    /// Maximum number of object references permitted in a single deserialization stream.
    pub max_refs: i64,
    /// Maximum object graph depth permitted.
    pub max_depth: i64,
    /// Maximum number of bytes permitted to be consumed from the input stream.
    pub max_bytes: i64,
    /// RMI `Remote` interface names allow-listed for dynamic proxy classes, mirroring
    /// `allowedRemoteInterfaces` (accumulated from `remoteIf=<classname>;` entries). Unlike the
    /// Java original, the named class is not validated to actually implement `Remote`
    /// (`Class.forName`/`Remote.class.isAssignableFrom` have no Rust equivalent); callers are
    /// expected to validate against their own known remote interface set if needed.
    pub allowed_remote_interfaces: Vec<String>,
}

/// Parses one or more concatenated `*.serial.filter` files' text into a [`ParsedSerialFilter`],
/// mirroring `GhidraObjectInputFilter.readFilterEntries(InputStream, Set)` and
/// `consumeSpecialValue(String)`, plus the default-limit backfill `initializeFilter` performs
/// once all files have been read.
///
/// Each non-comment, non-blank line must end with `;`; the `!` class-rejection prefix is
/// unsupported (matching the Java restrictions). `remoteIf=<name>;` entries are extracted into
/// [`ParsedSerialFilter::allowed_remote_interfaces`] rather than kept in the pattern text.
/// `maxarray=`/`maxrefs=`/`maxdepth=`/`maxbytes=` entries update the corresponding limit (taking
/// the maximum across every such entry seen, ignoring entries below that limit's compiled-in
/// default) while also remaining in the pattern text, matching `consumeSpecialValue`'s `return
/// false; // include in filter`.
pub fn parse_serial_filter_text(text: &str) -> Result<ParsedSerialFilter, String> {
    let mut pattern_entries: Vec<String> = Vec::new();
    let mut max_array = 0i64;
    let mut max_refs = 0i64;
    let mut max_depth = 0i64;
    let mut max_bytes = 0i64;
    let mut allowed_remote_interfaces = Vec::new();

    for raw_line in text.lines() {
        let mut line = raw_line;
        if let Some(hash_ix) = line.find('#') {
            line = &line[..hash_ix];
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.ends_with(';') {
            return Err("All filter statements must end with `;`".to_string());
        }
        if line.starts_with('!') {
            return Err("The class rejection prefix '!' is not supported".to_string());
        }

        if let Some(eq_ix) = line.find('=') {
            if eq_ix > 0 {
                let name = &line[..eq_ix];
                let value_str = &line[eq_ix + 1..line.len() - 1];
                match name {
                    REMOTE_INTERFACE => {
                        allowed_remote_interfaces.push(value_str.to_string());
                        continue;
                    }
                    MAXARRAY => {
                        if let Some(v) = parse_limit(name, value_str, MAXARRAY_DEFAULT)? {
                            max_array = max_array.max(v);
                        }
                    }
                    MAXREFS => {
                        if let Some(v) = parse_limit(name, value_str, MAXREFS_DEFAULT)? {
                            max_refs = max_refs.max(v);
                        }
                    }
                    MAXDEPTH => {
                        if let Some(v) = parse_limit(name, value_str, MAXDEPTH_DEFAULT)? {
                            max_depth = max_depth.max(v);
                        }
                    }
                    MAXBYTES => {
                        if let Some(v) = parse_limit(name, value_str, MAXBYTES_DEFAULT)? {
                            max_bytes = max_bytes.max(v);
                        }
                    }
                    _ => {}
                }
            }
        }

        let entry = line.to_string();
        if !pattern_entries.contains(&entry) {
            pattern_entries.push(entry);
        }
    }

    if max_array <= 0 {
        max_array = MAXARRAY_DEFAULT;
        pattern_entries.push(format!("{MAXARRAY}={MAXARRAY_DEFAULT};"));
    }
    if max_refs <= 0 {
        max_refs = MAXREFS_DEFAULT;
        pattern_entries.push(format!("{MAXREFS}={MAXREFS_DEFAULT};"));
    }
    if max_depth <= 0 {
        max_depth = MAXDEPTH_DEFAULT;
        pattern_entries.push(format!("{MAXDEPTH}={MAXDEPTH_DEFAULT};"));
    }
    if max_bytes <= 0 {
        max_bytes = MAXBYTES_DEFAULT;
        pattern_entries.push(format!("{MAXBYTES}={MAXBYTES_DEFAULT};"));
    }

    Ok(ParsedSerialFilter {
        pattern_text: pattern_entries.concat(),
        max_array,
        max_refs,
        max_depth,
        max_bytes,
        allowed_remote_interfaces,
    })
}

/// Validates and (if above `default_min`) returns a filter limit value, mirroring
/// `GhidraObjectInputFilter.parseLong(String, String, long)`. Returns `Ok(None)` for values below
/// `default_min` (mirroring the Java method's "ignore entry" `-1` return, minus the
/// `log().warn(...)` call, which has no logger here).
fn parse_limit(name: &str, value_str: &str, default_min: i64) -> Result<Option<i64>, String> {
    let value: i64 = value_str
        .parse()
        .map_err(|_| format!("Invalid '{name}' filter value: {value_str}"))?;
    if value <= 0 {
        return Err(format!("Invalid '{name}' filter value: {value_str}"));
    }
    if value < default_min {
        return Ok(None);
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockFilter {
        allowed_remote_interfaces: Vec<String>,
        initialized: bool,
        pattern_status: FilterStatus,
        rejections: RefCell<Vec<String>>,
    }

    impl MockFilter {
        fn new() -> Self {
            Self {
                allowed_remote_interfaces: vec!["ghidra.framework.remote.RepositoryHandle".to_string()],
                initialized: true,
                pattern_status: FilterStatus::Undecided,
                rejections: RefCell::new(Vec::new()),
            }
        }
    }

    impl GhidraObjectInputFilter for MockFilter {
        fn max_array(&self) -> i64 {
            MAXARRAY_DEFAULT
        }
        fn max_refs(&self) -> i64 {
            MAXREFS_DEFAULT
        }
        fn max_depth(&self) -> i64 {
            MAXDEPTH_DEFAULT
        }
        fn max_bytes(&self) -> i64 {
            MAXBYTES_DEFAULT
        }
        fn is_allowed_remote_interface(&self, interface_name: &str) -> bool {
            self.allowed_remote_interfaces.iter().any(|i| i == interface_name)
        }
        fn pattern_filter_initialized(&self) -> bool {
            self.initialized
        }
        fn pattern_filter_check(&self, _info: &FilterInfo) -> FilterStatus {
            self.pattern_status
        }
        fn log_rejection(&self, message: &str) {
            self.rejections.borrow_mut().push(message.to_string());
        }
    }

    fn plain_class_info(name: &str) -> FilterInfo {
        FilterInfo {
            serial_class_name: Some(name.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn uninitialized_filter_is_undecided() {
        let mut filter = MockFilter::new();
        filter.initialized = false;
        let status = filter.check_input(&plain_class_info("java.lang.String"));
        assert_eq!(status, FilterStatus::Undecided);
    }

    #[test]
    fn exceeding_max_refs_is_rejected() {
        let filter = MockFilter::new();
        let info = FilterInfo { references: MAXREFS_DEFAULT + 1, ..plain_class_info("java.lang.String") };
        assert_eq!(filter.check_input(&info), FilterStatus::Rejected);
        assert!(filter.rejections.borrow()[0].contains("maxrefs exceeded"));
    }

    #[test]
    fn exceeding_max_depth_is_rejected() {
        let filter = MockFilter::new();
        let info = FilterInfo { depth: MAXDEPTH_DEFAULT + 1, ..plain_class_info("java.lang.String") };
        assert_eq!(filter.check_input(&info), FilterStatus::Rejected);
    }

    #[test]
    fn exceeding_max_bytes_is_rejected() {
        let filter = MockFilter::new();
        let info = FilterInfo { stream_bytes: MAXBYTES_DEFAULT + 1, ..plain_class_info("java.lang.String") };
        assert_eq!(filter.check_input(&info), FilterStatus::Rejected);
    }

    #[test]
    fn primitive_array_within_limit_is_allowed() {
        let filter = MockFilter::new();
        let info = FilterInfo {
            is_array: true,
            component_type_is_primitive: true,
            array_length: 10,
            ..plain_class_info("[B")
        };
        assert_eq!(filter.check_input(&info), FilterStatus::Allowed);
    }

    #[test]
    fn array_exceeding_max_array_is_rejected() {
        let filter = MockFilter::new();
        let info = FilterInfo {
            is_array: true,
            component_type_is_primitive: true,
            array_length: MAXARRAY_DEFAULT + 1,
            ..plain_class_info("[B")
        };
        assert_eq!(filter.check_input(&info), FilterStatus::Rejected);
        assert!(filter.rejections.borrow()[0].contains("maxarray exceeded"));
    }

    #[test]
    fn non_primitive_array_defers_to_pattern_filter() {
        let mut filter = MockFilter::new();
        filter.pattern_status = FilterStatus::Allowed;
        let info = FilterInfo {
            is_array: true,
            component_type_is_primitive: false,
            array_length: 3,
            ..plain_class_info("[Ljava.lang.String;")
        };
        assert_eq!(filter.check_input(&info), FilterStatus::Allowed);
    }

    #[test]
    fn allowed_proxy_interface_is_allowed() {
        let filter = MockFilter::new();
        let info = FilterInfo {
            is_proxy_class: true,
            package_name: "jdk.proxy1".to_string(),
            interface_names: vec!["ghidra.framework.remote.RepositoryHandle".to_string()],
            ..plain_class_info("jdk.proxy1.$Proxy1")
        };
        assert_eq!(filter.check_input(&info), FilterStatus::Allowed);
    }

    #[test]
    fn unknown_proxy_interface_is_rejected() {
        let filter = MockFilter::new();
        let info = FilterInfo {
            is_proxy_class: true,
            package_name: "jdk.proxy1".to_string(),
            interface_names: vec!["some.other.Interface".to_string()],
            ..plain_class_info("jdk.proxy1.$Proxy1")
        };
        assert_eq!(filter.check_input(&info), FilterStatus::Rejected);
        assert!(filter.rejections.borrow()[0].contains("unknown proxy"));
    }

    #[test]
    fn pattern_filter_allow_wins() {
        let mut filter = MockFilter::new();
        filter.pattern_status = FilterStatus::Allowed;
        assert_eq!(filter.check_input(&plain_class_info("java.lang.String")), FilterStatus::Allowed);
    }

    #[test]
    fn pattern_filter_undecided_with_class_is_rejected() {
        let filter = MockFilter::new();
        assert_eq!(filter.check_input(&plain_class_info("java.lang.String")), FilterStatus::Rejected);
        assert!(filter.rejections.borrow()[0].contains("not allowed"));
    }

    #[test]
    fn pattern_filter_undecided_without_class_is_undecided() {
        let filter = MockFilter::new();
        let info = FilterInfo::default();
        assert_eq!(filter.check_input(&info), FilterStatus::Undecided);
    }

    #[test]
    fn rejection_message_includes_source_and_class_details() {
        struct WithSource(MockFilter);
        impl GhidraObjectInputFilter for WithSource {
            fn max_array(&self) -> i64 {
                self.0.max_array()
            }
            fn max_refs(&self) -> i64 {
                self.0.max_refs()
            }
            fn max_depth(&self) -> i64 {
                self.0.max_depth()
            }
            fn max_bytes(&self) -> i64 {
                self.0.max_bytes()
            }
            fn is_allowed_remote_interface(&self, interface_name: &str) -> bool {
                self.0.is_allowed_remote_interface(interface_name)
            }
            fn pattern_filter_initialized(&self) -> bool {
                self.0.pattern_filter_initialized()
            }
            fn pattern_filter_check(&self, info: &FilterInfo) -> FilterStatus {
                self.0.pattern_filter_check(info)
            }
            fn source_name(&self) -> Option<String> {
                Some("client-42".to_string())
            }
        }

        let filter = WithSource(MockFilter::new());
        let info = FilterInfo {
            is_array: true,
            array_length: 7,
            ..plain_class_info("evil.gadget.Chain")
        };
        let message = filter.rejection_message(&info, "not allowed");
        assert!(message.contains("from client-42"));
        assert!(message.contains("evil.gadget.Chain"));
        assert!(message.contains("array-length=7"));
        assert!(message.contains(README_PATH));
    }

    #[test]
    fn parse_rejects_rejection_prefix() {
        let err = parse_serial_filter_text("java.lang.*;\n!some.Bad;\n").unwrap_err();
        assert!(err.contains("rejection prefix"));
    }

    #[test]
    fn parse_extracts_remote_interfaces() {
        let parsed = parse_serial_filter_text(
            "java.lang.*;\nremoteIf=ghidra.framework.remote.RepositoryHandle;\n",
        )
        .unwrap();
        assert_eq!(
            parsed.allowed_remote_interfaces,
            vec!["ghidra.framework.remote.RepositoryHandle".to_string()]
        );
        assert!(parsed.pattern_text.contains("java.lang.*;"));
        assert!(!parsed.pattern_text.contains("remoteIf"));
    }

    #[test]
    fn parse_updates_limits_and_keeps_entry_in_pattern_text() {
        let parsed = parse_serial_filter_text("maxrefs=50000;\n").unwrap();
        assert_eq!(parsed.max_refs, 50_000);
        assert!(parsed.pattern_text.contains("maxrefs=50000;"));
    }

    #[test]
    fn parse_ignores_limit_below_default_minimum() {
        let parsed = parse_serial_filter_text("maxrefs=1;\n").unwrap();
        // Entry stays in the pattern text (still passed through to the real filter parser)...
        assert!(parsed.pattern_text.contains("maxrefs=1;"));
        // ...but the local threshold falls back to the compiled-in default since 1 < MAXREFS_DEFAULT,
        // which the backfill step then appends as its own pattern-text entry.
        assert_eq!(parsed.max_refs, MAXREFS_DEFAULT);
        assert!(parsed.pattern_text.contains(&format!("maxrefs={MAXREFS_DEFAULT};")));
    }

    #[test]
    fn parse_backfills_missing_limits_with_defaults() {
        let parsed = parse_serial_filter_text("java.lang.*;\n").unwrap();
        assert_eq!(parsed.max_array, MAXARRAY_DEFAULT);
        assert_eq!(parsed.max_refs, MAXREFS_DEFAULT);
        assert_eq!(parsed.max_depth, MAXDEPTH_DEFAULT);
        assert_eq!(parsed.max_bytes, MAXBYTES_DEFAULT);
        assert!(parsed.pattern_text.contains(&format!("{MAXARRAY_DEFAULT}")));
    }

    #[test]
    fn parse_deduplicates_repeated_entries() {
        let parsed = parse_serial_filter_text("java.lang.*;\njava.lang.*;\n").unwrap();
        assert_eq!(parsed.pattern_text.matches("java.lang.*;").count(), 1);
    }

    #[test]
    fn parse_rejects_missing_semicolon() {
        let err = parse_serial_filter_text("java.lang.*\n").unwrap_err();
        assert!(err.contains("must end with"));
    }

    #[test]
    fn parse_strips_comments_and_blank_lines() {
        let parsed = parse_serial_filter_text("# a comment\n\njava.lang.*; # trailing comment\n").unwrap();
        assert!(parsed.pattern_text.contains("java.lang.*;"));
    }

    #[test]
    fn parse_rejects_invalid_limit_value() {
        let err = parse_serial_filter_text("maxrefs=notanumber;\n").unwrap_err();
        assert!(err.contains("Invalid 'maxrefs'"));
    }
}
