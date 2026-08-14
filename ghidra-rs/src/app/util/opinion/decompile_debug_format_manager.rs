//! Port of `ghidra.app.util.opinion.DecompileDebugFormatManager`.
//!
//! Main manager for handling the coordination of the parsing of the XML and loading of the
//! program details into Ghidra.
//!
//! # Departures from the Java class
//!
//! * Java builds its own parser inside `getProgramInfo`/`read`
//!   (`XmlPullParserFactory.create(file, errorHandler, false)`). `XmlPullParserFactory` is not
//!   ported, and [`XmlPullParser`] exposes its element type as an associated type (so it cannot
//!   be a trait object), so both methods instead take the parser as a generic `&mut P`
//!   parameter. The [`file`](DecompileDebugFormatManager::file) field is still carried
//!   faithfully -- it is what the real factory call will be handed once it lands.
//! * As a consequence, [`MyErrorHandler`] -- Java's nested `ErrorHandler` implementation, which
//!   exists only to be passed to that factory -- is ported but not yet wired up by this type.
//! * Java's `XmlException` is an unchecked exception, so a structurally broken document escapes
//!   `read` as a runtime failure while a SAX/IO error is caught and re-thrown as
//!   `LoadException("File read error.")`. This port funnels both into the same `LoadException`
//!   (after logging), rather than panicking.
//! * `DecompileDebugXmlLoader.DecompileDebugProgramInfo` and the three sibling managers
//!   (`DecompileDebugDataTypeManager`, `DecompileDebugFunctionManager`,
//!   `DecompileDebugByteManager`) are not ported yet -- `DecompileDebugXmlLoader` is the forward
//!   half of a dependency cycle with this class -- so they come from
//!   [`crate::app::seam_stubs`] (see `STUBS.tsv`). The stubbed managers parse nothing; they only
//!   discard the subtree they are handed. Where Java would then hand a parsed `DataType` to
//!   `Listing.createData`, this port has no data type and skips the call, logging that it did.
//! * Java reads the peeked element unconditionally (`parser.peek().isStart()`), which throws at
//!   EOF; the loops here stop at EOF instead, via the [`peek_start`] helper.
//! * `CodeUnit.setComment` is reached through
//!   [`Listing::set_comment`](crate::program::model::listing::Listing::set_comment), since
//!   `getCodeUnitAt` hands back an `Arc<dyn CodeUnit>` that cannot be mutated through. The code
//!   unit is still looked up first, so an address with no code unit is a no-op here rather than
//!   Java's `NullPointerException`.
//! * `SymbolTable.createNameSpace` is reached through
//!   [`SymbolTable::get_or_create_name_space`](crate::program::model::symbol::SymbolTable::get_or_create_name_space),
//!   and `Symbol.setPrimary()` through
//!   [`SymbolTable::set_primary_symbol`](crate::program::model::symbol::SymbolTable::set_primary_symbol),
//!   which is how those operations are spelled in this crate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::app::seam_stubs::{
    DecompileDebugByteManager, DecompileDebugDataTypeManager, DecompileDebugFunctionManager,
    DecompileDebugProgramInfo, XmlMessageLog,
};
use crate::app::util::opinion::load_exception::LoadException;
use crate::app::util::xml::xml_error_handler::XmlParseException as SaxParseException;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::{CommentType, Program};
use crate::program::model::pcode::address_xml::{self, AddressXml};
use crate::program::model::pcode::ids::{
    ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_TYPE, ATTRIB_VAL,
};
use crate::program::model::symbol::{DefaultSymbolUtilities, Namespace, SourceType, SymbolUtilities};
use crate::util::task::TaskMonitor;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// The `readonly` attribute of a `<symbol>` element. `ghidra.program.model.pcode.AttributeId`'s
/// `ATTRIB_READONLY` has no counterpart in [`crate::program::model::pcode::ids`] yet, so the
/// name is spelled out here.
const ATTRIB_READONLY_NAME: &str = "readonly";

/// Returns the element at the front of `parser` when there is one and it is a start element.
///
/// Java writes `parser.peek().isStart()`, which throws at EOF; every loop that uses it relies on
/// the document being well-formed enough that an end element always follows.
fn peek_start<P: XmlPullParser>(parser: &P) -> Option<P::Element> {
    if !parser.has_next() {
        return None;
    }
    let element = parser.peek();
    if element.is_start() {
        Some(element)
    } else {
        None
    }
}

/// Returns the element at the front of `parser` when there is one and it is a start element
/// named `name`. Port of the `parser.peek().isStart(name)` idiom.
fn peek_start_named<P: XmlPullParser>(parser: &P, name: &str) -> Option<P::Element> {
    peek_start(parser).filter(|element| element.get_name() == name)
}

/// Decodes a hex string the way `HexFormat.of().parseHex(String)` does: two hex digits per byte,
/// rejecting an odd length or any non-hex digit.
fn parse_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd length hex string of length {}", hex.len()));
    }
    let digits = hex.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("not a hexadecimal digit: {}", pair[0] as char))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("not a hexadecimal digit: {}", pair[1] as char))?;
        bytes.push(((hi << 4) | lo) as u8);
    }
    Ok(bytes)
}

/// Main manager for handling the coordination of the parsing of the XML and loading of the
/// program details into Ghidra.
pub struct DecompileDebugFormatManager {
    /// The generated XML Decompile Debug file. `None` stands in for Java's `null` `File`, which
    /// [`from_byte_provider`](Self::from_byte_provider) can produce.
    file: Option<PathBuf>,
    prog_info: Option<DecompileDebugProgramInfo>,
    scope_map: BTreeMap<i64, Arc<dyn Namespace>>,
}

impl DecompileDebugFormatManager {
    /// Constructs a new program Decompiler Debug XML manager using the provided file. The file
    /// should be an XML file generated by the Ghidra Decompiler as a debug file.
    ///
    /// Port of `DecompileDebugFormatManager(File)`.
    pub fn new(file: impl Into<PathBuf>) -> Self {
        DecompileDebugFormatManager {
            file: Some(file.into()),
            prog_info: None,
            scope_map: BTreeMap::new(),
        }
    }

    /// Constructs a new program Decompiler Debug XML manager using the provided
    /// [`ByteProvider`].
    ///
    /// If the provider has an [`Fsrl`](crate::filesystem::gfilesystem::fsrl::Fsrl) and it is a
    /// simple local filepath, convert that to a normal local file path instead of using the
    /// provider's file property, which is probably located in the
    /// [`FileSystemService`](crate::filesystem::gfilesystem::file_system_service::FileSystemService)
    /// filecache directory -- which would break the ability to find the `*.bytes` file
    /// associated with this `.xml` file.
    ///
    /// Port of `DecompileDebugFormatManager(ByteProvider)`.
    pub fn from_byte_provider(provider: &dyn ByteProvider) -> Self {
        let file = match provider.get_fsrl() {
            Some(fsrl) if fsrl.nesting_depth() == 1 => fsrl.path().map(PathBuf::from),
            _ => provider.get_file(),
        };
        DecompileDebugFormatManager { file, prog_info: None, scope_map: BTreeMap::new() }
    }

    /// The generated XML Decompile Debug file this manager reads.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// The binary image / load spec details recovered by the most recent
    /// [`get_program_info`](Self::get_program_info) call, mirroring the Java `progInfo` field.
    pub fn program_info(&self) -> Option<&DecompileDebugProgramInfo> {
        self.prog_info.as_ref()
    }

    /// Initial parsing of the XML file to obtain the binary image info with load specs.
    ///
    /// Port of `getProgramInfo()`. See the module docs for why the parser is passed in.
    ///
    /// # Errors
    /// Returns a [`LoadException`] if the `<binaryimage>` element's `arch` attribute is missing
    /// or carries no `:` separator; Java fails the same input with a
    /// `StringIndexOutOfBoundsException` out of `String.substring`.
    pub fn get_program_info<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<DecompileDebugProgramInfo, LoadException> {
        let mut load_spec_string = String::new();
        let mut offset = String::new();

        while parser.has_next() {
            let element = parser.next();
            if element.is_start_with("binaryimage") {
                load_spec_string = element.get_attribute("arch").unwrap_or_default();
            } else if element.is_start_with("bytechunk") {
                offset = element.get_attribute(ATTRIB_OFFSET.name).unwrap_or_default();
                break;
            }
        }

        let (spec_string, compiler_string) = load_spec_string.rsplit_once(':').ok_or_else(|| {
            LoadException::new(format!(
                "binaryimage arch attribute is not a language:compiler pair: \"{}\"",
                load_spec_string
            ))
        })?;

        let prog_info = DecompileDebugProgramInfo::new(&offset, compiler_string, spec_string);
        self.prog_info = Some(prog_info.clone());
        parser.dispose();
        Ok(prog_info)
    }

    /// Perform the parsing from the underlying decompile debug XML file and populate the program
    /// fields. See `DecompileDebug.java` for reference on the generation of the XML file.
    ///
    /// Tags currently supported/expected: `<binaryimage>`, `<coretypes>`, `<typegrp>`,
    /// `<save_state>`, `<db>`, `<commentdb>`, `<stringmanage>`.
    ///
    /// NOTE: the `<optionslist>` subtree tag is not yet supported.
    ///
    /// Port of `read(Program, TaskMonitor, String)`.
    ///
    /// # Errors
    /// Returns a [`LoadException`] if there is a parsing issue with the XML file.
    pub fn read<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        prog: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        program_name: &str,
    ) -> Result<XmlMessageLog, LoadException> {
        let mut log = XmlMessageLog::new();
        self.scope_map = BTreeMap::new();
        if let Some(global_namespace) = prog.get_global_namespace() {
            self.scope_map.insert(0, global_namespace);
        }
        let transaction_id = prog.start_transaction("Loading");

        let result = self.read_subtrees(parser, prog, monitor, program_name, &mut log);

        monitor.set_message("Finished import");
        log.append_msg("Finished import");
        prog.end_transaction(transaction_id, true);
        parser.dispose();

        match result {
            Ok(()) => Ok(log),
            Err(e) => {
                log.append_exception(&e);
                Err(LoadException::new("File read error."))
            }
        }
    }

    /// The body of [`read`](Self::read), split out so that its callers' "finally" block (end the
    /// transaction, dispose the parser) runs on both paths.
    fn read_subtrees<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        prog: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        program_name: &str,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        monitor.set_message("Beginning Load");
        log.append_msg("Beginning Load");
        let start_savefile_element = parser.start(&["xml_savefile"])?;
        let mut save_state_element = None;
        let mut data_type_manager = DecompileDebugDataTypeManager::new(monitor, prog);

        while peek_start(parser).is_some() && !monitor.is_cancelled() {
            let name = parser.peek().get_name().to_string();
            match name.as_str() {
                "binaryimage" => {
                    let element = parser.start(&["binaryimage"])?;
                    Self::handle_binary_image_elements(parser, monitor, prog, program_name, log);
                    parser.end_matching(&element)?;
                }

                "coretypes" => {
                    monitor.set_message("Processing Core Data Types");
                    let element = parser.start(&["coretypes"])?;
                    Self::parse_data_types(parser, monitor, &mut data_type_manager, log);
                    parser.end_matching(&element)?;
                }

                "typegrp" => {
                    monitor.set_message("Processing Composite Data Types");
                    let element = parser.start(&["typegrp"])?;
                    Self::parse_data_types(parser, monitor, &mut data_type_manager, log);
                    parser.end_matching(&element)?;
                }

                // wrapper tag holding all the program details aside from the
                // binaryimage/memory
                "save_state" => {
                    save_state_element = Some(parser.start(&["save_state"])?);
                }

                "db" => {
                    let element = parser.start(&["db"])?;
                    self.handle_db_elements(
                        parser,
                        monitor,
                        prog,
                        &mut data_type_manager,
                        program_name,
                        log,
                    )?;
                    parser.end_matching(&element)?;
                }

                "commentdb" => {
                    let element = parser.start(&["commentdb"])?;
                    Self::parse_comments(parser, monitor, prog, log)?;
                    parser.end_matching(&element)?;
                }

                "stringmanage" => {
                    let element = parser.start(&["stringmanage"])?;
                    Self::parse_strings(parser, monitor, prog, log)?;
                    parser.end_matching(&element)?;
                }

                "context_points" => {
                    let element = parser.start(&["context_points"])?;
                    Self::parse_context_points(parser, monitor, prog, log)?;
                    parser.end_matching(&element)?;
                }

                _ => {
                    log.append_msg_at_line(
                        parser.get_line_number(),
                        format!(
                            "Level {} tag not currently supported: {}",
                            parser.get_current_level(),
                            name
                        ),
                    );
                    parser.discard_sub_tree_named(&name)?;
                }
            }
        }

        if let Some(save_state_element) = save_state_element {
            parser.end_matching(&save_state_element)?;
        }
        parser.end_matching(&start_savefile_element)?;
        Ok(())
    }

    /// Parse elements in the `<db>` subtree. The only element currently handled is `<scope>`.
    ///
    /// Port of `handleDBElements`.
    fn handle_db_elements<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        data_type_manager: &mut DecompileDebugDataTypeManager,
        program_name: &str,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        while peek_start(parser).is_some() && !monitor.is_cancelled() {
            if parser.peek().get_name() == "scope" {
                let scope_element = parser.start(&["scope"])?;
                let scope_id =
                    spec_xml_utils::decode_long(scope_element.get_attribute(ATTRIB_ID.name).as_deref());
                let namespace_name =
                    scope_element.get_attribute(ATTRIB_NAME.name).unwrap_or_default();

                let mut parent_id = 0;
                if parser.has_next() && parser.peek().get_name() == "parent" {
                    let parent_element = parser.start(&["parent"])?;
                    parent_id = spec_xml_utils::decode_long(
                        parent_element.get_attribute(ATTRIB_ID.name).as_deref(),
                    );
                    parser.end_matching(&parent_element)?;
                }

                // scopeMap is initialized with the global namespace, the first <scope> tag will
                // be the global one if it doesn't have a parent tag
                let mut namespace = self.scope_map.get(&scope_id).cloned();

                if namespace.is_none() {
                    let parent_namespace = self.scope_map.get(&parent_id).cloned();
                    if let (Some(parent_namespace), Some(symbol_table)) =
                        (parent_namespace, prog.get_symbol_table())
                    {
                        match symbol_table.get_or_create_name_space(
                            parent_namespace,
                            &namespace_name,
                            SourceType::Imported,
                        ) {
                            Ok(created) => {
                                namespace = Some(created.clone());
                                self.scope_map.insert(scope_id, created);
                            }
                            Err(e) => log.append_exception(&e),
                        }
                    }
                }

                Self::handle_scope_subtree(
                    &self.scope_map,
                    namespace,
                    parser,
                    monitor,
                    prog,
                    data_type_manager,
                    program_name,
                    log,
                )?;
                parser.end_matching(&scope_element)?;
            } else {
                log.append_msg_at_line(
                    parser.get_line_number(),
                    format!(
                        "Level {} tag not currently supported: {}",
                        parser.get_current_level(),
                        parser.peek().get_name()
                    ),
                );
                parser.discard_sub_tree();
            }
        }

        Ok(())
    }

    /// Parse element subtrees within the scope tag.
    ///
    /// NOTE: the scope tag must be parsed prior to a call to this method, with the resulting
    /// namespace passed as `namespace` (`None` where Java would pass a `null` namespace, i.e.
    /// where namespace creation failed).
    ///
    /// NOTE: it is expected that the wrapper `<symbollist>` tag is being used around the
    /// collection of `<mapsym>` tags.
    ///
    /// Port of `handleScopeSubtree`.
    #[allow(clippy::too_many_arguments)]
    fn handle_scope_subtree<P: XmlPullParser>(
        scope_map: &BTreeMap<i64, Arc<dyn Namespace>>,
        namespace: Option<Arc<dyn Namespace>>,
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        data_type_manager: &mut DecompileDebugDataTypeManager,
        program_name: &str,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        let mut symbollist_element = None;
        let mut function_manager =
            DecompileDebugFunctionManager::new(prog, monitor, data_type_manager);

        while peek_start(parser).is_some() && !monitor.is_cancelled() {
            let name = parser.peek().get_name().to_string();
            match name.as_str() {
                // this is a wrapper tag for <mapsym> tags
                "symbollist" => {
                    symbollist_element = Some(parser.start(&["symbollist"])?);
                }
                "mapsym" => {
                    let mapsym_type_element = parser.start(&["mapsym"])?;
                    monitor.set_message("Processing Symbols");
                    let symbol_type = parser.peek().get_name().to_string();
                    if symbol_type == "function" {
                        function_manager.parse_function_signature(parser, scope_map, log);
                        // any extra tags after the function tag before mapsym can be thrown
                        // away for now
                        while peek_start(parser).is_some() {
                            log.append_msg_at_line(
                                parser.get_line_number(),
                                format!(
                                    "Level {} tag not currently supported: {}",
                                    parser.get_current_level(),
                                    name
                                ),
                            );
                            parser.discard_sub_tree();
                        }
                    } else if symbol_type == "labelsym" {
                        Self::parse_label_symbol(prog, parser, log)?;
                    } else if symbol_type == "symbol" {
                        Self::parse_symbol(
                            prog,
                            parser,
                            data_type_manager,
                            namespace.clone(),
                            program_name,
                            monitor,
                            log,
                        )?;
                    }
                    parser.end_matching(&mapsym_type_element)?;
                }
                _ => {
                    log.append_msg_at_line(
                        parser.get_line_number(),
                        format!(
                            "Level {} tag not currently supported: {}",
                            parser.get_current_level(),
                            name
                        ),
                    );
                    parser.discard_sub_tree();
                }
            }
        }
        if let Some(symbollist_element) = symbollist_element {
            parser.end_matching(&symbollist_element)?;
        }
        Ok(())
    }

    /// Handle the `<binaryimage>` tag and subtree, which includes the `<bytechunk>` tag(s).
    ///
    /// Port of `handleBinaryImageElements`.
    fn handle_binary_image_elements<P: XmlPullParser>(
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        program_name: &str,
        log: &mut XmlMessageLog,
    ) {
        monitor.set_message("Processing binary image");
        while peek_start(parser).is_some() && !monitor.is_cancelled() {
            if parser.peek().get_name() == "bytechunk" {
                monitor.set_message("Processing Byte Chunk(s)");
                let mut byte_mngr = DecompileDebugByteManager::new(monitor, prog, program_name);
                byte_mngr.parse(parser, log);
            } else {
                log.append_msg_at_line(
                    parser.get_line_number(),
                    format!(
                        "Level {} tag not currently supported: {}",
                        parser.get_current_level(),
                        parser.peek().get_name()
                    ),
                );
                parser.discard_sub_tree();
            }
        }
    }

    /// Handle generation of labels from the `<labelsym>` tag.
    ///
    /// Port of `parseLabelSymbol`.
    fn parse_label_symbol<P: XmlPullParser>(
        prog: &mut dyn Program,
        parser: &mut P,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        let symbol_element = parser.start(&["labelsym"])?;
        let symbol_name = symbol_element.get_attribute(ATTRIB_NAME.name).unwrap_or_default();
        parser.end_matching(&symbol_element)?;
        let addr_element = parser.start(&["addr"])?;

        let compiler_spec = prog.get_compiler_spec();
        let symbol_addr = compiler_spec
            .as_deref()
            .map(|cspec| address_xml::restore_xml(&addr_element, cspec));

        match symbol_addr {
            Some(Ok(xml_addr)) => {
                let symbol_addr = xml_addr.get_first_address();
                if let Some(symbol_table) = prog.get_symbol_table() {
                    match symbol_table.create_label(
                        &symbol_addr,
                        &symbol_name,
                        SourceType::Imported,
                    ) {
                        Ok(created_symbol) => {
                            if let Err(e) = symbol_table.set_primary_symbol(created_symbol.get_id())
                            {
                                log.append_exception(&e);
                            }
                        }
                        Err(e) => log.append_exception(&e),
                    }
                }

                parser.end_matching(&addr_element)?;
                while peek_start(parser).is_some() {
                    log.append_msg_at_line(
                        parser.get_line_number(),
                        format!(
                            "Level {} tag not currently supported: {}",
                            parser.get_current_level(),
                            parser.peek().get_name()
                        ),
                    );
                    parser.discard_sub_tree();
                }
            }
            Some(Err(e)) => log.append_exception(&e),
            None => log.append_msg("No compiler spec available to restore the label address"),
        }

        Ok(())
    }

    /// Parse a `<symbol>` tag under the `<mapsym>` tag -- meaning it is outside of a function,
    /// so most likely these are data references.
    ///
    /// NOTE: we are currently not pulling the bytes for referenced functions or data; as a
    /// result we need to generate an initialized memory block for data references to avoid
    /// errors in the Listing pane.
    ///
    /// Port of `parseSymbol`. Java declares `throws LoadException`, but its body catches and
    /// logs every failure it can produce, so nothing here reports one either.
    #[allow(clippy::too_many_arguments)]
    fn parse_symbol<P: XmlPullParser>(
        prog: &mut dyn Program,
        parser: &mut P,
        data_type_manager: &mut DecompileDebugDataTypeManager,
        namespace: Option<Arc<dyn Namespace>>,
        program_name: &str,
        monitor: &dyn TaskMonitor,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        let symbol_element = parser.start(&["symbol"])?;
        let symbol_name = symbol_element.get_attribute(ATTRIB_NAME.name).unwrap_or_default();
        let data_type = data_type_manager.parse_data_type_tag(parser, log);
        // readOnly is only present if it's true
        let read_only = symbol_element.has_attribute(ATTRIB_READONLY_NAME);
        parser.end_matching(&symbol_element)?;
        let addr_element = parser.start(&["addr"])?;

        let compiler_spec = prog.get_compiler_spec();
        let xml_addr = compiler_spec
            .as_deref()
            .map(|cspec| address_xml::restore_xml(&addr_element, cspec));

        match xml_addr {
            Some(Ok(xml_addr)) => {
                let symbol_addr = xml_addr.get_first_address();
                let size = xml_addr.get_size();

                match DefaultSymbolUtilities.create_preferred_label_or_function_symbol(
                    prog,
                    &symbol_addr,
                    namespace,
                    &symbol_name,
                    SourceType::Imported,
                ) {
                    Ok(Some(created_symbol)) => {
                        if let Some(symbol_table) = prog.get_symbol_table() {
                            if let Err(e) = symbol_table.set_primary_symbol(created_symbol.get_id())
                            {
                                log.append_exception(&e);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => log.append_exception(&e),
                }

                Self::create_symbol_memory(
                    prog,
                    &symbol_addr,
                    size,
                    read_only,
                    program_name,
                    monitor,
                    log,
                );

                if let Some(data_type) = data_type {
                    let display_name = data_type.get_display_name();
                    if let Some(listing) = prog.get_listing() {
                        if let Err(e) =
                            listing.create_data_sized(symbol_addr.clone(), data_type, size as i32)
                        {
                            log.append_exception(&e);
                        }
                    } else {
                        log.append_msg(format!(
                            "No listing available to create data: {} at address: {}",
                            display_name, symbol_addr
                        ));
                    }
                } else {
                    log.append_msg(format!(
                        "No data type parsed for symbol: {} at address: {}",
                        symbol_name, symbol_addr
                    ));
                }
            }
            Some(Err(e)) => log.append_exception(&e),
            None => log.append_msg("No compiler spec available to restore the symbol address"),
        }

        parser.end_matching(&addr_element)?;
        // skip rangelist tag and any others not yet handled
        while peek_start(parser).is_some() {
            log.append_msg_at_line(
                parser.get_line_number(),
                format!(
                    "Level {} tag not currently supported: {}",
                    parser.get_current_level(),
                    parser.peek().get_name()
                ),
            );
            parser.discard_sub_tree();
        }

        Ok(())
    }

    /// Back a data symbol with a zero-filled block when its range is not already mapped, the
    /// memory half of [`parse_symbol`](Self::parse_symbol).
    fn create_symbol_memory(
        prog: &mut dyn Program,
        symbol_addr: &Address,
        size: i64,
        read_only: bool,
        program_name: &str,
        monitor: &dyn TaskMonitor,
        log: &mut XmlMessageLog,
    ) {
        let end = match symbol_addr.add_no_wrap(size - 1) {
            Ok(end) => end,
            Err(e) => {
                log.append_exception(&e);
                return;
            }
        };

        let Some(memory) = prog.get_memory_mut() else {
            log.append_msg(format!(
                "No writable memory available for data at address: {}",
                symbol_addr
            ));
            return;
        };

        // check to see if the data element would overlap existing blocks. Java asks
        // `memory.contains(symbolAddr, end)`, inherited from `AddressSetView`; this port's
        // `Memory` has no such supertrait, so containment is answered from the block at the
        // symbol's address (a range spanning two adjacent blocks therefore reads as not
        // contained, and the create below reports the conflict).
        if memory.get_block(symbol_addr).is_some_and(|block| block.contains(&end)) {
            return;
        }

        match memory.create_initialized_block(
            program_name,
            symbol_addr,
            size as u64,
            0,
            monitor,
            false,
        ) {
            Ok(_generated_block) => {
                // if readOnly is true, write should be false
                memory.set_block_write(symbol_addr, !read_only);
            }
            Err(e) => {
                log.append_msg(format!(
                    "Attempted to allocate overlapping memory block for data at address: {}",
                    symbol_addr
                ));
                log.append_exception(&e);
            }
        }
    }

    /// Handle parsing and loading of comments.
    ///
    /// Port of `parseComments`.
    fn parse_comments<P: XmlPullParser>(
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        while peek_start_named(parser, "comment").is_some() && !monitor.is_cancelled() {
            Self::parse_and_add_comment(parser, prog, log)?;
        }
        Ok(())
    }

    /// Parse comments from the `<commentdb>` tag and add them to the listing via
    /// [`setup_comments`](Self::setup_comments).
    ///
    /// Note: `<comment>` has two `<addr>` tags. The first is the function address, and the
    /// second is the [`CodeUnit`](crate::program::model::listing::CodeUnit) address where the
    /// comment should be placed. Discard the first address.
    ///
    /// Port of `parseAndAddComment`.
    fn parse_and_add_comment<P: XmlPullParser>(
        parser: &mut P,
        prog: &mut dyn Program,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        let comment_element = parser.start(&["comment"])?;
        let comment_type = comment_element.get_attribute(ATTRIB_TYPE.name).unwrap_or_default();
        let decoded_type = Self::decode_comment_type(&comment_type);
        // this is the address of the function
        parser.discard_sub_tree_named("addr")?;
        // this is the CodeUnit address where the comment goes
        let addr_element = parser.start(&["addr"])?;

        let compiler_spec = prog.get_compiler_spec();
        let comment_addr = compiler_spec
            .as_deref()
            .map(|cspec| address_xml::restore_xml(&addr_element, cspec));

        match comment_addr {
            Some(Ok(xml_addr)) => {
                let comment_addr = xml_addr.get_first_address();
                parser.end_matching(&addr_element)?;

                parser.start(&["text"])?;
                let comment_text = parser.end()?.get_text().to_string();
                match decoded_type {
                    Some(decoded_type) => {
                        Self::setup_comments(decoded_type, &comment_addr, &comment_text, prog)
                    }
                    None => log.append_msg(format!("Unknown comment type: {}", comment_type)),
                }
                parser.end_matching(&comment_element)?;
            }
            Some(Err(e)) => log.append_exception(&e),
            None => log.append_msg("No compiler spec available to restore the comment address"),
        }

        Ok(())
    }

    /// Set up comments from the `<comment>` tag, following the comment types found in
    /// [`CommentType`].
    ///
    /// Port of `setupComments`.
    fn setup_comments(
        decoded_type: CommentType,
        comment_addr: &Address,
        comment_text: &str,
        prog: &mut dyn Program,
    ) {
        let Some(listing) = prog.get_listing() else {
            return;
        };
        if listing.get_code_unit_at(comment_addr).is_some() {
            listing.set_comment(comment_addr, decoded_type, Some(comment_text.to_string()));
        }
    }

    /// See `DecompileCallback.java` for the encoding of the comments by `DecompileDebug.java`.
    /// Its `encodeCommentsType` method encodes the comment types found in `CodeUnit.java` under
    /// four alternative labels: `user1` (EOL), `user2` (PRE), `user3` (POST) and `header`
    /// (PLATE). To generate comments we re-encode those labels back into [`CommentType`].
    ///
    /// Port of `decodeCommentType`. Java's `default` branch calls `CommentType.valueOf("")`,
    /// which throws `IllegalArgumentException`; this port reports the unknown label as `None`
    /// and its caller logs it.
    fn decode_comment_type(type_name: &str) -> Option<CommentType> {
        match type_name {
            "user1" => Some(CommentType::Eol),
            "user2" => Some(CommentType::Pre),
            "user3" => Some(CommentType::Post),
            "header" => Some(CommentType::Plate),
            _ => None,
        }
    }

    /// Loop through the `<type>` tags in the `<coretypes>` subtree.
    ///
    /// Port of `parseDataTypes`. Java also takes the `Program`, which it never uses.
    fn parse_data_types<P: XmlPullParser>(
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        data_type_manager: &mut DecompileDebugDataTypeManager,
        log: &mut XmlMessageLog,
    ) {
        while peek_start(parser).is_some() && !monitor.is_cancelled() {
            data_type_manager.parse_data_type_tag(parser, log);
        }
    }

    /// Parse the `<stringmanage>` subtree.
    ///
    /// Port of `parseStrings`.
    fn parse_strings<P: XmlPullParser>(
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        while peek_start_named(parser, "string").is_some() && !monitor.is_cancelled() {
            Self::parse_and_add_strings(parser, prog, log)?;
        }
        Ok(())
    }

    /// Parse the `<string>` tag and insert its bytes into the program.
    ///
    /// Port of `parseAndAddStrings`. Java also takes the `TaskMonitor`, which it never uses.
    fn parse_and_add_strings<P: XmlPullParser>(
        parser: &mut P,
        prog: &mut dyn Program,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        let string_element = parser.start(&["string"])?;
        let addr_element = parser.start(&["addr"])?;

        let compiler_spec = prog.get_compiler_spec();
        let string_addr = compiler_spec
            .as_deref()
            .map(|cspec| address_xml::restore_xml(&addr_element, cspec));

        match string_addr {
            Some(Ok(xml_addr)) => {
                let string_addr = xml_addr.get_first_address();
                parser.end_matching(&addr_element)?;

                parser.start(&["bytes"])?;
                let hex_string: String = parser
                    .end()?
                    .get_text()
                    .trim()
                    .chars()
                    .filter(|c| *c != '\n' && *c != ' ')
                    .collect();
                match parse_hex(&hex_string) {
                    Ok(raw_bytes) => match prog.get_memory_mut() {
                        Some(memory) => {
                            if let Err(e) = memory.set_bytes(&string_addr, &raw_bytes) {
                                log.append_exception(&e);
                            }
                        }
                        None => log.append_msg(format!(
                            "No writable memory available for string at address: {}",
                            string_addr
                        )),
                    },
                    Err(message) => log.append_msg(message),
                }
            }
            Some(Err(e)) => log.append_exception(&e),
            None => log.append_msg("No compiler spec available to restore the string address"),
        }

        parser.end_matching(&string_element)?;
        Ok(())
    }

    /// Handle the parsing of the context pointset inside of the `<context_points>` subtree.
    ///
    /// Port of `parseContextPoints`.
    fn parse_context_points<P: XmlPullParser>(
        parser: &mut P,
        monitor: &dyn TaskMonitor,
        prog: &mut dyn Program,
        log: &mut XmlMessageLog,
    ) -> Result<(), XmlException> {
        while peek_start_named(parser, "context_pointset").is_some() {
            let context_element = parser.start(&["context_pointset"])?;

            let compiler_spec = prog.get_compiler_spec();
            let addr = compiler_spec
                .as_deref()
                .map(|cspec| address_xml::restore_xml(&context_element, cspec));

            match addr {
                Some(Ok(xml_addr)) => {
                    let addr = xml_addr.get_first_address();
                    while peek_start_named(parser, "set").is_some() && !monitor.is_cancelled() {
                        let set_element = parser.start(&["set"])?;
                        let reg_name =
                            set_element.get_attribute(ATTRIB_NAME.name).unwrap_or_default();
                        let reg_val = set_element
                            .get_attribute(ATTRIB_VAL.name)
                            .and_then(|val| val.parse::<i128>().ok());
                        Self::set_context_value(prog, &reg_name, reg_val, &addr, log);
                        parser.end_matching(&set_element)?;
                    }
                }
                Some(Err(e)) => log.append_exception(&e),
                None => {
                    log.append_msg("No compiler spec available to restore the context address")
                }
            }
            parser.end_matching(&context_element)?;
        }

        while peek_start_named(parser, "tracked_pointset").is_some() {
            log.append_msg_at_line(
                parser.get_line_number(),
                format!(
                    "Level {} tag not currently supported: {}",
                    parser.get_current_level(),
                    parser.peek().get_name()
                ),
            );
            parser.discard_sub_tree();
        }

        Ok(())
    }

    /// Apply one `<set>` element's register value, the program-context half of
    /// [`parse_context_points`](Self::parse_context_points). Java's `BigInteger` value maps to
    /// the `i128` this crate's [`ProgramContext`](crate::program::model::listing::ProgramContext)
    /// carries.
    fn set_context_value(
        prog: &mut dyn Program,
        reg_name: &str,
        reg_val: Option<i128>,
        addr: &Address,
        log: &mut XmlMessageLog,
    ) {
        let Some(program_context) = prog.get_program_context() else {
            return;
        };
        let Some(register) = program_context.get_register(reg_name) else {
            log.append_msg(format!("Unknown context register: {}", reg_name));
            return;
        };
        let register = register.borrow();
        if let Err(e) = program_context.set_value(&register, addr, addr, reg_val) {
            log.append_exception(&e);
        }
    }
}

/// Simple handling of error messages.
///
/// Port of the nested `DecompileDebugFormatManager.MyErrorHandler`, which implements
/// `org.xml.sax.ErrorHandler`. There is no ported SAX `ErrorHandler` contract to implement (see
/// [`XmlErrorHandler`](crate::app::util::xml::xml_error_handler::XmlErrorHandler), the ported
/// peer of `ghidra.app.util.xml.XMLErrorHandler`, which is likewise a plain struct), and the
/// parser factory that would install this handler is not ported yet, so this stands ready rather
/// than being wired up. It borrows its log instead of owning one, mirroring the way Java hands
/// it the same `MessageLog` the caller keeps using.
pub struct MyErrorHandler<'a> {
    log: &'a mut XmlMessageLog,
}

impl<'a> MyErrorHandler<'a> {
    /// Port of `MyErrorHandler(MessageLog)`.
    pub fn new(log: &'a mut XmlMessageLog) -> Self {
        MyErrorHandler { log }
    }

    /// Port of `warning(SAXParseException)`.
    pub fn warning(&mut self, exception: &SaxParseException) {
        self.log.append_msg(exception.message());
    }

    /// Port of `error(SAXParseException)`.
    pub fn error(&mut self, exception: &SaxParseException) {
        self.log.append_msg(exception.message());
    }

    /// Port of `fatalError(SAXParseException)`.
    pub fn fatal_error(&mut self, exception: &SaxParseException) {
        self.log.append_msg(exception.message());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Minimal [`XmlElement`] carrying the pieces the format manager reads: name, kind, level,
    /// attributes and text.
    #[derive(Clone)]
    struct MockElement {
        name: String,
        is_start: bool,
        is_end: bool,
        level: i32,
        line: i32,
        text: String,
        attributes: HashMap<String, String>,
    }

    impl MockElement {
        fn start(name: &str, level: i32, attributes: &[(&str, &str)]) -> Self {
            MockElement {
                name: name.to_string(),
                is_start: true,
                is_end: false,
                level,
                line: level + 1,
                text: String::new(),
                attributes: attributes
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }

        fn end(name: &str, level: i32) -> Self {
            MockElement {
                name: name.to_string(),
                is_start: false,
                is_end: true,
                level,
                line: level + 1,
                text: String::new(),
                attributes: HashMap::new(),
            }
        }
    }

    impl XmlElement for MockElement {
        fn get_level(&self) -> i32 {
            self.level
        }
        fn is_start(&self) -> bool {
            self.is_start
        }
        fn is_end(&self) -> bool {
            self.is_end
        }
        fn is_content(&self) -> bool {
            !self.is_start && !self.is_end
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_attributes(&self) -> HashMap<String, String> {
            self.attributes.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attributes.iter().map(|(k, v)| (k.clone(), v.clone())))
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attributes.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attributes.get(key).cloned()
        }
        fn get_text(&self) -> &str {
            &self.text
        }
        fn get_column_number(&self) -> i32 {
            0
        }
        fn get_line_number(&self) -> i32 {
            self.line
        }
        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attributes.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    /// [`XmlPullParser`] over a fixed queue of [`MockElement`]s.
    struct QueueParser {
        elements: Vec<MockElement>,
        index: usize,
        disposed: bool,
    }

    impl QueueParser {
        fn new(elements: Vec<MockElement>) -> Self {
            QueueParser { elements, index: 0, disposed: false }
        }
    }

    impl XmlPullParser for QueueParser {
        type Element = MockElement;

        fn get_name(&self) -> &str {
            "queue parser"
        }
        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }
        fn is_pulling_content(&self) -> bool {
            false
        }
        fn set_pulling_content(&mut self, _pulling_content: bool) {}
        fn has_next(&self) -> bool {
            self.index < self.elements.len()
        }
        fn peek(&self) -> MockElement {
            self.elements[self.index].clone()
        }
        fn next(&mut self) -> MockElement {
            let element = self.elements[self.index].clone();
            self.index += 1;
            element
        }
        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    struct MockProgram {
        transactions: Mutex<Vec<(String, bool)>>,
    }

    impl MockProgram {
        fn new() -> Self {
            MockProgram { transactions: Mutex::new(Vec::new()) }
        }

        fn transactions(&self) -> Vec<(String, bool)> {
            self.transactions.lock().unwrap().clone()
        }
    }

    impl crate::framework::model::DomainObject for MockProgram {
        fn start_transaction(&mut self, description: &str) -> i32 {
            self.transactions.lock().unwrap().push((description.to_string(), false));
            7
        }
        fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
            assert_eq!(transaction_id, 7);
            if let Some(last) = self.transactions.lock().unwrap().last_mut() {
                last.1 = commit;
            }
            commit
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// A [`TaskMonitor`] that records the messages the load reports, mirroring the sibling
    /// recording monitors in this crate's tests; only `set_message`/`is_cancelled` matter here.
    struct MockMonitor {
        messages: Mutex<Vec<String>>,
    }

    impl MockMonitor {
        fn new() -> Self {
            MockMonitor { messages: Mutex::new(Vec::new()) }
        }

        fn messages(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_message(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn get_message(&self) -> String {
            self.messages.lock().unwrap().last().cloned().unwrap_or_default()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    /// A provider whose bytes came from a nested filesystem, so its `getFile()` is what the
    /// constructor must fall back on.
    struct CachedProvider;

    impl ByteProvider for CachedProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(0)
        }
        fn is_valid_index(&mut self, _index: u64) -> bool {
            false
        }
        fn read_byte(&mut self, _index: u64) -> std::io::Result<u8> {
            unimplemented!("not needed for this smoke test")
        }
        fn read_bytes(&mut self, _index: u64, _length: usize) -> std::io::Result<Vec<u8>> {
            unimplemented!("not needed for this smoke test")
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_file(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/filecache/abc123"))
        }
    }

    #[test]
    fn get_program_info_splits_arch_at_the_last_colon() {
        // <binaryimage arch="x86:LE:32:default:gcc"> ... <bytechunk offset="0x100000">
        let mut parser = QueueParser::new(vec![
            MockElement::start("xml_savefile", 0, &[]),
            MockElement::start("binaryimage", 1, &[("arch", "x86:LE:32:default:gcc")]),
            MockElement::start("bytechunk", 2, &[("offset", "0x100000")]),
        ]);
        let mut manager = DecompileDebugFormatManager::new("/tmp/debug.xml");

        let info = manager.get_program_info(&mut parser).expect("arch attribute has a compiler");

        assert_eq!(info.offset, "0x100000");
        assert_eq!(info.compiler_string, "gcc");
        assert_eq!(info.spec_string, "x86:LE:32:default");
        // the record is retained in the progInfo field, as the Java version does
        assert_eq!(manager.program_info(), Some(&info));
        assert!(parser.disposed, "the parser is disposed before returning");
    }

    #[test]
    fn get_program_info_rejects_an_arch_without_a_compiler() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("binaryimage", 1, &[("arch", "x86")]),
            MockElement::start("bytechunk", 2, &[("offset", "0x0")]),
        ]);
        let mut manager = DecompileDebugFormatManager::new("/tmp/debug.xml");

        // Java fails this input inside String.substring(0, -1)
        assert!(manager.get_program_info(&mut parser).is_err());
        assert_eq!(manager.program_info(), None);
    }

    #[test]
    fn read_logs_unsupported_tags_and_commits_the_transaction() {
        // <xml_savefile><binaryimage/><optionslist/><save_state></save_state></xml_savefile>
        let mut parser = QueueParser::new(vec![
            MockElement::start("xml_savefile", 0, &[]),
            MockElement::start("binaryimage", 1, &[]),
            MockElement::end("binaryimage", 1),
            MockElement::start("optionslist", 1, &[]),
            MockElement::end("optionslist", 1),
            MockElement::start("save_state", 1, &[]),
            MockElement::end("save_state", 1),
            MockElement::end("xml_savefile", 0),
        ]);
        let mut program = MockProgram::new();
        let monitor = MockMonitor::new();
        let mut manager = DecompileDebugFormatManager::new("/tmp/debug.xml");

        let log = manager
            .read(&mut parser, &mut program, &monitor, "test_program")
            .expect("the document is well formed");

        assert_eq!(
            log.messages(),
            [
                "Beginning Load".to_string(),
                // <optionslist> is documented as not yet supported; level 1, line 2
                "Line #2 - Level 1 tag not currently supported: optionslist".to_string(),
                "Finished import".to_string(),
            ]
        );
        assert_eq!(
            monitor.messages().as_slice(),
            [
                "Beginning Load".to_string(),
                "Processing binary image".to_string(),
                "Finished import".to_string(),
            ]
        );
        // the "Loading" transaction is committed in the finally block
        assert_eq!(
            program.transactions().as_slice(),
            [("Loading".to_string(), true)]
        );
        assert!(parser.disposed);
    }

    #[test]
    fn read_reports_a_malformed_document_as_a_load_error() {
        // missing the <xml_savefile> wrapper the Java version starts with
        let mut parser = QueueParser::new(vec![MockElement::start("db", 0, &[])]);
        let mut program = MockProgram::new();
        let monitor = MockMonitor::new();
        let mut manager = DecompileDebugFormatManager::new("/tmp/debug.xml");

        let error = manager
            .read(&mut parser, &mut program, &monitor, "test_program")
            .expect_err("the document does not start with xml_savefile");

        assert_eq!(error.to_string(), "File read error.");
        // the transaction is still committed and the parser still disposed
        assert_eq!(
            program.transactions().as_slice(),
            [("Loading".to_string(), true)]
        );
        assert!(parser.disposed);
    }

    #[test]
    fn decode_comment_type_maps_the_decompiler_labels() {
        assert_eq!(
            DecompileDebugFormatManager::decode_comment_type("user1"),
            Some(CommentType::Eol)
        );
        assert_eq!(
            DecompileDebugFormatManager::decode_comment_type("user2"),
            Some(CommentType::Pre)
        );
        assert_eq!(
            DecompileDebugFormatManager::decode_comment_type("user3"),
            Some(CommentType::Post)
        );
        assert_eq!(
            DecompileDebugFormatManager::decode_comment_type("header"),
            Some(CommentType::Plate)
        );
        // Java's default branch is CommentType.valueOf(""), which throws
        assert_eq!(DecompileDebugFormatManager::decode_comment_type("user4"), None);
    }

    #[test]
    fn byte_provider_without_a_simple_fsrl_falls_back_to_its_file() {
        let manager = DecompileDebugFormatManager::from_byte_provider(&CachedProvider);

        assert_eq!(manager.file(), Some(Path::new("/filecache/abc123")));
    }

    #[test]
    fn parse_hex_matches_hex_format_parse_hex() {
        assert_eq!(parse_hex("48656c6c6f"), Ok(b"Hello".to_vec()));
        assert!(parse_hex("abc").is_err(), "odd length is rejected");
        assert!(parse_hex("zz").is_err(), "non-hex digits are rejected");
    }

    #[test]
    fn error_handler_appends_the_exception_message_to_the_log() {
        let mut log = XmlMessageLog::new();
        let mut handler = MyErrorHandler::new(&mut log);

        handler.warning(&SaxParseException::new(12, "mismatched tag"));
        handler.error(&SaxParseException::new(13, "bad attribute"));
        handler.fatal_error(&SaxParseException::new(14, "unexpected EOF"));

        assert_eq!(log.messages(), ["mismatched tag", "bad attribute", "unexpected EOF"]);
    }
}
