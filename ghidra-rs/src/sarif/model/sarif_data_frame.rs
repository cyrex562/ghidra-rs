//! Port of `sarif.model.SarifDataFrame`.

use std::collections::HashMap;

use serde_json::Value;

use crate::sarif::model::SarifColumnKey;
use crate::sarif::seam_stubs::{SarifController, SarifUtils};
use crate::sarif::SarifSchema210;

/// Parses a SARIF log into easier-to-use root structures, plus helper accessors.
///
/// Port of `sarif.model.SarifDataFrame`. SARIF payloads (`Run`, `Result`, `Tool`, `ToolComponent`,
/// `Artifact`, `ReportingDescriptorReference`, ...) are navigated as raw [`serde_json::Value`]
/// rather than typed `com.contrastsecurity.sarif` classes, matching the convention already set by
/// [`SarifSchema210`] and the `sarif::io` readers -- none of those SARIF-schema classes are
/// ported, and this crate's SARIF layer treats a parsed document as JSON throughout. `Clone` is
/// derived so [`SarifResultHandlerBase`](crate::sarif::handlers::SarifResultHandlerBase) and
/// [`SarifResultsTableProvider`](crate::sarif::seam_stubs::SarifResultsTableProvider) can hold an
/// owned snapshot the way Java's field assignment aliases the same object.
#[derive(Clone)]
pub struct SarifDataFrame {
    columns: Vec<SarifColumnKey>,
    table_results: Vec<HashMap<String, Value>>,
    table_results_as_map: HashMap<String, Vec<HashMap<String, Value>>>,
    controller: SarifController,
    component_map: HashMap<String, Value>,
    taxa_map: HashMap<String, Value>,
    source_language: Option<String>,
    compiler: Option<String>,
    tool_id: Option<String>,
    version: Option<String>,
}

impl SarifDataFrame {
    /// `SarifDataFrame(SarifSchema210 sarifLog, SarifController controller, boolean
    /// parseHeaderOnly)`.
    pub fn new(sarif_log: &SarifSchema210, controller: SarifController, parse_header_only: bool) -> Self {
        let mut df = SarifDataFrame {
            columns: vec![
                SarifColumnKey::new("Tool", true),
                SarifColumnKey::new("RuleId", true),
                SarifColumnKey::new("Address", false),
                SarifColumnKey::new("Message", false),
                SarifColumnKey::new("Kind", true),
                SarifColumnKey::new("Level", true),
            ],
            table_results: Vec::new(),
            table_results_as_map: HashMap::new(),
            controller,
            component_map: HashMap::new(),
            taxa_map: HashMap::new(),
            source_language: None,
            compiler: None,
            tool_id: None,
            version: None,
        };

        let empty_runs = Vec::new();
        let runs = sarif_log
            .as_value()
            .get("runs")
            .and_then(Value::as_array)
            .unwrap_or(&empty_runs)
            .clone();

        for run in &runs {
            df.parse_header(run);
            if parse_header_only {
                continue;
            }

            df.compile_component_map(run);
            let mut component_names: Vec<String> = df.component_map.keys().cloned().collect();
            component_names.sort();
            for name in component_names {
                df.columns.push(SarifColumnKey::new(name, false));
            }

            let mut keys: Vec<(String, bool)> = df
                .controller
                .get_program_sarif_mgr()
                .get_keys()
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, is_hidden) in keys {
                df.columns.push(SarifColumnKey::new(key, is_hidden));
            }

            SarifUtils::validate_run(run);
            SarifUtils::set_populating(true);

            let empty_results = Vec::new();
            let results = run.get("results").and_then(Value::as_array).unwrap_or(&empty_results).clone();
            let result_handlers = df.controller.get_sarif_result_handlers().to_vec();
            for result in &results {
                df.compile_taxa_map(run, result);

                let mut cur_table_result: HashMap<String, Value> = HashMap::new();
                for handler in &result_handlers {
                    if handler.is_enabled(&df) {
                        handler.handle(&df, run, result, &mut cur_table_result);
                    }
                }
                let ruleid = cur_table_result
                    .get("RuleId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                df.table_results_as_map.entry(ruleid).or_default().push(cur_table_result.clone());
                df.table_results.push(cur_table_result);
            }

            let run_handlers = df.controller.get_sarif_run_handlers().to_vec();
            for handler in &run_handlers {
                if handler.is_enabled(&df) {
                    handler.handle(&df, run);
                }
            }

            SarifUtils::set_populating(false);
        }

        df
    }

    /// `SarifDataFrame.parseHeader(Run)`.
    fn parse_header(&mut self, run: &Value) {
        if let Some(driver) = run.get("tool").and_then(|tool| tool.get("driver")) {
            self.tool_id = driver.get("name").and_then(Value::as_str).map(String::from);
            self.version = driver.get("version").and_then(Value::as_str).map(String::from);
        }

        let Some(artifacts) = run.get("artifacts").and_then(Value::as_array) else {
            return;
        };
        for artifact in artifacts {
            self.source_language = artifact.get("sourceLanguage").and_then(Value::as_str).map(String::from);
            self.compiler = artifact
                .get("description")
                .and_then(|description| description.get("text"))
                .and_then(Value::as_str)
                .map(String::from);
        }
    }

    /// `SarifDataFrame.compileComponentMap(Run)`.
    fn compile_component_map(&mut self, run: &Value) {
        self.component_map = HashMap::new();
        let Some(taxonomies) = run.get("taxonomies").and_then(Value::as_array) else {
            return;
        };
        for tool_component in taxonomies {
            if let Some(name) = tool_component.get("name").and_then(Value::as_str) {
                self.component_map.insert(name.to_string(), tool_component.clone());
            }
        }
    }

    /// `SarifDataFrame.compileTaxaMap(Run, Result)`.
    fn compile_taxa_map(&mut self, run: &Value, result: &Value) {
        self.taxa_map = HashMap::new();
        let Some(taxonomies) = run.get("taxonomies").and_then(Value::as_array) else {
            return;
        };
        let Some(taxa) = result.get("taxa").and_then(Value::as_array) else {
            return;
        };

        for reference in taxa {
            let Some(tool_component_ref) = reference.get("toolComponent") else {
                continue;
            };
            let index = tool_component_ref.get("index").and_then(Value::as_i64).unwrap_or(-1);
            if index >= 0 && (index as usize) < taxonomies.len() {
                if let Some(name) = taxonomies[index as usize].get("name").and_then(Value::as_str) {
                    self.taxa_map.insert(name.to_string(), reference.clone());
                }
            } else if let Some(name) = tool_component_ref.get("name").and_then(Value::as_str) {
                self.taxa_map.insert(name.to_string(), reference.clone());
            }
        }
    }

    /// `SarifDataFrame.getColumns()`.
    pub fn get_columns(&self) -> &[SarifColumnKey] {
        &self.columns
    }

    /// `SarifDataFrame.getTableResults()`.
    pub fn get_table_results(&self) -> &[HashMap<String, Value>] {
        &self.table_results
    }

    /// `SarifDataFrame.getTableResultsAsMap()`.
    pub fn get_table_results_as_map(&self) -> &HashMap<String, Vec<HashMap<String, Value>>> {
        &self.table_results_as_map
    }

    /// `SarifDataFrame.getController()`.
    pub fn get_controller(&self) -> &SarifController {
        &self.controller
    }

    /// `SarifDataFrame.getComponentMap()`.
    pub fn get_component_map(&self) -> &HashMap<String, Value> {
        &self.component_map
    }

    /// `SarifDataFrame.getTaxa()`.
    pub fn get_taxa(&self) -> &HashMap<String, Value> {
        &self.taxa_map
    }

    /// `SarifDataFrame.getSourceLanguage()`.
    pub fn get_source_language(&self) -> Option<&str> {
        self.source_language.as_deref()
    }

    /// `SarifDataFrame.getCompiler()`.
    pub fn get_compiler(&self) -> Option<&str> {
        self.compiler.as_deref()
    }

    /// `SarifDataFrame.getToolID()`.
    pub fn get_tool_id(&self) -> Option<&str> {
        self.tool_id.as_deref()
    }

    /// `SarifDataFrame.getVersion()`.
    pub fn get_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::seam_stubs::ProgramSarifMgr;

    fn controller() -> SarifController {
        SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new("."))
    }

    fn sarif_log(json: Value) -> SarifSchema210 {
        SarifSchema210::new(json)
    }

    #[test]
    fn header_only_parses_tool_id_and_version_without_populating_rows() {
        let log = sarif_log(serde_json::json!({
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "Ghidra", "version": "11.0" } },
                "results": [{ "ruleId": "R1" }],
            }],
        }));

        let df = SarifDataFrame::new(&log, controller(), true);

        assert_eq!(df.get_tool_id(), Some("Ghidra"));
        assert_eq!(df.get_version(), Some("11.0"));
        assert!(df.get_table_results().is_empty());
        // Header-only mode never adds the default six columns' extras.
        assert_eq!(df.get_columns().len(), 6);
    }

    #[test]
    fn default_columns_match_java_constructor_order() {
        let log = sarif_log(serde_json::json!({ "version": "2.1.0", "runs": [] }));
        let df = SarifDataFrame::new(&log, controller(), true);

        let names: Vec<&str> = df.get_columns().iter().map(SarifColumnKey::name).collect();
        assert_eq!(names, ["Tool", "RuleId", "Address", "Message", "Kind", "Level"]);
        assert!(df.get_columns()[0].is_hidden());
        assert!(!df.get_columns()[2].is_hidden());
    }

    #[test]
    fn parses_artifact_source_language_and_compiler() {
        let log = sarif_log(serde_json::json!({
            "version": "2.1.0",
            "runs": [{
                "artifacts": [{
                    "sourceLanguage": "c",
                    "description": { "text": "gcc 11.2" },
                }],
            }],
        }));

        let df = SarifDataFrame::new(&log, controller(), true);

        assert_eq!(df.get_source_language(), Some("c"));
        assert_eq!(df.get_compiler(), Some("gcc 11.2"));
    }

    #[test]
    fn full_parse_adds_taxonomy_and_program_mgr_columns() {
        let mut mgr_keys = HashMap::new();
        mgr_keys.insert("Namespace".to_string(), true);
        let ctrl = SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new(".").with_keys(mgr_keys));

        let log = sarif_log(serde_json::json!({
            "version": "2.1.0",
            "runs": [{
                "taxonomies": [{ "name": "CWE" }],
                "results": [],
            }],
        }));

        let df = SarifDataFrame::new(&log, ctrl, false);

        let names: Vec<&str> = df.get_columns().iter().map(SarifColumnKey::name).collect();
        assert!(names.contains(&"CWE"));
        assert!(names.contains(&"Namespace"));
        assert_eq!(df.get_component_map().len(), 1);
    }

    #[test]
    fn empty_document_produces_no_table_results() {
        let log = sarif_log(serde_json::json!({ "version": "2.1.0", "runs": [] }));
        let df = SarifDataFrame::new(&log, controller(), false);

        assert!(df.get_table_results().is_empty());
        assert!(df.get_table_results_as_map().is_empty());
    }
}
