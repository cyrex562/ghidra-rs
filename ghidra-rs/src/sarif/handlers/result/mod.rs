//! Port of `sarif.handlers.result` -- the concrete [`SarifResultHandler`](super::SarifResultHandler)
//! implementations.

pub mod sarif_address_result_handler;
pub mod sarif_code_flow_result_handler;
pub mod sarif_kind_result_handler;
pub mod sarif_level_result_handler;
pub mod sarif_property_result_handler;
pub mod sarif_rule_id_result_handler;
pub mod sarif_tool_result_handler;

pub use sarif_address_result_handler::SarifAddressResultHandler;
pub use sarif_code_flow_result_handler::SarifCodeFlowResultHandler;
pub use sarif_kind_result_handler::SarifKindResultHandler;
pub use sarif_level_result_handler::SarifLevelResultHandler;
pub use sarif_property_result_handler::SarifPropertyResultHandler;
pub use sarif_rule_id_result_handler::SarifRuleIdResultHandler;
pub use sarif_tool_result_handler::SarifToolResultHandler;
