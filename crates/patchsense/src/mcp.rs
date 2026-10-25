//! Read-only MCP server on stdio. Protocol bytes stay on stdout.

use std::path::Path;

use patchsense_core::lockfile::{parser_for, supported_file_names};
use rmcp::handler::server::ServerHandler;
use rmcp::{tool, tool_handler, tool_router};
use serde_json::json;

/// MCP server. It does not scan until a later tool asks it to.
#[derive(Debug, Clone, Default)]
pub struct McpServer;

#[tool_router]
impl McpServer {
    /// Lockfile names this build can parse, with their OSV ecosystems.
    #[tool(description = "List lockfile names PatchSense can parse and their OSV ecosystems")]
    fn list_supported_lockfiles(&self) -> String {
        let rows: Vec<_> = supported_file_names()
            .into_iter()
            .map(|name| {
                let ecosystem = parser_for(Path::new(name))
                    .map(|parser| parser.ecosystem().as_osv_str())
                    .unwrap_or("unknown");
                json!({ "file": name, "ecosystem": ecosystem })
            })
            .collect();
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
    }
}

#[tool_handler(
    name = "patchsense",
    instructions = "Read-only lockfile triage. Logs stay on stderr."
)]
impl ServerHandler for McpServer {}
