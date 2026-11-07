//! The VaultOS MCP bridge over stdio: the agent tools of `mcp/server.mjs`, with the same
//! names, descriptions and input schemas (`tools.json`). It keeps no vault state. Each call
//! is one request to the daemon, which enforces the agent's scopes, project and folder
//! grants and approvals. Only `reveal_secret` returns a value, and only with the reveal
//! scope.

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use vaultos_client::{enc, Client};

const TOOLS: &str = include_str!("tools.json");
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct Bridge {
    client: Arc<Client>,
    tools: Vec<Tool>,
}

/// The bridge's version and the SHA-256 of its executable, so a human can check which
/// build an agent is talking to.
fn bridge_version() -> Value {
    static HASH: OnceLock<Option<String>> = OnceLock::new();
    let hash = HASH.get_or_init(|| {
        let bytes = std::fs::read(std::env::current_exe().ok()?).ok()?;
        Some(
            Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    });
    json!({ "version": VERSION, "sha256": hash })
}

/// JavaScript truthiness, for the defaults `server.mjs` applies with `||`.
fn truthy(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    })
}

/// Runs one tool; `Err` is the message shown to the agent after "Error: ".
fn call(client: &Client, name: &str, a: &JsonObject) -> Result<Value, String> {
    let text = |k: &str| match a.get(k) {
        Some(Value::String(v)) => Ok(v.clone()),
        None | Some(Value::Null) => Err(format!("{k} is required")),
        Some(_) => Err(format!("{k} must be a string")),
    };
    // Arguments that were given, renamed for the API; like JSON.stringify, absent ones are
    // left out and the daemon validates the rest.
    let pick = |fields: &[(&str, &str)]| {
        let mut body = Map::new();
        for (arg, field) in fields {
            if let Some(v) = a.get(*arg) {
                body.insert((*field).to_owned(), v.clone());
            }
        }
        body
    };
    let send = |method: &str, route: &str, body: Option<Map<String, Value>>| {
        client
            .request(method, route, body.map(Value::Object).as_ref())
            .map_err(|e| e.message)
    };
    let secrets = || Ok::<_, String>(format!("/projects/{}/secrets", enc(&text("project")?)));
    match name {
        "vault_status" => {
            let mut status = client.status();
            if let Some(o) = status.as_object_mut() {
                o.insert("bridge".into(), bridge_version());
            }
            Ok(status)
        }
        "list_projects" => send("GET", "/projects", None),
        "list_secrets" => send("GET", &secrets()?, None),
        "create_project" => send("POST", "/projects", Some(pick(&[("name", "name")]))),
        "set_secret" => {
            let body = pick(&[
                ("key", "key"),
                ("value", "value"),
                ("provider", "provider"),
                ("note", "note"),
                ("username", "username"),
                ("email", "email"),
                ("password", "password"),
                ("url", "url"),
                ("permission", "permission"),
                ("expires_at", "expiresAt"),
            ]);
            send("POST", &secrets()?, Some(body))
        }
        "delete_secret" => {
            let route = format!("{}/{}", secrets()?, enc(&text("key")?));
            send("DELETE", &route, None)
        }
        "inject_secrets" => {
            let mut body = pick(&[("project", "project"), ("target_path", "target_path")]);
            let format = truthy(a.get("format")).cloned().unwrap_or(json!("dotenv"));
            body.insert("format".into(), format);
            let keys = truthy(a.get("keys")).cloned().unwrap_or(Value::Null);
            body.insert("keys".into(), keys);
            body.extend(pick(&[("merge", "merge")]));
            send("POST", "/inject", Some(body))
        }
        "reveal_secret" => send(
            "POST",
            "/reveal",
            Some(pick(&[("project", "project"), ("key", "key")])),
        ),
        "whoami" => send("GET", "/whoami", None),
        "compare" => send("GET", "/compare", None),
        "list_pending" => send("GET", "/pending", None),
        "search" => send("GET", &format!("/search?q={}", enc(&text("query")?)), None),
        "import_env" => {
            let mut body = pick(&[("project", "project"), ("env_path", "env_path")]);
            if a.get("createProject") == Some(&Value::Bool(true)) {
                body.insert("createProject".into(), Value::Bool(true));
            }
            send("POST", "/import", Some(body))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

impl ServerHandler for Bridge {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("vault-os", VERSION))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let client = Arc::clone(&self.client);
        let name = request.name.into_owned();
        let args = request.arguments.unwrap_or_default();
        // The client blocks on the socket (and on a daemon that is still unlocking).
        let out = tokio::task::spawn_blocking(move || call(&client, &name, &args))
            .await
            .unwrap_or_else(|_| Err("The bridge failed while handling this call".into()));
        let result = match out.and_then(|v| {
            serde_json::to_string_pretty(&v).map_err(|_| "The reply could not be encoded".into())
        }) {
            Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
            Err(m) => CallToolResult::error(vec![ContentBlock::text(format!("Error: {m}"))]),
        };
        Ok(result.into())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let data_dir = match vaultos_core::paths::default_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("vault-os-mcp: {e}");
            return ExitCode::from(2);
        }
    };
    let tools = match serde_json::from_str::<Vec<Tool>>(TOOLS) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("vault-os-mcp: bad tool definitions: {e}");
            return ExitCode::from(70);
        }
    };
    let bridge = Bridge {
        client: Arc::new(Client::from_env(data_dir)),
        tools,
    };
    let service = match bridge.serve(rmcp::transport::stdio()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vault-os-mcp: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("vault-os-mcp: ready");
    match service.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}
