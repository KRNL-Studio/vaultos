//! Request handling, ported from `api.js`. The transport (`server.rs`) has already checked the
//! peer's user id, the size of the body and the owner's session token; everything here runs
//! with the store locked. Agent permissions are enforced here, never in clients.

use serde_json::{json, Map, Value};
use vaultos_core::agents::Agent;
use vaultos_core::env::{self, Format};
use vaultos_core::model::agent_ref;
use vaultos_core::{Error, Fields, SecretKey, SecretString, Store};

pub const MAX_BODY: usize = 1024 * 1024;
const RESERVED: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// What the transport hands over: the parts of a request routing needs.
#[derive(Default)]
pub struct Request {
    pub method: String,
    /// The path and query, as sent.
    pub target: String,
    pub agent_token: Option<String>,
    pub approver: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Tokens and the body (which can carry a value) are never printed.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(PartialEq)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

/// The body can carry a revealed value, so only the status is printed.
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Reply {
    pub fn ok(body: Value) -> Reply {
        Reply { status: 200, body }
    }

    pub fn error(status: u16, message: impl Into<String>) -> Reply {
        Reply {
            status,
            body: json!({ "error": message.into() }),
        }
    }

    fn from_error(e: &Error) -> Reply {
        let message = match e {
            // OS errors can name paths or echo arguments.
            Error::Io { .. } => "File operation failed; check permissions and retry".to_owned(),
            other => other.to_string(),
        };
        let status = match e {
            Error::NeedsUpgrade | Error::TooNew { .. } => 409,
            other => other.status(),
        };
        Reply::error(status, message)
    }
}

type Result<T> = std::result::Result<T, Error>;

fn invalid(msg: &str) -> Error {
    Error::Invalid(msg.to_owned())
}

fn deny(msg: impl Into<String>) -> Error {
    Error::Forbidden(msg.into())
}

/// `validation.js` `object`, applied to a request body.
fn parse_body(req: &Request) -> std::result::Result<Map<String, Value>, Reply> {
    if req.body.is_empty() {
        return Ok(Map::new());
    }
    let json = req
        .content_type
        .as_deref()
        .is_some_and(|c| c.starts_with("application/json"));
    if !json {
        return Err(Reply::error(415, "JSON required"));
    }
    let Ok(value) = serde_json::from_slice::<Value>(&req.body) else {
        return Err(Reply::error(400, "Invalid JSON"));
    };
    let Value::Object(map) = value else {
        return Err(Reply::error(400, "Expected an object"));
    };
    if RESERVED.iter().any(|k| map.contains_key(*k)) {
        return Err(Reply::error(400, "Reserved object key"));
    }
    Ok(map)
}

fn text<'a>(body: &'a Map<String, Value>, field: &str, label: &str) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("Invalid {label}")))
}

/// An optional string field: absent is `None`; present but not a string is an error, as in
/// `validation.js` `secret`.
fn optional(body: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    match body.get(field) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::Invalid(format!("Invalid {field}"))),
    }
}

fn fields_from(body: &Map<String, Value>) -> Result<Fields> {
    Ok(Fields {
        key: text(body, "key", "key name")?.to_owned(),
        value: optional(body, "value")?.map(SecretString::new),
        password: optional(body, "password")?.map(SecretString::new),
        note: optional(body, "note")?,
        username: optional(body, "username")?,
        email: optional(body, "email")?,
        url: optional(body, "url")?,
        provider: optional(body, "provider")?,
        permission: optional(body, "permission")?,
        expires_at: optional(body, "expiresAt")?,
        kind: optional(body, "kind")?,
        tags: match body.get("tags") {
            None => None,
            Some(Value::Array(a)) => Some(
                a.iter()
                    .map(|t| t.as_str().map(str::to_owned))
                    .collect::<Option<_>>()
                    .ok_or_else(|| invalid("Invalid tags"))?,
            ),
            Some(_) => return Err(invalid("Invalid tags")),
        },
        // Favorites, archiving and custom fields are the app's.
        ..Fields::default()
    })
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Format(e.to_string()))
}

fn decode(segment: &str) -> Result<String> {
    percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| invalid("URI malformed"))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Owner routes other than `/status`, `/shutdown` and `/sync`, which the transport answers.
pub fn owner(store: &mut Store, req: &Request) -> Option<Reply> {
    let route = (req.method.as_str(), req.target.as_str());
    if !matches!(route, ("POST", "/unlock") | ("POST", "/lock")) {
        return None;
    }
    if req.agent_token.is_some() {
        return Some(Reply::error(403, "Agents cannot lock or unlock the vault"));
    }
    if route.1 == "/lock" {
        store.lock();
        return Some(Reply::ok(json!({ "ok": true, "locked": true })));
    }
    let body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return Some(r),
    };
    Some(unlock(store, &body).unwrap_or_else(|e| Reply::from_error(&e)))
}

fn unlock(store: &mut Store, body: &Map<String, Value>) -> Result<Reply> {
    if store.is_unlocked() {
        return Ok(Reply::ok(json!({ "ok": true, "locked": false })));
    }
    let password = SecretString::new(text(body, "password", "master password")?);
    let secret_key = optional(body, "secretKey")?
        .filter(|s| !s.trim().is_empty())
        .map(|s| SecretKey::parse(&s))
        .transpose()?;
    store.unlock(&password, secret_key.as_ref())?;
    Ok(Reply::ok(json!({
        "ok": true,
        "locked": false,
        "auditProblem": store.audit_problem(),
    })))
}

/// Everything after the owner's routes: agent requests and the approval relay.
pub fn handle(store: &mut Store, req: &Request) -> Reply {
    if !store.is_unlocked() {
        return Reply::error(423, "Vault is locked. Unlock the app.");
    }
    if let Err(e) = store.reload_if_changed() {
        // A file this session can no longer open (a new password or Secret Key, or damage)
        // ends the session; a writer holding the lock does not.
        if !matches!(e, Error::Busy | Error::Io { .. } | Error::Conflict(_)) {
            store.lock();
        }
        return Reply::error(
            409,
            "The vault changed on disk and could not be reloaded. Unlock the app again.",
        );
    }
    let relay = req.method == "POST" && req.target == "/pending/decide";
    let agent = if relay {
        None
    } else {
        let token = req.agent_token.as_deref().unwrap_or("");
        match store.authenticate_agent(token) {
            Ok(Some(a)) => Some(a),
            Ok(None) => return Reply::error(403, "An enrolled, active agent token is required"),
            Err(e) => return Reply::from_error(&e),
        }
    };
    if let Some(a) = &agent {
        store.note_agent_seen(&a.id);
    }
    let body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let result = match &agent {
        None => relay_decision(store, req.approver.as_deref().unwrap_or(""), &body),
        Some(a) => route(store, a, req, &body),
    };
    match result {
        Ok(v) => Reply::ok(v),
        Err(e) => Reply::from_error(&e),
    }
}

fn relay_decision(store: &mut Store, presented: &str, body: &Map<String, Value>) -> Result<Value> {
    if !store.approver_configured()? {
        return Err(deny("The approval relay is not configured"));
    }
    if !store.verify_approver(presented)? {
        return Err(deny(
            "Only the configured approval relay can decide pending keys",
        ));
    }
    let Some(approve) = body.get("approve").and_then(Value::as_bool) else {
        return Err(invalid(
            "project, key and approve (true/false) are required",
        ));
    };
    let project = text(body, "project", "project")?;
    let key = text(body, "key", "key name")?;
    to_json(&store.relay_decision(presented, project, key, approve)?)
}

/// One request, as `api.js` `route` handles it.
struct Ctx<'a> {
    agent: &'a Agent,
    actor: String,
}

impl Ctx<'_> {
    fn scope(&self, name: &str) -> Result<()> {
        if self.agent.has_scope(name) {
            Ok(())
        } else {
            Err(deny(format!("This agent does not have the {name} scope")))
        }
    }

    fn allowed(&self, id: Option<&str>) -> bool {
        id.is_some_and(|id| self.agent.allowed_project(id))
    }

    /// The project's id and name, if it exists and this agent may use it. Unknown and
    /// unapproved projects are refused alike, so an agent cannot probe for names.
    fn project(&self, store: &Store, name: Option<&str>) -> Result<(String, String)> {
        let found = match name {
            Some(n) => store.find_project(n)?,
            None => None,
        };
        match found {
            Some((id, name)) if self.agent.allowed_project(&id) => Ok((id, name)),
            _ => Err(deny("Project is not approved for this agent")),
        }
    }

    fn file(&self, store: &Store, target: Option<&Value>) -> Result<std::path::PathBuf> {
        let target = target
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("An absolute file path is required"))?;
        self.agent.file_target(target, store.data_dir())
    }

    /// Creates a project and grants it to this agent in one save.
    fn create_project(&self, store: &mut Store, name: Option<&Value>) -> Result<(String, String)> {
        self.scope("add")?;
        let name = name
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Invalid project name"))?;
        let agent_id = self.agent.id.clone();
        let actor = self.actor.clone();
        store.batch(|s| {
            let (id, name) = s.create_project(name, &actor)?;
            s.grant_project(&agent_id, &id)?;
            Ok((id, name))
        })
    }

    fn write_secret(&self, store: &mut Store, project: &str, fields: &Fields) -> Result<Value> {
        match store.find_item(project, &fields.key)? {
            None => self.scope("add")?,
            Some(item) if item.owner == self.actor => self.scope("edit:own")?,
            Some(_) => self.scope("edit:delegated")?,
        }
        to_json(&store.set_item(project, fields, &self.actor)?)
    }
}

fn route(
    store: &mut Store,
    agent: &Agent,
    req: &Request,
    body: &Map<String, Value>,
) -> Result<Value> {
    let cx = Ctx {
        agent,
        actor: agent_ref(&agent.id),
    };
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    let m = req.method.as_str();
    match (m, path) {
        ("GET", "/whoami") => {
            return Ok(json!({
                "identity": cx.actor,
                "name": agent.name,
                "scopes": agent.scopes,
                "projects": agent.projects,
                "roots": agent.roots,
                "allProjects": agent.all_projects,
                "anyRoot": agent.any_root,
            }))
        }
        ("GET", "/projects") => {
            cx.scope("read")?;
            let all = store.list_projects()?;
            let mine: Vec<_> = all.iter().filter(|p| cx.allowed(Some(&p.id))).collect();
            return to_json(&mine);
        }
        ("POST", "/projects") => {
            let (id, name) = cx.create_project(store, body.get("name"))?;
            return Ok(json!({ "id": id, "name": name }));
        }
        ("GET", "/search") => {
            cx.scope("read")?;
            let q = query_param(query, "q").unwrap_or_default();
            let mut out = Vec::new();
            for hit in store.search(&q)? {
                let name = match &hit {
                    vaultos_core::store::SearchHit::Project { project }
                    | vaultos_core::store::SearchHit::Secret { project, .. } => project,
                };
                let id = store.find_project(name)?.map(|(id, _)| id);
                if cx.allowed(id.as_deref()) {
                    out.push(hit);
                }
            }
            return to_json(&out);
        }
        ("GET", "/pending") => {
            cx.scope("read")?;
            let mut out = Vec::new();
            for p in store.pending_approvals()? {
                let id = store.find_project(&p.project)?.map(|(id, _)| id);
                if cx.allowed(id.as_deref()) {
                    out.push(p);
                }
            }
            return to_json(&out);
        }
        ("POST", "/reveal") => {
            cx.scope("reveal")?;
            let (id, _) = cx.project(store, body.get("project").and_then(Value::as_str))?;
            let key = text(body, "key", "key name")?;
            let r = store.reveal(&id, key, &cx.actor)?;
            return Ok(json!({
                "key": r.key,
                "value": r.value.expose(),
                "provider": r.provider,
                "username": r.username,
                "email": r.email,
                "password": r.password.expose(),
                "url": r.url,
            }));
        }
        ("GET", "/compare") => {
            cx.scope("reveal")?;
            let all = store.fingerprints()?;
            let mine: Vec<_> = all
                .iter()
                .filter(|f| cx.allowed(Some(&f.project_id)))
                .collect();
            return to_json(&mine);
        }
        ("POST", "/inject") => return inject(store, &cx, body),
        ("POST", "/import") => return import(store, &cx, body),
        _ => {}
    }
    if let Some(rest) = path.strip_prefix("/projects/") {
        let mut parts = rest.split('/');
        let (Some(p), Some("secrets"), key, None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::NotFound("Not found".into()));
        };
        let (id, _) = cx.project(store, Some(&decode(p)?))?;
        match (m, key) {
            ("GET", None) => {
                cx.scope("read")?;
                // Archived items are kept out of agents' way, as out of inject.
                let mut items = store.list_items(&id)?;
                if vaultos_core::model::is_agent(&cx.actor) {
                    items.retain(|i| !i.archived);
                }
                return to_json(&items);
            }
            ("POST", None) => return cx.write_secret(store, &id, &fields_from(body)?),
            ("DELETE", Some(k)) if !k.is_empty() => {
                cx.scope("delete:own")?;
                let key = store.delete_item(&id, &decode(k)?, &cx.actor)?;
                return Ok(json!({ "ok": true, "key": key }));
            }
            _ => {}
        }
    }
    Err(Error::NotFound("Not found".into()))
}

fn inject(store: &mut Store, cx: &Ctx<'_>, body: &Map<String, Value>) -> Result<Value> {
    cx.scope("inject")?;
    let (id, _) = cx.project(store, body.get("project").and_then(Value::as_str))?;
    let keys: Option<Vec<String>> = match body.get("keys") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|k| k.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| invalid("keys must be a list of names"))?,
        ),
        Some(_) => return Err(invalid("keys must be a list of names")),
    };
    let merge = match body.get("merge") {
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(invalid("merge must be boolean")),
    };
    let format = match body.get("format") {
        None | Some(Value::Null) => Format::Dotenv,
        Some(Value::String(s)) if s.is_empty() => Format::Dotenv,
        Some(Value::String(s)) => Format::parse(s)?,
        Some(_) => return Err(invalid("Unsupported format")),
    };
    let target = cx.file(store, body.get("target_path"))?;
    to_json(&store.inject(&id, &target, format, merge, keys.as_deref(), &cx.actor)?)
}

fn import(store: &mut Store, cx: &Ctx<'_>, body: &Map<String, Value>) -> Result<Value> {
    cx.scope("add")?;
    let create = match body.get("createProject") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(invalid("createProject must be boolean")),
    };
    let source = cx.file(store, body.get("env_path"))?;
    let pairs = env::read_env_file(&source)?;
    let name = body.get("project").and_then(Value::as_str);
    let exists = match name {
        Some(n) => store.find_project(n)?.is_some(),
        None => false,
    };
    let (id, pname) = if create && !exists {
        cx.create_project(store, body.get("project"))?
    } else {
        cx.project(store, name)?
    };
    let (keys, refused) = store.batch(|s| {
        let (mut keys, mut refused) = (Vec::new(), Vec::new());
        for (key, value) in &pairs {
            let fields = Fields {
                key: key.clone(),
                value: Some(SecretString::new(value.as_str())),
                ..Default::default()
            };
            match cx.write_secret(s, &id, &fields) {
                Ok(_) => keys.push(key.clone()),
                Err(_) => refused.push(key.clone()),
            }
        }
        Ok((keys, refused))
    })?;
    store.audit(
        "import",
        &format!("{pname}: {} keys", keys.len()),
        &cx.actor,
    )?;
    Ok(json!({ "project": pname, "keys": keys, "refused": refused }))
}

/// `/status`: answered without the session token, so it says nothing about the vault's
/// contents.
pub fn status(unlocked: bool, sync: Value) -> Value {
    json!({
        "app": "VaultOS-Preview",
        "ok": true,
        "server": "vaultosd",
        "locked": !unlocked,
        "formatVersion": vaultos_core::format::VERSION,
        "deployment": deployment(),
        "sync": sync,
    })
}

pub fn deployment() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "formatVersion": vaultos_core::format::VERSION,
        "minReaderVersion": vaultos_core::format::VERSION,
    })
}
