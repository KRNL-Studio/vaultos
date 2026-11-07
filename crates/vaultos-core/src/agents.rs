//! Enrolled agents, ported from `agents.js`: identity, token hashes, scopes, and grants to
//! projects and folders. Records live in the vault's metadata in the JavaScript app's shape.

use crate::crypto::{ct_eq, hex, random_array, random_id, sha256_hex};
use crate::error::{Error, Result};
use crate::model::{agent_ref, now_iso};
use crate::secret::SecretString;
use crate::store::Store;
use crate::validate;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub const ALL_SCOPES: [&str; 7] = [
    "read",
    "add",
    "edit:own",
    "edit:delegated",
    "delete:own",
    "inject",
    "reveal",
];
pub const DEFAULT_SCOPES: [&str; 2] = ["read", "inject"];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub roots: Vec<String>,
    #[serde(default)]
    pub all_projects: bool,
    #[serde(default)]
    pub any_root: bool,
    #[serde(default)]
    pub enrolled_at: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Agent {
    pub fn reference(&self) -> String {
        agent_ref(&self.id)
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn allowed_project(&self, id: &str) -> bool {
        !id.is_empty() && (self.all_projects || self.projects.iter().any(|p| p == id))
    }
}

/// What `agents list` shows: everything but the token hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub name: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub scopes: Vec<String>,
    pub enrolled_at: String,
    pub last_seen_at: Option<String>,
    pub revoked: bool,
    pub revoked_at: Option<String>,
    pub projects: Vec<String>,
    pub roots: Vec<String>,
    pub all_projects: bool,
    pub any_root: bool,
}

/// A new or reissued token. It is shown once, to be written to a private file.
#[derive(Debug)]
pub struct Issued {
    pub id: String,
    pub name: String,
    pub reference: String,
    pub token: SecretString,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wildcards {
    pub all_projects: bool,
    pub any_root: bool,
}

pub fn new_token() -> SecretString {
    SecretString::new(hex(&random_array::<32>()))
}

pub fn token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

fn check_scopes(scopes: &[String]) -> Result<Vec<String>> {
    let bad: Vec<&str> = scopes
        .iter()
        .filter(|s| !ALL_SCOPES.contains(&s.as_str()))
        .map(String::as_str)
        .collect();
    if !bad.is_empty() {
        return Err(Error::invalid(format!(
            "unknown scope(s): {}",
            bad.join(", ")
        )));
    }
    let mut out: Vec<String> = Vec::new();
    for s in scopes {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    Ok(out)
}

fn not_found() -> Error {
    Error::not_found("Agent not found")
}

impl Store {
    pub fn agent_records(&self) -> Result<Vec<Agent>> {
        self.agents()?
            .iter()
            .map(|v| {
                serde_json::from_value(v.clone())
                    .map_err(|_| Error::Format("an agent record is malformed".into()))
            })
            .collect()
    }

    fn save_agents(&mut self, agents: &[Agent]) -> Result<()> {
        let values = agents
            .iter()
            .map(|a| serde_json::to_value(a).map_err(|e| Error::Format(e.to_string())))
            .collect::<Result<Vec<_>>>()?;
        self.set_agents(values)
    }

    pub fn list_agents(&self) -> Result<Vec<Summary>> {
        Ok(self
            .agent_records()?
            .into_iter()
            .map(|a| Summary {
                reference: a.reference(),
                revoked: a.revoked_at.is_some(),
                id: a.id,
                name: a.name,
                scopes: a.scopes,
                enrolled_at: a.enrolled_at,
                last_seen_at: a.last_seen_at,
                revoked_at: a.revoked_at,
                projects: a.projects,
                roots: a.roots,
                all_projects: a.all_projects,
                any_root: a.any_root,
            })
            .collect())
    }

    /// An agent by id or (case-insensitive) name.
    pub fn find_agent(&self, id_or_name: &str) -> Result<Option<Agent>> {
        let lower = id_or_name.to_lowercase();
        let all = self.agent_records()?;
        Ok(all
            .iter()
            .find(|a| a.name.to_lowercase() == lower)
            .or_else(|| all.iter().find(|a| a.id == id_or_name))
            .cloned())
    }

    /// Checks grants: projects must exist (they are stored by id) and folders must be real,
    /// absolute directories that neither are the filesystem root nor contain the vault.
    pub fn validate_access(
        &self,
        projects: &[String],
        roots: &[String],
    ) -> Result<(Vec<String>, Vec<String>)> {
        if projects.len() > 1000 || roots.len() > 100 {
            return Err(Error::invalid("Invalid agent access"));
        }
        let mut ids: Vec<String> = Vec::new();
        for p in projects {
            let (id, _) = self
                .find_project(p)?
                .ok_or_else(|| Error::not_found("Project not found"))?;
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        let data = std::fs::canonicalize(self.data_dir())
            .map_err(Error::io("cannot resolve the data directory"))?;
        let mut folders: Vec<String> = Vec::new();
        for r in roots {
            let choose = || Error::invalid("Choose an existing absolute folder");
            let path = Path::new(r);
            if !path.is_absolute() || !path.is_dir() {
                return Err(choose());
            }
            let canonical = std::fs::canonicalize(path).map_err(|_| choose())?;
            if canonical.parent().is_none() || data == canonical || data.starts_with(&canonical) {
                return Err(Error::invalid(
                    "Choose a project folder, not a folder containing the vault",
                ));
            }
            let s = canonical.to_string_lossy().into_owned();
            if !folders.contains(&s) {
                folders.push(s);
            }
        }
        Ok((ids, folders))
    }

    pub fn enrol_agent(
        &mut self,
        name: &str,
        scopes: Option<&[String]>,
        projects: &[String],
        roots: &[String],
        wildcards: Wildcards,
    ) -> Result<Issued> {
        validate::text(name, "agent name", 100, false)?;
        let (projects, roots) = self.validate_access(projects, roots)?;
        let mut all = self.agent_records()?;
        let lower = name.to_lowercase();
        if all.iter().any(|a| a.name.to_lowercase() == lower) {
            return Err(Error::Conflict(format!(
                "an agent named \"{name}\" is already enrolled"
            )));
        }
        let scopes = match scopes {
            Some(s) => check_scopes(s)?,
            None => DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        };
        let token = new_token();
        let agent = Agent {
            id: random_id(),
            name: name.trim().to_owned(),
            token_hash: token_hash(token.expose()),
            scopes,
            projects,
            roots,
            all_projects: wildcards.all_projects,
            any_root: wildcards.any_root,
            enrolled_at: now_iso(),
            last_seen_at: None,
            revoked_at: None,
            extra: Map::new(),
        };
        let issued = Issued {
            id: agent.id.clone(),
            name: agent.name.clone(),
            reference: agent.reference(),
            token,
        };
        all.push(agent);
        self.save_agents(&all)?;
        Ok(issued)
    }

    fn change_agent<R>(&mut self, id: &str, f: impl FnOnce(&mut Agent) -> R) -> Result<R> {
        let mut all = self.agent_records()?;
        let a = all.iter_mut().find(|a| a.id == id).ok_or_else(not_found)?;
        let r = f(a);
        self.save_agents(&all)?;
        Ok(r)
    }

    pub fn set_agent_access(
        &mut self,
        id: &str,
        projects: &[String],
        roots: &[String],
        wildcards: Wildcards,
    ) -> Result<()> {
        let (projects, roots) = self.validate_access(projects, roots)?;
        self.change_agent(id, |a| {
            a.projects = projects;
            a.roots = roots;
            a.all_projects = wildcards.all_projects;
            a.any_root = wildcards.any_root;
        })
    }

    pub fn set_agent_scopes(&mut self, id: &str, scopes: &[String]) -> Result<()> {
        let scopes = check_scopes(scopes)?;
        self.change_agent(id, |a| a.scopes = scopes)
    }

    /// A new token for an agent; the old one stops working, and a revoked agent is restored.
    pub fn reissue_agent(&mut self, id: &str) -> Result<Issued> {
        let token = new_token();
        let hash = token_hash(token.expose());
        self.change_agent(id, |a| {
            a.token_hash = hash;
            a.revoked_at = None;
            Issued {
                id: a.id.clone(),
                name: a.name.clone(),
                reference: a.reference(),
                token,
            }
        })
    }

    /// Adds a project to an agent's grants (the agent created it).
    pub fn grant_project(&mut self, id: &str, project_id: &str) -> Result<()> {
        self.change_agent(id, |a| {
            if !a.projects.iter().any(|p| p == project_id) {
                a.projects.push(project_id.to_owned());
            }
        })
    }

    pub fn revoke_agent(&mut self, id: &str) -> Result<()> {
        self.change_agent(id, |a| a.revoked_at = Some(now_iso()))
    }

    /// The active agent holding `token`, comparing hashes in constant time.
    pub fn authenticate_agent(&self, token: &str) -> Result<Option<Agent>> {
        if token.is_empty() {
            return Ok(None);
        }
        let h = token_hash(token);
        Ok(self
            .agent_records()?
            .into_iter()
            .find(|a| ct_eq(a.token_hash.as_bytes(), h.as_bytes()))
            .filter(|a| a.revoked_at.is_none()))
    }
}

/// Lexically resolves `..` and `.` in an absolute path, as Node's `path.resolve` does.
pub fn resolve_lexically(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn absolute(target: &str) -> Result<PathBuf> {
    let p = Path::new(target);
    if !p.is_absolute() || target.contains('\0') {
        return Err(Error::invalid("An absolute file path is required"));
    }
    Ok(resolve_lexically(p))
}

fn symlink_at(p: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(p) {
        Ok(m) => Ok(m.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("cannot inspect a file path")(e)),
    }
}

/// `fs-safe.js` `checkedPath`: a path inside one of the agent's folders, with no symbolic link
/// between the folder and the file, and the folder itself unchanged since it was approved.
pub fn checked_path(target: &str, roots: &[String]) -> Result<PathBuf> {
    let target = absolute(target)?;
    let root = roots
        .iter()
        .map(PathBuf::from)
        .find(|r| target.starts_with(r) && target != *r)
        .ok_or_else(|| {
            Error::invalid("This path is outside the folders approved for this agent")
        })?;
    if std::fs::canonicalize(&root).ok().as_deref() != Some(root.as_path()) {
        return Err(Error::invalid("Approved folder changed; approve it again"));
    }
    let mut p = root.clone();
    for part in target
        .strip_prefix(&root)
        .unwrap_or(Path::new(""))
        .components()
    {
        p.push(part);
        if symlink_at(&p)? {
            return Err(Error::invalid(
                "Symbolic links are not allowed in file paths",
            ));
        }
    }
    Ok(target)
}

/// `api.js` `canonicalTarget`, for agents allowed any folder: the real path of the deepest
/// existing ancestor, plus the parts that do not exist yet. A link as the target is refused.
pub fn canonical_target(target: &str) -> Result<PathBuf> {
    let full = absolute(target)?;
    let mut base = full;
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::symlink_metadata(&base) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (Some(name), Some(parent)) = (base.file_name(), base.parent()) else {
                    return Err(Error::io("cannot resolve the file path")(e));
                };
                rest.insert(0, name.to_owned());
                base = parent.to_path_buf();
            }
            Err(e) => return Err(Error::io("cannot resolve the file path")(e)),
        }
    }
    if rest.is_empty() && symlink_at(&base)? {
        return Err(Error::invalid(
            "Symbolic links are not allowed as file paths",
        ));
    }
    let mut out =
        std::fs::canonicalize(&base).map_err(Error::io("cannot resolve the file path"))?;
    out.extend(rest);
    Ok(out)
}

impl Agent {
    /// Where this agent may read or write a file: inside its folders, or anywhere when it is
    /// allowed any folder, but never the vault's own files.
    pub fn file_target(&self, target: &str, data_dir: &Path) -> Result<PathBuf> {
        let resolved = if self.any_root {
            canonical_target(target)?
        } else {
            checked_path(target, &self.roots)?
        };
        let real = std::fs::canonicalize(data_dir).ok();
        for dir in std::iter::once(data_dir).chain(real.as_deref()) {
            if resolved.starts_with(dir) {
                return Err(Error::forbidden("Vault files are not export destinations"));
            }
        }
        Ok(resolved)
    }
}
