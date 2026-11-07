//! `vaultos-agent`: VaultOS for enrolled agents. Every command
//! is one request to `vaultosd` with this agent's token; values are never printed. `run`
//! gives an allowed command a project's values and masks them in its output.

use clap::error::ErrorKind;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use vaultos_cli::{emit, read_stdin, Fail, Result};
use vaultos_client::{enc, Client};

const TOKEN_HELP: &str = "Token: VAULTOS_AGENT_TOKEN, VAULTOS_AGENT_TOKEN_FILE (mode 0600), or \
VAULTOS_AGENT=NAME for <data dir>/agents/NAME.token. VAULTOS_DATA_DIR selects a non-default \
data directory.";

#[derive(Debug, Parser)]
#[command(
    name = "vaultos-agent",
    version,
    about = "VaultOS for enrolled agents (values are never printed)",
    after_help = TOKEN_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Dotenv,
    Json,
    Shell,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Is VaultOS running and unlocked?
    Status,
    /// This agent's identity and grants
    Whoami,
    /// Ask the human for temporary scopes on one project; they confirm in the app
    RequestAccess {
        #[arg(long)]
        project: String,
        /// A scope to ask for (repeatable): read, add, edit:own, edit:delegated, delete:own,
        /// inject, run or reveal
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        /// 1 to 60 (default 15)
        #[arg(long)]
        minutes: Option<u64>,
        /// What the access is for, shown to the human
        #[arg(long)]
        reason: String,
    },
    /// Approved projects
    Projects,
    /// Key names and metadata
    Keys { project: String },
    /// Find keys across approved projects
    Search {
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
    },
    /// Write approved keys into FILE (merges by default)
    Inject {
        project: String,
        file: PathBuf,
        /// Only these keys (comma-separated)
        #[arg(long, value_name = "A,B")]
        keys: Option<String>,
        #[arg(long, value_enum, default_value = "dotenv")]
        format: Format,
        /// Replace the file instead of merging into it
        #[arg(long)]
        replace: bool,
    },
    /// Store a key; the value is read from stdin only:  printf %s "$VALUE" | vaultos-agent add PROJECT KEY
    Add {
        project: String,
        key: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        /// Caught so that a value passed by mistake is refused, never echoed.
        #[arg(hide = true, num_args = 0.., allow_hyphen_values = true)]
        extra: Vec<String>,
    },
    /// Store every KEY=VALUE from an env file
    Import {
        project: String,
        env_file: PathBuf,
        #[arg(long)]
        create_project: bool,
    },
    /// Explain how sync runs (owner-only)
    Sync,
    /// Agent-created keys awaiting human approval
    Pending,
    /// Run an allowed command here with a project's values in its environment, masked in
    /// its output (run scope)
    Run {
        project: String,
        /// Only these keys (comma-separated)
        #[arg(long, value_name = "A,B")]
        keys: Option<String>,
        /// The command and its arguments, after --
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
}

/// `path.resolve`: relative to the working directory, with `.` and `..` resolved.
fn absolute(p: &std::path::Path) -> Result<String> {
    let cwd =
        std::env::current_dir().map_err(|_| Fail::new("cannot read the working directory"))?;
    Ok(vaultos_core::agents::resolve_lexically(&cwd.join(p))
        .to_string_lossy()
        .into_owned())
}

fn run(command: Command, client: &Client) -> Result<()> {
    let get = |route: &str| client.request("GET", route, None).map_err(Fail::from);
    match command {
        Command::Status => emit(&client.status()),
        Command::Whoami => emit(&get("/whoami")?),
        Command::RequestAccess {
            project,
            scopes,
            minutes,
            reason,
        } => {
            let body = json!({ "project": project, "scopes": scopes, "minutes": minutes, "reason": reason });
            emit(&client.request("POST", "/access/request", Some(&body))?)
        }
        Command::Projects => emit(&get("/projects")?),
        Command::Keys { project } => emit(&get(&format!("/projects/{}/secrets", enc(&project)))?),
        Command::Search { text } => emit(&get(&format!("/search?q={}", enc(&text.join(" "))))?),
        Command::Pending => emit(&get("/pending")?),
        Command::Inject {
            project,
            file,
            keys,
            format,
            replace,
        } => {
            let keys = keys.map(|k| {
                k.split(',')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            });
            let format = match format {
                Format::Dotenv => "dotenv",
                Format::Json => "json",
                Format::Shell => "shell",
            };
            let body = json!({
                "project": project,
                "target_path": absolute(&file)?,
                "format": format,
                "merge": !replace,
                "keys": keys,
            });
            let r = client.request("POST", "/inject", Some(&body))?;
            let mut out = Map::new();
            out.insert("project".into(), r["project"].clone());
            out.insert("file".into(), r["target"].clone());
            out.insert("format".into(), r["format"].clone());
            out.insert("wrote".into(), r["count"].clone());
            if r["heldForApproval"].as_array().is_some_and(|h| !h.is_empty()) {
                out.insert("heldForApproval".into(), r["heldForApproval"].clone());
            }
            emit(&out)
        }
        Command::Add {
            project,
            key,
            note,
            provider,
            extra,
        } => {
            let usage = "pipe the value on stdin, e.g. printf %s \"$VALUE\" | vaultos-agent add PROJECT KEY";
            if !extra.is_empty() {
                return Err(Fail::usage(
                    "The value is read from stdin only; never pass it as an argument",
                ));
            }
            if std::io::stdin().is_terminal() {
                return Err(Fail::usage(usage));
            }
            let mut value = read_stdin(65536, "Value is too large")?;
            if value.ends_with('\n') {
                value.pop();
                if value.ends_with('\r') {
                    value.pop();
                }
            }
            if value.is_empty() {
                return Err(Fail::usage("No value was received on stdin"));
            }
            let mut body = Map::new();
            body.insert("key".into(), json!(key));
            body.insert("value".into(), json!(value.as_str()));
            if let Some(n) = note {
                body.insert("note".into(), json!(n));
            }
            if let Some(p) = provider {
                body.insert("provider".into(), json!(p));
            }
            let mut body = Value::Object(body);
            let route = format!("/projects/{}/secrets", enc(&project));
            let r = client.request("POST", &route, Some(&body));
            if let Some(Value::String(v)) = body.get_mut("value") {
                zeroize::Zeroize::zeroize(v);
            }
            let r = r?;
            emit(&json!({
                "project": project,
                "stored": r["key"],
                "owner": r["owner"],
                "injectApproved": r["injectApproved"],
            }))
        }
        Command::Import {
            project,
            env_file,
            create_project,
        } => {
            let mut body = json!({ "project": project, "env_path": absolute(&env_file)? });
            if create_project {
                body["createProject"] = json!(true);
            }
            emit(&client.request("POST", "/import", Some(&body))?)
        }
        Command::Run {
            project,
            keys,
            command,
        } => {
            use vaultos_client::run::{stream, Program};
            let keys = keys.map(|k| {
                k.split(',')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            });
            let body = json!({
                "project": project,
                "command": command,
                "cwd": absolute(std::path::Path::new("."))?,
                "keys": keys,
            });
            let r = client.request("POST", "/run/env", Some(&body))?;
            if let Some(held) = r["heldForApproval"].as_array().filter(|h| !h.is_empty()) {
                let names: Vec<&str> = held.iter().filter_map(Value::as_str).collect();
                eprintln!("vaultos-agent: left out keys awaiting approval: {}", names.join(", "));
            }
            let env = r["values"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .map(|p| {
                            let value = p["value"].as_str().unwrap_or_default().to_owned();
                            (
                                p["key"].as_str().unwrap_or_default().to_owned(),
                                zeroize::Zeroizing::new(value),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let program = Program {
                argv: command.into_iter().map(Into::into).collect(),
                cwd: r["cwd"].as_str().map(Into::into),
                env,
                plain: Vec::new(),
            };
            match stream(&program, true)
                .map_err(|e| Fail::new(format!("cannot run the command: {e}")))?
            {
                0 => Ok(()),
                c => Err(Fail::quiet(u8::try_from(c).unwrap_or(1))),
            }
        }
        Command::Sync => match client.request("POST", "/sync", None) {
            Ok(r) => emit(&r),
            Err(e) if e.status == Some(404) => Err(Fail::new(
                "This VaultOS owner has no sync route. Ask the human to run `vaultos sync push` or `vaultos sync pull`.",
            )),
            Err(e) if e.status == Some(403) => Err(Fail::new(
                "Sync is an owner action, not an agent permission. Autosync runs in the owner when enabled; a human can run `vaultos sync now`.",
            )),
            Err(e) => Err(e.into()),
        },
    }
}

fn main() -> ExitCode {
    vaultos_core::hardening::harden_process();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
            let _ = e.print();
            return ExitCode::SUCCESS;
        }
        // An unexpected argument may be a value typed in the wrong place; do not echo it.
        Err(e) if e.kind() == ErrorKind::UnknownArgument => {
            eprintln!("vaultos-agent: unexpected argument (not shown); run vaultos-agent help");
            return ExitCode::from(2);
        }
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(2);
        }
    };
    let data_dir = match vaultos_core::paths::default_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("vaultos-agent: {e}");
            return ExitCode::from(2);
        }
    };
    match run(cli.command, &Client::from_env(data_dir)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            if !f.message.is_empty() {
                eprintln!("vaultos-agent: {}", f.message);
            }
            ExitCode::from(f.code)
        }
    }
}
