//! Implementation of the CLI subcommands.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use crate::cli::{AuthorizedAction, Command};
use crate::client::{self, ExecArgs};
use crate::config::{Config, resolve_port};
use crate::error::RenfieldError;
use crate::identity::Identity;
use crate::pairing::{PairParams, TerminalPrompt, local_name, source_flow};
use crate::proto::{ShellKind, Stream};
use crate::server::{self, FilePolicy, ServerOptions};
use crate::store::{Authorized, Registry};

/// Runs a parsed subcommand and returns the process exit code.
pub async fn dispatch(dir: &Path, command: Command) -> Result<i32, RenfieldError> {
    match command {
        Command::Listen {
            port,
            config,
            accept_key,
            timeout,
        } => {
            let window = accept_key.then(|| Duration::from_secs(timeout));
            listen(dir, port, config, window).await.map(|_| 0)
        }
        Command::List => list(dir).map(|_| 0),
        Command::Remove { name } => remove(dir, &name).map(|_| 0),
        Command::Authorized { action } => match action {
            AuthorizedAction::List => authorized_list(dir).map(|_| 0),
            AuthorizedAction::Revoke { target } => authorized_revoke(dir, &target).map(|_| 0),
        },
        Command::Mcp => crate::mcp::run_stdio(dir.to_path_buf())
            .await
            .map(|_| 0)
            .map_err(|e| RenfieldError::Io(format!("MCP server stopped: {e}"))),
        Command::Put {
            name,
            local,
            remote,
        } => put(dir, &name, &local, &remote).await.map(|_| 0),
        Command::Get {
            name,
            remote,
            local,
        } => get(dir, &name, &remote, &local).await.map(|_| 0),
        Command::Pair {
            name,
            addr,
            both,
            listen_port,
            force,
        } => {
            let params = PairParams {
                dir: dir.to_path_buf(),
                name,
                addr,
                own_name: local_name(),
                both,
                listen_port,
                force,
            };
            source_flow(params, Arc::new(TerminalPrompt))
                .await
                .map(|_| {
                    println!("Paired. Try: renfield exec <name> -- hostname");
                    0
                })
        }
        Command::Exec {
            name,
            shell,
            cwd,
            timeout,
            command,
        } => exec(dir, &name, shell, cwd, timeout, command).await,
    }
}

/// Starts dest: loads or creates the identity and serves until the process is stopped.
pub async fn listen(
    dir: &Path,
    port: Option<u16>,
    config: Option<PathBuf>,
    pairing_window: Option<Duration>,
) -> Result<(), RenfieldError> {
    let io = |e: anyhow::Error| RenfieldError::Io(format!("{e:#}"));
    let cfg = match &config {
        Some(path) => Config::load(path, true),
        None => Config::load_default(dir),
    }
    .map_err(io)?;
    let id = Identity::load_or_create(dir).map_err(io)?;
    let port = resolve_port(port, &cfg);
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| RenfieldError::Io(format!("cannot listen on port {port}: {e} (is another renfield running, or is the port in use?)")))?;
    println!(
        "renfield listening on port {port}, key fingerprint {}",
        id.fingerprint()
    );
    let policy = Arc::new(FilePolicy::new(dir));
    let mut opts = ServerOptions {
        default_cwd: cfg.default_cwd,
        max_timeout_secs: cfg.max_timeout_secs,
        prompt: None,
        ..ServerOptions::default()
    };
    if let Some(window) = pairing_window {
        opts.prompt = Some(Arc::new(TerminalPrompt));
        policy.open_pairing_for(window);
        println!(
            "Pairing mode: accepting a new key for the next {} seconds.",
            window.as_secs()
        );
    }
    server::serve(listener, id, policy, opts).await.map_err(io)
}

/// Runs a remote command, mirroring its output; returns the remote exit code.
pub async fn exec(
    dir: &Path,
    name: &str,
    shell: Option<ShellKind>,
    cwd: Option<String>,
    timeout: Option<u64>,
    command: Vec<String>,
) -> Result<i32, RenfieldError> {
    let mut conn = client::connect(dir, name).await?;
    let args = ExecArgs {
        command: command.join(" "),
        shell,
        cwd,
        timeout_secs: timeout,
    };
    let outcome = conn
        .exec(args, |stream, bytes| match stream {
            Stream::Stdout => write_flush(&mut std::io::stdout(), bytes),
            Stream::Stderr => write_flush(&mut std::io::stderr(), bytes),
        })
        .await?;
    if outcome.timed_out {
        return Err(RenfieldError::Timeout(format!(
            "the command on '{name}' was killed after the timeout"
        )));
    }
    Ok(outcome.exit_code.unwrap_or(1))
}

/// Writes and flushes, ignoring a closed output (for example a broken pipe).
fn write_flush<W: Write>(out: &mut W, bytes: &[u8]) {
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

/// Files at least this big show a progress line.
const PROGRESS_MIN_BYTES: u64 = 8 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// Returns a progress callback printing whole MiB on stderr (silent for small files).
fn progress_printer() -> impl FnMut(u64, u64) + Send {
    let mut last = u64::MAX;
    move |done, total| {
        if total < PROGRESS_MIN_BYTES {
            return;
        }
        let mib = done / MIB;
        if mib != last {
            last = mib;
            eprint!("\r{mib}/{} MiB", total / MIB);
        }
        if done == total {
            eprintln!();
        }
    }
}

/// Uploads a local file to a paired machine.
pub async fn put(dir: &Path, name: &str, local: &Path, remote: &str) -> Result<(), RenfieldError> {
    let mut conn = client::connect(dir, name).await?;
    let bytes = conn
        .put_file(local, remote, &mut progress_printer())
        .await?;
    println!(
        "{} -> {name}:{remote} ({bytes} bytes, checksum verified)",
        local.display()
    );
    Ok(())
}

/// Downloads a file from a paired machine.
pub async fn get(dir: &Path, name: &str, remote: &str, local: &Path) -> Result<(), RenfieldError> {
    let mut conn = client::connect(dir, name).await?;
    let bytes = conn
        .get_file(remote, local, &mut progress_printer())
        .await?;
    println!(
        "{name}:{remote} -> {} ({bytes} bytes, checksum verified)",
        local.display()
    );
    Ok(())
}

/// Converts a store failure into a renfield error.
fn store_error(e: anyhow::Error) -> RenfieldError {
    RenfieldError::Io(format!("{e:#}"))
}

/// Prints the registry: name, address and the start of the pinned key.
pub fn list(dir: &Path) -> Result<(), RenfieldError> {
    let registry = Registry::load(dir).map_err(store_error)?;
    if registry.machine.is_empty() {
        println!("No machines paired yet. Pair one with: renfield pair <name> <host:port>");
        return Ok(());
    }
    println!("{:<20} {:<24} KEY", "NAME", "ADDRESS");
    for m in &registry.machine {
        println!("{:<20} {:<24} {}", m.name, m.addr, short(&m.fingerprint));
    }
    Ok(())
}

/// Shows the first characters of a fingerprint.
fn short(fingerprint: &str) -> String {
    fingerprint.chars().take(16).collect()
}

/// Removes a machine from the registry.
pub fn remove(dir: &Path, name: &str) -> Result<(), RenfieldError> {
    let mut registry = Registry::load(dir).map_err(store_error)?;
    if !registry.remove(name) {
        return Err(RenfieldError::NotPaired(name.to_string()));
    }
    registry.save(dir).map_err(store_error)?;
    println!("Removed '{name}'.");
    Ok(())
}

/// Prints the keys allowed to command this machine.
pub fn authorized_list(dir: &Path) -> Result<(), RenfieldError> {
    let authorized = Authorized::load(dir).map_err(store_error)?;
    if authorized.key.is_empty() {
        println!(
            "No key is authorized: nobody can command this machine. Pair with: renfield listen --accept-key"
        );
        return Ok(());
    }
    println!("{:<20} FINGERPRINT", "LABEL");
    for k in &authorized.key {
        println!("{:<20} {}", k.label, k.fingerprint);
    }
    Ok(())
}

/// Revokes an authorized key by label or fingerprint.
pub fn authorized_revoke(dir: &Path, target: &str) -> Result<(), RenfieldError> {
    let mut authorized = Authorized::load(dir).map_err(store_error)?;
    if !authorized.revoke(target) {
        return Err(RenfieldError::Usage(format!(
            "no authorized key matches '{target}'. See the labels and fingerprints with: renfield authorized list"
        )));
    }
    authorized.save(dir).map_err(store_error)?;
    println!("Revoked '{target}': it can no longer command this machine.");
    Ok(())
}
