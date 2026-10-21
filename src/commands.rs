//! Implementation of the CLI subcommands.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::cli::Command;
use crate::client::{self, ExecArgs};
use crate::config::{Config, resolve_port};
use crate::error::RenfieldError;
use crate::identity::Identity;
use crate::proto::{ShellKind, Stream};
use crate::server::{self, FilePolicy, ServerOptions};

/// Runs a parsed subcommand and returns the process exit code.
pub async fn dispatch(dir: &Path, command: Command) -> Result<i32, RenfieldError> {
    match command {
        Command::Listen { port, config } => listen(dir, port, config).await.map(|_| 0),
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
    let opts = ServerOptions {
        default_cwd: cfg.default_cwd,
        max_timeout_secs: cfg.max_timeout_secs,
    };
    let policy = Arc::new(FilePolicy::new(dir));
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
