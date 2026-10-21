//! Command execution on dest: shell selection, streaming output, timeout and process tree kill.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::proto::{ShellKind, Stream};

/// How long output readers may keep going after the command exited (background children).
const PUMP_GRACE: Duration = Duration::from_secs(1);
/// Size of the buffer used to read command output.
const CHUNK: usize = 8192;
/// PowerShell prefix that makes its output UTF-8.
const PS_UTF8: &str = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ";

/// What to run and how.
pub struct ExecSpec {
    pub command: String,
    pub shell: ShellKind,
    pub cwd: PathBuf,
    pub timeout: Option<Duration>,
}

/// How a command ended.
#[derive(Debug, PartialEq)]
pub struct ExecResult {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// Returns the program and arguments that run `command` with `shell`.
pub fn command_line(shell: ShellKind, command: &str) -> (&'static str, Vec<String>) {
    match shell {
        ShellKind::Bash => ("bash", vec!["-c".into(), command.into()]),
        ShellKind::Sh => ("sh", vec!["-c".into(), command.into()]),
        ShellKind::Powershell | ShellKind::Pwsh => {
            let program = if shell == ShellKind::Pwsh {
                "pwsh"
            } else {
                "powershell.exe"
            };
            let args = ["-NoProfile", "-NonInteractive", "-Command"]
                .map(String::from)
                .to_vec();
            (
                program,
                [args, vec![format!("{PS_UTF8}{command}")]].concat(),
            )
        }
        ShellKind::Cmd => (
            "cmd",
            vec!["/C".into(), format!("chcp 65001>nul & {command}")],
        ),
    }
}

/// Builds the process: no stdin, piped output, own process group (unix).
fn build(spec: &ExecSpec) -> Command {
    let (program, args) = command_line(spec.shell, &spec.command);
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    if spec.shell == ShellKind::Cmd {
        use std::os::windows::process::CommandExt;
        cmd.as_std_mut().raw_arg("/C").raw_arg(&args[1]);
    } else {
        cmd.args(&args);
    }
    #[cfg(not(windows))]
    cmd.args(&args);
    cmd.current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    cmd
}

/// Kills a process and all its descendants.
fn kill_tree(pid: Option<u32>) {
    let Some(pid) = pid else { return };
    #[cfg(unix)]
    // SAFETY: plain kill(2) on the process group created for the command.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .output();
    }
}

/// Forwards everything read from a pipe to the channel until the pipe closes.
async fn pump<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: Stream,
    tx: mpsc::Sender<(Stream, Vec<u8>)>,
) {
    let mut buf = [0u8; CHUNK];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if tx.send((stream, buf[..n].to_vec())).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Converts a finished process status into the exit code (128 + signal on unix when killed).
fn exit_code_of(status: std::process::ExitStatus) -> Option<i32> {
    status.code().or_else(|| signal_code(&status))
}

/// The conventional shell exit code for a process killed by a signal.
#[cfg(unix)]
fn signal_code(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|s| 128 + s)
}

/// Windows has no signals: a process without an exit code has none to report.
#[cfg(not(unix))]
fn signal_code(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Runs a command, sending output chunks to `tx` as they are produced.
pub async fn run(spec: ExecSpec, tx: mpsc::Sender<(Stream, Vec<u8>)>) -> Result<ExecResult> {
    if !spec.cwd.is_dir() {
        bail!(
            "working directory {} does not exist on this machine",
            spec.cwd.display()
        );
    }
    let (program, _) = command_line(spec.shell, &spec.command);
    let mut child = build(&spec)
        .spawn()
        .with_context(|| format!("cannot start shell '{program}' on this machine"))?;
    let pid = child.id();
    let stdout = child.stdout.take().context("stdout not captured")?;
    let stderr = child.stderr.take().context("stderr not captured")?;
    let mut out_task: JoinHandle<()> = tokio::spawn(pump(stdout, Stream::Stdout, tx.clone()));
    let mut err_task: JoinHandle<()> = tokio::spawn(pump(stderr, Stream::Stderr, tx));
    let (status, timed_out) = match spec.timeout {
        None => (child.wait().await?, false),
        Some(limit) => match tokio::time::timeout(limit, child.wait()).await {
            Ok(status) => (status?, false),
            Err(_) => {
                kill_tree(pid);
                (child.wait().await?, true)
            }
        },
    };
    let drained = async {
        let _ = (&mut out_task).await;
        let _ = (&mut err_task).await;
    };
    if tokio::time::timeout(PUMP_GRACE, drained).await.is_err() {
        out_task.abort();
        err_task.abort();
    }
    Ok(ExecResult {
        exit_code: exit_code_of(status),
        timed_out,
    })
}
