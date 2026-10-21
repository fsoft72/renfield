//! The dest side: accepts TLS connections and serves requests from authorized sources.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::exec::{self, ExecSpec};
use crate::files;
use crate::home;
use crate::identity::Identity;
use crate::pairing::{self, DestContext, Offer, Prompt};
use crate::proto::{self, Frame, Request, Response, ShellKind, Stream};
use crate::store::Authorized;
use crate::timefmt::{format_utc, now_secs};
use crate::tls::{self, PeerPolicy};
use crate::transfer::{self, Incoming, TransferError};

/// Settings of a running dest.
#[derive(Clone, Default)]
pub struct ServerOptions {
    /// Working directory of commands when the caller gives none.
    pub default_cwd: Option<String>,
    /// Hard upper bound, in seconds, for any command.
    pub max_timeout_secs: Option<u64>,
    /// Asks the human to accept a key; when absent this dest never pairs.
    pub prompt: Option<Arc<dyn Prompt>>,
    /// How long a new connection may stay silent (handshake, then first request); default 10 s.
    pub first_contact_timeout: Option<Duration>,
}

/// Default for [`ServerOptions::first_contact_timeout`].
const DEFAULT_FIRST_CONTACT: Duration = Duration::from_secs(10);

/// Authorization policy backed by `authorized.toml`, re-read on every check so changes apply at once.
pub struct FilePolicy {
    dir: PathBuf,
    pairing: AtomicBool,
    busy: AtomicBool,
}

impl FilePolicy {
    /// Creates a policy reading the authorized keys from `dir`.
    pub fn new(dir: &Path) -> FilePolicy {
        FilePolicy {
            dir: dir.to_path_buf(),
            pairing: AtomicBool::new(false),
            busy: AtomicBool::new(false),
        }
    }

    /// The configuration directory this policy reads and writes.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Opens or closes the pairing window (unknown peers may connect while it is open).
    pub fn set_pairing(&self, open: bool) {
        self.pairing.store(open, Ordering::SeqCst);
    }

    /// Opens the pairing window and closes it again after `window`.
    pub fn open_pairing_for(self: &Arc<Self>, window: Duration) {
        self.set_pairing(true);
        let policy = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            if policy.pairing_open() {
                policy.set_pairing(false);
                println!("pairing window closed");
            }
        });
    }

    /// Claims the single pairing slot; false when the window is closed or another pairing is running.
    pub fn try_begin_pairing(&self) -> bool {
        if !self.pairing_open() {
            return false;
        }
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Ends the running pairing and closes the window: one attempt per window.
    pub fn finish_pairing(&self) {
        self.set_pairing(false);
        self.busy.store(false, Ordering::SeqCst);
    }
}

impl PeerPolicy for FilePolicy {
    fn is_authorized(&self, fingerprint: &str) -> bool {
        Authorized::load(&self.dir)
            .map(|a| a.contains(fingerprint))
            .unwrap_or(false)
    }

    fn pairing_open(&self) -> bool {
        self.pairing.load(Ordering::SeqCst)
    }
}

/// Everything a connection handler needs to know about the server.
struct Shared {
    own_fingerprint: String,
    policy: Arc<FilePolicy>,
    opts: ServerOptions,
}

/// Accepts connections forever, serving each one on its own task.
pub async fn serve(
    listener: TcpListener,
    id: Identity,
    policy: Arc<FilePolicy>,
    opts: ServerOptions,
) -> Result<()> {
    let config = tls::server_config(&id, policy.clone())?;
    let acceptor = TlsAcceptor::from(config);
    let shared = Arc::new(Shared {
        own_fingerprint: id.fingerprint(),
        policy,
        opts,
    });
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("cannot accept a connection: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        tokio::spawn(async move {
            let limit = shared
                .opts
                .first_contact_timeout
                .unwrap_or(DEFAULT_FIRST_CONTACT);
            let mut stream = match tokio::time::timeout(limit, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    eprintln!("refused connection from {peer}: {e}");
                    return;
                }
                Err(_) => return,
            };
            let fingerprint = tls::peer_fingerprint(stream.get_ref().1).unwrap_or_default();
            if let Err(e) = handle_connection(&mut stream, &fingerprint, peer, &shared).await
                && !is_normal_close(&e)
            {
                eprintln!("connection from {peer} ended with error: {e}");
            }
        });
    }
}

/// Serves requests on one connection until the peer closes it.
async fn handle_connection<S>(
    stream: &mut S,
    fingerprint: &str,
    peer: SocketAddr,
    shared: &Shared,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let label = peer_label(&shared.policy, fingerprint);
    let mut first_contact = Some(
        shared
            .opts
            .first_contact_timeout
            .unwrap_or(DEFAULT_FIRST_CONTACT),
    );
    while let Some(request) = read_request(stream, first_contact.take()).await? {
        let operation = describe(&request);
        let mut summary = String::from("ok");
        match request {
            Request::PairOffer {
                source_name,
                both,
                source_listen_port,
            } => {
                audit(
                    &label,
                    &format!("pairing offer from '{source_name}'"),
                    "handled",
                );
                let ctx = DestContext {
                    policy: &shared.policy,
                    own_fingerprint: &shared.own_fingerprint,
                    peer_fingerprint: fingerprint,
                    peer_addr: peer,
                    prompt: shared.opts.prompt.clone(),
                };
                return pairing::dest_handle_offer(
                    stream,
                    &ctx,
                    Offer {
                        source_name,
                        both,
                        source_listen_port,
                    },
                )
                .await;
            }
            _ if !shared.policy.is_authorized(fingerprint) => {
                audit(
                    &label,
                    &operation.unwrap_or_default(),
                    "refused: key not authorized",
                );
                return proto::send(stream, &Response::NotAuthorized).await;
            }
            Request::Exec {
                command,
                args,
                shell,
                cwd,
                timeout_secs,
            } => {
                let job = ExecJob {
                    command,
                    args,
                    shell,
                    cwd,
                    timeout_secs,
                };
                handle_exec(stream, &shared.opts, job, &mut summary).await?;
            }
            Request::ReadFile { .. }
            | Request::WriteFile { .. }
            | Request::EditFile { .. }
            | Request::ListDir { .. } => {
                let response = handle_file_request(request).await;
                if let Response::Error { message } = &response {
                    summary = format!("error: {message}");
                }
                proto::send(stream, &response).await?;
            }
            Request::PutFile { path, size } => {
                let in_sync = handle_put(stream, &path, size, &mut summary).await;
                audit(&label, &operation.unwrap_or_default(), &summary);
                if !in_sync? {
                    return Ok(());
                }
                continue;
            }
            Request::GetFile { path } => handle_get(stream, &path, &mut summary).await?,
            Request::PairCommit | Request::PairAbort => {
                let message = "unexpected pairing message, no pairing is in progress".to_string();
                return proto::send(stream, &Response::Error { message }).await;
            }
        }
        audit(&label, &operation.unwrap_or_default(), &summary);
    }
    Ok(())
}

/// Reads the next request; with a `limit`, a peer that stays silent that long is dropped.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: Option<Duration>,
) -> std::io::Result<Option<Request>> {
    let Some(limit) = limit else {
        return proto::recv(stream).await;
    };
    match tokio::time::timeout(limit, proto::recv(stream)).await {
        Ok(read) => read,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no request received in time",
        )),
    }
}

/// The name shown in the audit log for a peer: its authorization label, else its key prefix.
fn peer_label(policy: &FilePolicy, fingerprint: &str) -> String {
    let label = Authorized::load(policy.dir())
        .ok()
        .and_then(|a| a.find(fingerprint).map(|k| k.label.clone()));
    label.unwrap_or_else(|| fingerprint.chars().take(12).collect())
}

/// Describes a request for the audit log (nothing for the pairing messages, which log themselves).
fn describe(request: &Request) -> Option<String> {
    Some(match request {
        Request::Exec { command, args, .. } => {
            let line = std::iter::once(command.as_str())
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            format!("exec '{}'", audit_text(&line))
        }
        Request::ReadFile { path, .. } => format!("read {}", audit_text(path)),
        Request::WriteFile { path, .. } => format!("write {}", audit_text(path)),
        Request::EditFile { path, .. } => format!("edit {}", audit_text(path)),
        Request::ListDir { path, .. } => format!("list {}", audit_text(path)),
        Request::PutFile { path, size } => format!("put {} ({size} bytes)", audit_text(path)),
        Request::GetFile { path } => format!("get {}", audit_text(path)),
        _ => return None,
    })
}

/// Longest text shown for a command or path in the audit log.
const AUDIT_MAX_CHARS: usize = 80;

/// Flattens line breaks and shortens text so one request is one audit line.
fn audit_text(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= AUDIT_MAX_CHARS {
        return flat;
    }
    let cut: String = flat.chars().take(AUDIT_MAX_CHARS).collect();
    format!("{cut}...")
}

/// Formats one audit line: time, peer, operation and result.
fn audit_line(secs: i64, peer: &str, operation: &str, result: &str) -> String {
    format!("[{}] {peer} {operation} -> {result}", format_utc(secs))
}

/// Prints one audit line for a request served to a peer.
fn audit(peer: &str, operation: &str, result: &str) {
    println!("{}", audit_line(now_secs(), peer, operation, result));
}

/// Serves a file request on a blocking thread and turns any failure into an `Error` answer.
async fn handle_file_request(request: Request) -> Response {
    let work = tokio::task::spawn_blocking(move || -> anyhow::Result<Response> {
        match request {
            Request::ReadFile {
                path,
                offset,
                limit,
            } => files::read_text(&path, offset, limit).map(Response::FileText),
            Request::WriteFile { path, content } => {
                files::write_text(&path, &content).map(|bytes| Response::FileWritten { bytes })
            }
            Request::EditFile {
                path,
                old_string,
                new_string,
                replace_all,
            } => files::edit_text(&path, &old_string, &new_string, replace_all)
                .map(|replacements| Response::FileEdited { replacements }),
            Request::ListDir { path, recursive } => {
                files::list(&path, recursive).map(Response::DirListing)
            }
            _ => anyhow::bail!("not a file request"),
        }
    });
    match work.await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => Response::Error {
            message: format!("{e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("file operation failed: {e}"),
        },
    }
}

/// Receives an uploaded file; returns false when the stream is out of sync and must be closed.
async fn handle_put<S>(
    stream: &mut S,
    path: &str,
    size: u64,
    summary: &mut String,
) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = home::expand(path);
    let incoming = match Incoming::create(&target).await {
        Ok(i) => i,
        Err(e) => {
            *summary = format!("error: {e}");
            proto::send(
                stream,
                &Response::Error {
                    message: e.to_string(),
                },
            )
            .await?;
            return Ok(true);
        }
    };
    proto::send(stream, &Response::TransferReady).await?;
    match incoming.receive(stream, size, &mut |_| {}).await {
        Ok(bytes) => proto::send(stream, &Response::TransferDone { size: bytes })
            .await
            .map(|_| true),
        Err(TransferError::Stream(e)) => {
            *summary = format!("error: {e}");
            Err(e)
        }
        Err(e) => {
            *summary = format!("error: {e}");
            let in_sync = matches!(e, TransferError::Checksum);
            proto::send(
                stream,
                &Response::Error {
                    message: e.to_string(),
                },
            )
            .await?;
            Ok(in_sync)
        }
    }
}

/// Sends a requested file, or an `Error` when it cannot be opened.
async fn handle_get<S>(stream: &mut S, path: &str, summary: &mut String) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let opened = async {
        let file = tokio::fs::File::open(home::expand(path))
            .await
            .map_err(|e| format!("cannot open {path}: {e}"))?;
        let meta = file
            .metadata()
            .await
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{path} is not a regular file"));
        }
        Ok((file, meta.len()))
    }
    .await;
    let (file, size) = match opened {
        Ok(v) => v,
        Err(message) => {
            *summary = format!("error: {message}");
            return proto::send(stream, &Response::Error { message }).await;
        }
    };
    proto::send(stream, &Response::TransferStart { size }).await?;
    match transfer::send_file(stream, file, size, &mut |_| {}).await {
        Ok(()) => Ok(()),
        Err(TransferError::Stream(e)) => Err(e),
        Err(e) => Err(std::io::Error::other(e.to_string())),
    }
}

/// An exec request as received from the source.
struct ExecJob {
    command: String,
    args: Vec<String>,
    shell: Option<ShellKind>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
}

/// Runs a command and streams its output back, ending with `ExecDone` or `Error`.
async fn handle_exec<S>(
    stream: &mut S,
    opts: &ServerOptions,
    job: ExecJob,
    summary: &mut String,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ExecJob {
        command,
        args,
        shell,
        cwd,
        timeout_secs,
    } = job;
    let cwd = home::expand(
        cwd.as_deref()
            .or(opts.default_cwd.as_deref())
            .unwrap_or("~"),
    );
    let limit = match (timeout_secs, opts.max_timeout_secs) {
        (Some(t), Some(max)) => Some(t.min(max)),
        (t, max) => t.or(max),
    };
    let shell = shell.unwrap_or_else(ShellKind::default_for_os);
    let spec = ExecSpec {
        command: exec::compose(shell, &command, &args),
        shell,
        cwd,
        timeout: limit.map(Duration::from_secs),
    };
    let (tx, mut rx) = mpsc::channel::<(Stream, Vec<u8>)>(16);
    let (result, forwarded) = {
        let (mut reader, mut writer) = tokio::io::split(&mut *stream);
        let forward = async {
            while let Some((stream_kind, bytes)) = rx.recv().await {
                proto::send(
                    &mut writer,
                    &Response::ExecOutput {
                        stream: stream_kind,
                    },
                )
                .await?;
                proto::write_frame(&mut writer, &Frame::Data(bytes)).await?;
            }
            Ok::<(), std::io::Error>(())
        };
        let source_gone = async {
            let mut scratch = [0u8; 64];
            while matches!(reader.read(&mut scratch).await, Ok(n) if n > 0) {}
        };
        tokio::select! {
            both = async { tokio::join!(exec::run(spec, tx), forward) } => both,
            _ = source_gone => {
                *summary = "source disconnected, command killed".to_string();
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "source disconnected"));
            }
        }
    };
    forwarded?;
    *summary = match &result {
        Ok(r) if r.timed_out => "killed after the timeout".to_string(),
        Ok(r) => r
            .exit_code
            .map_or("exit none".to_string(), |c| format!("exit {c}")),
        Err(e) => format!("error: {e:#}"),
    };
    match result {
        Ok(r) => {
            proto::send(
                stream,
                &Response::ExecDone {
                    exit_code: r.exit_code,
                    timed_out: r.timed_out,
                },
            )
            .await
        }
        Err(e) => {
            proto::send(
                stream,
                &Response::Error {
                    message: format!("{e:#}"),
                },
            )
            .await
        }
    }
}

/// Tells whether a connection error is just the peer hanging up (not worth logging).
fn is_normal_close(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_hangup_is_a_normal_close() {
        let eof = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no close_notify");
        assert!(is_normal_close(&eof));
    }

    #[test]
    fn real_failures_are_not_normal_closes() {
        let bad = std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large");
        assert!(!is_normal_close(&bad));
    }

    #[test]
    fn audit_line_has_timestamp_peer_operation_and_result() {
        let line = audit_line(1_700_000_000, "laptop", "exec 'ls -la'", "exit 0");
        assert_eq!(line, "[2023-11-14 22:13:20] laptop exec 'ls -la' -> exit 0");
    }

    #[test]
    fn audit_shortens_long_text_and_flattens_newlines() {
        let long = format!("echo {}\nsecond line", "x".repeat(300));
        let shown = audit_text(&long);
        assert!(
            shown.chars().count() <= AUDIT_MAX_CHARS + 3,
            "{}",
            shown.len()
        );
        assert!(shown.ends_with("..."));
        assert!(!shown.contains('\n'));
        assert_eq!(audit_text("short"), "short");
    }
}
