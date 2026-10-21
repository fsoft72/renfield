//! The dest side: accepts TLS connections and serves requests from authorized sources.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
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
}

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
        let (tcp, peer) = listener.accept().await?;
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("refused connection from {peer}: {e}");
                    return;
                }
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
    while let Some(request) = proto::recv::<_, Request>(stream).await? {
        match request {
            Request::PairOffer {
                source_name,
                both,
                source_listen_port,
            } => {
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
                let message = "this key is not authorized on this machine".to_string();
                return proto::send(stream, &Response::Error { message }).await;
            }
            Request::Exec {
                command,
                shell,
                cwd,
                timeout_secs,
            } => {
                handle_exec(stream, &shared.opts, command, shell, cwd, timeout_secs).await?;
            }
            Request::ReadFile { .. }
            | Request::WriteFile { .. }
            | Request::EditFile { .. }
            | Request::ListDir { .. } => {
                let response = handle_file_request(request).await;
                proto::send(stream, &response).await?;
            }
            Request::PutFile { path, size } => {
                if !handle_put(stream, &path, size).await? {
                    return Ok(());
                }
            }
            Request::GetFile { path } => handle_get(stream, &path).await?,
            Request::PairCommit | Request::PairAbort => {
                let message = "unexpected pairing message, no pairing is in progress".to_string();
                return proto::send(stream, &Response::Error { message }).await;
            }
        }
    }
    Ok(())
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
async fn handle_put<S>(stream: &mut S, path: &str, size: u64) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = home::expand(path);
    let incoming = match Incoming::create(&target).await {
        Ok(i) => i,
        Err(e) => {
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
        Err(TransferError::Stream(e)) => Err(e),
        Err(e) => {
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
async fn handle_get<S>(stream: &mut S, path: &str) -> std::io::Result<()>
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
        Err(message) => return proto::send(stream, &Response::Error { message }).await,
    };
    proto::send(stream, &Response::TransferStart { size }).await?;
    match transfer::send_file(stream, file, size, &mut |_| {}).await {
        Ok(()) => Ok(()),
        Err(TransferError::Stream(e)) => Err(e),
        Err(e) => Err(std::io::Error::other(e.to_string())),
    }
}

/// Runs a command and streams its output back, ending with `ExecDone` or `Error`.
async fn handle_exec<S>(
    stream: &mut S,
    opts: &ServerOptions,
    command: String,
    shell: Option<ShellKind>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cwd = home::expand(
        cwd.as_deref()
            .or(opts.default_cwd.as_deref())
            .unwrap_or("~"),
    );
    let limit = match (timeout_secs, opts.max_timeout_secs) {
        (Some(t), Some(max)) => Some(t.min(max)),
        (t, max) => t.or(max),
    };
    let spec = ExecSpec {
        command,
        shell: shell.unwrap_or_else(ShellKind::default_for_os),
        cwd,
        timeout: limit.map(Duration::from_secs),
    };
    let (tx, mut rx) = mpsc::channel::<(Stream, Vec<u8>)>(16);
    let forward = async {
        while let Some((stream_kind, bytes)) = rx.recv().await {
            proto::send(
                stream,
                &Response::ExecOutput {
                    stream: stream_kind,
                },
            )
            .await?;
            proto::write_frame(stream, &Frame::Data(bytes)).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let (result, forwarded) = tokio::join!(exec::run(spec, tx), forward);
    forwarded?;
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
}
