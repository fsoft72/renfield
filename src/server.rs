//! The dest side: accepts TLS connections and serves requests from authorized sources.

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
use crate::home;
use crate::identity::Identity;
use crate::proto::{self, Frame, Request, Response, ShellKind, Stream};
use crate::store::Authorized;
use crate::tls::{self, PeerPolicy};

/// Settings of a running dest.
#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    /// Working directory of commands when the caller gives none.
    pub default_cwd: Option<String>,
    /// Hard upper bound, in seconds, for any command.
    pub max_timeout_secs: Option<u64>,
}

/// Authorization policy backed by `authorized.toml`, re-read on every check so changes apply at once.
pub struct FilePolicy {
    dir: PathBuf,
    pairing: AtomicBool,
}

impl FilePolicy {
    /// Creates a policy reading the authorized keys from `dir`.
    pub fn new(dir: &Path) -> FilePolicy {
        FilePolicy {
            dir: dir.to_path_buf(),
            pairing: AtomicBool::new(false),
        }
    }

    /// Opens or closes the pairing window (unknown peers may connect while it is open).
    pub fn set_pairing(&self, open: bool) {
        self.pairing.store(open, Ordering::SeqCst);
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

/// Accepts connections forever, serving each one on its own task.
pub async fn serve(
    listener: TcpListener,
    id: Identity,
    policy: Arc<FilePolicy>,
    opts: ServerOptions,
) -> Result<()> {
    let config = tls::server_config(&id, policy.clone())?;
    let acceptor = TlsAcceptor::from(config);
    let opts = Arc::new(opts);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (acceptor, policy, opts) = (acceptor.clone(), policy.clone(), opts.clone());
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("refused connection from {peer}: {e}");
                    return;
                }
            };
            let fingerprint = tls::peer_fingerprint(stream.get_ref().1).unwrap_or_default();
            if let Err(e) = handle_connection(&mut stream, &fingerprint, &policy, &opts).await {
                eprintln!("connection from {peer} ended with error: {e}");
            }
        });
    }
}

/// Serves requests on one connection until the peer closes it.
async fn handle_connection<S>(
    stream: &mut S,
    fingerprint: &str,
    policy: &FilePolicy,
    opts: &ServerOptions,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(request) = proto::recv::<_, Request>(stream).await? {
        if !policy.is_authorized(fingerprint) {
            let message = "this key is not authorized on this machine".to_string();
            return proto::send(stream, &Response::Error { message }).await;
        }
        match request {
            Request::Exec {
                command,
                shell,
                cwd,
                timeout_secs,
            } => {
                handle_exec(stream, opts, command, shell, cwd, timeout_secs).await?;
            }
        }
    }
    Ok(())
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
