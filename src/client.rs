//! The source side: connect to a paired machine and issue requests.

use std::path::Path;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::error::RenfieldError;
use crate::identity::Identity;
use crate::proto::{self, Frame, ListResult, ReadResult, Request, Response, ShellKind, Stream};
use crate::store::Registry;
use crate::tls;
use crate::transfer::{self, Incoming, TransferError};

/// Largest text accepted by `write_file` (bigger files go through `put`).
pub const MAX_WRITE_BYTES: usize = 8 * 1024 * 1024;
/// How long to wait for the TCP connection before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An open, authenticated connection to a dest machine.
pub struct Conn {
    stream: TlsStream<TcpStream>,
    machine: String,
}

/// What to run remotely.
#[derive(Debug, Clone, Default)]
pub struct ExecArgs {
    pub command: String,
    pub shell: Option<ShellKind>,
    pub cwd: Option<String>,
    pub timeout_secs: Option<u64>,
}

/// How a remote command ended.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// Wraps any displayable failure into a local I/O error.
fn local_error(e: impl std::fmt::Display) -> RenfieldError {
    RenfieldError::Io(format!("{e:#}"))
}

/// Connects to a machine from the registry in `dir`, pinning the key stored at pairing time.
pub async fn connect(dir: &Path, name: &str) -> Result<Conn, RenfieldError> {
    let registry = Registry::load(dir).map_err(local_error)?;
    let entry = registry
        .get(name)
        .ok_or_else(|| RenfieldError::NotPaired(name.to_string()))?;
    let id = Identity::load_or_create(dir).map_err(local_error)?;
    connect_addr(&id, name, &entry.addr, Some(entry.fingerprint.clone())).await
}

/// Connects to an explicit address; `expected_fp` pins dest's key, `None` accepts any (pairing only).
pub async fn connect_addr(
    id: &Identity,
    machine: &str,
    addr: &str,
    expected_fp: Option<String>,
) -> Result<Conn, RenfieldError> {
    let connect_error = |reason: String| RenfieldError::Connect {
        machine: machine.into(),
        addr: addr.into(),
        reason,
    };
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| connect_error("timed out".into()))?
        .map_err(|e| connect_error(e.to_string()))?;
    let config = tls::client_config(id, expected_fp).map_err(local_error)?;
    let stream = TlsConnector::from(config)
        .connect(tls::server_name(), tcp)
        .await
        .map_err(|e| tls::map_io_error(machine, &e))?;
    Ok(Conn {
        stream,
        machine: machine.to_string(),
    })
}

impl Conn {
    /// The registry name of the machine this connection talks to.
    pub fn machine(&self) -> &str {
        &self.machine
    }

    /// The fingerprint of the certificate dest presented.
    pub fn peer_fingerprint(&self) -> Option<String> {
        tls::peer_fingerprint(self.stream.get_ref().1)
    }

    /// Maps an I/O error of this connection to a renfield error.
    fn io(&self, e: std::io::Error) -> RenfieldError {
        tls::map_io_error(&self.machine, &e)
    }

    /// Sends one request.
    pub async fn send_request(&mut self, request: &Request) -> Result<(), RenfieldError> {
        proto::send(&mut self.stream, request)
            .await
            .map_err(|e| self.io(e))
    }

    /// Receives one response; a closed connection is an error.
    pub async fn recv_response(&mut self) -> Result<Response, RenfieldError> {
        let response = proto::recv::<_, Response>(&mut self.stream)
            .await
            .map_err(|e| self.io(e))?;
        response.ok_or_else(|| {
            RenfieldError::Io(format!(
                "'{}' closed the connection unexpectedly",
                self.machine
            ))
        })
    }

    /// Sends a request and returns its single answer; a remote `Error` becomes `RenfieldError::Remote`.
    async fn call(&mut self, request: Request) -> Result<Response, RenfieldError> {
        self.send_request(&request).await?;
        match self.recv_response().await? {
            Response::Error { message } => Err(RenfieldError::Remote(format!(
                "'{}' reported: {message}",
                self.machine
            ))),
            other => Ok(other),
        }
    }

    /// Builds the error for an answer of the wrong kind.
    fn unexpected(&self, response: Response) -> RenfieldError {
        RenfieldError::Protocol(format!(
            "unexpected answer from '{}': {response:?}",
            self.machine
        ))
    }

    /// Reads lines of a UTF-8 text file on the remote machine.
    pub async fn read_file(
        &mut self,
        path: &str,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<ReadResult, RenfieldError> {
        match self
            .call(Request::ReadFile {
                path: path.into(),
                offset,
                limit,
            })
            .await?
        {
            Response::FileText(r) => Ok(r),
            other => Err(self.unexpected(other)),
        }
    }

    /// Creates or overwrites a text file on the remote machine; returns the bytes written.
    pub async fn write_file(&mut self, path: &str, content: &str) -> Result<usize, RenfieldError> {
        if content.len() > MAX_WRITE_BYTES {
            return Err(RenfieldError::Usage(format!(
                "content is {} bytes, more than the {MAX_WRITE_BYTES} byte limit of a text write: use 'renfield put' for big files",
                content.len()
            )));
        }
        match self
            .call(Request::WriteFile {
                path: path.into(),
                content: content.into(),
            })
            .await?
        {
            Response::FileWritten { bytes } => Ok(bytes),
            other => Err(self.unexpected(other)),
        }
    }

    /// Replaces an exact string in a remote text file; returns the number of replacements.
    pub async fn edit_file(
        &mut self,
        path: &str,
        old: &str,
        new: &str,
        replace_all: bool,
    ) -> Result<usize, RenfieldError> {
        let request = Request::EditFile {
            path: path.into(),
            old_string: old.into(),
            new_string: new.into(),
            replace_all,
        };
        match self.call(request).await? {
            Response::FileEdited { replacements } => Ok(replacements),
            other => Err(self.unexpected(other)),
        }
    }

    /// Lists a remote directory.
    pub async fn list_dir(
        &mut self,
        path: &str,
        recursive: bool,
    ) -> Result<ListResult, RenfieldError> {
        match self
            .call(Request::ListDir {
                path: path.into(),
                recursive,
            })
            .await?
        {
            Response::DirListing(l) => Ok(l),
            other => Err(self.unexpected(other)),
        }
    }

    /// Maps a transfer failure to a renfield error.
    fn transfer_error(&self, e: TransferError) -> RenfieldError {
        match e {
            TransferError::Stream(io) => self.io(io),
            TransferError::Protocol(m) => RenfieldError::Protocol(m),
            other => RenfieldError::Io(other.to_string()),
        }
    }

    /// Uploads a local file; `progress(done, total)` is called as bytes are sent. Returns the size.
    pub async fn put_file(
        &mut self,
        local: &Path,
        remote: &str,
        progress: &mut (dyn FnMut(u64, u64) + Send),
    ) -> Result<u64, RenfieldError> {
        let cannot = |e: std::io::Error| {
            RenfieldError::Io(format!("cannot read local file {}: {e}", local.display()))
        };
        let file = tokio::fs::File::open(local).await.map_err(cannot)?;
        let meta = file.metadata().await.map_err(cannot)?;
        if !meta.is_file() {
            return Err(RenfieldError::Usage(format!(
                "{} is not a regular file",
                local.display()
            )));
        }
        let size = meta.len();
        match self
            .call(Request::PutFile {
                path: remote.into(),
                size,
            })
            .await?
        {
            Response::TransferReady => {}
            other => return Err(self.unexpected(other)),
        }
        transfer::send_file(&mut self.stream, file, size, &mut |done| {
            progress(done, size)
        })
        .await
        .map_err(|e| self.transfer_error(e))?;
        match self.recv_response().await? {
            Response::TransferDone { size } => Ok(size),
            Response::Error { message } => Err(RenfieldError::Remote(format!(
                "'{}' reported: {message}",
                self.machine
            ))),
            other => Err(self.unexpected(other)),
        }
    }

    /// Downloads a remote file; the local file appears only when the checksum matches. Returns the size.
    pub async fn get_file(
        &mut self,
        remote: &str,
        local: &Path,
        progress: &mut (dyn FnMut(u64, u64) + Send),
    ) -> Result<u64, RenfieldError> {
        let incoming = Incoming::create(local)
            .await
            .map_err(|e| self.transfer_error(e))?;
        let size = match self
            .call(Request::GetFile {
                path: remote.into(),
            })
            .await
        {
            Ok(Response::TransferStart { size }) => size,
            Ok(other) => {
                incoming.discard().await;
                return Err(self.unexpected(other));
            }
            Err(e) => {
                incoming.discard().await;
                return Err(e);
            }
        };
        incoming
            .receive(&mut self.stream, size, &mut |done| progress(done, size))
            .await
            .map_err(|e| self.transfer_error(e))
    }

    /// Runs a command remotely, calling `on_output` for every chunk as it arrives.
    pub async fn exec<F: FnMut(Stream, &[u8])>(
        &mut self,
        args: ExecArgs,
        mut on_output: F,
    ) -> Result<ExecOutcome, RenfieldError> {
        let request = Request::Exec {
            command: args.command,
            shell: args.shell,
            cwd: args.cwd,
            timeout_secs: args.timeout_secs,
        };
        self.send_request(&request).await?;
        loop {
            match self.recv_response().await? {
                Response::ExecOutput { stream } => {
                    match proto::read_frame(&mut self.stream)
                        .await
                        .map_err(|e| self.io(e))?
                    {
                        Some(Frame::Data(bytes)) => on_output(stream, &bytes),
                        _ => {
                            return Err(RenfieldError::Protocol(
                                "expected output data after an output header".into(),
                            ));
                        }
                    }
                }
                Response::ExecDone {
                    exit_code,
                    timed_out,
                } => {
                    return Ok(ExecOutcome {
                        exit_code,
                        timed_out,
                    });
                }
                Response::Error { message } => {
                    return Err(RenfieldError::Remote(format!(
                        "'{}' reported: {message}",
                        self.machine
                    )));
                }
                other => {
                    return Err(RenfieldError::Protocol(format!(
                        "unexpected answer to a command: {other:?}"
                    )));
                }
            }
        }
    }
}
