//! The source side: connect to a paired machine and issue requests.

use std::path::Path;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::error::RenfieldError;
use crate::identity::Identity;
use crate::proto::{self, Frame, Request, Response, ShellKind, Stream};
use crate::store::Registry;
use crate::tls;

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
        proto::send(&mut self.stream, &request)
            .await
            .map_err(|e| self.io(e))?;
        loop {
            let response = proto::recv::<_, Response>(&mut self.stream)
                .await
                .map_err(|e| self.io(e))?;
            match response {
                Some(Response::ExecOutput { stream }) => match proto::read_frame(&mut self.stream)
                    .await
                    .map_err(|e| self.io(e))?
                {
                    Some(Frame::Data(bytes)) => on_output(stream, &bytes),
                    _ => {
                        return Err(RenfieldError::Protocol(
                            "expected output data after an output header".into(),
                        ));
                    }
                },
                Some(Response::ExecDone {
                    exit_code,
                    timed_out,
                }) => {
                    return Ok(ExecOutcome {
                        exit_code,
                        timed_out,
                    });
                }
                Some(Response::Error { message }) => {
                    return Err(RenfieldError::Remote(format!(
                        "'{}' reported: {message}",
                        self.machine
                    )));
                }
                None => {
                    return Err(RenfieldError::Io(format!(
                        "'{}' closed the connection before the command finished",
                        self.machine
                    )));
                }
            }
        }
    }
}
