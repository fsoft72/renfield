//! Wire framing: a frame is a u32 big endian body length, one kind byte, then the body.

use std::io::{Error, ErrorKind, Result};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version spoken by this build.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest accepted frame body in bytes.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

const KIND_JSON: u8 = 0;
const KIND_DATA: u8 = 1;

/// A unit of communication: a JSON control message or a chunk of raw bytes.
#[derive(Debug, PartialEq)]
pub enum Frame {
    Json(Vec<u8>),
    Data(Vec<u8>),
}

/// Writes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let (kind, body) = match frame {
        Frame::Json(b) => (KIND_JSON, b),
        Frame::Data(b) => (KIND_DATA, b),
    };
    if body.len() > MAX_FRAME {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "frame too large to send",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&[kind]).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Reads one frame; `Ok(None)` means a clean end of stream between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    let mut header = [0u8; 5];
    let mut got = 0;
    while got < header.len() {
        let n = r.read(&mut header[got..]).await?;
        if n == 0 && got == 0 {
            return Ok(None);
        }
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed in the middle of a frame",
            ));
        }
        got += n;
    }
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len > MAX_FRAME {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("frame too large ({len} bytes)"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    match header[4] {
        KIND_JSON => Ok(Some(Frame::Json(body))),
        KIND_DATA => Ok(Some(Frame::Data(body))),
        other => Err(Error::new(
            ErrorKind::InvalidData,
            format!("unknown frame kind {other}"),
        )),
    }
}

/// Sends a value as a JSON frame.
pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    write_frame(w, &Frame::Json(body)).await
}

/// Receives a JSON frame as a value; `Ok(None)` on clean end of stream.
pub async fn recv<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    match read_frame(r).await? {
        None => Ok(None),
        Some(Frame::Json(body)) => serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("malformed message: {e}"))),
        Some(Frame::Data(_)) => Err(Error::new(
            ErrorKind::InvalidData,
            "unexpected data frame, expected a message",
        )),
    }
}

/// Which shell runs a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    Bash,
    Sh,
    Powershell,
    Pwsh,
    Cmd,
}

impl ShellKind {
    /// The shell used when the caller does not choose one: PowerShell on Windows, bash (else sh) elsewhere.
    pub fn default_for_os() -> ShellKind {
        if cfg!(windows) {
            return ShellKind::Powershell;
        }
        if on_path("bash") {
            ShellKind::Bash
        } else {
            ShellKind::Sh
        }
    }
}

/// Tells whether an executable with this name exists in a PATH directory.
fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

/// Which output stream a chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A request from source to dest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Run a command; output comes back as `ExecOutput` messages, each followed by a data frame.
    Exec {
        command: String,
        shell: Option<ShellKind>,
        cwd: Option<String>,
        timeout_secs: Option<u64>,
    },
}

/// An answer from dest to source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Announces that the next frame is a chunk of output of this stream.
    ExecOutput { stream: Stream },
    /// The command ended (or was killed because of the timeout).
    ExecDone {
        exit_code: Option<i32>,
        timed_out: bool,
    },
    /// The request failed; the message explains why.
    Error { message: String },
}
