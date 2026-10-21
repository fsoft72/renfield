//! Wire framing: a frame is a u32 big endian body length, one kind byte, then the body.

use std::io::{Error, ErrorKind, Result};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version spoken by this build.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest accepted frame body in bytes.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Most memory reserved for a frame before its bytes have actually arrived.
const READ_AHEAD: usize = 1024 * 1024;
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
    let mut body = Vec::with_capacity(len.min(READ_AHEAD));
    let got = (&mut *r).take(len as u64).read_to_end(&mut body).await?;
    if got < len {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "connection closed in the middle of a frame",
        ));
    }
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
        /// Extra arguments: when present, `command` is the program and each argument is quoted for the shell.
        #[serde(default)]
        args: Vec<String>,
        shell: Option<ShellKind>,
        cwd: Option<String>,
        timeout_secs: Option<u64>,
    },
    /// Read a UTF-8 text file; `offset` is the 1-based first line, `limit` the number of lines.
    ReadFile {
        path: String,
        offset: Option<usize>,
        limit: Option<usize>,
    },
    /// Create or overwrite a UTF-8 text file (parent directories are created).
    WriteFile { path: String, content: String },
    /// Replace an exact string in a text file.
    EditFile {
        path: String,
        old_string: String,
        new_string: String,
        replace_all: bool,
    },
    /// List a directory.
    ListDir { path: String, recursive: bool },
    /// Upload: dest prepares a file of `size` bytes, answers `TransferReady`, then receives data frames.
    PutFile { path: String, size: u64 },
    /// Download: dest answers `TransferStart`, then sends data frames.
    GetFile { path: String },
    /// Offer this machine's key for pairing; `both` also asks dest to be able to command source.
    PairOffer {
        source_name: String,
        both: bool,
        source_listen_port: Option<u16>,
    },
    /// Source confirms the pairing after seeing dest's key.
    PairCommit,
    /// Source declines the pairing after seeing dest's key.
    PairAbort,
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
        /// The timeout dest actually applied (the request's, capped by dest's own maximum).
        #[serde(default)]
        limit_secs: Option<u64>,
    },
    /// Answer to `ReadFile`.
    FileText(ReadResult),
    /// Answer to `WriteFile`: bytes written.
    FileWritten { bytes: usize },
    /// Answer to `EditFile`: how many replacements were made.
    FileEdited { replacements: usize },
    /// Answer to `ListDir`.
    DirListing(ListResult),
    /// Dest is ready to receive the uploaded file.
    TransferReady,
    /// Dest starts sending the requested file of `size` bytes.
    TransferStart { size: u64 },
    /// The upload was received, verified and saved.
    TransferDone { size: u64 },
    /// Dest accepted the offered key and waits for the source to commit or abort.
    PairOffered { dest_name: String },
    /// The pairing was stored on dest.
    PairDone,
    /// The peer's key is not authorized on this machine (it may complete the handshake during pairing).
    NotAuthorized,
    /// The request failed; the message explains why.
    Error { message: String },
}

/// The part of a text file selected by a read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadResult {
    /// The selected lines, joined with `\n` (line endings normalized).
    pub text: String,
    /// 1-based number of the first returned line.
    pub first_line: usize,
    /// Number of lines in the whole file.
    pub total_lines: usize,
    /// True when the output was cut at the size cap.
    pub truncated: bool,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Name, relative to the listed directory (with `/` separators when recursive).
    pub name: String,
    /// `file`, `dir`, `symlink` or `other`.
    pub kind: String,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime_secs: i64,
}

/// A directory listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResult {
    pub entries: Vec<DirEntry>,
    /// True when the listing was cut at the entry cap.
    pub truncated: bool,
}

/// Sent after the last data frame of a transfer: the SHA-256 of everything that was sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferTrailer {
    pub sha256: String,
}
