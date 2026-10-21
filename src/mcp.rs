//! MCP server (JSON-RPC 2.0 over stdio): exposes remote machines to Claude Code as tools.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::client::{self, ExecArgs};
use crate::error::RenfieldError;
use crate::proto::{ShellKind, Stream};

/// Timeout applied to `remote_exec` when the caller gives none.
pub const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 120;
/// Largest amount of stdout (and of stderr) returned by one `remote_exec`.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Protocol version announced when the client does not ask for one.
const FALLBACK_PROTOCOL: &str = "2024-11-05";

/// JSON-RPC error code: the line is not valid JSON.
const PARSE_ERROR: i64 = -32700;
/// JSON-RPC error code: the message is not a valid request.
const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC error code: unknown method.
const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC error code: invalid parameters (for example an unknown tool).
const INVALID_PARAMS: i64 = -32602;

/// Describes how remote paths are written, repeated in the tools that take one.
const PATH_RULES: &str = "Paths use the native format of the remote machine (for example C:\\Users\\me\\x on Windows, /home/me/x on Linux). A leading ~ is the home directory of the user running renfield there, and relative paths start from that home.";

/// Keeps the last `cap` bytes pushed into it, remembering whether anything was dropped.
pub struct TailBuffer {
    data: Vec<u8>,
    cap: usize,
    truncated: bool,
}

impl TailBuffer {
    /// Creates a buffer keeping at most `cap` bytes.
    pub fn new(cap: usize) -> TailBuffer {
        TailBuffer {
            data: Vec::new(),
            cap,
            truncated: false,
        }
    }

    /// Appends bytes; memory stays bounded by roughly twice the cap.
    pub fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        if self.data.len() > self.cap * 2 {
            self.trim();
        }
    }

    /// Drops the oldest bytes beyond the cap.
    fn trim(&mut self) {
        if self.data.len() > self.cap {
            let excess = self.data.len() - self.cap;
            self.data.drain(..excess);
            self.truncated = true;
        }
    }

    /// Returns the kept bytes and whether older bytes were dropped.
    pub fn finish(mut self) -> (Vec<u8>, bool) {
        self.trim();
        (self.data, self.truncated)
    }
}

/// Formats seconds since the Unix epoch as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The result of a tool: text for the model, flagged as an error or not.
struct Outcome {
    text: String,
    is_error: bool,
}

impl Outcome {
    fn ok(text: String) -> Outcome {
        Outcome {
            text,
            is_error: false,
        }
    }

    fn failed(text: String) -> Outcome {
        Outcome {
            text,
            is_error: true,
        }
    }
}

impl From<RenfieldError> for Outcome {
    fn from(e: RenfieldError) -> Outcome {
        Outcome::failed(e.to_string())
    }
}

/// Parses tool arguments, turning serde errors into a message the model can act on.
fn parse<T: DeserializeOwned>(args: Value) -> Result<T, Outcome> {
    serde_json::from_value(args).map_err(|e| Outcome::failed(format!("invalid arguments: {e}")))
}

#[derive(Deserialize)]
struct ExecIn {
    machine: String,
    command: String,
    shell: Option<ShellKind>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Deserialize)]
struct ReadIn {
    machine: String,
    path: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct WriteIn {
    machine: String,
    path: String,
    content: String,
}

#[derive(Deserialize)]
struct EditIn {
    machine: String,
    path: String,
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
}

#[derive(Deserialize)]
struct ListIn {
    machine: String,
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Deserialize)]
struct PutIn {
    machine: String,
    local_path: PathBuf,
    remote_path: String,
}

#[derive(Deserialize)]
struct GetIn {
    machine: String,
    remote_path: String,
    local_path: PathBuf,
}

/// The MCP server state: where the registry lives and the default command timeout.
pub struct Server {
    dir: PathBuf,
    default_timeout: u64,
}

impl Server {
    /// Creates a server using the registry in `dir`.
    pub fn new(dir: PathBuf) -> Server {
        Server {
            dir,
            default_timeout: DEFAULT_EXEC_TIMEOUT_SECS,
        }
    }

    /// Overrides the default `remote_exec` timeout (seconds).
    pub fn with_default_timeout(mut self, secs: u64) -> Server {
        self.default_timeout = secs;
        self
    }

    /// The `remote_exec` timeout used when the caller gives none.
    pub fn default_timeout(&self) -> u64 {
        self.default_timeout
    }

    /// Handles one JSON-RPC message; notifications and responses get no answer.
    pub async fn handle(&self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            return id.map(|id| error_response(id, INVALID_REQUEST, "missing method"));
        };
        let id = id?;
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let reply = match method {
            "initialize" => Ok(initialize_result(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_definitions() })),
            "tools/call" => self.call_tool(params).await,
            other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
        };
        Some(match reply {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_response(id, code, &message),
        })
    }

    /// Runs a `tools/call` request.
    async fn call_tool(&self, params: Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let outcome = match name.as_str() {
            "remote_exec" => self.tool_exec(args).await,
            "remote_read" => self.tool_read(args).await,
            "remote_write" => self.tool_write(args).await,
            "remote_edit" => self.tool_edit(args).await,
            "remote_list" => self.tool_list(args).await,
            "remote_put" => self.tool_put(args).await,
            "remote_get" => self.tool_get(args).await,
            other => return Err((INVALID_PARAMS, format!("unknown tool: {other}"))),
        };
        let outcome = outcome.unwrap_or_else(|failure| failure);
        Ok(
            json!({ "content": [{ "type": "text", "text": outcome.text }], "isError": outcome.is_error }),
        )
    }

    /// `remote_exec`: runs a command and returns exit code and (capped) output.
    async fn tool_exec(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: ExecIn = parse(args)?;
        let timeout = a.timeout_secs.unwrap_or(self.default_timeout);
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let (mut out, mut err) = (
            TailBuffer::new(MAX_OUTPUT_BYTES),
            TailBuffer::new(MAX_OUTPUT_BYTES),
        );
        let exec = ExecArgs {
            command: a.command,
            shell: a.shell,
            cwd: a.cwd,
            timeout_secs: Some(timeout),
        };
        let outcome = conn
            .exec(exec, |stream, bytes| match stream {
                Stream::Stdout => out.push(bytes),
                Stream::Stderr => err.push(bytes),
            })
            .await?;
        let mut text = match outcome.exit_code {
            Some(code) => format!("exit code: {code}\n"),
            None => "exit code: none (the process was terminated)\n".to_string(),
        };
        if outcome.timed_out {
            text.push_str(&format!(
                "timed out: the command was killed after {timeout}s\n"
            ));
        }
        for (label, buffer) in [("stdout", out), ("stderr", err)] {
            let (bytes, truncated) = buffer.finish();
            if bytes.is_empty() {
                continue;
            }
            let note = if truncated {
                format!(
                    " (truncated: only the last {} bytes are shown)",
                    bytes.len()
                )
            } else {
                String::new()
            };
            text.push_str(&format!(
                "--- {label}{note} ---\n{}\n",
                String::from_utf8_lossy(&bytes)
            ));
        }
        Ok(Outcome {
            text,
            is_error: outcome.timed_out,
        })
    }

    /// `remote_read`: returns numbered lines of a text file.
    async fn tool_read(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: ReadIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let r = conn.read_file(&a.path, a.offset, a.limit).await?;
        let mut text = String::new();
        let mut shown = 0;
        for (i, line) in r.text.lines().enumerate() {
            text.push_str(&format!("{:>6}\t{line}\n", r.first_line + i));
            shown += 1;
        }
        if shown == 0 {
            text.push_str(&format!(
                "[no lines in this range, the file has {} lines]",
                r.total_lines
            ));
        } else {
            let last = r.first_line + shown - 1;
            text.push_str(&format!(
                "[lines {}-{last} of {}]",
                r.first_line, r.total_lines
            ));
            if r.truncated {
                text.push_str(&format!(
                    " (output truncated at 1 MiB, continue with offset={})",
                    last + 1
                ));
            }
        }
        Ok(Outcome::ok(text))
    }

    /// `remote_write`: creates or overwrites a text file.
    async fn tool_write(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: WriteIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let bytes = conn.write_file(&a.path, &a.content).await?;
        Ok(Outcome::ok(format!(
            "wrote {bytes} bytes to {}:{}",
            a.machine, a.path
        )))
    }

    /// `remote_edit`: replaces an exact string in a text file.
    async fn tool_edit(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: EditIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let n = conn
            .edit_file(&a.path, &a.old_string, &a.new_string, a.replace_all)
            .await?;
        Ok(Outcome::ok(format!(
            "replaced {n} occurrence(s) in {}:{}",
            a.machine, a.path
        )))
    }

    /// `remote_list`: lists a directory.
    async fn tool_list(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: ListIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let listing = conn.list_dir(&a.path, a.recursive).await?;
        if listing.entries.is_empty() {
            return Ok(Outcome::ok("(empty directory)".to_string()));
        }
        let mut text = String::new();
        for e in &listing.entries {
            let slash = if e.kind == "dir" { "/" } else { "" };
            text.push_str(&format!(
                "{:<7} {:>12} {}  {}{slash}\n",
                e.kind,
                e.size,
                format_utc(e.mtime_secs),
                e.name
            ));
        }
        if listing.truncated {
            text.push_str("[listing truncated at 10000 entries]\n");
        }
        Ok(Outcome::ok(text))
    }

    /// `remote_put`: copies a local file to the remote machine.
    async fn tool_put(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: PutIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let bytes = conn
            .put_file(Path::new(&a.local_path), &a.remote_path, &mut |_, _| {})
            .await?;
        Ok(Outcome::ok(format!(
            "sent {bytes} bytes to {}:{} (checksum verified)",
            a.machine, a.remote_path
        )))
    }

    /// `remote_get`: copies a remote file to this machine.
    async fn tool_get(&self, args: Value) -> Result<Outcome, Outcome> {
        let a: GetIn = parse(args)?;
        let mut conn = client::connect(&self.dir, &a.machine).await?;
        let bytes = conn
            .get_file(&a.remote_path, &a.local_path, &mut |_, _| {})
            .await?;
        Ok(Outcome::ok(format!(
            "received {bytes} bytes into {} (checksum verified)",
            a.local_path.display()
        )))
    }
}

/// Builds a JSON-RPC error response.
fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Answers `initialize`: echo the client's protocol version and announce the tools capability.
fn initialize_result(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(FALLBACK_PROTOCOL);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "renfield", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Tools to work on other machines paired with renfield: run commands, read, write and edit text files, list directories and copy single files. Every tool takes the machine name. Remote paths use the remote machine's native format.",
    })
}

/// Builds the JSON schema of one tool.
fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    let mut props = properties;
    props["machine"] = json!({ "type": "string", "description": "Name of the paired machine, as shown by `renfield list`." });
    let mut required: Vec<&str> = required.to_vec();
    required.insert(0, "machine");
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": props, "required": required },
    })
}

/// The list of tools offered to the client.
fn tool_definitions() -> Vec<Value> {
    let path = |what: &str| json!({ "type": "string", "description": what });
    vec![
        tool(
            "remote_exec",
            &format!(
                "Run a shell command on a paired machine and return its exit code, stdout and stderr (non interactive: no stdin, no terminal). Output is capped at 1 MiB per stream (the tail is kept). The default timeout is {DEFAULT_EXEC_TIMEOUT_SECS} seconds. Default shell: bash (sh) on Linux, Windows PowerShell on Windows. {PATH_RULES}"
            ),
            json!({
                "command": { "type": "string", "description": "The command line to run." },
                "shell": { "type": "string", "enum": ["bash", "sh", "powershell", "pwsh", "cmd"], "description": "Shell to use; default depends on the remote OS." },
                "cwd": path("Working directory; default is the home directory."),
                "timeout_secs": { "type": "integer", "minimum": 1, "description": "Kill the command after this many seconds." },
            }),
            &["command"],
        ),
        tool(
            "remote_read",
            &format!(
                "Read a UTF-8 text file on a paired machine. Returns numbered lines. Binary files are refused (use remote_get). {PATH_RULES}"
            ),
            json!({
                "path": path("File to read."),
                "offset": { "type": "integer", "minimum": 1, "description": "First line to return (1-based)." },
                "limit": { "type": "integer", "minimum": 1, "description": "Number of lines to return." },
            }),
            &["path"],
        ),
        tool(
            "remote_write",
            &format!(
                "Create or overwrite a UTF-8 text file on a paired machine (parent directories are created; existing CRLF line endings are kept). For files over 8 MiB or binary files use remote_put. {PATH_RULES}"
            ),
            json!({ "path": path("File to write."), "content": { "type": "string", "description": "Full new content." } }),
            &["path", "content"],
        ),
        tool(
            "remote_edit",
            &format!(
                "Replace an exact string in a text file on a paired machine. Fails if old_string is not found, or is not unique unless replace_all is true. Line endings (LF or CRLF) are handled. {PATH_RULES}"
            ),
            json!({
                "path": path("File to edit."),
                "old_string": { "type": "string", "description": "Exact text to replace." },
                "new_string": { "type": "string", "description": "Replacement text." },
                "replace_all": { "type": "boolean", "description": "Replace every occurrence." },
            }),
            &["path", "old_string", "new_string"],
        ),
        tool(
            "remote_list",
            &format!(
                "List a directory on a paired machine (kind, size, modification time, name; hidden files included). {PATH_RULES}"
            ),
            json!({ "path": path("Directory to list."), "recursive": { "type": "boolean", "description": "Descend into subdirectories." } }),
            &["path"],
        ),
        tool(
            "remote_put",
            &format!(
                "Copy one local file to a paired machine (any size, binary safe, checksum verified). The local path is on the machine running this MCP server. {PATH_RULES}"
            ),
            json!({ "local_path": path("Local file to send."), "remote_path": path("Destination path on the remote machine.") }),
            &["local_path", "remote_path"],
        ),
        tool(
            "remote_get",
            &format!(
                "Copy one file from a paired machine to this machine (any size, binary safe, checksum verified). {PATH_RULES}"
            ),
            json!({ "remote_path": path("File to fetch on the remote machine."), "local_path": path("Local destination path.") }),
            &["remote_path", "local_path"],
        ),
    ]
}

/// Serves newline delimited JSON-RPC from `reader` to `writer`, running requests concurrently.
pub async fn serve_io<R, W>(server: Arc<Server>, reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let mut line = message.to_string();
            line.push('\n');
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                return;
            }
        }
    });
    let mut lines = reader.lines();
    let mut tasks = JoinSet::new();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Err(e) => {
                let _ = tx.send(error_response(
                    Value::Null,
                    PARSE_ERROR,
                    &format!("parse error: {e}"),
                ));
            }
            Ok(message) => {
                let (server, tx) = (server.clone(), tx.clone());
                tasks.spawn(async move {
                    if let Some(answer) = server.handle(message).await {
                        let _ = tx.send(answer);
                    }
                });
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    drop(tx);
    let _ = writer_task.await;
    Ok(())
}

/// Runs the MCP server on stdin and stdout until stdin closes.
pub async fn run_stdio(dir: PathBuf) -> std::io::Result<()> {
    let server = Arc::new(Server::new(dir));
    serve_io(
        server,
        tokio::io::BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_buffer_keeps_the_last_bytes() {
        let mut b = TailBuffer::new(10);
        for chunk in [b"0123456789".as_slice(), b"abcdefghij", b"KLM"] {
            b.push(chunk);
        }
        let (data, truncated) = b.finish();
        assert_eq!(data, b"defghijKLM");
        assert!(truncated);
    }

    #[test]
    fn tail_buffer_small_input_is_not_truncated() {
        let mut b = TailBuffer::new(10);
        b.push(b"abc");
        assert_eq!(b.finish(), (b"abc".to_vec(), false));
    }

    #[test]
    fn utc_formatting_matches_known_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20");
    }
}
