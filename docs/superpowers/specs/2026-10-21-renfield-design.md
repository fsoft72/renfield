# renfield - design

Date: 2026-10-21
Status: draft, pending user approval

Note: the project directory is called `remsh`, the program (and the Rust crate / binary) is called `renfield`.

## 1. Intent and why

Fabio needs Claude Code, running on a Linux machine, to work on a Windows machine: run commands, read and edit source files, move files back and forth. The Windows machine has no `sshd`, and installing OpenSSH server there is complex. He wants something lean: one small executable on each machine, secure by default, usable by an AI agent first and by a human second.

`renfield` is a cross-platform terminal program (no UI) that connects two machines securely. One side is the **source** (it sends commands and requests), the other is the **dest** (it listens, executes in its own shell, answers). Any OS can be source or dest, but the first release targets Linux and Windows, with Linux commanding Windows as the primary scenario.

The main consumer is Claude Code, through an MCP server mode (`renfield mcp`). The plain CLI (`renfield exec`, ...) is the secondary interface, for manual use and scripting.

## 2. Goals

- G1. Claude Code can, on a remote machine, run shell commands, read files, write files, edit files (exact string replacement, like the local Edit tool), list directories, in a way that feels close to working locally.
- G2. Real time output streaming and exact exit code for every command.
- G3. Single self contained executable per OS, zero runtime dependencies (no OpenSSL, no system libs to install, no runtime interpreter).
- G4. Secure transport: TLS 1.3 with mutual authentication, keys pinned at pairing time. Login only by key exchange, never by password.
- G5. Explicit, safe pairing flow with manual fingerprint confirmation on dest.
- G6. Clear, actionable error messages (what failed, on which machine, why, what to try).
- G7. Linux and Windows (x86_64) supported from the first release. Code must not preclude macOS.
- G8. Single file transfer in both directions, including large files, with integrity verification.

## 3. Non goals (for the first release)

- No interactive sessions: no PTY, no stdin interaction, no vim/top/prompts.
- No directory transfer (single files only).
- No NAT traversal, relay or discovery: same LAN, dest listens on a known port, source connects.
- No restrictions on dest: no allowed roots, no command allowlist, no sandbox (see anti goals and decision D6).
- No service / daemon packaging (systemd unit, Windows service). Dest is started by hand. The design must not make this hard to add later.
- No password or token login, no user accounts, no roles.
- No port forwarding, no tunnelling.
- No GUI.

## 4. Anti goals (it fails even if it technically works)

- Needing anything installed on the machine besides the `renfield` executable.
- Silent trust: a key being accepted without an explicit, informed human confirmation on dest.
- Silent failures, swallowed errors, or vague messages like "connection failed" with no cause.
- A pairing that unintentionally gives dest power over source (pairing is one way unless `--both` is explicitly given).
- Inventing a custom cryptographic protocol.

## 5. Constraints

- Language: Rust, stable toolchain. Code and comments in English.
- Packaging: `cargo build --release` yields one binary per OS. Use a pure Rust TLS stack (`rustls`), no OpenSSL. Windows: statically linked C runtime. Linux: prefer a build that runs on any distribution (for example musl target or a conservative glibc baseline, builder's choice, but it must run without extra packages).
- Transport: TLS 1.3 only, mutual authentication, self signed certificates, peer identity verified by pinned public key fingerprint (not by CA chains, not by hostname).
- Key type: Ed25519 (builder may choose another modern type if rustls interop requires it, and must note it in the code docs).
- Non interactive only.
- Follow Fabio's global code rules: exit conditions at the top of functions, doc comments on functions, `_` prefix for private functions in Python/C only (not applicable to Rust, use normal Rust visibility), UPPER_CASE constants, `CHANGES.md` at project root, text files end with an empty line, `pnpm` not relevant here.

## 6. Decisions made by Fabio

- D1. Names: program `renfield`; roles `source` (commands) and `dest` (executes).
- D2. Network: same LAN. Dest listens on a port set by `--port` or by a config file. Source connects to dest.
- D3. Pairing: explicit command `renfield pair <name> <host:port>`. Dest must be started in a special "accept key" mode. In that mode dest shows the fingerprint of the key presented by source and the human confirms manually (yes/no) on dest.
- D4. Keys are exchanged in both directions at pairing, so source also pins dest's key. Permission is one way by default: source may command dest, not the reverse. `--both` makes the pairing bidirectional (each machine may command the other) when explicitly requested.
- D5. Registry: source keeps a local registry mapping a machine name (chosen by the user, for example `win-pc`) to address:port and dest's pinned key. Entries are created by the pairing command, never implicitly on first connection.
- D6. Dest is unrestricted: commands and file operations run with the permissions of the OS user that started dest, nothing more, nothing less. Access control is done by Claude Code's own per tool confirmations on source. This must be stated clearly in the documentation.
- D7. Usage: non interactive only. Output streamed in real time, exit code returned.
- D8. MCP is the main deliverable. Claude Code gets dedicated remote tools (exec, read, write, edit, list at least) instead of relying on shell tricks. The CLI is secondary.
- D9. File transfer: single files, both directions, large files supported.
- D10. Transport: TLS 1.3 with mutual authentication.
- D11. Dest is started manually for now. A service mode is a future feature.
- D12. Quality bar: single executable, zero runtime dependencies, clear error messages.

## 7. Builder's calls (Claude's proposals, to be checked by Fabio)

These were not decided by Fabio. They are sensible defaults.

- C1. CLI surface:
  - `renfield listen [--port N] [--config FILE]` starts dest.
  - `renfield listen --accept-key [--timeout SECS]` starts dest in pairing mode. Default window 120 seconds, closes after the first key is accepted or rejected.
  - `renfield pair <name> <host:port> [--both]` run on source.
  - `renfield exec <name> [--shell SHELL] [--cwd DIR] [--timeout SECS] -- <command>`.
  - `renfield put <name> <local> <remote>` and `renfield get <name> <remote> <local>`.
  - `renfield list` shows registered machines; `renfield remove <name>` deletes one; `renfield authorized list|revoke` manages keys that dest accepts.
  - `renfield mcp` runs the MCP server on stdio.
- C2. Shell selection: per OS default (Linux: `bash` if present, else `sh`; Windows: PowerShell), overridable per command with `--shell` (`bash`, `sh`, `powershell`, `cmd`). No stdin is attached to the command (non interactive).
- C3. Pairing confirmation happens on both sides: dest asks yes/no on the presented source key (mandatory, D3). Source also shows dest's fingerprint and asks yes/no before saving it in the registry. Both screens display BOTH fingerprints, labelled "this machine" and "other machine", so the human compares the same two values on the two screens. If either side rejects, nothing is stored on either side: dest rolls back its authorization, so there is never a half trusted key.
- C3b. Pairing hardening (no custom crypto, no PAKE): while in `--accept-key` mode dest handles one pairing attempt at a time and refuses concurrent ones; the window closes after the first accept or reject, or at timeout. Extra attempts get a clear "pairing in progress" refusal. The human fingerprint comparison is the trust anchor, as decided in D3.
- C3c. `--both` is a single pairing run with one handshake and two trust grants: source authorizes dest's key and dest authorizes source's key. Source tells dest its own listen address:port (given with `--listen-port`, default the same default port) and a name for itself (default: its hostname, shown and confirmed on dest). Dest stores both in its own registry. One identity key per machine serves both roles. Source must still run `renfield listen` to be commanded.
- C4. Config and key locations: `~/.config/renfield/` on Linux/macOS, `%APPDATA%\renfield\` on Windows. Private key file readable only by its owner. Registry and authorized keys in TOML (or similarly readable text), so they can be inspected and edited by hand.
- C5. Concurrency: dest accepts multiple concurrent connections; the MCP server uses one connection per request or a multiplexed one (builder's choice), so that Claude Code can run tool calls in parallel.
- C6. MCP tools (names are proposals): `remote_exec`, `remote_read`, `remote_write`, `remote_edit`, `remote_list`, `remote_put`, `remote_get`. Every tool takes the machine name as a parameter. `remote_edit` replaces an exact string and fails if the match is missing or not unique (unless a replace all flag is given), mirroring the local Edit tool. A `remote_grep` is optional for the first release (it can be done with `remote_exec`).
- C7. `remote_exec` returns stdout, stderr, exit code and a flag for "timed out". Streaming progress on the CLI is real time; over MCP the output is returned at the end unless the MCP client supports progress notifications (builder's choice).
- C8. File integrity: `put`/`get` verify a SHA-256 over the full file. Writes go to a temporary file and are renamed on success, so a failed transfer never leaves a half written target. Resume of interrupted transfers is not required.
- C9. Text handling: `remote_read`/`remote_write`/`remote_edit` operate on UTF-8 text, preserve the file's existing line endings (LF or CRLF) and report clearly on non UTF-8 input.
- C10. Exit codes of the CLI: the remote command's exit code is passed through when the command ran; renfield's own failures (cannot connect, key mismatch, not paired, ...) use a distinct reserved range documented in the README, so scripts can tell them apart.
- C11. Dest logs every incoming request (who, what, result) to its console as an audit trail.
- C12. Default port: builder picks one unregistered port and documents it.
- C14. `remote_read` mirrors the local Read tool: `offset` and `limit` in lines, output with line numbers, size cap of 1 MiB of text per call. Binary or non UTF-8 files return an error that points to `remote_get`. `remote_list` is non recursive by default (optional recursive flag), includes hidden files, and returns name, type, size and modification time for each entry.
- C15. Paths: relative paths and the default working directory of a command are resolved against the home directory of the user running dest (not dest's startup directory), `~` is expanded, and dest config may set `default_cwd`. Absolute paths use the native format of dest (`C:\...` on Windows, UNC allowed); the MCP tool descriptions say so explicitly. `--cwd` / the `cwd` tool parameter overrides it per call.
- C16. Windows default shell is Windows PowerShell 5.1 (`powershell.exe`, always present). `pwsh` (PowerShell 7) is available as an opt-in `--shell pwsh` value if installed. Dest forces UTF-8 output for the shell it launches and converts as needed, so the source always receives UTF-8.
- C17. `exec` limits: default timeout of 120 seconds on MCP calls and no default timeout on the CLI; both settable per call, with a hard maximum configurable on dest. Each of stdout and stderr is capped at 1 MiB per call in non streaming (MCP) mode: when exceeded, the tail is kept and the response carries a `truncated` flag. On timeout the process tree is killed, the response carries `timed_out: true`, and the CLI exits with a renfield reserved code (see C10).
- C13. Tests: integration tests on loopback covering pairing (accepted, rejected, timeout, key mismatch), exec (exit code, stderr, streaming, timeout), file ops, large file transfer. CI builds both Linux and Windows targets.

## 8. Left to the builder

- Wire protocol framing and message encoding on top of TLS (any simple, well documented, versioned scheme).
- Crates choice (`rustls`, `tokio`, `clap`, `serde`, an MCP implementation, ...), keeping the "single binary, no runtime dependencies" rule.
- How dest spawns shells on Windows (quoting rules, code pages, process tree kill on timeout).
- Internal module layout.

## 9. Future (explicitly out of the first release, must not be blocked)

- Dest as systemd service / Windows service.
- macOS support.
- Interactive PTY sessions.
- Directory transfer.
- Optional restrictions on dest (allowed roots, command filter).
- Key rotation.

## 10. Acceptance picture

Fabio starts `renfield listen --accept-key` on the Windows machine, runs `renfield pair win-pc 192.168.1.20:7000` on Linux, compares the fingerprint shown on both sides, confirms on dest. From Claude Code, with `renfield mcp` registered as an MCP server, Claude edits a source file on the Windows machine, runs the build there, sees the live output and the exit code, and copies the resulting binary back to Linux. At no point is anything other than the `renfield` executable installed on either machine.
