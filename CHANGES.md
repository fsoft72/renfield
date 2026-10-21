# Changes

## 2026-10-21

- Added the renfield design document (docs/superpowers/specs/2026-10-21-renfield-design.md).
- Scaffolded the crate (lib + bin), config home resolution, machine identity (self signed Ed25519) and the registry and authorized key stores.
- Added the framed wire protocol (u32 length, kind byte, body) and mutual TLS 1.3 with peers pinned by certificate fingerprint, plus the error type with reserved exit codes.
- Added the dest server (listen) and streaming command execution (exec) with shell selection, working directory, timeout and process tree kill; config file with port, default_cwd and max_timeout_secs.
- Added explicit two phase pairing: `listen --accept-key` (timed window, one attempt, manual confirmation) and `pair <name> <host:port> [--both] [--force]`; nothing is stored unless both humans confirm.
- Added remote text file operations: read (offset/limit, size cap), write (atomic, keeps CRLF), edit (exact unique string, keeps CRLF and permissions) and list (hidden files, metadata, recursive).
- Added single file transfer in both directions (`put` / `get`): streamed in 256 KiB frames, SHA-256 verified before the file appears, partial files never left behind, progress line for big files.
- Added the MCP server (`renfield mcp`, JSON-RPC over stdio) with seven tools: remote_exec, remote_read, remote_write, remote_edit, remote_list, remote_put, remote_get. Calls run concurrently; exec output is capped at 1 MiB per stream (tail kept) with a 120 s default timeout.
- Added `list`, `remove`, `authorized list|revoke`, the reserved exit codes (200-207) verified end to end on the real binary, and an audit line on dest for every request (time, peer label, operation, result).
- Release profile (fat LTO, stripped), static musl Linux build and Windows exe verified (system DLLs only, exercised under Wine), README with quick start, security model, exit codes and limits.
- Hardening after the final review: pairing names are validated (no forged prompts), silent peers are dropped (handshake and first request timeouts), frame bodies are read incrementally, a vanished source kills its running command tree, kills are bounded on Windows, children run with a hidden console on Windows, and writes go through symlinks.
- Fixed a panic in `remote_read` when `limit` (or `offset`) was huge: the line range now uses a saturating sum.
- `exec` with several arguments now keeps their boundaries: dest quotes each argument for its shell (bash/sh, PowerShell, cmd). A single argument is still a command line for the remote shell.
- A connection that dies before dest ever answers (reset, broken pipe, early EOF) is now reported as "not authorized" (exit 202) instead of a generic I/O error: dest rejects unknown keys right after the handshake, and under load the client saw the reset before the TLS alert.
- A verified download whose final rename fails no longer leaves its `.renfield-part` file behind.
- An unknown key that connects while the pairing window is open and tries to run something now gets "not authorized" (exit 202) instead of a generic remote error (207).
- The MCP server ignores JSON-RPC responses sent by the client instead of answering them with an error.
- MCP: the timeout message reports the limit dest actually applied (its own maximum may be lower than the requested one), and the remote_edit description explains how mixed line endings are matched.
- The pairing prompts on both machines say explicitly when `--both` lets the other machine command this one.
- The name a machine gives itself in pairings now comes from the OS host name (gethostname on unix, COMPUTERNAME on Windows), so macOS no longer falls back to a fixed name.
- The private key is created owner-only from the start (mode 0600 at creation) instead of being chmod-ed after it was written.
- The pairing question has a 300 s time limit, a newer question replaces a pending older one, and a source that disconnects while dest is waiting for the human frees the pairing slot without closing the window, so no stale prompt blocks a retry.
