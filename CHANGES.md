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
