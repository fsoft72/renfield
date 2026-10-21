# renfield

Secure remote commands, file editing and file transfer between your machines, with no `sshd` and nothing to install except one small executable.

`renfield` is a single binary with two roles:

- **dest** listens on a port, runs the commands it receives in its own shell and answers.
- **source** connects to a dest it has been paired with and sends commands and requests.

Any machine can be source or dest. Its main user is **Claude Code**: `renfield mcp` is an MCP server that gives Claude tools to run commands, read, write and edit text files and copy files on the other machine, almost as if it were local. The plain CLI is there for manual use and scripts.

Non interactive only: no terminal, no stdin for commands, no `vim` or `top`.

## Install

Copy the executable to each machine. There is nothing else to install.

- Linux: `renfield` (static binary, runs on any distribution).
- Windows: `renfield.exe` (uses only DLLs that ship with Windows).

Build from source (Rust stable):

```bash
cargo build --release                                      # this machine
cargo build --release --target x86_64-unknown-linux-musl   # static Linux binary
cargo build --release --target x86_64-pc-windows-gnu       # Windows exe, cross compiled
```

## Quick start

On the machine you want to command (dest, for example Windows):

```
renfield listen --accept-key
```

It listens on port 47822 (change with `--port` or `config.toml`) and, for 120 seconds (`--timeout`), is willing to accept one new key.

On the machine that commands (source, for example Linux):

```
renfield pair win-pc 192.168.1.20:47822
```

Both machines print the same two fingerprints (with the labels "This machine" and "Other machine" swapped). Compare them, answer `y` on dest first, then on source. Only then both sides store the keys. If anybody answers no, or the window expires, nothing is stored.

From now on:

```
renfield exec win-pc -- dir C:\projects
renfield exec win-pc --shell cmd --timeout 60 -- "build.bat"
renfield put win-pc ./app.zip C:\temp\app.zip
renfield get win-pc C:\temp\log.txt ./log.txt
```

Start `renfield listen` (without `--accept-key`) on dest whenever you want to be commanded. Pairing is needed only once.

### Pairing in both directions

Pairing gives the source power over the dest and nothing else. If the dest must also command the source, pair with `--both` (and run `renfield listen` on the source too):

```
renfield pair win-pc 192.168.1.20:47822 --both
```

## Use with Claude Code

Register the MCP server on the machine where Claude Code runs (the source):

```
claude mcp add renfield -- renfield mcp
```

Claude then gets these tools, each taking the machine `name`:

| Tool | What it does |
| --- | --- |
| `remote_exec` | Run a command: exit code, stdout, stderr. 120 s default timeout, 1 MiB per stream (the tail is kept). |
| `remote_read` | Read a text file, with line numbers, optional `offset` and `limit`. |
| `remote_write` | Create or overwrite a text file (keeps existing CRLF endings). |
| `remote_edit` | Replace an exact string; fails if missing or not unique unless `replace_all`. |
| `remote_list` | List a directory (hidden files included, optional recursion). |
| `remote_put` | Copy one local file to the machine (any size, checksum verified). |
| `remote_get` | Copy one file from the machine (any size, checksum verified). |

Remote paths use the native format of the remote machine (`C:\Users\me\x`, `/home/me/x`). `~` is the home directory of the user running dest, and relative paths start from it.

## Commands

| Command | Purpose |
| --- | --- |
| `renfield listen [--port N] [--config FILE] [--accept-key [--timeout SECS]]` | Run as dest. |
| `renfield pair <name> <host:port> [--both] [--listen-port N] [--force]` | Pair with a dest. |
| `renfield exec <name> [--shell S] [--cwd DIR] [--timeout SECS] -- <command>` | Run a command; exits with its exit code. |
| `renfield put <name> <local> <remote>` / `renfield get <name> <remote> <local>` | Copy one file. |
| `renfield list` / `renfield remove <name>` | Show or forget the machines you can command. |
| `renfield authorized list` / `renfield authorized revoke <label-or-fingerprint>` | Show or revoke who may command this machine. |
| `renfield mcp` | MCP server on stdio. |

Shells (`--shell`): `bash`, `sh`, `powershell` (Windows PowerShell 5.1), `pwsh` (PowerShell 7, if installed), `cmd`. Default: `bash` (else `sh`) on Linux, Windows PowerShell on Windows.

## Security model

- Transport: TLS 1.3 only, with **mutual authentication**. Each machine has a self signed Ed25519 certificate; peers are recognised by the SHA-256 fingerprint of that certificate, pinned at pairing time. No passwords, no CA, no host names.
- Login is only by key exchange. A dest never accepts an unknown key, except during the short `--accept-key` window, one attempt at a time, and only after a human confirms the fingerprints on both machines.
- A dest that sees a different key from the pinned one is refused by the source (exit code 203).
- Every request served by a dest is logged on its console (time, who, what, result).

**A dest is not restricted.** Whoever is authorized can run any command and read or write any file with the permissions of the OS user that started dest. There is no sandbox, allowlist or path limit. Run dest as a user with only the rights you are willing to give, and revoke keys you no longer need (`renfield authorized revoke`). When Claude Code is the source, its own per tool confirmations are the access control on the source side.

## Files

Configuration directory: `~/.config/renfield/` (Linux, macOS), `%APPDATA%\renfield\` (Windows), or the directory in `RENFIELD_HOME`.

| File | Content |
| --- | --- |
| `identity.crt`, `identity.key` | This machine's certificate and private key (the key is readable only by its owner). |
| `registry.toml` | Machines this one can command: name, address, pinned fingerprint. |
| `authorized.toml` | Keys allowed to command this machine. |
| `config.toml` | Optional dest settings: `port`, `default_cwd`, `max_timeout_secs`. |

## Exit codes

`renfield exec` exits with the exit code of the remote command. renfield's own failures use a reserved range:

| Code | Meaning |
| --- | --- |
| 200 | Cannot connect to the machine. |
| 201 | The name is not paired. |
| 202 | The machine does not authorize this key (pair again). |
| 203 | The machine's key changed since pairing. |
| 204 | The remote command was killed by the timeout. |
| 205 | Protocol error. |
| 206 | Wrong usage. |
| 207 | I/O error, or the machine reported an error. |

## Status and limits

- Verified: Linux (unit and end to end tests, static musl build). The Windows build compiles and its imports are only system DLLs; pairing, `cmd`, exit codes, file operations and 5 MB transfers with `C:\` paths were exercised against `renfield.exe` running under Wine. It has not been run on a real Windows machine yet, and Windows PowerShell paths are untested.
- Not included yet: interactive sessions (PTY), directory transfer, running dest as a service, macOS builds, restrictions on dest, resuming interrupted transfers.
- Text files are read and written as UTF-8. Use `put` and `get` for binary files or files over 8 MiB.
