//! Error type and reserved exit codes of renfield.

use thiserror::Error;

/// Exit code: cannot connect to the dest machine.
pub const EXIT_CONNECT: i32 = 200;
/// Exit code: the machine name is not in the registry.
pub const EXIT_NOT_PAIRED: i32 = 201;
/// Exit code: dest refused our key.
pub const EXIT_NOT_AUTHORIZED: i32 = 202;
/// Exit code: dest presented a key different from the pinned one.
pub const EXIT_KEY_MISMATCH: i32 = 203;
/// Exit code: the remote command timed out.
pub const EXIT_TIMEOUT: i32 = 204;
/// Exit code: protocol violation or unexpected answer.
pub const EXIT_PROTOCOL: i32 = 205;
/// Exit code: wrong command line usage.
pub const EXIT_USAGE: i32 = 206;
/// Exit code: local or remote I/O failure.
pub const EXIT_IO: i32 = 207;

/// Errors raised by renfield itself, each mapped to a reserved exit code.
#[derive(Debug, Error)]
pub enum RenfieldError {
    #[error("'{0}' is not paired. Pair it first: renfield pair {0} <host:port>")]
    NotPaired(String),
    #[error(
        "this machine is not authorized on '{0}'. On '{0}' run 'renfield listen --accept-key', then here run 'renfield pair {0} <host:port>'"
    )]
    NotAuthorized(String),
    #[error(
        "the key of '{0}' is different from the one pinned at pairing (reinstall or impostor). If expected, run 'renfield remove {0}' and pair again"
    )]
    KeyMismatch(String),
    #[error("cannot connect to '{machine}' at {addr}: {reason}")]
    Connect {
        machine: String,
        addr: String,
        reason: String,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("{0}")]
    Usage(String),
    #[error("I/O error: {0}")]
    Io(String),
}

impl RenfieldError {
    /// Returns the reserved process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            RenfieldError::Connect { .. } => EXIT_CONNECT,
            RenfieldError::NotPaired(_) => EXIT_NOT_PAIRED,
            RenfieldError::NotAuthorized(_) => EXIT_NOT_AUTHORIZED,
            RenfieldError::KeyMismatch(_) => EXIT_KEY_MISMATCH,
            RenfieldError::Timeout(_) => EXIT_TIMEOUT,
            RenfieldError::Protocol(_) => EXIT_PROTOCOL,
            RenfieldError::Usage(_) => EXIT_USAGE,
            RenfieldError::Io(_) => EXIT_IO,
        }
    }
}
