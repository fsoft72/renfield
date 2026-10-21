//! Command line definition.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::proto::ShellKind;

/// Secure remote commands, file editing and transfer between your machines.
#[derive(Debug, Parser)]
#[command(name = "renfield", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The renfield subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run as dest: listen for authorized sources and execute their requests.
    Listen {
        /// TCP port to listen on (default: config file, then 47822).
        #[arg(long)]
        port: Option<u16>,
        /// Configuration file (default: config.toml in the renfield config directory).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Pairing mode: for a short time accept the key of a new source, after manual confirmation.
        #[arg(long)]
        accept_key: bool,
        /// Seconds the pairing window stays open (with --accept-key).
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// Run as an MCP server on stdio, giving Claude Code tools for the paired machines.
    Mcp,
    /// Copy a local file to a paired machine.
    Put {
        /// Name of the machine in the registry.
        name: String,
        /// Local file to send.
        local: PathBuf,
        /// Destination path on the remote machine.
        remote: String,
    },
    /// Copy a file from a paired machine to this one.
    Get {
        /// Name of the machine in the registry.
        name: String,
        /// File to fetch on the remote machine.
        remote: String,
        /// Local destination path.
        local: PathBuf,
    },
    /// Pair this machine (source) with a dest started with `listen --accept-key`.
    Pair {
        /// Name to register the machine under.
        name: String,
        /// Address of dest, host:port.
        addr: String,
        /// Let dest command this machine too (this machine must also run `listen`).
        #[arg(long)]
        both: bool,
        /// Port this machine listens on, told to dest with --both.
        #[arg(long)]
        listen_port: Option<u16>,
        /// Replace an existing machine of the same name.
        #[arg(long)]
        force: bool,
    },
    /// Run a command on a paired machine and stream its output.
    Exec {
        /// Name of the machine in the registry.
        name: String,
        /// Shell to use on the remote machine.
        #[arg(long, value_enum)]
        shell: Option<ShellKind>,
        /// Working directory on the remote machine.
        #[arg(long)]
        cwd: Option<String>,
        /// Kill the command after this many seconds.
        #[arg(long)]
        timeout: Option<u64>,
        /// The command line to run.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}
