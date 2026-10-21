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
