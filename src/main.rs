//! renfield command line entry point.

use clap::Parser;
use renfield::cli::Cli;
use renfield::{commands, home};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("renfield: {e}");
            e.exit_code()
        }
    };
    std::process::exit(code);
}

/// Resolves the configuration directory and runs the subcommand.
async fn run(cli: Cli) -> Result<i32, renfield::error::RenfieldError> {
    let dir = home::dir().map_err(|e| renfield::error::RenfieldError::Io(format!("{e:#}")))?;
    commands::dispatch(&dir, cli.command).await
}
