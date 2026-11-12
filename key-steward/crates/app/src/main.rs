//! `key-steward`: the headless M2 CLI. Locations and SSH key rotation.
//! No window yet (SPEC 16 item 1).
//!
//! Exit codes: 0 done, 1 error, 2 refused (pre-flight, lock, usage),
//! 3 rotation stopped with a failed location (retry, skip or abort).

mod cli;
mod locations;
mod rotate;
mod setup;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Cmd};

/// Why a command ended without success.
#[derive(Debug)]
pub enum Fail {
    /// Refused before any change (exit 2).
    Refused(String),
    /// Any other error (exit 1).
    Error(String),
}

impl Fail {
    pub fn error(e: impl std::fmt::Display) -> Fail {
        Fail::Error(e.to_string())
    }
}

/// Exit code of a command that ran.
pub const STOPPED: u8 = 3;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("key-steward: cannot start: {e}");
            return ExitCode::from(1);
        }
    };
    let result = rt.block_on(async {
        let paths = setup::Paths::from_cli(&cli.global)?;
        match cli.cmd {
            Cmd::Locations(c) => locations::run(&paths, c).await,
            Cmd::Rotate(c) => rotate::run(&paths, c).await,
        }
    });
    match result {
        Ok(code) => ExitCode::from(code),
        Err(Fail::Refused(m)) => {
            eprintln!("key-steward: refused: {m}");
            ExitCode::from(2)
        }
        Err(Fail::Error(m)) => {
            eprintln!("key-steward: error: {m}");
            ExitCode::from(1)
        }
    }
}
