//! Command line (plan.md, "CLI shape").

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "key-steward",
    version,
    about = "Know where your keys are, and rotate them safely"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Paths for tests and odd setups.
#[derive(Args, Debug, Clone)]
pub struct Global {
    /// The database (default: $XDG_DATA_HOME/key-steward/inventory.db).
    #[arg(long, global = true, value_name = "FILE")]
    pub db: Option<PathBuf>,
    /// The ssh dir with your keys (default: ~/.ssh).
    #[arg(long, global = true, value_name = "DIR")]
    pub ssh_dir: Option<PathBuf>,
    /// Your ssh config (default: <ssh dir>/config).
    #[arg(long, global = true, value_name = "FILE")]
    pub ssh_config: Option<PathBuf>,
    /// The known_hosts file for the checks (default: ssh's own).
    #[arg(long, global = true, value_name = "FILE")]
    pub known_hosts: Option<PathBuf>,
    /// The ssh program to run (default: ssh from PATH).
    #[arg(long, global = true, value_name = "FILE")]
    pub ssh_program: Option<PathBuf>,
    /// Read an ssh config that can run commands (`Match exec`).
    #[arg(long, global = true)]
    pub allow_config_commands: bool,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Where your keys are installed.
    #[command(subcommand)]
    Locations(LocationsCmd),
    /// Replace an SSH key everywhere it is installed.
    #[command(subcommand)]
    Rotate(RotateCmd),
}

#[derive(Subcommand)]
pub enum LocationsCmd {
    /// List the stored locations.
    List {
        /// Only the locations of this key (path or SHA256 fingerprint).
        #[arg(long)]
        key: Option<String>,
    },
    /// Add a location for each host in the ssh config and key it offers.
    ImportSshConfig,
    /// Add a forge account location.
    AddForge {
        #[arg(long, value_enum)]
        kind: ForgeKind,
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        account: String,
        /// The key (path or SHA256 fingerprint).
        #[arg(long)]
        key: String,
        #[arg(long, value_enum)]
        purpose: KeyPurpose,
    },
    /// Check every location of a key and store the result.
    Check {
        #[arg(long)]
        key: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ForgeKind {
    Github,
    Gitlab,
    Forgejo,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KeyPurpose {
    Auth,
    Signing,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum NewKeyType {
    Ed25519,
    Ecdsa,
    Rsa,
}

#[derive(Args, Clone)]
pub struct PlanArgs {
    /// The key to replace (path or SHA256 fingerprint).
    #[arg(long)]
    pub key: String,
    #[arg(long = "type", value_enum, default_value = "ed25519")]
    pub key_type: NewKeyType,
    /// Where the new key goes (default: <old path>-<YYYYMMDD>).
    #[arg(long)]
    pub new_path: Option<PathBuf>,
    /// Leave this location out (the old key stays there). Repeatable.
    #[arg(long, value_name = "LOCATION ID")]
    pub skip: Vec<i64>,
    /// Add the new key to the ssh config `IdentityFile` lines.
    #[arg(long)]
    pub update_config: bool,
    /// Make the new key without a passphrase.
    #[arg(long)]
    pub no_passphrase: bool,
    /// Comment of the new key.
    #[arg(long)]
    pub comment: Option<String>,
}

#[derive(Subcommand)]
pub enum RotateCmd {
    /// Dry-run: show every action. Changes nothing.
    Plan {
        #[command(flatten)]
        args: PlanArgs,
        /// The plan as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the plan, ask, and run the rotation.
    Start {
        #[command(flatten)]
        args: PlanArgs,
        /// Do not ask: start, and move the old key files at the end.
        #[arg(long)]
        yes: bool,
    },
    /// Show a rotation (default: the open one).
    Status { id: Option<i64> },
    /// Go on with an open rotation after a stop or a crash.
    Resume {
        id: i64,
        #[arg(long)]
        yes: bool,
    },
    /// Run a failed step again.
    Retry {
        id: i64,
        /// The failed location (none: the rotation's own step).
        #[arg(long)]
        location: Option<i64>,
        #[arg(long)]
        yes: bool,
    },
    /// Leave a failed location; the old key stays there.
    Skip {
        id: i64,
        #[arg(long)]
        location: i64,
        #[arg(long)]
        yes: bool,
    },
    /// Stop the rotation.
    Abort {
        id: i64,
        /// Remove the new key where the old key still works.
        #[arg(long)]
        rollback: bool,
    },
    /// The journal and the network log of a rotation.
    Log { id: i64 },
}
