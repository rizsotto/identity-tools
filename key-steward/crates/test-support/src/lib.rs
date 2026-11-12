//! Test helpers for Key Steward: a test sshd run as the current user, temp
//! `HOME` and `GNUPGHOME`, and a guard against the real home dir.
//!
//! Use this crate only under `[dev-dependencies]`. See
//! `spec/key-steward/decisions/0002-ssh-test-servers.md`.

mod guard;
mod home;
mod sshd;

pub use guard::{User, check_dir_chain, check_not_real_home, current_user, refuse_root};
pub use home::{TempGnupgHome, TempHome};
pub use sshd::{ALIAS, Sshd};
