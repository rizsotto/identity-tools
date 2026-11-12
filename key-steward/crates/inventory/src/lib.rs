//! Key inventory: local keys and where each one is installed.
//!
//! Only locations and their check results are stored. Keys are scanned each
//! time. Nothing here holds a token (S-4).

mod location;
mod ssh_config;
mod store;

pub use location::{
    Location, LocationId, LocationKind, NewLocation, Purpose, SshHost, Status, Target,
};
pub use ssh_config::{
    ImportError, ImportOptions, ImportReport, KnownKey, Resolved, host_aliases, import_ssh_config,
    resolve,
};
pub use store::{Added, Store, StoreError};
