//! Safe SSH rotation state machine and journal.

mod config;
mod files;
mod keygen;

pub use config::{
    ConfigError, ConfigPlan, FileUpdate, LineChange, ListedLine, TextUpdate, apply_config_update,
    backup_path, plan_config_update, restore_config, update_text,
};
pub use files::{Moved, RETIRED_DIR, retire};
pub use keygen::{
    GEN_DIR_PREFIX, Generated, KeyType, KeygenError, KeygenRequest, Passphrase, Recovered,
    generate, recover,
};
