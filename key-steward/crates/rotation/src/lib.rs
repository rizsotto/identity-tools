//! Safe SSH rotation state machine and journal.

mod config;
mod engine;
mod files;
mod gate;
mod hooks;
mod invariants;
mod keygen;
mod lock;
mod sites;

pub use config::{
    ConfigError, ConfigMode, ConfigPlan, FileUpdate, LineChange, ListedLine, TextUpdate,
    apply_config_update, backup_path, change_text, plan_config_change, plan_config_update,
    restore_config, restore_config_change, update_text,
};
pub use engine::{
    CA_REASON, Ctx, Ending, Engine, EngineEnv, EngineError, Failure, RotationState, STILL_ACCEPTED,
    Summary, UNCHECKED,
};
pub use files::{Moved, RETIRED_DIR, retire};
pub use hooks::{Confirm, Crash, Hooks, JournalPoint, NoHooks, Point};
pub use invariants::{KeyPresence, check_invariants};
pub use keygen::{
    GEN_DIR_PREFIX, Generated, KeyType, KeygenError, KeygenRequest, Passphrase, Recovered,
    generate, recover,
};
pub use lock::{LockError, RotationLock, lock_path};
pub use providers::OldKeyCheck;
pub use sites::{ProviderMap, Providers, Removed};
