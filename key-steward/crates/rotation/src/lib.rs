//! Safe SSH rotation state machine and journal.

mod files;
mod keygen;

pub use files::{Moved, RETIRED_DIR, retire};
pub use keygen::{
    GEN_DIR_PREFIX, Generated, KeyType, KeygenError, KeygenRequest, Passphrase, Recovered,
    generate, recover,
};
