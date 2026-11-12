//! Test points and questions the engine asks (plan.md, "Fault injection
//! at every journal point").

use std::path::PathBuf;

use inventory::{LocationId, Step};

/// Where in a step the engine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Point {
    /// Before the `start` entry is written.
    BeforeStart,
    /// The `start` entry is written; the action has not run.
    AfterStart,
    /// The action has run; its `done` or `failed` entry is not written.
    AfterAction,
    /// The `done` or `failed` entry is written.
    AfterDone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalPoint {
    pub point: Point,
    pub step: Step,
    pub location: Option<LocationId>,
}

/// Returned by a hook to stop the engine at once, like a crash: nothing
/// more is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crash;

/// Called at every journal point. Tests use it to crash the engine or to
/// check the invariants; the production hook is [`NoHooks`].
pub trait Hooks {
    fn at(&self, point: &JournalPoint) -> Result<(), Crash>;
}

/// Does nothing.
pub struct NoHooks;

impl Hooks for NoHooks {
    fn at(&self, _: &JournalPoint) -> Result<(), Crash> {
        Ok(())
    }
}

/// Questions for the user during a run.
pub trait Confirm {
    /// May the old key files (`files`) move to `~/.ssh/retired/`? Asked
    /// once, after the old key is gone from every location (S-2).
    fn retire(&self, files: &[PathBuf]) -> bool;
}
