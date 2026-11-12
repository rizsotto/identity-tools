use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use inventory::{LocationKind, Target};

/// One network call: an ssh run or an HTTP request (NFR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetLogEntry {
    pub time: SystemTime,
    pub kind: LocationKind,
    pub target: String,
    /// The command line or `METHOD url`. Never a token.
    pub action: String,
    /// Short result: exit code and reason, or HTTP status.
    pub outcome: String,
}

/// Per-workflow log of network calls that the user can read (NFR-2).
/// Cheap to clone; clones share the same log.
///
/// Callers must not pass tokens in. The HTTP client scrubs them before it
/// records an entry (S-4).
#[derive(Debug, Clone, Default)]
pub struct NetLog {
    entries: Arc<Mutex<Vec<NetLogEntry>>>,
}

impl NetLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &self,
        kind: LocationKind,
        target: &Target,
        action: impl Into<String>,
        outcome: impl Into<String>,
    ) {
        let entry = NetLogEntry {
            time: SystemTime::now(),
            kind,
            target: target.label(),
            action: action.into(),
            outcome: outcome.into(),
        };
        self.lock().push(entry);
    }

    pub fn entries(&self) -> Vec<NetLogEntry> {
        self.lock().clone()
    }

    /// The log as plain text, one line per call.
    pub fn render(&self) -> String {
        self.lock()
            .iter()
            .map(|e| format!("{} {}: {} -> {}\n", e.kind, e.target, e.action, e.outcome))
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<NetLogEntry>> {
        // A panic while holding the lock cannot leave a half-written entry.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inventory::SshHost;

    #[test]
    fn netlog_records_entry() {
        let log = NetLog::new();
        let shared = log.clone();
        let target = Target::Ssh(SshHost::new("build"));
        let before = SystemTime::now();
        shared.record(
            LocationKind::SshServer,
            &target,
            "ssh -o BatchMode=yes build true",
            "exit 0",
        );
        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.kind, LocationKind::SshServer);
        assert_eq!(e.target, "build");
        assert_eq!(e.action, "ssh -o BatchMode=yes build true");
        assert_eq!(e.outcome, "exit 0");
        assert!(e.time >= before);
        assert_eq!(
            log.render(),
            "ssh_server build: ssh -o BatchMode=yes build true -> exit 0\n"
        );
    }
}
