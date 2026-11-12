use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// One network action of a lookup: a DNS check or an HTTP request (NFR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetLogEntry {
    pub time: SystemTime,
    /// `GET <url>` or `DNS <host>`, with the real URL (never a mock address).
    pub action: String,
    /// Short result: HTTP status and size, redirect target, or the error.
    /// Never holds response bytes.
    pub outcome: String,
}

/// Log of network actions the user can read (`lookup --verbose`).
/// Cheap to clone; clones share the same log.
#[derive(Debug, Clone, Default)]
pub struct NetLog {
    entries: Arc<Mutex<Vec<NetLogEntry>>>,
}

impl NetLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, action: impl Into<String>, outcome: impl Into<String>) {
        let entry = NetLogEntry {
            time: SystemTime::now(),
            action: action.into(),
            outcome: outcome.into(),
        };
        self.lock().push(entry);
    }

    pub fn entries(&self) -> Vec<NetLogEntry> {
        self.lock().clone()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Entries from index `start` on, to list one lookup's actions.
    pub fn entries_since(&self, start: usize) -> Vec<NetLogEntry> {
        self.lock().get(start..).unwrap_or_default().to_vec()
    }

    /// The log as plain text, one line per action.
    pub fn render(&self) -> String {
        self.lock()
            .iter()
            .map(|e| format!("{} -> {}\n", e.action, e.outcome))
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

    #[test]
    fn netlog_records_and_slices() {
        let log = NetLog::new();
        let shared = log.clone();
        assert!(log.is_empty());
        shared.record("GET https://a.example.org/", "HTTP 200, 3 bytes");
        shared.record("DNS openpgpkey.example.org", "has an address");
        assert_eq!(log.len(), 2);
        assert_eq!(log.entries_since(1)[0].action, "DNS openpgpkey.example.org");
        assert!(log.entries_since(5).is_empty());
        assert_eq!(
            log.render(),
            "GET https://a.example.org/ -> HTTP 200, 3 bytes\n\
             DNS openpgpkey.example.org -> has an address\n"
        );
    }
}
