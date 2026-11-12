//! Key inventory: local keys and where each one is installed.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::version().is_empty());
    }
}
