use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use inventory::{LocationKind, Target};

/// A forge token. `Debug` hides the value and there is no `Display`, so it
/// cannot end up in a log or an error by accident (S-4).
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn new(value: impl Into<String>) -> Self {
        Token(value.into())
    }

    /// The secret value. Use it only to build a request header.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Which account a token belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKey {
    pub kind: LocationKind,
    pub base_url: String,
    pub account: String,
}

impl TokenKey {
    /// The key for an account target. SSH targets have no token.
    pub fn for_target(kind: LocationKind, target: &Target) -> Option<TokenKey> {
        match target {
            Target::Account { base_url, account } => Some(TokenKey {
                kind,
                base_url: base_url.clone(),
                account: account.clone(),
            }),
            Target::Ssh(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// No token store to read from, for example no Secret Service. The
    /// text says why and what to do.
    #[error("token storage is not available: {0}")]
    Unavailable(String),
}

/// Where tokens come from. The real one is Secret Service (T18); tests use
/// [`InMemoryTokenSource`]. Tokens are never stored anywhere else (S-4).
#[async_trait]
pub trait TokenSource: Send + Sync {
    /// The token for this account, or `None` if none is stored.
    async fn token(&self, key: &TokenKey) -> Result<Option<Token>, TokenError>;
}

/// Tokens held in memory only. For tests.
#[derive(Default)]
pub struct InMemoryTokenSource {
    tokens: Mutex<HashMap<TokenKey, Token>>,
}

impl InMemoryTokenSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, key: TokenKey, token: Token) {
        self.tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, token);
    }
}

#[async_trait]
impl TokenSource for InMemoryTokenSource {
    async fn token(&self, key: &TokenKey) -> Result<Option<Token>, TokenError> {
        Ok(self
            .tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inventory::SshHost;

    fn account(name: &str) -> Target {
        Target::Account {
            base_url: "https://gitlab.example.org".into(),
            account: name.into(),
        }
    }

    #[tokio::test]
    async fn in_memory_token_source() {
        let src = InMemoryTokenSource::new();
        let key = TokenKey::for_target(LocationKind::GitLab, &account("me")).unwrap();
        assert_eq!(src.token(&key).await.unwrap(), None);
        src.insert(key.clone(), Token::new("glpat-fake-0000"));
        let got = src.token(&key).await.unwrap().unwrap();
        assert_eq!(got.expose(), "glpat-fake-0000");

        let other = TokenKey::for_target(LocationKind::GitLab, &account("you")).unwrap();
        assert_eq!(src.token(&other).await.unwrap(), None);
        let other_kind = TokenKey::for_target(LocationKind::GitHub, &account("me")).unwrap();
        assert_eq!(src.token(&other_kind).await.unwrap(), None);

        let dynsrc: &dyn TokenSource = &src;
        assert!(dynsrc.token(&key).await.unwrap().is_some());
    }

    #[test]
    fn token_debug_hides_value() {
        let t = Token::new("ghp_fake_secret");
        assert_eq!(format!("{t:?}"), "Token(<redacted>)");
        assert!(!format!("{:?}", Some(t)).contains("ghp_fake_secret"));
    }

    #[test]
    fn ssh_target_has_no_token_key() {
        let t = Target::Ssh(SshHost::new("build"));
        assert!(TokenKey::for_target(LocationKind::SshServer, &t).is_none());
    }
}
