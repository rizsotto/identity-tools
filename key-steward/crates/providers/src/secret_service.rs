//! Tokens from the Secret Service through `oo7` (SPEC 7.4, S-4, T18).
//!
//! Outside a sandbox this is the D-Bus Secret Service (GNOME Keyring,
//! KeePassXC, ...). Inside Flatpak, `oo7` uses its file backend with a key
//! from the Secret portal (SPEC 15, `oo7` item). With no Secret Service,
//! connecting fails with a clear [`TokenError::Unavailable`]; tokens are
//! never kept anywhere else.

use std::collections::HashMap;

use async_trait::async_trait;
use oo7::Keyring;

use crate::token::{Token, TokenError, TokenKey, TokenSource};

/// Value of the `application` attribute on our items. The app ID is not
/// decided yet (SPEC 16, item 1).
const APPLICATION: &str = "key-steward";

const NO_SERVICE: &str = "Key Steward keeps forge tokens only in a Secret Service, such as \
    GNOME Keyring or KeePassXC with its Secret Service turned on. Start one and try again.";

/// Reads forge tokens from the Secret Service.
#[derive(Debug)]
pub struct SecretServiceTokens {
    keyring: Keyring,
}

impl SecretServiceTokens {
    /// Connects to the user's Secret Service (or the Secret portal inside a
    /// sandbox).
    pub async fn connect() -> Result<Self, TokenError> {
        Keyring::new()
            .await
            .map(|keyring| SecretServiceTokens { keyring })
            .map_err(unavailable)
    }

    /// Connects to a Secret Service on the given D-Bus connection. For
    /// tests.
    pub async fn connect_with(connection: oo7::zbus::Connection) -> Result<Self, TokenError> {
        Keyring::host_with_connection(connection)
            .await
            .map(|keyring| SecretServiceTokens { keyring })
            .map_err(unavailable)
    }
}

/// The error for a failed connection. The oo7 text names the cause; it
/// holds no token, since none was read.
fn unavailable(e: oo7::Error) -> TokenError {
    TokenError::Unavailable(format!("no Secret Service ({e}). {NO_SERVICE}"))
}

/// The attributes that find the token of one account.
fn attributes(key: &TokenKey) -> HashMap<&'static str, String> {
    HashMap::from([
        ("application", APPLICATION.to_string()),
        ("kind", key.kind.as_str().to_string()),
        ("base_url", key.base_url.clone()),
        ("account", key.account.clone()),
    ])
}

#[async_trait]
impl TokenSource for SecretServiceTokens {
    async fn token(&self, key: &TokenKey) -> Result<Option<Token>, TokenError> {
        let fail = |what: &str, e: oo7::Error| {
            TokenError::Unavailable(format!("cannot {what} the Secret Service: {e}"))
        };
        let items = self
            .keyring
            .search_items(&attributes(key))
            .await
            .map_err(|e| fail("search", e))?;
        let Some(item) = items.first() else {
            return Ok(None);
        };
        if item.is_locked().await.map_err(|e| fail("read", e))? {
            item.unlock().await.map_err(|e| fail("unlock", e))?;
        }
        let secret = item.secret().await.map_err(|e| fail("read", e))?;
        let text = secret
            .as_str()
            .ok_or_else(|| TokenError::Unavailable("the stored token is not text".into()))?;
        Ok(Some(Token::new(text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inventory::{LocationKind, Target};
    use std::os::unix::net::UnixStream;
    use zbus::{Guid, connection::Builder};

    /// A D-Bus peer that answers but has no Secret Service on it.
    async fn empty_bus() -> (zbus::Connection, zbus::Connection) {
        let (a, b) = UnixStream::pair().unwrap();
        let guid = Guid::generate();
        let server = Builder::unix_stream(a).server(guid).p2p().build();
        let client = Builder::unix_stream(b).p2p().build();
        let (server, client) = tokio::join!(server, client);
        let server = server.unwrap();
        // Start the object server, so calls to objects that do not exist
        // get an error reply instead of no reply.
        server.object_server();
        (server, client.unwrap())
    }

    #[tokio::test]
    async fn no_secret_service_gives_clear_error() {
        let limit = std::time::Duration::from_secs(20);
        let (_server, client) = tokio::time::timeout(limit, empty_bus())
            .await
            .expect("D-Bus peer setup timed out");
        let err = tokio::time::timeout(limit, SecretServiceTokens::connect_with(client))
            .await
            .expect("connect timed out")
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, TokenError::Unavailable(_)), "{err:?}");
        assert!(
            text.starts_with("token storage is not available: no Secret Service"),
            "{text}"
        );
        assert!(text.contains("GNOME Keyring"), "{text}");
    }

    #[test]
    fn attributes_name_the_account() {
        let target = Target::Account {
            base_url: "https://codeberg.org".into(),
            account: "me".into(),
        };
        let key = TokenKey::for_target(LocationKind::Forgejo, &target).unwrap();
        let a = attributes(&key);
        assert_eq!(a["application"], "key-steward");
        assert_eq!(a["kind"], "forgejo");
        assert_eq!(a["base_url"], "https://codeberg.org");
        assert_eq!(a["account"], "me");
    }
}
