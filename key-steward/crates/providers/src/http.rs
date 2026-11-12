//! Shared HTTP client for the forge providers (FR-4, NFR-2, S-4).
//!
//! - One base URL per account, so tests point it at wiremock.
//! - The token goes only into a request header, and only to the base URL's
//!   origin: no redirects are followed, and pagination links to another
//!   origin are refused. Plain `http` is allowed only for loopback hosts.
//! - Every request is written to the [`NetLog`]. The token is scrubbed from
//!   every log entry and error text.

use std::time::Duration;

use inventory::{LocationKind, Target};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LINK, USER_AGENT};
use reqwest::{Client, StatusCode, Url, redirect};

use crate::error::ProviderError;
use crate::netlog::NetLog;
use crate::token::Token;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body we read.
const MAX_BODY: usize = 10 * 1024 * 1024;
/// Most pages one listing may have.
const MAX_PAGES: usize = 100;
const REDACTED: &str = "[redacted]";

/// How a forge wants the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <token>` (GitHub, GitLab).
    Bearer,
    /// `PRIVATE-TOKEN: <token>` (GitLab).
    PrivateToken,
    /// `Authorization: token <token>` (Forgejo, Gitea).
    TokenPrefix,
}

/// HTTP client for one account on one forge.
#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
    base: Url,
    kind: LocationKind,
    target: Target,
    token: Option<Token>,
    netlog: NetLog,
}

impl HttpClient {
    /// `base_url` is the API root, for example `https://api.github.com` or
    /// `https://gitlab.example.org/api/v4`. `headers` are sent with every
    /// request, next to the auth header.
    pub fn new(
        kind: LocationKind,
        target: &Target,
        base_url: &str,
        auth: AuthStyle,
        token: Option<Token>,
        headers: &[(&'static str, &str)],
        netlog: NetLog,
    ) -> Result<HttpClient, ProviderError> {
        let scrub = |s: &str| scrub_token(s, token.as_ref());
        let base = Url::parse(base_url)
            .map_err(|e| ProviderError::Http(scrub(&format!("bad base URL: {e}"))))?;
        check_scheme(&base)?;

        let mut default = HeaderMap::new();
        default.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("key-steward/", env!("CARGO_PKG_VERSION"))),
        );
        for (name, value) in headers {
            let value = HeaderValue::from_str(value)
                .map_err(|_| ProviderError::Http(format!("bad value for header {name}")))?;
            default.insert(HeaderName::from_static(name), value);
        }
        if let Some(token) = &token {
            let (name, value) = match auth {
                AuthStyle::Bearer => ("authorization", format!("Bearer {}", token.expose())),
                AuthStyle::PrivateToken => ("private-token", token.expose().to_string()),
                AuthStyle::TokenPrefix => ("authorization", format!("token {}", token.expose())),
            };
            let mut value = HeaderValue::from_str(&value).map_err(|_| {
                ProviderError::Http("the token has characters a header cannot hold".into())
            })?;
            value.set_sensitive(true);
            default.insert(HeaderName::from_static(name), value);
        }
        let client = Client::builder()
            .default_headers(default)
            .redirect(redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| ProviderError::Http(scrub(&e.to_string())))?;
        Ok(HttpClient {
            client,
            base,
            kind,
            target: target.clone(),
            token,
            netlog,
        })
    }

    /// `GET <base><path>` and parse the body as JSON.
    pub async fn get_json(&self, path: &str) -> Result<serde_json::Value, ProviderError> {
        let url = self.url(path)?;
        Ok(self.get(url).await?.0)
    }

    /// `GET <base><path>`, then follow `link: <...>; rel="next"` (or
    /// GitLab's `x-next-page`) while there is one. Each page must be a JSON array; returns all items in order.
    pub async fn get_all_pages(&self, path: &str) -> Result<Vec<serde_json::Value>, ProviderError> {
        let mut url = self.url(path)?;
        let mut items = Vec::new();
        for _ in 0..MAX_PAGES {
            let (body, next) = self.get(url).await?;
            match body {
                serde_json::Value::Array(page) => items.extend(page),
                _ => return Err(ProviderError::Http("expected a JSON list".into())),
            }
            match next {
                Some(n) => url = n,
                None => return Ok(items),
            }
        }
        Err(ProviderError::Http(format!(
            "more than {MAX_PAGES} pages; stopped"
        )))
    }

    fn url(&self, path: &str) -> Result<Url, ProviderError> {
        let mut base = self.base.as_str().trim_end_matches('/').to_string();
        base.push_str(path);
        Url::parse(&base).map_err(|e| ProviderError::Http(self.scrub(&format!("bad URL: {e}"))))
    }

    fn same_origin(&self, url: &Url) -> bool {
        url.scheme() == self.base.scheme()
            && url.host_str() == self.base.host_str()
            && url.port_or_known_default() == self.base.port_or_known_default()
    }

    async fn get(&self, url: Url) -> Result<(serde_json::Value, Option<Url>), ProviderError> {
        let action = self.scrub(&format!("GET {url}"));
        let result = self.fetch(url).await;
        let outcome = match &result {
            Ok((_, Some(_))) => "HTTP 200, more pages".to_string(),
            Ok((_, None)) => "HTTP 200".to_string(),
            Err(e) => e.to_string(),
        };
        self.netlog.record(self.kind, &self.target, action, outcome);
        result
    }

    async fn fetch(&self, url: Url) -> Result<(serde_json::Value, Option<Url>), ProviderError> {
        if !self.same_origin(&url) {
            return Err(ProviderError::Http(self.scrub(&format!(
                "refused to send the token to {}, which is not {}",
                url.origin().ascii_serialization(),
                self.base.origin().ascii_serialization()
            ))));
        }
        let mut resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| ProviderError::Http(self.scrub(&error_chain(&e))))?;
        let status = resp.status();
        if status != StatusCode::OK {
            return Err(ProviderError::HttpStatus {
                status: status.as_u16(),
                url: self.scrub(url.as_str()),
            });
        }
        let next = next_link(resp.headers())
            .map(|n| url.join(&n))
            .transpose()
            .map_err(|e| ProviderError::Http(self.scrub(&format!("bad next page link: {e}"))))?
            .or_else(|| next_page_param(resp.headers()).map(|n| with_page(&url, n)));

        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProviderError::Http(self.scrub(&error_chain(&e))))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(ProviderError::Http(format!(
                    "response larger than {MAX_BODY} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let json = serde_json::from_slice(&body)
            .map_err(|e| ProviderError::Http(format!("response is not valid JSON: {e}")))?;
        Ok((json, next))
    }

    fn scrub(&self, text: &str) -> String {
        scrub_token(text, self.token.as_ref())
    }
}

fn check_scheme(base: &Url) -> Result<(), ProviderError> {
    let loopback = match base.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };
    match base.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        other => Err(ProviderError::Http(format!(
            "refused: the API URL must use https, not {other}"
        ))),
    }
}

/// The error and its sources, which hold the useful part (for example
/// "Connection refused").
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Replaces the token, and its URL-encoded form, with `[redacted]`.
pub(crate) fn scrub_token(text: &str, token: Option<&Token>) -> String {
    let Some(token) = token else {
        return text.to_string();
    };
    let secret = token.expose();
    if secret.is_empty() {
        return text.to_string();
    }
    let mut out = text.replace(secret, REDACTED);
    let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    if encoded != secret {
        out = out.replace(&encoded, REDACTED);
    }
    out
}

/// GitLab's `x-next-page` header, for when it sends no `link` header.
/// Empty on the last page.
fn next_page_param(headers: &HeaderMap) -> Option<u32> {
    headers
        .get("x-next-page")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// `url` with its `page` query parameter set to `page`.
fn with_page(url: &Url, page: u32) -> Url {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "page")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut out = url.clone();
    out.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("page", &page.to_string());
    out
}

/// The `rel="next"` target of a `link` header, if any.
fn next_link(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(LINK) {
        let Ok(value) = value.to_str() else { continue };
        for part in value.split(',') {
            let mut fields = part.split(';');
            let Some(target) = fields.next() else {
                continue;
            };
            let target = target.trim();
            let is_next = fields.any(|f| {
                let f = f.trim();
                f == "rel=\"next\"" || f == "rel=next"
            });
            if is_next && target.starts_with('<') && target.ends_with('>') {
                return Some(target[1..target.len() - 1].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_next_link() {
        let mut h = HeaderMap::new();
        h.insert(
            LINK,
            HeaderValue::from_static(
                "<https://api.github.com/user/keys?page=3>; rel=\"next\", \
                 <https://api.github.com/user/keys?page=5>; rel=\"last\"",
            ),
        );
        assert_eq!(
            next_link(&h).as_deref(),
            Some("https://api.github.com/user/keys?page=3")
        );
        let mut h = HeaderMap::new();
        h.insert(
            LINK,
            HeaderValue::from_static(
                "<https://x/?page=1>; rel=\"prev\", <https://x/?page=1>; rel=\"first\"",
            ),
        );
        assert_eq!(next_link(&h), None);
        assert_eq!(next_link(&HeaderMap::new()), None);
    }

    #[test]
    fn x_next_page_sets_page_param() {
        let mut h = HeaderMap::new();
        h.insert("x-next-page", HeaderValue::from_static("3"));
        assert_eq!(next_page_param(&h), Some(3));
        h.insert("x-next-page", HeaderValue::from_static(""));
        assert_eq!(next_page_param(&h), None);
        assert_eq!(next_page_param(&HeaderMap::new()), None);
        let url = Url::parse("https://gl.example/api/v4/user/keys?per_page=100&page=2").unwrap();
        assert_eq!(
            with_page(&url, 3).as_str(),
            "https://gl.example/api/v4/user/keys?per_page=100&page=3"
        );
    }

    #[test]
    fn scrubs_plain_and_encoded_token() {
        let t = Token::new("a b/c");
        assert_eq!(
            scrub_token("x a b/c y a+b%2Fc z", Some(&t)),
            "x [redacted] y [redacted] z"
        );
        assert_eq!(scrub_token("abc", None), "abc");
        assert_eq!(scrub_token("abc", Some(&Token::new(""))), "abc");
    }

    #[test]
    fn plain_http_only_for_loopback() {
        let t = Target::Account {
            base_url: "x".into(),
            account: "me".into(),
        };
        let mk = |url: &str| {
            HttpClient::new(
                LocationKind::GitHub,
                &t,
                url,
                AuthStyle::Bearer,
                None,
                &[],
                NetLog::new(),
            )
        };
        assert!(mk("https://api.github.com").is_ok());
        assert!(mk("http://127.0.0.1:8080").is_ok());
        assert!(mk("http://[::1]:8080").is_ok());
        assert!(mk("http://localhost:8080").is_ok());
        assert!(mk("http://gitlab.example.org").is_err());
        assert!(mk("ftp://gitlab.example.org").is_err());
    }
}
