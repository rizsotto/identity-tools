//! The resolver's small HTTP layer (plan.md "Runtime and HTTP").
//!
//! - https only. Redirects are followed by hand, at most
//!   [`ResolverConfig::max_redirects`] hops, each one https.
//! - A body over [`MAX_KEY_INPUT`] is refused while reading (S-7). Errors
//!   never hold response bytes.
//! - Every request is written to the [`NetLog`] with its real URL (NFR-2).
//! - Tests map https origins to loopback mock servers with
//!   [`Net::with_mock_origins`]. A host outside the map gets an error, never
//!   a connection. The shipped binary has no way to turn this on.
//! - Rate limits: a 429, or a 403 with `x-ratelimit-remaining: 0`, puts the
//!   host on a cooldown for the life of this `Net`. Never an automatic retry.
//! - The WKD DNS check ([`Net::host_has_address`]) keeps its answer, and
//!   the request to that host uses it (no second lookup).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dns_lookup::LookupErrorKind;

use identity_core::MAX_KEY_INPUT;
use reqwest::header::{HeaderMap, LOCATION, RETRY_AFTER};
use reqwest::{Client, StatusCode, redirect};
use tokio::time::{Instant, timeout_at};
use url::{Position, Url};

use crate::ResolverConfig;
use crate::netlog::NetLog;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = concat!("send-secret/", env!("CARGO_PKG_VERSION"));
/// Cooldown after a rate limit answer without a usable `Retry-After`.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);
/// Longest cooldown a server can ask for.
const MAX_COOLDOWN: Duration = Duration::from_secs(3600);

/// A network error. The text never holds response bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("not found (HTTP 404)")]
    NotFound,
    #[error("timed out")]
    Timeout,
    #[error("the answer is larger than {MAX_KEY_INPUT} bytes")]
    TooLarge,
    #[error("HTTP {0}")]
    Http(u16),
    #[error("HTTP 401: the server asked for a login, which is never answered")]
    LoginRequired,
    #[error("rate limited by the server{}", wait_text(*.retry_after))]
    RateLimited { retry_after: Option<Duration> },
    #[error("skipped: {host} rate limited us{}", wait_text(Some(*.wait)))]
    CoolingDown { host: String, wait: Duration },
    #[error("DNS lookup failed: {0}")]
    Dns(String),
    #[error("refused: {0} is not an https URL")]
    NotHttps(String),
    #[error("more than {0} redirects; stopped")]
    TooManyRedirects(u8),
    #[error("a redirect without a valid Location")]
    BadRedirect,
    #[error("no mock server for {0}; request not sent")]
    Unmapped(String),
    #[error("{0}")]
    Transport(String),
    #[error("cannot set up the HTTP client: {0}")]
    Setup(String),
}

/// A successful (HTTP 200) answer.
#[derive(Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The URL that answered, after redirects.
    pub url: Url,
    /// The URL first asked.
    pub first_url: Url,
    pub body: Vec<u8>,
}

impl fmt::Debug for Fetched {
    /// The body is never printed, only its length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetched")
            .field("url", &self.url.as_str())
            .field("first_url", &self.first_url.as_str())
            .field("body", &format_args!("{} bytes", self.body.len()))
            .finish()
    }
}

/// Tests only: https origins and the loopback mock server that stands in
/// for each.
#[derive(Debug, Clone, Default)]
pub struct OriginMap {
    map: HashMap<(String, u16), SocketAddr>,
}

impl OriginMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// `origin` is `https://host[:port]`, with no path.
    pub fn insert(&mut self, origin: &str, mock: SocketAddr) -> Result<(), NetError> {
        let bad = || NetError::Setup(format!("bad mock origin {origin}"));
        let url = Url::parse(origin).map_err(|_| bad())?;
        if url.scheme() != "https" {
            return Err(NetError::NotHttps(origin.to_string()));
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() {
            return Err(bad());
        }
        let host = url.host_str().ok_or_else(bad)?.to_ascii_lowercase();
        let port = url.port_or_known_default().ok_or_else(bad)?;
        self.map.insert((host, port), mock);
        Ok(())
    }

    fn get(&self, url: &Url) -> Option<SocketAddr> {
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        self.map.get(&(host, port)).copied()
    }
}

#[derive(Debug)]
enum Mode {
    Real,
    Mock(OriginMap),
}

/// Addresses found by the DNS check, by lower case host name.
type DnsCache = Arc<Mutex<HashMap<String, Vec<IpAddr>>>>;

#[derive(Debug)]
struct Inner {
    client: Client,
    mode: Mode,
    log: NetLog,
    max_redirects: u8,
    dns: DnsCache,
    cooldowns: Mutex<HashMap<String, Instant>>,
}

/// The HTTP layer. Cheap to clone; clones share the client and the log.
#[derive(Debug, Clone)]
pub struct Net {
    inner: Arc<Inner>,
}

enum Hop {
    Done(Vec<u8>),
    Redirect(Url),
}

impl Net {
    /// The real client: https only, system DNS, system CA store, proxies
    /// from the environment.
    pub fn new(cfg: &ResolverConfig) -> Result<Net, NetError> {
        let dns = DnsCache::default();
        let client = base_builder()
            .https_only(true)
            .dns_resolver(CachedDns(dns.clone()))
            .build()
            .map_err(|e| NetError::Setup(error_chain(&e)))?;
        Ok(Net::from_parts(client, Mode::Real, cfg, dns))
    }

    /// Tests only, by API (no env var, no config file, no CLI flag): every
    /// https origin in `map` goes to its `http://127.0.0.1:PORT` (or
    /// `[::1]`) mock. Non-loopback targets are refused. A request to a host
    /// not in the map fails with an error, never a real connection.
    pub fn with_mock_origins(cfg: &ResolverConfig, map: OriginMap) -> Result<Net, NetError> {
        if let Some(addr) = map.map.values().find(|a| !a.ip().is_loopback()) {
            return Err(NetError::Setup(format!(
                "mock target {addr} is not a loopback address"
            )));
        }
        let client = base_builder()
            .no_proxy()
            .dns_resolver(NoDns)
            .build()
            .map_err(|e| NetError::Setup(error_chain(&e)))?;
        Ok(Net::from_parts(
            client,
            Mode::Mock(map),
            cfg,
            DnsCache::default(),
        ))
    }

    fn from_parts(client: Client, mode: Mode, cfg: &ResolverConfig, dns: DnsCache) -> Net {
        Net {
            inner: Arc::new(Inner {
                client,
                mode,
                log: NetLog::new(),
                max_redirects: cfg.max_redirects,
                dns,
                cooldowns: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The WKD DNS check: does `host` have an address? `Ok(false)` only for
    /// "no such name" or "no address" (`EAI_NONAME`, `EAI_NODATA`); "try
    /// again" and other failures are errors. Logged (NFR-2). In test mode,
    /// a host has an address when it is in the origin map.
    pub async fn host_has_address(&self, host: &str, deadline: Instant) -> Result<bool, NetError> {
        let host = host.to_ascii_lowercase();
        let result = match &self.inner.mode {
            Mode::Mock(map) => Ok(map.map.keys().any(|(h, _)| *h == host)),
            Mode::Real => {
                let name = host.clone();
                let lookup = tokio::task::spawn_blocking(move || system_lookup(&name));
                match timeout_at(deadline, lookup).await {
                    Err(_) => Err(NetError::Timeout),
                    Ok(Err(e)) => Err(NetError::Dns(e.to_string())),
                    Ok(Ok(Err(e))) => Err(e),
                    Ok(Ok(Ok(addrs))) => {
                        let found = !addrs.is_empty();
                        if found {
                            lock(&self.inner.dns).insert(host.clone(), addrs);
                        }
                        Ok(found)
                    }
                }
            }
        };
        let outcome = match &result {
            Ok(true) => "has an address".to_string(),
            Ok(false) => "no address".to_string(),
            Err(e) => e.to_string(),
        };
        self.inner.log.record(format!("DNS {host}"), outcome);
        result
    }

    pub fn log(&self) -> &NetLog {
        &self.inner.log
    }

    /// `GET url`, following https redirects, all before `deadline`.
    /// 404 is [`NetError::NotFound`]; any other status but 200 is an error.
    pub async fn get(&self, url: &Url, deadline: Instant) -> Result<Fetched, NetError> {
        let mut current = url.clone();
        let mut redirects = 0u8;
        loop {
            match self.hop(&current, deadline).await? {
                Hop::Done(body) => {
                    return Ok(Fetched {
                        url: current,
                        first_url: url.clone(),
                        body,
                    });
                }
                Hop::Redirect(next) => {
                    if redirects >= self.inner.max_redirects {
                        return Err(NetError::TooManyRedirects(self.inner.max_redirects));
                    }
                    redirects += 1;
                    current = next;
                }
            }
        }
    }

    /// One request, logged.
    async fn hop(&self, url: &Url, deadline: Instant) -> Result<Hop, NetError> {
        let action = format!("GET {url}");
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let result = match self.cooling_down(&host) {
            Some(wait) => Err(NetError::CoolingDown {
                host: host.clone(),
                wait,
            }),
            None => match timeout_at(deadline, self.send(url)).await {
                Ok(r) => r,
                Err(_) => Err(NetError::Timeout),
            },
        };
        if let Err(NetError::RateLimited { retry_after }) = &result {
            let wait = retry_after.unwrap_or(DEFAULT_COOLDOWN);
            lock(&self.inner.cooldowns).insert(host, Instant::now() + wait);
        }
        let outcome = match &result {
            Ok((_, Hop::Done(body))) => format!("HTTP 200, {} bytes", body.len()),
            Ok((status, Hop::Redirect(next))) => format!("HTTP {status}, redirect to {next}"),
            Err(e) => e.to_string(),
        };
        self.inner.log.record(action, outcome);
        result.map(|(_, hop)| hop)
    }

    async fn send(&self, url: &Url) -> Result<(u16, Hop), NetError> {
        if url.scheme() != "https" {
            return Err(NetError::NotHttps(url.to_string()));
        }
        let target = self.target(url)?;
        let mut resp = self
            .inner
            .client
            .get(target)
            .send()
            .await
            .map_err(|e| NetError::Transport(error_chain(&e.without_url())))?;
        let status = resp.status();
        if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
            let next = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| url.join(v).ok())
                .ok_or(NetError::BadRedirect)?;
            if next.scheme() != "https" {
                return Err(NetError::NotHttps(next.to_string()));
            }
            return Ok((status.as_u16(), Hop::Redirect(next)));
        }
        match status {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(NetError::NotFound),
            StatusCode::UNAUTHORIZED => return Err(NetError::LoginRequired),
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(NetError::RateLimited {
                    retry_after: retry_after(resp.headers()),
                });
            }
            StatusCode::FORBIDDEN
                if header_str(resp.headers(), "x-ratelimit-remaining") == Some("0") =>
            {
                return Err(NetError::RateLimited {
                    retry_after: retry_after(resp.headers()),
                });
            }
            other => return Err(NetError::Http(other.as_u16())),
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_KEY_INPUT as u64)
        {
            return Err(NetError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| NetError::Transport(error_chain(&e.without_url())))?
        {
            if body.len() + chunk.len() > MAX_KEY_INPUT {
                return Err(NetError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((200, Hop::Done(body)))
    }

    /// The URL to connect to: the URL itself, or its mock in test mode.
    fn target(&self, url: &Url) -> Result<Url, NetError> {
        match &self.inner.mode {
            Mode::Real => Ok(url.clone()),
            Mode::Mock(map) => {
                let host = url.host_str().unwrap_or_default().to_string();
                let addr = map.get(url).ok_or(NetError::Unmapped(host))?;
                let rest = &url[Position::BeforePath..Position::AfterQuery];
                Url::parse(&format!("http://{addr}{rest}"))
                    .map_err(|e| NetError::Setup(e.to_string()))
            }
        }
    }
}

impl Net {
    /// Time left on `host`'s cooldown, if any.
    fn cooling_down(&self, host: &str) -> Option<Duration> {
        let mut cooldowns = lock(&self.inner.cooldowns);
        let until = *cooldowns.get(host)?;
        let now = Instant::now();
        if until > now {
            Some(until - now)
        } else {
            cooldowns.remove(host);
            None
        }
    }
}

fn wait_text(wait: Option<Duration>) -> String {
    match wait {
        Some(d) => format!("; try again in {} s", d.as_secs().max(1)),
        None => String::new(),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok().map(str::trim)
}

/// `Retry-After` in seconds, else GitHub's `x-ratelimit-reset` (Unix
/// time). HTTP dates are not read. Capped at [`MAX_COOLDOWN`].
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let wait = if let Some(v) = header_str(headers, RETRY_AFTER.as_str()) {
        Duration::from_secs(v.parse().ok()?)
    } else {
        let reset: u64 = header_str(headers, "x-ratelimit-reset")?.parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Duration::from_secs(reset.saturating_sub(now))
    };
    Some(wait.min(MAX_COOLDOWN))
}

/// `getaddrinfo` for `host`. Empty when the name does not exist or has no
/// address; an error when the answer may change on a retry.
fn system_lookup(host: &str) -> Result<Vec<IpAddr>, NetError> {
    match dns_lookup::lookup_host(host) {
        Ok(addrs) => Ok(addrs.collect()),
        Err(e) if is_no_address(e.kind()) => Ok(Vec::new()),
        Err(e) => Err(NetError::Dns(format!(
            "{} (try again later)",
            std::io::Error::from(e)
        ))),
    }
}

fn is_no_address(kind: LookupErrorKind) -> bool {
    matches!(kind, LookupErrorKind::NoName | LookupErrorKind::NoData)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn base_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .redirect(redirect::Policy::none())
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
}

/// Mock mode resolver: every name lookup fails, so no DNS query can leave
/// a test even if a request slips past the origin map.
struct NoDns;

impl reqwest::dns::Resolve for NoDns {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async { Err("DNS is off in mock mode".into()) })
    }
}

/// Real mode resolver: the address the DNS check found, else `getaddrinfo`
/// on a blocking thread.
struct CachedDns(DnsCache);

impl reqwest::dns::Resolve for CachedDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let cached = lock(&self.0).get(&host).cloned();
        Box::pin(async move {
            let addrs = match cached {
                Some(a) => a,
                None => tokio::task::spawn_blocking(move || system_lookup(&host)).await??,
            };
            if addrs.is_empty() {
                return Err("no address for this host".into());
            }
            let addrs: reqwest::dns::Addrs =
                Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_map_parses_origins() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut m = OriginMap::new();
        m.insert("https://Example.ORG", addr).unwrap();
        m.insert("https://example.org:8443/", addr).unwrap();
        assert!(m.insert("http://example.org", addr).is_err());
        assert!(m.insert("https://example.org/path", addr).is_err());
        assert!(m.insert("https://example.org/?q", addr).is_err());
        assert!(m.insert("not a url", addr).is_err());
        let u = |s: &str| Url::parse(s).unwrap();
        assert_eq!(m.get(&u("https://example.org/x")), Some(addr));
        assert_eq!(m.get(&u("https://example.org:443/x")), Some(addr));
        assert_eq!(m.get(&u("https://example.org:8443/x")), Some(addr));
        assert_eq!(m.get(&u("https://example.org:8444/x")), None);
        assert_eq!(m.get(&u("https://other.example.org/x")), None);
    }

    #[test]
    fn mock_target_keeps_path_and_query() {
        let mut m = OriginMap::new();
        m.insert("https://example.org", "127.0.0.1:4000".parse().unwrap())
            .unwrap();
        let net = Net::with_mock_origins(&ResolverConfig::default(), m).unwrap();
        let t = net
            .target(&Url::parse("https://example.org/a/b%2Bc?l=J%C3%BC#frag").unwrap())
            .unwrap();
        assert_eq!(t.as_str(), "http://127.0.0.1:4000/a/b%2Bc?l=J%C3%BC");
    }

    #[tokio::test]
    async fn localhost_has_address() {
        // Real getaddrinfo, answered from /etc/hosts: no DNS query.
        let net = Net::new(&ResolverConfig::default()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(net.host_has_address("localhost", deadline).await.unwrap());
        let cached = lock(&net.inner.dns).get("localhost").cloned().unwrap();
        assert!(cached.iter().all(|ip| ip.is_loopback()), "{cached:?}");
        assert_eq!(net.log().entries()[0].action, "DNS localhost");
        assert_eq!(net.log().entries()[0].outcome, "has an address");
    }

    #[tokio::test]
    async fn cached_dns_answers_from_the_check() {
        use reqwest::dns::Resolve;
        let cache = DnsCache::default();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        lock(&cache).insert("openpgpkey.example.org".into(), vec![ip]);
        let addrs: Vec<SocketAddr> = CachedDns(cache.clone())
            .resolve("OpenPGPKey.example.org".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, [SocketAddr::new(ip, 0)]);
        lock(&cache).insert("empty.example.org".into(), Vec::new());
        let empty = CachedDns(cache)
            .resolve("empty.example.org".parse().unwrap())
            .await;
        assert!(empty.is_err());
    }

    #[test]
    fn only_noname_and_nodata_mean_no_address() {
        assert!(is_no_address(LookupErrorKind::NoName));
        assert!(is_no_address(LookupErrorKind::NoData));
        for k in [
            LookupErrorKind::Again,
            LookupErrorKind::Fail,
            LookupErrorKind::System,
            LookupErrorKind::Memory,
            LookupErrorKind::IO,
        ] {
            assert!(!is_no_address(k), "{k:?}");
        }
    }

    #[test]
    fn retry_after_parsing() {
        let h = |pairs: &[(&'static str, String)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(*k, v.parse().unwrap());
            }
            m
        };
        assert_eq!(
            retry_after(&h(&[("retry-after", "120".into())])),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after(&h(&[("retry-after", "999999".into())])),
            Some(MAX_COOLDOWN)
        );
        assert_eq!(
            retry_after(&h(&[(
                "retry-after",
                "Wed, 21 Oct 2026 07:28:00 GMT".into()
            )])),
            None
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset = retry_after(&h(&[("x-ratelimit-reset", (now + 30).to_string())])).unwrap();
        assert!((29..=30).contains(&reset.as_secs()), "{reset:?}");
        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn real_client_builds_without_a_request() {
        let net = Net::new(&ResolverConfig::default()).unwrap();
        assert!(net.log().is_empty());
    }

    #[test]
    fn fetched_debug_hides_body() {
        let u = Url::parse("https://example.org/k").unwrap();
        let f = Fetched {
            url: u.clone(),
            first_url: u,
            body: b"-----BEGIN PGP PUBLIC KEY BLOCK-----".to_vec(),
        };
        let dbg = format!("{f:?}");
        assert!(!dbg.contains("BEGIN"), "{dbg}");
        assert!(dbg.contains("36 bytes"), "{dbg}");
    }
}
