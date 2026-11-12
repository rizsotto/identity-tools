//! Recipient queries (FR-1): parsing and the canonical form the trust store
//! uses as a contact key.
//!
//! Every value that can end up in a URL is checked here, so a bad user name,
//! host or address never reaches a request (S-7). Sources still put values
//! into URLs only through `url::Url` path segment and query APIs.

use std::fmt;

use identity_core::MAX_KEY_INPUT;

/// What the user typed in the recipient box, with its type detected.
#[derive(Clone, PartialEq, Eq)]
pub enum Query {
    /// `alice@example.org`
    Email(Email),
    /// `github:alice`
    GitHub { user: String },
    /// `gitlab:alice` (gitlab.com) or `gitlab:git.example.org/alice`
    GitLab { host: Option<Host>, user: String },
    /// 40 or 64 hex digits, upper case, spaces removed.
    Fingerprint(String),
    /// Anything else: the name of a stored contact. Local sources only.
    Contact(String),
    /// A pasted key (OpenPGP, SSH lines, age recipients), at most 1 MB.
    Pasted(Vec<u8>),
}

/// An email address. The local part is kept as typed (WKD hashes it and
/// sends it as typed); the domain is ASCII lower case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    local: String,
    domain: String,
}

/// A self-hosted GitLab host, with an optional port. ASCII lower case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    name: String,
    port: Option<u16>,
}

/// Why a query was refused. The text never repeats the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("the query is empty")]
    Empty,
    #[error("not a valid email address: {0}")]
    BadEmail(&'static str),
    #[error("type the domain in its xn-- form (international domain names are not supported yet)")]
    IdnDomain,
    #[error("IP addresses are not allowed, use a domain name")]
    IpLiteral,
    #[error("not a valid GitHub user name: {0}")]
    BadGitHubUser(&'static str),
    #[error("not a valid GitLab user name: {0}")]
    BadGitLabUser(&'static str),
    #[error("not a valid GitLab host: {0}")]
    BadHost(&'static str),
    #[error("not a valid contact name: {0}")]
    BadContactName(&'static str),
    #[error("the pasted key is empty")]
    PastedEmpty,
    #[error("the pasted key is larger than {MAX_KEY_INPUT} bytes")]
    PastedTooLarge,
}

const MAX_LOCAL_PART: usize = 64;
const MAX_DOMAIN: usize = 253;
const MAX_LABEL: usize = 63;
const MAX_GITHUB_USER: usize = 39;
const MAX_GITLAB_USER: usize = 255;
const MAX_CONTACT_NAME: usize = 256;
const GITLAB_COM: &str = "gitlab.com";

/// Detects the type of a typed query and checks it. Pasted keys come from
/// bytes, see [`Query::pasted`].
pub fn parse_query(s: &str) -> Result<Query, QueryError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(QueryError::Empty);
    }
    if let Some(rest) = strip_prefix_ci(s, "github:") {
        return parse_github_user(rest).map(|user| Query::GitHub { user });
    }
    if let Some(rest) = strip_prefix_ci(s, "gitlab:") {
        return parse_gitlab(rest);
    }
    if s.contains('@') {
        return Email::parse(s).map(Query::Email);
    }
    if let Some(fpr) = parse_fingerprint(s) {
        return Ok(Query::Fingerprint(fpr));
    }
    parse_contact_name(s).map(Query::Contact)
}

impl Query {
    /// A pasted key, as bytes. Refused when empty or over 1 MB (S-7).
    pub fn pasted(bytes: Vec<u8>) -> Result<Query, QueryError> {
        if bytes.is_empty() {
            return Err(QueryError::PastedEmpty);
        }
        if bytes.len() > MAX_KEY_INPUT {
            return Err(QueryError::PastedTooLarge);
        }
        Ok(Query::Pasted(bytes))
    }

    /// The canonical form, which the trust store uses as the contact key:
    /// `alice@example.org`, `github:alice`, `gitlab:alice`,
    /// `gitlab:git.example.org/alice`. `None` for contact names,
    /// fingerprints and pasted keys.
    pub fn contact_key(&self) -> Option<String> {
        match self {
            Query::Email(e) => Some(e.canonical()),
            Query::GitHub { user } => Some(format!("github:{}", user.to_ascii_lowercase())),
            Query::GitLab { host: None, user } => {
                Some(format!("gitlab:{}", user.to_ascii_lowercase()))
            }
            Query::GitLab {
                host: Some(h),
                user,
            } => Some(format!("gitlab:{h}/{}", user.to_ascii_lowercase())),
            Query::Fingerprint(_) | Query::Contact(_) | Query::Pasted(_) => None,
        }
    }
}

impl fmt::Debug for Query {
    /// Pasted key bytes are never printed, only their length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Email(e) => f.debug_tuple("Email").field(e).finish(),
            Query::GitHub { user } => f.debug_struct("GitHub").field("user", user).finish(),
            Query::GitLab { host, user } => f
                .debug_struct("GitLab")
                .field("host", host)
                .field("user", user)
                .finish(),
            Query::Fingerprint(s) => f.debug_tuple("Fingerprint").field(s).finish(),
            Query::Contact(s) => f.debug_tuple("Contact").field(s).finish(),
            Query::Pasted(b) => write!(f, "Pasted({} bytes)", b.len()),
        }
    }
}

impl Email {
    pub fn parse(s: &str) -> Result<Email, QueryError> {
        let (local, domain) = s
            .split_once('@')
            .ok_or(QueryError::BadEmail("no @ in it"))?;
        if domain.contains('@') {
            return Err(QueryError::BadEmail("more than one @"));
        }
        if local.is_empty() {
            return Err(QueryError::BadEmail("nothing before the @"));
        }
        if local.len() > MAX_LOCAL_PART {
            return Err(QueryError::BadEmail(
                "the part before the @ is longer than 64 bytes",
            ));
        }
        if local
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "<>()[],;:\\\"".contains(c))
        {
            return Err(QueryError::BadEmail(
                "the part before the @ has spaces or characters like < > , ; : \"",
            ));
        }
        if domain.starts_with('[') {
            return Err(QueryError::IpLiteral);
        }
        let domain = parse_domain(domain).map_err(|e| match e {
            DomainError::Idn => QueryError::IdnDomain,
            DomainError::Ip => QueryError::IpLiteral,
            DomainError::Bad(why) => QueryError::BadEmail(why),
        })?;
        if is_local_host_name(&domain) {
            return Err(QueryError::BadEmail("localhost is not allowed"));
        }
        Ok(Email {
            local: local.to_string(),
            domain,
        })
    }

    /// The local part as typed.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The domain, ASCII lower case.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The address with the local part as typed.
    pub fn address(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }

    /// The whole address in ASCII lower case (gpg and WKD match addresses
    /// case-insensitively).
    pub fn canonical(&self) -> String {
        self.address().to_ascii_lowercase()
    }
}

impl Host {
    pub fn parse(s: &str) -> Result<Host, QueryError> {
        if s.contains('@') {
            return Err(QueryError::BadHost(
                "user names in the host are not allowed",
            ));
        }
        if s.starts_with('[') {
            return Err(QueryError::IpLiteral);
        }
        let (name, port) = match s.split_once(':') {
            Some((n, p)) => (n, Some(parse_port(p)?)),
            None => (s, None),
        };
        let name = parse_domain(name).map_err(|e| match e {
            DomainError::Idn => QueryError::IdnDomain,
            DomainError::Ip => QueryError::IpLiteral,
            DomainError::Bad(why) => QueryError::BadHost(why),
        })?;
        if is_local_host_name(&name) {
            return Err(QueryError::BadHost("localhost is not allowed"));
        }
        let port = port.filter(|&p| p != 443);
        Ok(Host { name, port })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(p) => write!(f, "{}:{p}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

fn parse_port(p: &str) -> Result<u16, QueryError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(QueryError::BadHost("the port must be a number"));
    }
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(QueryError::BadHost("the port must be from 1 to 65535")),
        Ok(n) => Ok(n),
    }
}

enum DomainError {
    Idn,
    Ip,
    Bad(&'static str),
}

/// ASCII domain with at least one dot, labels `[a-z0-9-]`, no IP address.
/// Returns it in lower case.
fn parse_domain(d: &str) -> Result<String, DomainError> {
    if !d.is_ascii() {
        return Err(DomainError::Idn);
    }
    let d = d.to_ascii_lowercase();
    if d.is_empty() {
        return Err(DomainError::Bad("the domain is empty"));
    }
    if d.len() > MAX_DOMAIN {
        return Err(DomainError::Bad("the domain is too long"));
    }
    if d.parse::<std::net::IpAddr>().is_ok() {
        return Err(DomainError::Ip);
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err(DomainError::Bad("the domain needs at least one dot"));
    }
    for label in &labels {
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err(DomainError::Bad("the domain has an empty or too long part"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(DomainError::Bad(
                "the domain may only hold letters, digits, - and dots",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::Bad(
                "a part of the domain starts or ends with -",
            ));
        }
    }
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(DomainError::Ip);
    }
    Ok(d)
}

/// `localhost` or a name under it (RFC 6761), with or without the final dot.
pub(crate) fn is_local_host_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `[A-Za-z0-9-]`, 1 to 39 chars, no leading or trailing `-`, no `--`.
fn parse_github_user(u: &str) -> Result<String, QueryError> {
    if u.is_empty() {
        return Err(QueryError::BadGitHubUser("it is empty"));
    }
    if u.len() > MAX_GITHUB_USER {
        return Err(QueryError::BadGitHubUser("longer than 39 characters"));
    }
    if !u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(QueryError::BadGitHubUser(
            "only letters, digits and - are allowed",
        ));
    }
    if u.starts_with('-') || u.ends_with('-') || u.contains("--") {
        return Err(QueryError::BadGitHubUser(
            "it starts or ends with -, or has --",
        ));
    }
    Ok(u.to_string())
}

/// `gitlab:user` or `gitlab:host[:port]/user`.
fn parse_gitlab(rest: &str) -> Result<Query, QueryError> {
    let (host, user) = match rest.split_once('/') {
        Some((h, u)) => {
            if u.contains('/') {
                return Err(QueryError::BadGitLabUser("it has a /"));
            }
            (Some(Host::parse(h)?), u)
        }
        None => (None, rest),
    };
    let user = parse_gitlab_user(user)?;
    let host = host.filter(|h| !(h.name == GITLAB_COM && h.port.is_none()));
    Ok(Query::GitLab { host, user })
}

/// `[A-Za-z0-9_.-]`, 1 to 255 chars, starts with a letter, digit or `_`,
/// no `..`, does not end in `.`, `.git`, `.atom`, `.keys` or `.gpg`.
fn parse_gitlab_user(u: &str) -> Result<String, QueryError> {
    if u.is_empty() {
        return Err(QueryError::BadGitLabUser("it is empty"));
    }
    if u.len() > MAX_GITLAB_USER {
        return Err(QueryError::BadGitLabUser("longer than 255 characters"));
    }
    if !u
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        return Err(QueryError::BadGitLabUser(
            "only letters, digits, _, . and - are allowed",
        ));
    }
    if !u
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(QueryError::BadGitLabUser(
            "it must start with a letter, a digit or _",
        ));
    }
    if u.contains("..") {
        return Err(QueryError::BadGitLabUser("it has .."));
    }
    let lower = u.to_ascii_lowercase();
    if [".", ".git", ".atom", ".keys", ".gpg"]
        .iter()
        .any(|end| lower.ends_with(end))
    {
        return Err(QueryError::BadGitLabUser(
            "it ends in ., .git, .atom, .keys or .gpg",
        ));
    }
    Ok(u.to_string())
}

/// 40 or 64 hex digits, spaces allowed. Upper case, spaces removed.
fn parse_fingerprint(s: &str) -> Option<String> {
    let hex: String = s.chars().filter(|&c| c != ' ').collect();
    let ok = matches!(hex.len(), 40 | 64) && hex.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| hex.to_ascii_uppercase())
}

fn parse_contact_name(s: &str) -> Result<String, QueryError> {
    if s.chars().count() > MAX_CONTACT_NAME {
        return Err(QueryError::BadContactName("longer than 256 characters"));
    }
    if s.chars().any(char::is_control) {
        return Err(QueryError::BadContactName("it has control characters"));
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(local: &str, domain: &str) -> Query {
        Query::Email(Email {
            local: local.into(),
            domain: domain.into(),
        })
    }

    fn gh(user: &str) -> Query {
        Query::GitHub { user: user.into() }
    }

    fn gl(host: Option<(&str, Option<u16>)>, user: &str) -> Query {
        Query::GitLab {
            host: host.map(|(n, port)| Host {
                name: n.into(),
                port,
            }),
            user: user.into(),
        }
    }

    #[test]
    fn query_table_good() {
        let fpr40 = "0123456789ABCDEF0123456789ABCDEF01234567";
        let fpr64 = "0123456789ABCDEF".repeat(4);
        let cases: Vec<(String, Query)> = vec![
            ("alice@example.org".into(), email("alice", "example.org")),
            (
                "  alice@example.org\n".into(),
                email("alice", "example.org"),
            ),
            (
                "Joe.Doe@Example.ORG".into(),
                email("Joe.Doe", "example.org"),
            ),
            ("a+b@example.org".into(), email("a+b", "example.org")),
            (
                "Ünïcode@example.org".into(),
                email("Ünïcode", "example.org"),
            ),
            (
                "x@xn--bcher-kva.example".into(),
                email("x", "xn--bcher-kva.example"),
            ),
            (
                "x@mail.example-1.org".into(),
                email("x", "mail.example-1.org"),
            ),
            ("github:alice".into(), gh("alice")),
            ("GitHub:Alice-B".into(), gh("Alice-B")),
            (format!("github:{}", "a".repeat(39)), gh(&"a".repeat(39))),
            ("github:a1-b2-c3".into(), gh("a1-b2-c3")),
            ("gitlab:alice".into(), gl(None, "alice")),
            ("gitlab:_al.ice-x".into(), gl(None, "_al.ice-x")),
            ("gitlab:gitlab.com/alice".into(), gl(None, "alice")),
            (
                "gitlab:gitlab.com:8443/alice".into(),
                gl(Some(("gitlab.com", Some(8443))), "alice"),
            ),
            (
                "gitlab:Git.Example.org/alice".into(),
                gl(Some(("git.example.org", None)), "alice"),
            ),
            (
                "gitlab:git.example.org:8443/alice".into(),
                gl(Some(("git.example.org", Some(8443))), "alice"),
            ),
            (fpr40.into(), Query::Fingerprint(fpr40.into())),
            (fpr40.to_lowercase(), Query::Fingerprint(fpr40.into())),
            (
                "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567".into(),
                Query::Fingerprint(fpr40.into()),
            ),
            (fpr64.clone(), Query::Fingerprint(fpr64.clone())),
            ("Alice".into(), Query::Contact("Alice".into())),
            ("Alice Smith".into(), Query::Contact("Alice Smith".into())),
            ("DEADBEEF".into(), Query::Contact("DEADBEEF".into())),
            (
                "keybase:alice".into(),
                Query::Contact("keybase:alice".into()),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(parse_query(&input), Ok(want), "input {input:?}");
        }
    }

    #[test]
    fn query_table_bad() {
        use QueryError::*;
        let long_local = format!("{}@example.org", "a".repeat(65));
        let gh40 = format!("github:{}", "a".repeat(40));
        let gl256 = format!("gitlab:{}", "a".repeat(256));
        let long_name = "n".repeat(257);
        type Check = fn(&QueryError) -> bool;
        let cases: Vec<(&str, Check)> = vec![
            ("", |e| *e == Empty),
            ("   ", |e| *e == Empty),
            ("@example.org", |e| matches!(e, BadEmail(_))),
            ("alice@", |e| matches!(e, BadEmail(_))),
            ("a@b@example.org", |e| matches!(e, BadEmail(_))),
            ("al ice@example.org", |e| matches!(e, BadEmail(_))),
            ("al\nice@example.org", |e| matches!(e, BadEmail(_))),
            ("\"a\"@example.org", |e| matches!(e, BadEmail(_))),
            (&long_local, |e| matches!(e, BadEmail(_))),
            ("alice@example", |e| matches!(e, BadEmail(_))),
            ("alice@example..org", |e| matches!(e, BadEmail(_))),
            ("alice@-example.org", |e| matches!(e, BadEmail(_))),
            ("alice@exa_mple.org", |e| matches!(e, BadEmail(_))),
            ("alice@example.org/x", |e| matches!(e, BadEmail(_))),
            ("alice@example.org:443", |e| matches!(e, BadEmail(_))),
            ("alice@bücher.example", |e| *e == IdnDomain),
            ("alice@[127.0.0.1]", |e| *e == IpLiteral),
            ("alice@127.0.0.1", |e| *e == IpLiteral),
            ("alice@[::1]", |e| *e == IpLiteral),
            ("github:", |e| matches!(e, BadGitHubUser(_))),
            (&gh40, |e| matches!(e, BadGitHubUser(_))),
            ("github:al--ice", |e| matches!(e, BadGitHubUser(_))),
            ("github:-alice", |e| matches!(e, BadGitHubUser(_))),
            ("github:alice-", |e| matches!(e, BadGitHubUser(_))),
            ("github:al_ice", |e| matches!(e, BadGitHubUser(_))),
            ("github:alice/x", |e| matches!(e, BadGitHubUser(_))),
            ("github:../x", |e| matches!(e, BadGitHubUser(_))),
            ("github:al%2Fice", |e| matches!(e, BadGitHubUser(_))),
            ("gitlab:", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.keys", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.KEYS", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.gpg", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.git", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.atom", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:alice.", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:al..ice", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:.alice", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:-alice", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:al ice", |e| matches!(e, BadGitLabUser(_))),
            (&gl256, |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:git.example.org/a/b", |e| {
                matches!(e, BadGitLabUser(_))
            }),
            ("gitlab:git.example.org/", |e| matches!(e, BadGitLabUser(_))),
            ("gitlab:me@git.example.org/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:me:pw@git.example.org/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:git.example.org:0/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:git.example.org:65536/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:git.example.org:x/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:git.example.org:/alice", |e| matches!(e, BadHost(_))),
            ("gitlab:git.example.org:1:2/alice", |e| {
                matches!(e, BadHost(_))
            }),
            ("gitlab:localhost/alice", |e| matches!(e, BadHost(_))),
            ("alice@localhost.localhost", |e| matches!(e, BadEmail(_))),
            ("alice@a.LOCALHOST", |e| matches!(e, BadEmail(_))),
            ("gitlab:a.localhost/alice", |e| matches!(e, BadHost(_))),
            ("gitlab:intranet/alice", |e| matches!(e, BadHost(_))),
            ("gitlab:/alice", |e| matches!(e, BadHost(_))),
            ("gitlab:10.0.0.1/alice", |e| *e == IpLiteral),
            ("gitlab:[::1]/alice", |e| *e == IpLiteral),
            ("gitlab:[::1]:80/alice", |e| *e == IpLiteral),
            ("gitlab:gït.example.org/alice", |e| *e == IdnDomain),
            ("Al\u{7}ice", |e| matches!(e, BadContactName(_))),
            (&long_name, |e| matches!(e, BadContactName(_))),
        ];
        for (input, check) in cases {
            match parse_query(input) {
                Err(e) => assert!(check(&e), "input {input:?} gave {e:?}"),
                Ok(q) => panic!("input {input:?} was accepted as {q:?}"),
            }
        }
    }

    #[test]
    fn errors_do_not_echo_input() {
        for input in [
            "sec\u{1b}[2Jret@example.org",
            "github:sec/ret",
            "gitlab:sec..ret",
        ] {
            let msg = parse_query(input).unwrap_err().to_string();
            assert!(!msg.contains("sec"), "{msg}");
        }
    }

    #[test]
    fn local_host_names() {
        for h in [
            "localhost",
            "LocalHost",
            "a.localhost",
            "localhost.",
            "a.localhost.",
        ] {
            assert!(is_local_host_name(h), "{h}");
        }
        for h in ["example.org", "localhost.example.org", "mylocalhost"] {
            assert!(!is_local_host_name(h), "{h}");
        }
    }

    #[test]
    fn contact_key_is_canonical() {
        let key = |s: &str| parse_query(s).unwrap().contact_key();
        assert_eq!(
            key("Joe.Doe@Example.ORG").as_deref(),
            Some("joe.doe@example.org")
        );
        assert_eq!(
            key("Ünïcode@example.org").as_deref(),
            Some("Ünïcode@example.org")
        );
        assert_eq!(key("GitHub:Alice").as_deref(), Some("github:alice"));
        assert_eq!(key("gitlab:Alice").as_deref(), Some("gitlab:alice"));
        assert_eq!(
            key("gitlab:gitlab.com:443/alice").as_deref(),
            Some("gitlab:alice")
        );
        assert_eq!(
            key("gitlab:git.example.org:443/alice").as_deref(),
            Some("gitlab:git.example.org/alice")
        );
        assert_eq!(
            key("gitlab:GitLab.com/Alice").as_deref(),
            Some("gitlab:alice")
        );
        assert_eq!(
            key("gitlab:Git.Example.org:8443/Alice").as_deref(),
            Some("gitlab:git.example.org:8443/alice")
        );
        assert_eq!(key("Alice"), None);
        assert_eq!(key("0123456789ABCDEF0123456789ABCDEF01234567"), None);
        assert_eq!(Query::pasted(b"x".to_vec()).unwrap().contact_key(), None);
    }

    #[test]
    fn email_keeps_local_part_as_typed() {
        let Query::Email(e) = parse_query("Joe.Doe@Example.ORG").unwrap() else {
            panic!("not an email");
        };
        assert_eq!(e.local(), "Joe.Doe");
        assert_eq!(e.domain(), "example.org");
        assert_eq!(e.address(), "Joe.Doe@example.org");
        assert_eq!(e.canonical(), "joe.doe@example.org");
    }

    #[test]
    fn pasted_limits_and_debug() {
        assert_eq!(Query::pasted(Vec::new()), Err(QueryError::PastedEmpty));
        assert_eq!(
            Query::pasted(vec![b'a'; MAX_KEY_INPUT + 1]),
            Err(QueryError::PastedTooLarge)
        );
        let q = Query::pasted(b"ssh-ed25519 AAAAsecret".to_vec()).unwrap();
        let dbg = format!("{q:?}");
        assert_eq!(dbg, "Pasted(22 bytes)");
        assert!(Query::pasted(vec![b'a'; MAX_KEY_INPUT]).is_ok());
    }
}
