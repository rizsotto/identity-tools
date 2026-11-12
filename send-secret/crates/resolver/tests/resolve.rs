//! Resolver merge and order with fake in-memory sources (no network).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use identity_core::{Fingerprint, KeyAlgo, OpenPgpKey, PublicKey, SshPublicKey};
use resolver::{
    Found, FoundKey, KeyBytes, KeySource, Mode, Net, OriginMap, Query, RejectReason, Rejected,
    Resolver, ResolverConfig, Source, SourceError, SourceKind, Unusable, parse_query,
};
use tokio::time::Instant;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg() -> ResolverConfig {
    ResolverConfig {
        source_timeout: Duration::from_millis(300),
        max_redirects: 5,
    }
}

fn source(kind: SourceKind) -> Source {
    Source {
        kind,
        location: format!("{kind} location"),
        first_url: None,
    }
}

fn pgp(fpr: &str, kind: SourceKind) -> FoundKey {
    FoundKey {
        key: PublicKey::OpenPgp(OpenPgpKey {
            algo: KeyAlgo::Ed25519,
            fingerprint: Fingerprint::OpenPgp(fpr.into()),
            created: None,
            expiry: None,
            user_ids: Vec::new(),
            subkeys: Vec::new(),
            can_encrypt: true,
            can_sign: true,
            revoked: false,
            expired: false,
            disabled: false,
            invalid: false,
        }),
        bytes: KeyBytes::OpenPgp(format!("bytes of {fpr} from {kind}").into_bytes()),
        source: source(kind),
        usable: Ok(()),
        shown_user_ids: Vec::new(),
    }
}

fn ssh(name: &str, algo: KeyAlgo, kind: SourceKind) -> FoundKey {
    FoundKey {
        key: PublicKey::Ssh(SshPublicKey {
            algo,
            fingerprint: Fingerprint::Ssh(format!("SHA256:{name}")),
            comment: None,
            encoded: format!("ssh-ed25519 AAAASECRETBASE64{name}"),
        }),
        bytes: KeyBytes::Ssh(format!("ssh-ed25519 AAAASECRETBASE64{name}")),
        source: source(kind),
        usable: Ok(()),
        shown_user_ids: Vec::new(),
    }
}

struct Fake {
    kind: SourceKind,
    result: Result<Found, SourceError>,
    delay: Option<Duration>,
    calls: Arc<AtomicUsize>,
    /// Fetch this URL through the given Net first.
    fetch: Option<Url>,
}

impl Fake {
    fn new(kind: SourceKind, keys: Vec<FoundKey>) -> Fake {
        Fake {
            kind,
            result: Ok(Found {
                keys,
                rejected: Vec::new(),
            }),
            delay: None,
            calls: Arc::default(),
            fetch: None,
        }
    }

    fn boxed(self) -> Box<dyn KeySource> {
        Box::new(self)
    }
}

#[async_trait]
impl KeySource for Fake {
    fn kind(&self) -> SourceKind {
        self.kind
    }

    fn accepts(&self, q: &Query) -> bool {
        !matches!(q, Query::Contact(name) if name == "nobody")
    }

    async fn lookup(
        &self,
        _q: &Query,
        net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(net.is_some(), self.kind.is_network(), "{}", self.kind);
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        if let (Some(u), Some(net)) = (&self.fetch, net) {
            net.get(u, deadline).await?;
        }
        self.result.clone()
    }
}

fn mock_net() -> Net {
    Net::with_mock_origins(&cfg(), OriginMap::new()).unwrap()
}

fn q() -> Query {
    parse_query("alice@example.org").unwrap()
}

fn kinds(sources: &[Source]) -> Vec<SourceKind> {
    sources.iter().map(|s| s.kind).collect()
}

const FPR_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FPR_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

#[tokio::test]
async fn one_fingerprint_from_three_sources_merges() {
    use SourceKind::*;
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(Vks, vec![pgp(FPR_A, Vks)]).boxed(),
            Fake::new(Keyring, vec![pgp(FPR_A, Keyring)]).boxed(),
            Fake::new(Wkd, vec![pgp(FPR_A, Wkd), pgp(FPR_B, Wkd)]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.candidates.len(), 2);
    let a = &r.candidates[0];
    assert_eq!(a.fingerprint.as_str(), FPR_A);
    assert_eq!(kinds(&a.sources), [Keyring, Wkd, Vks]);
    assert_eq!(a.key.source.kind, Keyring);
    assert_eq!(
        a.key.bytes,
        KeyBytes::OpenPgp(format!("bytes of {FPR_A} from GnuPG keyring").into_bytes())
    );
    let b = &r.candidates[1];
    assert_eq!(b.fingerprint.as_str(), FPR_B);
    assert_eq!(kinds(&b.sources), [Wkd]);
}

#[tokio::test]
async fn wkd_copy_wins_over_vks() {
    use SourceKind::*;
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(Vks, vec![pgp(FPR_A, Vks)]).boxed(),
            Fake::new(Wkd, vec![pgp(FPR_A, Wkd)]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].key.source.kind, Wkd);
    assert_eq!(kinds(&r.candidates[0].sources), [Wkd, Vks]);
}

#[tokio::test]
async fn candidates_ordered_by_rank_then_return_order() {
    use SourceKind::*;
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(Pasted, vec![ssh("c", KeyAlgo::Ed25519, Pasted)]).boxed(),
            Fake::new(
                GitHub,
                vec![
                    ssh("b", KeyAlgo::Ed25519, GitHub),
                    ssh("a", KeyAlgo::Ed25519, GitHub),
                ],
            )
            .boxed(),
            Fake::new(GitLab, vec![ssh("a", KeyAlgo::Ed25519, GitLab)]).boxed(),
            Fake::new(Contacts, vec![ssh("d", KeyAlgo::Ed25519, Contacts)]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    let order: Vec<_> = r
        .candidates
        .iter()
        .map(|c| c.fingerprint.as_str().to_string())
        .collect();
    assert_eq!(order, ["SHA256:d", "SHA256:b", "SHA256:a", "SHA256:c"]);
    assert_eq!(kinds(&r.candidates[2].sources), [GitHub, GitLab]);
}

#[tokio::test]
async fn timing_out_source_gives_timeout_others_return() {
    use SourceKind::*;
    let mut slow = Fake::new(Wkd, vec![pgp(FPR_B, Wkd)]);
    slow.delay = Some(Duration::from_secs(2));
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            slow.boxed(),
            Fake::new(Vks, vec![pgp(FPR_A, Vks)]).boxed(),
            Fake::new(Keyring, vec![pgp(FPR_A, Keyring)]).boxed(),
        ],
    );
    let start = Instant::now();
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert!(start.elapsed() < Duration::from_millis(1500));
    assert_eq!(r.errors, [(Wkd, SourceError::Timeout)]);
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(kinds(&r.candidates[0].sources), [Keyring, Vks]);
}

#[tokio::test]
async fn local_only_never_needs_a_net() {
    use SourceKind::*;
    let wkd = Fake::new(Wkd, vec![pgp(FPR_B, Wkd)]);
    let wkd_calls = wkd.calls.clone();
    let resolver = Resolver::new(
        cfg(),
        None,
        vec![
            wkd.boxed(),
            Fake::new(Contacts, vec![pgp(FPR_A, Contacts)]).boxed(),
            Fake::new(Keyring, vec![pgp(FPR_A, Keyring)]).boxed(),
        ],
    );
    assert!(resolver.net().is_none());
    let r = resolver.resolve(&q(), Mode::LocalOnly).await;
    assert_eq!(wkd_calls.load(Ordering::SeqCst), 0);
    assert!(r.errors.is_empty());
    assert!(r.requests.is_empty());
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(kinds(&r.candidates[0].sources), [Contacts, Keyring]);

    // Full mode without a Net: network sources report it, local ones work.
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert_eq!(wkd_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(r.errors.as_slice(), [(Wkd, SourceError::Net(_))]));
    assert_eq!(r.candidates.len(), 1);
}

#[tokio::test]
async fn local_only_skips_network_sources_even_with_a_net() {
    use SourceKind::*;
    let gh = Fake::new(GitHub, vec![ssh("a", KeyAlgo::Ed25519, GitHub)]);
    let calls = gh.calls.clone();
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            gh.boxed(),
            Fake::new(Pasted, vec![ssh("p", KeyAlgo::Ed25519, Pasted)]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::LocalOnly).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r.candidates.len(), 1);
    assert_eq!(r.candidates[0].key.source.kind, Pasted);
}

#[tokio::test]
async fn unusable_keys_kept_with_notes() {
    use SourceKind::*;
    let mut ecdsa = ssh("e", KeyAlgo::Ecdsa("nistp256".into()), GitHub);
    ecdsa.usable = Err(Unusable::EcdsaNotAge);
    let mut rsa = ssh("r", KeyAlgo::Rsa(1024), GitHub);
    rsa.usable = Err(Unusable::RsaSize(1024));
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(
                GitHub,
                vec![ssh("ok", KeyAlgo::Ed25519, GitHub), ecdsa.clone(), rsa],
            )
            .boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert_eq!(r.candidates.len(), 3);
    assert_eq!(r.candidates[0].key.usable, Ok(()));
    assert_eq!(r.candidates[1].key.usable, Err(Unusable::EcdsaNotAge));
    assert_eq!(r.candidates[2].key.usable, Err(Unusable::RsaSize(1024)));
    assert_eq!(
        Unusable::RsaSize(1024).to_string(),
        "RSA 1024 bits: age takes RSA keys from 2048 to 4096 bits"
    );
}

#[tokio::test]
async fn usable_copy_wins_over_better_ranked_unusable_one() {
    use SourceKind::*;
    let mut expired = pgp(FPR_A, Keyring);
    expired.usable = Err(Unusable::Expired);
    let mut also_expired = pgp(FPR_A, Contacts);
    also_expired.usable = Err(Unusable::Expired);
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(Vks, vec![pgp(FPR_A, Vks)]).boxed(),
            Fake::new(Keyring, vec![expired]).boxed(),
            Fake::new(Contacts, vec![also_expired]).boxed(),
            Fake::new(Wkd, vec![pgp(FPR_A, Wkd)]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert_eq!(r.candidates.len(), 1);
    let c = &r.candidates[0];
    assert_eq!(c.key.usable, Ok(()));
    assert_eq!(c.key.source.kind, Wkd);
    assert_eq!(kinds(&c.sources), [Contacts, Keyring, Wkd, Vks]);

    // All copies unusable: the best ranked one stays.
    let mut k1 = pgp(FPR_A, Keyring);
    k1.usable = Err(Unusable::Expired);
    let mut k2 = pgp(FPR_A, Wkd);
    k2.usable = Err(Unusable::Revoked);
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![
            Fake::new(Wkd, vec![k2]).boxed(),
            Fake::new(Keyring, vec![k1]).boxed(),
        ],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert_eq!(r.candidates[0].key.source.kind, Keyring);
    assert_eq!(r.candidates[0].key.usable, Err(Unusable::Expired));
}

#[tokio::test]
async fn rejected_and_errors_in_rank_order() {
    use SourceKind::*;
    let mut vks = Fake::new(Vks, Vec::new());
    vks.result = Ok(Found {
        keys: Vec::new(),
        rejected: vec![Rejected {
            fingerprint: Some(Fingerprint::OpenPgp(FPR_B.into())),
            source: source(Vks),
            reason: RejectReason::EmailMismatch,
        }],
    });
    let mut wkd = Fake::new(Wkd, Vec::new());
    wkd.result = Ok(Found {
        keys: Vec::new(),
        rejected: vec![Rejected {
            fingerprint: None,
            source: source(Wkd),
            reason: RejectReason::TooManyKeys,
        }],
    });
    let mut gl = Fake::new(GitLab, Vec::new());
    gl.result = Err(SourceError::NotFound);
    let mut gh = Fake::new(GitHub, Vec::new());
    gh.result = Err(SourceError::RateLimited {
        retry_after: Some(Duration::from_secs(60)),
    });
    let resolver = Resolver::new(
        cfg(),
        Some(mock_net()),
        vec![gl.boxed(), vks.boxed(), gh.boxed(), wkd.boxed()],
    );
    let r = resolver.resolve(&q(), Mode::Full).await;
    assert!(r.candidates.is_empty());
    let rej: Vec<_> = r.rejected.iter().map(|x| x.source.kind).collect();
    assert_eq!(rej, [Wkd, Vks]);
    let errs: Vec<_> = r.errors.iter().map(|(k, _)| *k).collect();
    assert_eq!(errs, [GitHub, GitLab]);
    assert_eq!(r.errors[0].1.to_string(), "rate limited; try again in 60 s");
}

#[tokio::test]
async fn sources_that_do_not_accept_are_not_run() {
    use SourceKind::*;
    let contacts = Fake::new(Contacts, vec![pgp(FPR_A, Contacts)]);
    let calls = contacts.calls.clone();
    let resolver = Resolver::new(cfg(), None, vec![contacts.boxed()]);
    let r = resolver
        .resolve(&parse_query("nobody").unwrap(), Mode::LocalOnly)
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(r, Default::default());
}

#[tokio::test]
async fn requests_of_this_lookup_are_listed() {
    use SourceKind::*;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x"))
        .mount(&server)
        .await;
    let mut map = OriginMap::new();
    map.insert("https://github.com", *server.address()).unwrap();
    let net = Net::with_mock_origins(&cfg(), map).unwrap();
    let mut gh = Fake::new(GitHub, vec![ssh("a", KeyAlgo::Ed25519, GitHub)]);
    gh.fetch = Some(Url::parse("https://github.com/alice.keys").unwrap());
    let resolver = Resolver::new(cfg(), Some(net), vec![gh.boxed()]);
    for _ in 0..2 {
        let r = resolver.resolve(&q(), Mode::Full).await;
        assert_eq!(r.requests.len(), 1);
        assert_eq!(r.requests[0].action, "GET https://github.com/alice.keys");
    }
}

#[test]
fn debug_never_shows_key_material() {
    let k = ssh("a", KeyAlgo::Ed25519, SourceKind::GitHub);
    let dbg = format!("{k:?}");
    assert!(!dbg.contains("SECRETBASE64"), "{dbg}");
    assert!(dbg.contains("SHA256:a"), "{dbg}");
    let p = pgp(FPR_A, SourceKind::Wkd);
    assert!(!format!("{p:?}").contains("bytes of"));
}
