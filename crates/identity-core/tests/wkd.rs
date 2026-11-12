//! WKD hash and URLs (Send Secret M2 T02). Vectors checked with
//! `gpg-wks-client --print-wkd-hash` (GnuPG 2.4.9), see Send Secret M2 plan.

use std::io::Write;
use std::process::{Command, Stdio};

use identity_core::{WkdError, WkdUrls, wkd_hash};

const VECTORS: &[(&str, &str)] = &[
    ("Joe.Doe@Example.ORG", "iy9q119eutrkn8s1mk4r39qejnbu3n5q"),
    ("alice@example.org", "kei1q4tipxxu1yj79k9kfukdhfy631xe"),
    ("a+b@Example.ORG", "i6wwpbayndmjsnjzbzdj15jgc77g8a4f"),
    ("Ünïcode@example.org", "hss8e8o6az1fjiz8iujfffi83416i73g"),
    ("ÜNÏCODE@example.org", "me6bhw5jgh86yue7p4s8pfoqcfkuz3au"),
];

fn local(address: &str) -> &str {
    address.rsplit_once('@').unwrap().0
}

#[test]
fn wkd_hash_matches_known_vectors() {
    for (address, hash) in VECTORS {
        assert_eq!(wkd_hash(local(address)), *hash, "{address}");
    }
}

/// 20 generated addresses: upper and lower case, digits, punctuation,
/// non-ASCII, long local parts.
fn generated() -> Vec<String> {
    let parts = [
        "x",
        "X",
        "John.Smith",
        "UPPER",
        "MiXeD.Case_1",
        "a-b",
        "o'neil",
        "first+tag",
        "1234567890",
        "ÄÖÜäöü",
        "Ünï.Côdé",
        "日本語",
        "émile",
        "zz~top",
        "a.b.c.d.e",
        "AbCdEfGhIjKlMnOpQrStUvWxYz",
        "under_score",
        "x!#$%&*",
        "Ω.omega",
        "tab9",
    ];
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| format!("{p}@Host{i}.Example.ORG"))
        .collect()
}

/// `gpg-wks-client --print-wkd-hash` output lines `<hash> <address>`, in
/// input order.
fn gpg_wks_client_hashes(addresses: &[String]) -> Vec<String> {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new("gpg-wks-client")
        .arg("--print-wkd-hash")
        .env_clear()
        .env("HOME", home.path())
        .env("GNUPGHOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("gpg-wks-client runs");
    let input: String = addresses.iter().map(|a| format!("{a}\n")).collect();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), addresses.len(), "{text}");
    lines
        .iter()
        .zip(addresses)
        .map(|(line, address)| {
            let (hash, rest) = line.split_once(' ').unwrap();
            // gpg-wks-client prints `local@domain`, both lowered (ASCII).
            assert_eq!(rest.to_lowercase(), address.to_lowercase(), "{line}");
            hash.to_string()
        })
        .collect()
}

#[test]
fn wkd_matches_gpg_wks_client() {
    let mut addresses: Vec<String> = VECTORS.iter().map(|(a, _)| a.to_string()).collect();
    addresses.extend(generated());
    assert_eq!(addresses.len(), VECTORS.len() + 20);
    let theirs = gpg_wks_client_hashes(&addresses);
    for (address, hash) in addresses.iter().zip(theirs) {
        assert_eq!(wkd_hash(local(address)), hash, "{address}");
    }
}

#[test]
fn wkd_urls_match_draft_example() {
    let urls = WkdUrls::for_address("Joe.Doe@Example.ORG").unwrap();
    assert_eq!(
        urls.advanced,
        "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
    );
    assert_eq!(
        urls.direct,
        "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
    );
}

#[test]
fn wkd_urls_escape_local_part() {
    let urls = WkdUrls::for_address("a+b@Example.ORG").unwrap();
    assert!(
        urls.direct
            .ends_with("/hu/i6wwpbayndmjsnjzbzdj15jgc77g8a4f?l=a%2Bb")
    );
    let urls = WkdUrls::for_address("Ünïcode@example.org").unwrap();
    assert!(
        urls.direct.ends_with("?l=%C3%9Cn%C3%AFcode"),
        "{}",
        urls.direct
    );
}

#[test]
fn wkd_urls_refuse_bad_addresses() {
    for bad in ["", "alice", "@example.org", "a@b@example.org"] {
        assert!(
            matches!(WkdUrls::for_address(bad), Err(WkdError::NotAnAddress)),
            "{bad}"
        );
    }
    for bad in [
        "alice@",
        "alice@example",
        "alice@exa_mple.org",
        "alice@example.org/x",
        "alice@example.org?l=x",
        "alice@example.org:443",
        "alice@-example.org",
        "alice@example..org",
        "alice@192.168.0.1",
        "alice@[::1]",
        "alice@exämple.org",
        "alice@example.org.",
    ] {
        assert!(
            matches!(WkdUrls::for_address(bad), Err(WkdError::BadDomain)),
            "{bad}"
        );
    }
}
