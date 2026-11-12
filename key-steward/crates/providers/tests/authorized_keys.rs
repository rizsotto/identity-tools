//! `authorized_keys` editor against the fixtures in
//! `key-steward/tests/authorized-keys/` (FR-6).
//!
//! `add/` cases run `add_like(OLD, NEW)`, `remove/` cases run
//! `remove(OLD, keep NEW)`. `<case>.in` is the file before, `<case>.out`
//! the file after. A `.in` without `.out` must be refused. `{OLD}`,
//! `{NEW}`, `{OTHER}` and `{CA}` stand for `<type> <base64>` of a key, so
//! the same files can run with keys made for a test server.

use std::fs;
use std::path::PathBuf;

use identity_core::{Fingerprint, PublicKey, SshPublicKey, parse_public_keys};
use providers::authorized_keys::{AuthorizedKeys, EditError};

const OLD: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP3xJfcaGYrwTcdoje/Ka7JhNrATYv7RJIjLUBvVJAq old@example.org";
const NEW: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHWibp60yBURS/kgHeSClf48V14E1uwNw+NlNW+YCrh2 new@example.org";
const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEmx8dXIIcUqQbL1Ce7GbCHobl0JjY0hkavHhoSbOAHK other@example.org";
const CA: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ6hL7+eK8mwd2z4ykvayoFCjON81KsB2Zt9swdDJf9O ca@example.org";

fn key(line: &str) -> SshPublicKey {
    match &parse_public_keys(line.as_bytes()).unwrap()[0].key {
        Ok(PublicKey::Ssh(k)) => k.clone(),
        other => panic!("{other:?}"),
    }
}

fn fpr(line: &str) -> Fingerprint {
    key(line).fingerprint
}

fn fill(template: &[u8]) -> Vec<u8> {
    let mut s = String::from_utf8(template.to_vec()).unwrap();
    for (name, line) in [("OLD", OLD), ("NEW", NEW), ("OTHER", OTHER), ("CA", CA)] {
        s = s.replace(&format!("{{{name}}}"), &key(line).encoded);
    }
    s.into_bytes()
}

struct Case {
    name: String,
    input: Vec<u8>,
    expected: Option<Vec<u8>>,
}

fn cases(dir: &str) -> Vec<Case> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/authorized-keys")
        .join(dir);
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "in") {
            let expected = fs::read(path.with_extension("out")).ok().map(|b| fill(&b));
            out.push(Case {
                name: path.file_stem().unwrap().to_string_lossy().into_owned(),
                input: fill(&fs::read(&path).unwrap()),
                expected,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(!out.is_empty(), "no fixtures in {}", dir.display());
    out
}

fn add(input: &[u8]) -> Result<Vec<u8>, EditError> {
    AuthorizedKeys::parse(input)
        .unwrap()
        .add_like(&fpr(OLD), &key(NEW))
}

fn remove(input: &[u8]) -> Result<Vec<u8>, EditError> {
    AuthorizedKeys::parse(input)
        .unwrap()
        .remove(&fpr(OLD), &fpr(NEW))
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn fixtures_add_like() {
    let mut n = 0;
    for c in cases("add") {
        let Some(want) = &c.expected else { continue };
        let got = add(&c.input).unwrap_or_else(|e| panic!("{}: {e}", c.name));
        assert_eq!(show(&got), show(want), "add/{}", c.name);
        n += 1;
    }
    assert!(n >= 10, "only {n} add fixtures");
}

#[test]
fn add_refuses_without_old_key() {
    let refused: Vec<Case> = cases("add")
        .into_iter()
        .filter(|c| c.expected.is_none())
        .collect();
    assert!(!refused.is_empty());
    for c in refused {
        assert_eq!(
            add(&c.input),
            Err(EditError::OldKeyMissing),
            "add/{}",
            c.name
        );
    }
}

#[test]
fn add_is_idempotent() {
    for c in cases("add") {
        let Some(want) = &c.expected else { continue };
        assert_eq!(show(&add(want).unwrap()), show(want), "add/{}", c.name);
    }
}

#[test]
fn fixtures_remove_keeps_other_bytes() {
    let mut n = 0;
    for c in cases("remove") {
        let Some(want) = &c.expected else { continue };
        let got = remove(&c.input).unwrap_or_else(|e| panic!("{}: {e}", c.name));
        assert_eq!(show(&got), show(want), "remove/{}", c.name);
        // A second run changes nothing.
        assert_eq!(
            show(&remove(&got).unwrap()),
            show(want),
            "remove/{}",
            c.name
        );
        n += 1;
    }
    assert!(n >= 5, "only {n} remove fixtures");
}

#[test]
fn remove_refuses_without_new_key() {
    let refused: Vec<Case> = cases("remove")
        .into_iter()
        .filter(|c| c.expected.is_none())
        .collect();
    assert!(!refused.is_empty());
    for c in refused {
        assert_eq!(
            remove(&c.input),
            Err(EditError::NewKeyMissing),
            "remove/{}",
            c.name
        );
    }
    // Removing the old key from the add results always leaves the new key.
    for c in cases("add") {
        if let Some(added) = &c.expected {
            assert!(remove(added).is_ok(), "add/{}", c.name);
        }
    }
}

#[test]
fn same_key_and_bad_comment_are_refused() {
    let file = AuthorizedKeys::parse(&fill(b"{OLD} old\n{NEW} new\n")).unwrap();
    assert_eq!(file.add_like(&fpr(OLD), &key(OLD)), Err(EditError::SameKey));
    assert_eq!(file.remove(&fpr(OLD), &fpr(OLD)), Err(EditError::SameKey));
    let mut bad = key(NEW);
    bad.comment = Some("new\rcommand=\"x\"".into());
    assert_eq!(file.add_like(&fpr(OLD), &bad), Err(EditError::BadComment));
}

#[test]
fn keys_lists_login_and_ca_lines() {
    let file = AuthorizedKeys::parse(&fill(
        b"# c\nrestrict {OLD} a\ncert-authority {CA} b\nbroken {NEW}x\n",
    ))
    .unwrap();
    let keys: Vec<_> = file.keys().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].line, 2);
    assert_eq!(keys[0].options.as_deref(), Some("restrict"));
    assert_eq!(keys[0].key.fingerprint, fpr(OLD));
    assert!(!keys[0].cert_authority);
    assert!(keys[1].cert_authority);
    assert_eq!(keys[1].key.fingerprint, fpr(CA));
}
