//! SSH and age public key parsing against the fixtures from
//! `tests/fixtures/gen.sh`.

use std::path::{Path, PathBuf};
use std::process::Command;

use identity_core::{
    Fingerprint, KeyAlgo, KeyError, KeyKind, MAX_KEY_INPUT, parse_public_keys, read_key_file,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn parse_one(name: &str) -> identity_core::PublicKey {
    let mut keys = parse_public_keys(&read_key_file(&fixture(name)).unwrap()).unwrap();
    assert_eq!(keys.len(), 1);
    keys.remove(0)
}

const SSH_FIXTURES: &[&str] = &[
    "ed25519.pub",
    "rsa3072.pub",
    "rsa2048.pub",
    "ecdsa256.pub",
    "ecdsa384.pub",
    "sk-ed25519.pub",
    "sk-ecdsa.pub",
];

#[test]
fn ssh_fingerprint_matches_ssh_keygen() {
    for name in SSH_FIXTURES {
        let out = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(fixture(name))
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen -lf {name}");
        // "<bits> SHA256:<fp> <comment> (<TYPE>)"
        let line = String::from_utf8(out.stdout).unwrap();
        let fields: Vec<&str> = line.split_whitespace().collect();

        let key = parse_one(name);
        assert_eq!(key.kind, KeyKind::Ssh);
        assert_eq!(
            key.fingerprint,
            Fingerprint::Ssh(fields[1].to_string()),
            "{name}"
        );
        assert_eq!(key.comment.as_deref(), Some(fields[2]), "{name}");
        if let KeyAlgo::Rsa(bits) = key.algo {
            assert_eq!(bits.to_string(), fields[0], "{name}");
        }
    }
}

#[test]
fn ssh_algorithms() {
    let cases = [
        ("ed25519.pub", KeyAlgo::Ed25519),
        ("rsa3072.pub", KeyAlgo::Rsa(3072)),
        ("rsa2048.pub", KeyAlgo::Rsa(2048)),
        ("ecdsa256.pub", KeyAlgo::Ecdsa("nistp256".into())),
        ("ecdsa384.pub", KeyAlgo::Ecdsa("nistp384".into())),
        ("sk-ed25519.pub", KeyAlgo::SkEd25519),
        ("sk-ecdsa.pub", KeyAlgo::SkEcdsa("nistp256".into())),
    ];
    for (name, algo) in cases {
        assert_eq!(parse_one(name).algo, algo, "{name}");
    }
}

#[test]
fn ecdsa_and_sk_keys_are_listed_but_not_age_recipients() {
    for name in ["ed25519.pub", "rsa3072.pub", "rsa2048.pub", "age.txt"] {
        assert!(parse_one(name).is_age_recipient(), "{name}");
    }
    for name in [
        "ecdsa256.pub",
        "ecdsa384.pub",
        "sk-ed25519.pub",
        "sk-ecdsa.pub",
    ] {
        assert!(!parse_one(name).is_age_recipient(), "{name}");
    }
}

#[test]
fn encoded_ssh_key_has_no_comment_and_parses_again() {
    let key = parse_one("ed25519.pub");
    assert_eq!(key.encoded.split(' ').count(), 2);
    let again = parse_public_keys(key.encoded.as_bytes()).unwrap();
    assert_eq!(again[0].fingerprint, key.fingerprint);
    assert_eq!(again[0].comment, None);
}

#[test]
fn key_list_returns_every_key() {
    let keys = parse_public_keys(&read_key_file(&fixture("keys-list.txt")).unwrap()).unwrap();
    let algos: Vec<_> = keys.iter().map(|k| k.algo.clone()).collect();
    assert_eq!(
        algos,
        [
            KeyAlgo::Ed25519,
            KeyAlgo::Rsa(3072),
            KeyAlgo::Ecdsa("nistp256".into()),
            KeyAlgo::SkEd25519,
        ]
    );
}

#[test]
fn blank_lines_comments_and_crlf_are_fine() {
    let line = std::fs::read_to_string(fixture("ed25519.pub")).unwrap();
    let input = format!("# my keys\r\n\r\n{}\r\n", line.trim());
    let keys = parse_public_keys(input.as_bytes()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].comment.as_deref(), Some("ed25519@example.org"));
}

#[test]
fn age_recipient_parses() {
    let text = std::fs::read_to_string(fixture("age.txt")).unwrap();
    let key = parse_one("age.txt");
    assert_eq!(key.kind, KeyKind::Age);
    assert_eq!(key.algo, KeyAlgo::X25519);
    assert_eq!(key.encoded, text.trim());
    assert_eq!(key.fingerprint, Fingerprint::Age(text.trim().to_string()));
}

#[test]
fn bad_age_recipients_are_rejected() {
    let good = std::fs::read_to_string(fixture("age.txt")).unwrap();
    let good = good.trim();
    let mut bad_checksum = good.to_string();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'q' { 'p' } else { 'q' });
    let short = format!("age1{}", &good[4..good.len() - 10]);
    for input in [bad_checksum, good.to_uppercase(), short] {
        assert!(
            matches!(
                parse_public_keys(input.as_bytes()),
                Err(KeyError::Malformed { line: 1, .. })
            ),
            "{input}"
        );
    }
}

#[test]
fn garbage_is_rejected_with_its_line() {
    let line = std::fs::read_to_string(fixture("ed25519.pub")).unwrap();
    let input = format!("{line}not a key\n");
    assert!(matches!(
        parse_public_keys(input.as_bytes()),
        Err(KeyError::Malformed { line: 2, .. })
    ));
    assert!(matches!(
        parse_public_keys(b"ssh-ed25519 AAAA!!!"),
        Err(KeyError::Malformed { line: 1, .. })
    ));
    assert!(matches!(
        parse_public_keys(&[0xff, 0xfe, 0x00]),
        Err(KeyError::NotText)
    ));
    assert!(matches!(
        parse_public_keys(b"\n# nothing\n"),
        Err(KeyError::Empty)
    ));
}

#[test]
fn errors_do_not_echo_the_input() {
    let err = parse_public_keys(b"ssh-ed25519 SECRETMARKER").unwrap_err();
    assert!(!err.to_string().contains("SECRETMARKER"), "{err}");
}

#[test]
fn openpgp_and_private_keys_are_refused() {
    let armor = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxx\n-----END PGP PUBLIC KEY BLOCK-----\n";
    assert!(matches!(
        parse_public_keys(armor),
        Err(KeyError::UnsupportedFormat("OpenPGP"))
    ));
    for input in [
        &b"-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n"[..],
        &b"AGE-SECRET-KEY-1QQQ\n"[..],
    ] {
        assert!(matches!(
            parse_public_keys(input),
            Err(KeyError::UnsupportedFormat("private key"))
        ));
    }
}

#[test]
fn input_over_one_mib_is_rejected() {
    let line = std::fs::read_to_string(fixture("ed25519.pub")).unwrap();
    let mut input = line.into_bytes();
    input.resize(MAX_KEY_INPUT, b'\n');
    assert_eq!(parse_public_keys(&input).unwrap().len(), 1);

    input.push(b'\n');
    assert!(matches!(
        parse_public_keys(&input),
        Err(KeyError::TooLarge { .. })
    ));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.pub");
    std::fs::write(&path, &input).unwrap();
    assert!(matches!(
        read_key_file(&path),
        Err(KeyError::TooLarge { .. })
    ));
    input.pop();
    std::fs::write(&path, &input).unwrap();
    assert_eq!(read_key_file(&path).unwrap().len(), MAX_KEY_INPUT);
}
