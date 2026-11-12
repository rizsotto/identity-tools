//! SSH and age public key parsing against the fixtures from
//! `tests/fixtures/gen.sh`.

use std::path::{Path, PathBuf};
use std::process::Command;

use identity_core::{
    Fingerprint, KeyAlgo, KeyError, KeyKind, LineError, MAX_KEY_INPUT, PublicKey, SshPublicKey,
    parse_public_keys, read_key_file,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap()
}

fn parse_one(name: &str) -> PublicKey {
    let mut lines = parse_public_keys(&read_key_file(&fixture(name)).unwrap()).unwrap();
    assert_eq!(lines.len(), 1);
    lines.remove(0).key.unwrap()
}

fn ssh(key: PublicKey) -> SshPublicKey {
    match key {
        PublicKey::Ssh(k) => k,
        other => panic!("not SSH: {other:?}"),
    }
}

/// Results of each non-comment line, in order.
fn results(input: &str) -> Vec<Result<KeyAlgo, LineError>> {
    parse_public_keys(input.as_bytes())
        .unwrap()
        .into_iter()
        .map(|l| l.key.map(|k| k.algo()))
        .collect()
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
        assert_eq!(key.kind(), KeyKind::Ssh);
        assert_eq!(
            key.fingerprint(),
            Fingerprint::Ssh(fields[1].to_string()),
            "{name}"
        );
        if let KeyAlgo::Rsa(bits) = key.algo() {
            assert_eq!(bits.to_string(), fields[0], "{name}");
        }
        assert_eq!(ssh(key).comment.as_deref(), Some(fields[2]), "{name}");
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
        assert_eq!(parse_one(name).algo(), algo, "{name}");
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
fn age_takes_rsa_only_from_2048_to_4096_bits() {
    let rsa = |bits| {
        PublicKey::Ssh(SshPublicKey {
            algo: KeyAlgo::Rsa(bits),
            fingerprint: Fingerprint::Ssh("SHA256:x".into()),
            comment: None,
            encoded: String::new(),
        })
    };
    for (bits, ok) in [
        (1024, false),
        (2047, false),
        (2048, true),
        (4096, true),
        (4097, false),
        (8192, false),
    ] {
        assert_eq!(rsa(bits).is_age_recipient(), ok, "{bits}");
    }
}

#[test]
fn encoded_ssh_key_has_no_comment_and_parses_again() {
    let key = ssh(parse_one("ed25519.pub"));
    assert_eq!(key.encoded.split(' ').count(), 2);
    let again = parse_public_keys(key.encoded.as_bytes()).unwrap();
    let again = ssh(again[0].key.clone().unwrap());
    assert_eq!(again.fingerprint, key.fingerprint);
    assert_eq!(again.comment, None);
}

#[test]
fn key_list_returns_every_key() {
    let lines = parse_public_keys(&read_key_file(&fixture("keys-list.txt")).unwrap()).unwrap();
    let algos: Vec<_> = lines
        .iter()
        .map(|l| l.key.as_ref().unwrap().algo())
        .collect();
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
fn bad_lines_are_skipped_one_by_one() {
    let ed = fixture_text("ed25519.pub");
    let ed = ed.trim();
    let (ty, rest) = ed.split_once(' ').unwrap();
    let (blob, _) = rest.split_once(' ').unwrap();
    let input = [
        "# my keys",
        "",
        ed,
        "ssh-foo AAAAB3NzaC1yc2E user@host",
        &format!("ssh-ed25519-cert-v01@openssh.com {blob} cert"),
        &format!("no-pty,from=\"10.0.0.1\" {ty} {blob} opts"),
        "ssh-ed25519 AAAA!!!",
        &format!("ssh-rsa {blob} wrong type"),
        "age1notarecipient",
        &format!("{ty}\t{blob}\twith tab"),
        &format!("{ty}  {blob}   two  spaces"),
    ]
    .join("\n");
    let lines = parse_public_keys(input.as_bytes()).unwrap();
    let numbers: Vec<_> = lines.iter().map(|l| l.line).collect();
    assert_eq!(numbers, [3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!(
        results(&input),
        [
            Ok(KeyAlgo::Ed25519),
            Err(LineError::UnknownType),
            Err(LineError::Certificate),
            Err(LineError::Options),
            Err(LineError::Malformed),
            Err(LineError::Malformed),
            Err(LineError::BadAgeRecipient),
            Ok(KeyAlgo::Ed25519),
            Ok(KeyAlgo::Ed25519),
        ]
    );
    let comments: Vec<_> = lines[7..]
        .iter()
        .map(|l| ssh(l.key.clone().unwrap()).comment.unwrap())
        .collect();
    assert_eq!(comments, ["with tab", "two  spaces"]);
}

#[test]
fn blank_lines_comments_and_crlf_are_fine() {
    let line = fixture_text("ed25519.pub");
    let input = format!("# my keys\r\n\r\n{}\r\n", line.trim());
    let lines = parse_public_keys(input.as_bytes()).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].line, 3);
    let key = ssh(lines[0].key.clone().unwrap());
    assert_eq!(key.comment.as_deref(), Some("ed25519@example.org"));
    assert!(parse_public_keys(b"\n# nothing\n").unwrap().is_empty());
}

#[test]
fn comment_display_drops_control_and_bidi_characters() {
    let ed = fixture_text("ed25519.pub");
    let mut parts = ed.trim().splitn(3, ' ');
    let (ty, blob) = (parts.next().unwrap(), parts.next().unwrap());
    let raw = "alice\u{1b}[2J\u{202e}gpj.exe\u{2066}x\u{7f}";
    let input = format!("{ty} {blob} {raw}\n");
    let key = ssh(parse_public_keys(input.as_bytes()).unwrap()[0]
        .key
        .clone()
        .unwrap());
    assert_eq!(key.comment.as_deref(), Some(raw));
    assert_eq!(key.comment_display().as_deref(), Some("alice[2Jgpj.exex"));
}

#[test]
fn age_recipient_parses() {
    let text = fixture_text("age.txt");
    let key = parse_one("age.txt");
    assert_eq!(key.kind(), KeyKind::Age);
    assert_eq!(key.algo(), KeyAlgo::X25519);
    assert_eq!(key.fingerprint(), Fingerprint::Age(text.trim().to_string()));
    let PublicKey::Age(r) = key else { panic!() };
    assert_eq!(r.as_str(), text.trim());
}

#[test]
fn bad_age_recipients_are_rejected() {
    let good = fixture_text("age.txt");
    let good = good.trim();
    let mut bad_checksum = good.to_string();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'q' { 'p' } else { 'q' });
    let short = format!("age1{}", &good[4..good.len() - 10]);
    let with_comment = format!("{good} comment");
    for input in [bad_checksum, short, with_comment] {
        assert_eq!(
            results(&input),
            [Err(LineError::BadAgeRecipient)],
            "{input}"
        );
    }
    // Upper case does not start with "age1", so it is not taken for age.
    assert_eq!(results(&good.to_uppercase()), [Err(LineError::UnknownType)]);
}

#[test]
fn errors_never_echo_the_input() {
    let marker = "SECRETMARKER\u{1b}[2J";
    let ed = fixture_text("ed25519.pub");
    let (ty, rest) = ed.trim().split_once(' ').unwrap();
    let (blob, _) = rest.split_once(' ').unwrap();
    let inputs = [
        format!("ssh-ed25519 {marker}"),
        format!("{marker} {blob}"),
        format!("{marker}-cert-v01@openssh.com {blob}"),
        format!("{marker} {ty} {blob}"),
        format!("ssh-rsa {blob} {marker}"),
        format!("age1{marker}"),
        format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{marker}"),
    ];
    for input in inputs {
        for l in parse_public_keys(input.as_bytes()).unwrap() {
            let err = l.key.unwrap_err();
            for text in [err.to_string(), format!("{err:?}")] {
                assert!(!text.contains("SECRETMARKER"), "{text}");
                assert!(!text.contains('\u{1b}'), "{text}");
            }
        }
    }
    let mut big = marker.as_bytes().to_vec();
    big.resize(MAX_KEY_INPUT + 1, b'x');
    let mut not_text = marker.as_bytes().to_vec();
    not_text.push(0xff);
    for input in [
        big,
        not_text,
        format!("-----BEGIN PGP {marker}").into_bytes(),
    ] {
        let err = parse_public_keys(&input).unwrap_err();
        for text in [err.to_string(), format!("{err:?}")] {
            assert!(!text.contains("SECRETMARKER"), "{text}");
        }
    }
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
    assert!(matches!(
        parse_public_keys(&[0xff, 0xfe, 0x00]),
        Err(KeyError::NotText)
    ));
}

#[test]
fn input_over_one_mb_is_rejected() {
    assert_eq!(MAX_KEY_INPUT, 1_000_000);
    let mut input = fixture_text("ed25519.pub").into_bytes();
    input.resize(1_000_000, b'\n');
    assert_eq!(parse_public_keys(&input).unwrap().len(), 1);

    input.push(b'\n');
    assert_eq!(input.len(), 1_000_001);
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
    assert_eq!(read_key_file(&path).unwrap().len(), 1_000_000);
}
