//! Private key header check (Key Steward S-1). Keys are made at test time
//! in a temp dir and deleted after.

use std::path::{Path, PathBuf};
use std::process::Command;

use identity_core::{PrivateKeyProtection, private_key_protection};

fn keygen(dir: &Path, name: &str, args: &[&str]) -> PathBuf {
    let path = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-C", "test@example.org", "-f"])
        .arg(&path)
        .args(args)
        .status()
        .unwrap()
        .success();
    assert!(ok, "ssh-keygen {args:?}");
    path
}

#[test]
fn detects_encrypted_and_plain_keys() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    use PrivateKeyProtection::{Encrypted, Unencrypted};
    let cases = [
        ("ed25519", vec!["-t", "ed25519", "-N", ""], Unencrypted),
        (
            "ed25519-pass",
            vec!["-t", "ed25519", "-N", "passphrase"],
            Encrypted,
        ),
        (
            "rsa",
            vec!["-t", "rsa", "-b", "3072", "-N", ""],
            Unencrypted,
        ),
        (
            "rsa-pass",
            vec!["-t", "rsa", "-b", "3072", "-N", "passphrase"],
            Encrypted,
        ),
        ("ecdsa", vec!["-t", "ecdsa", "-N", ""], Unencrypted),
        (
            "pem-rsa",
            vec!["-t", "rsa", "-m", "PEM", "-N", ""],
            Unencrypted,
        ),
        (
            "pem-rsa-pass",
            vec!["-t", "rsa", "-m", "PEM", "-N", "passphrase"],
            Encrypted,
        ),
        (
            "pem-ec",
            vec!["-t", "ecdsa", "-m", "PEM", "-N", ""],
            Unencrypted,
        ),
        (
            "pem-ec-pass",
            vec!["-t", "ecdsa", "-m", "PEM", "-N", "passphrase"],
            Encrypted,
        ),
        (
            "pkcs8",
            vec!["-t", "ecdsa", "-m", "PKCS8", "-N", ""],
            Unencrypted,
        ),
        (
            "pkcs8-pass",
            vec!["-t", "ecdsa", "-m", "PKCS8", "-N", "passphrase"],
            Encrypted,
        ),
    ];
    for (name, args, want) in cases {
        let path = keygen(d, name, &args);
        assert_eq!(private_key_protection(&path).unwrap(), want, "{name}");
    }
}

#[test]
fn unknown_format_is_not_unencrypted() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let plain = keygen(d, "plain", &["-t", "ed25519", "-N", ""]);
    let text = std::fs::read_to_string(&plain).unwrap();
    let openssh_head = text.lines().next().unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        (
            "public key",
            std::fs::read(plain.with_extension("pub")).unwrap(),
        ),
        ("text", b"hello\nworld\n".to_vec()),
        ("binary", vec![0xff; 300]),
        ("long line", vec![b'-'; 5000]),
        (
            "putty",
            b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n".to_vec(),
        ),
        (
            "truncated openssh",
            format!("{openssh_head}\nb3Blbn").into_bytes(),
        ),
        (
            "bad magic",
            format!("{openssh_head}\n{}\n", "A".repeat(100)).into_bytes(),
        ),
        (
            "many newlines",
            format!("{openssh_head}\n{}", "\n".repeat(5_000_000)).into_bytes(),
        ),
        (
            "pem without body",
            b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec(),
        ),
        (
            "pem odd proc-type",
            b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,SOMETHING\n".to_vec(),
        ),
    ];
    for (name, content) in cases {
        let path = d.join("case");
        std::fs::write(&path, content).unwrap();
        assert_eq!(
            private_key_protection(&path).unwrap(),
            PrivateKeyProtection::Unknown,
            "{name}"
        );
    }
}

#[test]
fn missing_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(private_key_protection(&dir.path().join("nope")).is_err());
}
