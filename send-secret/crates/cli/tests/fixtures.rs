//! Checks that every fixture made by `send-secret/tests/fixtures/gen.sh`
//! exists, has the right type, and holds only fake example.org identities.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn read(rel: &str) -> String {
    fs::read_to_string(fixtures().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn run(cmd: &mut Command, home: &Path) -> String {
    let out = cmd
        .env_clear()
        .env("HOME", home)
        .env("GNUPGHOME", home.join("gnupg"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("tool runs");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 output")
}

fn temp_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp dir");
    let gnupg = home.path().join("gnupg");
    fs::create_dir(&gnupg).unwrap();
    fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700)).unwrap();
    home
}

const FILES: &[&str] = &[
    "openpgp/alice.asc",
    "openpgp/alice.sec.asc",
    "openpgp/bob-rsa.asc",
    "openpgp/bob-rsa.sec.asc",
    "openpgp/sender.asc",
    "openpgp/sender.sec.asc",
    "openpgp/carol-pw.asc",
    "openpgp/carol-pw.sec.asc",
    "age/dave.txt",
    "age/dave.pub",
    "ssh/erin_ed25519",
    "ssh/erin_ed25519.pub",
    "ssh/frank_rsa",
    "ssh/frank_rsa.pub",
    "ssh/grace_ed25519_pw",
    "ssh/grace_ed25519_pw.pub",
    "ssh/heidi_ecdsa",
    "ssh/heidi_ecdsa.pub",
    "ssh/ivan_rsa8192.pub",
    "ssh/kim_rsa1024.pub",
    "ssh/judy_sk.pub",
    "ssh/multi.keys",
    "ciphertext/openpgp-armored.asc",
    "ciphertext/openpgp-binary.gpg",
    "ciphertext/age-armored.age",
    "ciphertext/age-binary.age",
];

#[test]
fn every_fixture_exists_and_is_not_executable() {
    for rel in FILES {
        let meta = fs::metadata(fixtures().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(meta.is_file(), "{rel} is not a file");
        assert!(meta.len() > 0 && meta.len() < 1024 * 1024, "{rel} size");
        assert_eq!(meta.permissions().mode() & 0o111, 0, "{rel} is executable");
    }
    let script = fs::metadata(fixtures().join("gen.sh")).unwrap();
    assert_ne!(
        script.permissions().mode() & 0o100,
        0,
        "gen.sh not executable"
    );
}

#[test]
fn openpgp_fixtures_have_expected_algorithms() {
    // (file, record type of primary, primary algo, subkey algo, uid email)
    let cases = [
        (
            "alice.asc",
            "pub",
            "ed25519",
            "cv25519",
            "alice@example.org",
        ),
        (
            "alice.sec.asc",
            "sec",
            "ed25519",
            "cv25519",
            "alice@example.org",
        ),
        (
            "bob-rsa.asc",
            "pub",
            "rsa3072",
            "rsa3072",
            "bob@example.org",
        ),
        (
            "bob-rsa.sec.asc",
            "sec",
            "rsa3072",
            "rsa3072",
            "bob@example.org",
        ),
        (
            "sender.asc",
            "pub",
            "ed25519",
            "cv25519",
            "sender@example.org",
        ),
        (
            "sender.sec.asc",
            "sec",
            "ed25519",
            "cv25519",
            "sender@example.org",
        ),
        (
            "carol-pw.asc",
            "pub",
            "ed25519",
            "cv25519",
            "carol@example.org",
        ),
        (
            "carol-pw.sec.asc",
            "sec",
            "ed25519",
            "cv25519",
            "carol@example.org",
        ),
    ];
    let home = temp_home();
    for (file, kind, primary, sub, email) in cases {
        let path = fixtures().join("openpgp").join(file);
        let out = run(
            Command::new("gpg")
                .args(["--batch", "--with-colons", "--show-keys"])
                .arg(&path),
            home.path(),
        );
        let algo = |rec: &[&str]| -> String {
            // field 4 is the algorithm number, field 3 the size, field 17 the curve
            match rec[3] {
                "1" => format!("rsa{}", rec[2]),
                _ => rec[16].to_string(),
            }
        };
        let recs: Vec<Vec<&str>> = out.lines().map(|l| l.split(':').collect()).collect();
        let prim = recs
            .iter()
            .find(|r| r[0] == kind)
            .unwrap_or_else(|| panic!("{file}: no {kind}"));
        assert_eq!(algo(prim), primary, "{file} primary");
        assert!(
            prim[11].contains('s') && prim[11].contains('c'),
            "{file} primary usage"
        );
        let subkey = recs
            .iter()
            .find(|r| r[0] == "sub" || r[0] == "ssb")
            .unwrap_or_else(|| panic!("{file}: no subkey"));
        assert_eq!(algo(subkey), sub, "{file} subkey");
        assert!(subkey[11].contains('e'), "{file} subkey usage");
        let uids: Vec<&str> = recs
            .iter()
            .filter(|r| r[0] == "uid")
            .map(|r| r[9])
            .collect();
        assert_eq!(uids.len(), 1, "{file} uids");
        assert!(
            uids[0].ends_with(&format!(" Example (test fixture) <{email}>")),
            "{file} uid {}",
            uids[0]
        );
    }
}

#[test]
fn ssh_fixtures_have_expected_types() {
    let cases = [
        ("erin_ed25519.pub", "256", "ED25519"),
        ("frank_rsa.pub", "3072", "RSA"),
        ("grace_ed25519_pw.pub", "256", "ED25519"),
        ("heidi_ecdsa.pub", "256", "ECDSA"),
        ("ivan_rsa8192.pub", "8192", "RSA"),
        ("kim_rsa1024.pub", "1024", "RSA"),
        ("judy_sk.pub", "256", "ED25519-SK"),
        ("erin_ed25519", "256", "ED25519"),
        ("frank_rsa", "3072", "RSA"),
        ("heidi_ecdsa", "256", "ECDSA"),
    ];
    let home = temp_home();
    for (file, bits, kind) in cases {
        let path = fixtures().join("ssh").join(file);
        let out = run(
            Command::new("ssh-keygen").arg("-l").arg("-f").arg(&path),
            home.path(),
        );
        assert!(out.starts_with(&format!("{bits} SHA256:")), "{file}: {out}");
        assert!(
            out.trim_end().ends_with(&format!("({kind})")),
            "{file}: {out}"
        );
        assert!(out.contains("@example.org"), "{file}: {out}");
    }
}

#[test]
fn ssh_private_keys_have_expected_protection() {
    let home = temp_home();
    for (file, pass) in [("erin_ed25519", ""), ("frank_rsa", ""), ("heidi_ecdsa", "")] {
        let path = fixtures().join("ssh").join(file);
        // ssh-keygen -y refuses keys readable by others; use a 0600 copy.
        let copy = home.path().join(file);
        fs::copy(&path, &copy).unwrap();
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
        let public = run(
            Command::new("ssh-keygen")
                .args(["-y", "-P", pass, "-f"])
                .arg(&copy),
            home.path(),
        );
        let expected = read(&format!("ssh/{file}.pub"));
        let key = |s: &str| s.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        assert_eq!(key(&public), key(&expected), "{file}");
    }
    let copy = home.path().join("grace");
    fs::copy(fixtures().join("ssh/grace_ed25519_pw"), &copy).unwrap();
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
    let status = Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(&copy)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .unwrap()
        .status;
    assert!(!status.success(), "grace_ed25519_pw must need a passphrase");
}

#[test]
fn multi_keys_lists_six_keys() {
    let expected: String = [
        "erin_ed25519.pub",
        "frank_rsa.pub",
        "heidi_ecdsa.pub",
        "judy_sk.pub",
        "ivan_rsa8192.pub",
        "kim_rsa1024.pub",
    ]
    .iter()
    .map(|f| read(&format!("ssh/{f}")))
    .collect();
    assert_eq!(read("ssh/multi.keys"), expected);
}

#[test]
fn age_fixtures_match() {
    let public = read("age/dave.pub");
    let public = public.trim();
    assert!(public.starts_with("age1") && !public.contains('\n'));
    let identity = read("age/dave.txt");
    assert!(identity.lines().any(|l| l.starts_with("AGE-SECRET-KEY-1")));
    assert!(identity.contains(&format!("# public key: {public}")));
}

#[test]
fn sample_ciphertexts_have_expected_headers() {
    let head = |rel: &str| fs::read(fixtures().join(rel)).unwrap();
    assert!(head("ciphertext/openpgp-armored.asc").starts_with(b"-----BEGIN PGP MESSAGE-----"));
    assert!(head("ciphertext/age-armored.age").starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(head("ciphertext/age-binary.age").starts_with(b"age-encryption.org/v1\n"));
    // Binary OpenPGP starts with a packet tag byte (bit 7 set).
    assert_ne!(head("ciphertext/openpgp-binary.gpg")[0] & 0x80, 0);
}
