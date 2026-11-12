//! FR-1 key list against a temp SSH dir and a temp GNUPGHOME.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use identity_core::{Fingerprint, Gpg, KeyAlgo, KeyKind, Severity, WeakReason};
use inventory::{
    Created, KeyList, KeyRow, KeySource, LocationKind, NewLocation, Purpose, SshHost, Store, Target,
};
use test_support::{TempGnupgHome, TempHome};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn keygen(dir: &Path, name: &str, args: &[&str]) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-f"])
        .arg(dir.join(name))
        .args(args)
        .output()
        .expect("ssh-keygen (openssh-clients) must be installed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn gpg(home: &TempGnupgHome, args: &[&str]) -> String {
    let mut cmd = Command::new("gpg");
    home.apply(&mut cmd)
        .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
        .args(["--passphrase", ""])
        .args(args);
    let out = cmd.output().expect("gpg (gnupg2) must be installed");
    assert!(
        out.status.success(),
        "gpg {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn fpr_of(home: &TempGnupgHome, uid: &str) -> String {
    gpg(home, &["--with-colons", "--list-keys", uid])
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .map(|l| l.split(':').nth(9).unwrap().to_string())
        .unwrap()
}

fn row<'a>(list: &'a KeyList, name: &str) -> &'a KeyRow {
    list.rows
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no row {name}: {list:#?}"))
}

fn reasons(r: &KeyRow) -> Vec<(Severity, WeakReason)> {
    r.warnings
        .iter()
        .map(|w| (w.severity, w.reason.clone()))
        .collect()
}

fn recent(t: Option<Created>, file_date: bool) -> bool {
    let t = match (t, file_date) {
        (Some(Created::FileDate(t)), true) | (Some(Created::Key(t)), false) => t,
        _ => return false,
    };
    let age = SystemTime::now().duration_since(t).unwrap_or_default();
    age < Duration::from_secs(600)
}

#[test]
fn key_list_has_all_fr1_fields() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    keygen(&ssh, "id_work", &["-t", "ed25519", "-N", "", "-C", "work"]);
    keygen(
        &ssh,
        "id_old",
        &["-t", "rsa", "-b", "2048", "-N", "", "-C", "old"],
    );
    keygen(
        &ssh,
        "id_safe",
        &["-t", "ed25519", "-N", "secret pass", "-C", ""],
    );
    fs::write(ssh.join("broken.pub"), "ssh-ed25519 not-base64\n").unwrap();

    let gnupg = TempGnupgHome::new();
    gpg(
        &gnupg,
        &[
            "--quick-gen-key",
            "Alice <alice@example.invalid>",
            "ed25519",
            "sign",
            "1y",
        ],
    );
    let alice = fpr_of(&gnupg, "alice@example.invalid");
    gpg(
        &gnupg,
        &["--quick-add-key", &alice, "cv25519", "encr", "2y"],
    );
    gpg(
        &gnupg,
        &[
            "--quick-gen-key",
            "Bob <bob@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
    );
    let bob = fpr_of(&gnupg, "bob@example.invalid");
    // A public key without its secret key is someone else's: not listed.
    gpg(
        &gnupg,
        &[
            "--quick-gen-key",
            "Carol <carol@example.invalid>",
            "ed25519",
            "sign",
            "1y",
        ],
    );
    let carol = fpr_of(&gnupg, "carol@example.invalid");
    gpg(&gnupg, &["--yes", "--delete-secret-keys", &carol]);

    let mut store = Store::open_in_memory().unwrap();
    let mut gpg_backend = Gpg::with_home(gnupg.path()).unwrap();
    let first = KeyList::load(&ssh, &mut gpg_backend, &store).unwrap();
    let work_fpr = row(&first, "work").fingerprint.clone();
    for host in ["build", "web"] {
        store
            .add(&NewLocation {
                kind: LocationKind::SshServer,
                target: Target::Ssh(SshHost::new(host)),
                key: work_fpr.clone(),
                purpose: Purpose::SshAuth,
            })
            .unwrap();
    }
    store
        .add(&NewLocation {
            kind: LocationKind::GitHub,
            target: Target::Account {
                base_url: "https://github.com".into(),
                account: "alice".into(),
            },
            key: Fingerprint::OpenPgp(alice.clone()),
            purpose: Purpose::OpenPgp,
        })
        .unwrap();

    let list = KeyList::load(&ssh, &mut gpg_backend, &store).unwrap();
    assert_eq!(list.rows.len(), 5, "{list:#?}");

    let work = row(&list, "work");
    assert_eq!(work.kind, KeyKind::Ssh);
    assert_eq!(work.algo, KeyAlgo::Ed25519);
    assert!(matches!(&work.fingerprint, Fingerprint::Ssh(f) if f.starts_with("SHA256:")));
    assert!(recent(work.created, true), "{:?}", work.created);
    assert_eq!(work.expiry, None);
    assert!(work.subkeys.is_empty());
    assert_eq!(work.location_count, 2);
    assert_eq!(
        reasons(work),
        vec![(Severity::Warning, WeakReason::PrivateKeyUnencrypted)]
    );
    assert_eq!(
        work.source,
        KeySource::Ssh {
            public_path: ssh.join("id_work.pub"),
            private_path: Some(ssh.join("id_work")),
        }
    );

    let old = row(&list, "old");
    assert_eq!(old.algo, KeyAlgo::Rsa(2048));
    assert_eq!(old.location_count, 0);
    assert_eq!(
        reasons(old),
        vec![
            (Severity::Warning, WeakReason::RsaTooShort(2048)),
            (Severity::Warning, WeakReason::PrivateKeyUnencrypted),
        ]
    );

    // No comment: the file name is the name. Encrypted: no warning.
    let safe = row(&list, "id_safe.pub");
    assert!(reasons(safe).is_empty(), "{:?}", safe.warnings);

    let a = row(&list, "Alice <alice@example.invalid>");
    assert_eq!(a.kind, KeyKind::OpenPgp);
    assert_eq!(a.algo, KeyAlgo::Ed25519);
    assert_eq!(a.fingerprint, Fingerprint::OpenPgp(alice.clone()));
    assert!(recent(a.created, false), "{:?}", a.created);
    let expiry = a.expiry.expect("Alice's key expires");
    assert!(expiry > SystemTime::now() + Duration::from_secs(300 * 86400));
    assert_eq!(a.location_count, 1);
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    assert_eq!(a.source, KeySource::OpenPgp);
    assert_eq!(a.subkeys.len(), 1, "{:?}", a.subkeys);
    let sub = &a.subkeys[0];
    assert_eq!(sub.algo, KeyAlgo::Cv25519);
    assert!(sub.can_encrypt);
    assert!(sub.expiry.expect("subkey expires") > expiry);

    let b = row(&list, "Bob <bob@example.invalid>");
    assert_eq!(b.fingerprint, Fingerprint::OpenPgp(bob));
    assert_eq!(b.expiry, None);
    assert_eq!(reasons(b), vec![(Severity::Info, WeakReason::NoExpiry)]);

    assert!(
        !list
            .rows
            .iter()
            .any(|r| r.fingerprint == Fingerprint::OpenPgp(carol.clone())),
        "a key without a secret key is listed"
    );

    assert_eq!(list.problems.len(), 1, "{:?}", list.problems);
    assert!(list.problems[0].source.ends_with("broken.pub"));
}

#[test]
fn missing_ssh_dir_lists_no_ssh_keys() {
    let home = TempHome::new(BASE);
    let gnupg = TempGnupgHome::new();
    let store = Store::open_in_memory().unwrap();
    let mut gpg_backend = Gpg::with_home(gnupg.path()).unwrap();
    let list = KeyList::load(&home.path().join("nope"), &mut gpg_backend, &store).unwrap();
    assert!(list.rows.is_empty(), "{list:#?}");
    assert!(list.problems.is_empty(), "{:?}", list.problems);
}
