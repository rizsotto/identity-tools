//! OpenPGP backend through the facade (M1 T08b, T09). Every test uses its
//! own temp GnuPG homes with fixture keys.

use std::path::{Path, PathBuf};
use std::process::Command;

use crypto::{
    DecryptCtx, EncryptOpts, Error, Format, MessagePlan, OpenPgpCert, OpenPgpSelf, Person,
    Recipient, SignatureStatus, decrypt, encrypt, encrypt_each, openpgp_user, plan, self_plan,
};
use tempfile::TempDir;

const MSG: &[u8] = b"Send Secret OpenPGP test message";

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(fixture(rel)).unwrap()
}

/// A throwaway GnuPG home. Kills its agent on drop.
struct Home {
    dir: TempDir,
}

impl Home {
    /// A home with these fixture files imported (`openpgp/<name>`).
    fn with(files: &[&str]) -> Self {
        // Short path under /tmp: the agent socket path has a length limit.
        let dir = tempfile::Builder::new()
            .prefix("ss-pgp")
            .tempdir_in("/tmp")
            .unwrap();
        let home = Home { dir };
        for f in files {
            home.gpg(&[
                "--import",
                fixture(&format!("openpgp/{f}")).to_str().unwrap(),
            ]);
        }
        home
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn gpg(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
            .args(["--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn opts(&self, armor: bool) -> EncryptOpts {
        EncryptOpts {
            armor,
            sign: true,
            gnupg_home: Some(self.path().to_path_buf()),
            signer: openpgp_user(Some(self.path())).unwrap().signer,
        }
    }

    fn ctx(&self) -> DecryptCtx {
        let mut ctx = DecryptCtx::new();
        ctx.set_gnupg_home(self.path());
        ctx
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .status();
    }
}

/// Primary fingerprint of a fixture key.
fn fpr(file: &str) -> String {
    colons(file, "fpr")
}

/// Key ID of the encryption subkey of a fixture key.
fn enc_keyid(file: &str) -> String {
    colons(file, "sub")
}

fn colons(file: &str, record: &str) -> String {
    let home = Home::with(&[]);
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--with-colons", "--show-keys"])
        .arg(fixture(&format!("openpgp/{file}")))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text.lines().find(|l| l.starts_with(record)).unwrap();
    let field = if record == "fpr" { 9 } else { 4 };
    line.split(':').nth(field).unwrap().to_string()
}

/// Key IDs in the public-key encrypted session key packets.
fn packet_keyids(ct: &[u8]) -> Vec<String> {
    let home = Home::with(&[]);
    let path = home.path().join("msg");
    std::fs::write(&path, ct).unwrap();
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--list-packets"])
        .arg(&path)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("pubkey enc packet"))
        .map(|l| l.rsplit("keyid ").next().unwrap().trim().to_string())
        .collect()
}

fn alice_plan() -> MessagePlan {
    let alice = Person {
        label: "alice".into(),
        keys: vec![Recipient::OpenPgp(
            OpenPgpCert::new(read("openpgp/alice.asc")).unwrap(),
        )],
    };
    plan(&[alice], None).unwrap().remove(0)
}

fn encrypt_to(plan: &MessagePlan, opts: &EncryptOpts) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt(MSG, &mut out, plan, opts).unwrap();
    out
}

fn open(ct: &[u8], home: &Home) -> Result<(Vec<u8>, crypto::Decrypted), Error> {
    let mut out = Vec::new();
    let found = decrypt(ct, &mut out, &home.ctx())?;
    assert_eq!(found.format, Format::OpenPgp);
    Ok((out, found))
}

#[test]
fn openpgp_round_trip_signed_armored_and_binary() {
    let sender = Home::with(&["sender.sec.asc"]);
    let alice = Home::with(&["alice.sec.asc", "sender.asc"]);
    for armor in [true, false] {
        let ct = encrypt_to(&alice_plan(), &sender.opts(armor));
        assert_eq!(
            ct.starts_with(b"-----BEGIN PGP MESSAGE-----\n"),
            armor,
            "armor {armor}"
        );
        let (plain, found) = open(&ct, &alice).unwrap();
        assert_eq!(plain, MSG);
        let signer = found.signer.expect("signed");
        assert_eq!(signer.fingerprint.as_str(), fpr("sender.asc"));
        assert_eq!(signer.status, SignatureStatus::Good);
        assert!(!found.more_messages);
    }
}

#[test]
fn signer_without_public_key_is_reported_unknown() {
    let sender = Home::with(&["sender.sec.asc"]);
    let alice = Home::with(&["alice.sec.asc"]);
    let ct = encrypt_to(&alice_plan(), &sender.opts(true));
    let (plain, found) = open(&ct, &alice).unwrap();
    assert_eq!(plain, MSG);
    let signer = found.signer.unwrap();
    assert_eq!(signer.status, SignatureStatus::UnknownKey);
    assert!(fpr("sender.asc").ends_with(signer.fingerprint.as_str()));
}

#[test]
fn signer_is_the_default_key_not_another_secret_key() {
    // Two secret keys; gpg.conf names sender as default-key. Signing and
    // the self copy both use it.
    let sender = Home::with(&["bob-rsa.sec.asc", "sender.sec.asc"]);
    std::fs::write(
        sender.path().join("gpg.conf"),
        format!("default-key {}\n", fpr("sender.asc")),
    )
    .unwrap();
    let user = openpgp_user(Some(sender.path())).unwrap();
    assert_eq!(user.signer.as_deref(), Some(fpr("sender.asc").as_str()));
    let alice = Home::with(&["alice.sec.asc", "sender.asc", "bob-rsa.asc"]);
    let ct = encrypt_to(&alice_plan(), &sender.opts(false));
    let (_, found) = open(&ct, &alice).unwrap();
    assert_eq!(
        found.signer.unwrap().fingerprint.as_str(),
        fpr("sender.asc")
    );
}

#[test]
fn no_sign_gives_unsigned_message() {
    let sender = Home::with(&["sender.sec.asc"]);
    let alice = Home::with(&["alice.sec.asc"]);
    let opts = EncryptOpts {
        sign: false,
        ..sender.opts(true)
    };
    let (plain, found) = open(&encrypt_to(&alice_plan(), &opts), &alice).unwrap();
    assert_eq!(plain, MSG);
    assert!(found.signer.is_none());
}

#[test]
fn tampered_input_fails() {
    let sender = Home::with(&["sender.sec.asc"]);
    let alice = Home::with(&["alice.sec.asc", "sender.asc"]);
    let ct = encrypt_to(&alice_plan(), &sender.opts(false));
    for at in [ct.len() / 2, ct.len() - 3] {
        let mut bad = ct.clone();
        bad[at] ^= 0x01;
        let res = open(&bad, &alice);
        assert!(
            matches!(
                res,
                Err(Error::Corrupt | Error::BadSignature | Error::OpenPgp(_))
            ),
            "byte {at}: {:?}",
            res.map(|(_, d)| d)
        );
    }
    let mut cut = ct.clone();
    cut.truncate(ct.len() - 10);
    assert!(open(&cut, &alice).is_err());
}

#[test]
fn wrong_recipient_is_no_matching_key() {
    let sender = Home::with(&["sender.sec.asc"]);
    let bob = Home::with(&["bob-rsa.sec.asc"]);
    let ct = encrypt_to(&alice_plan(), &sender.opts(true));
    assert!(matches!(open(&ct, &bob), Err(Error::NoMatchingKey)));
}

#[test]
fn decrypts_gpg_fixture_in_backticks_and_notes_second_message() {
    let alice = Home::with(&["alice.sec.asc"]);
    let armored = read("ciphertext/openpgp-armored.asc");
    let mut pasted = b"\xef\xbb\xbfEncrypted for Alice.\n```\n".to_vec();
    pasted.extend(&armored);
    pasted.extend(b"```\n");
    let (plain, found) = open(&pasted, &alice).unwrap();
    assert_eq!(plain, b"Send Secret fixture message");
    assert!(found.signer.is_none());
    assert!(!found.more_messages);

    let mut two = armored.clone();
    two.extend(&armored);
    let (plain, found) = open(&two, &alice).unwrap();
    assert_eq!(plain, b"Send Secret fixture message", "only the first");
    assert!(found.more_messages);

    let (plain, _) = open(&read("ciphertext/openpgp-binary.gpg"), &alice).unwrap();
    assert_eq!(plain, b"Send Secret fixture message");
}

#[test]
fn default_key_without_encryption_subkey_cannot_encrypt() {
    let home = Home::with(&[]);
    home.gpg(&[
        "--quick-gen-key",
        "Sign Only (test fixture) <signonly@example.org>",
        "ed25519",
        "sign",
        "1y",
    ]);
    let user = openpgp_user(Some(home.path())).unwrap();
    assert!(matches!(user.self_key, OpenPgpSelf::CannotEncrypt));
    assert!(user.signer.is_some(), "it can still sign");

    let empty = Home::with(&[]);
    let user = openpgp_user(Some(empty.path())).unwrap();
    assert!(matches!(user.self_key, OpenPgpSelf::NoSecretKey));
    assert!(user.signer.is_none());
}

#[test]
fn signing_without_signer_writes_nothing() {
    let home = Home::with(&[]);
    let opts = home.opts(true);
    assert!(opts.signer.is_none());
    let mut opened = 0;
    let err = encrypt_each(
        || {
            opened += 1;
            Ok(MSG)
        },
        |_| -> std::io::Result<Vec<u8>> { Ok(Vec::new()) },
        &[alice_plan()],
        &opts,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NoSigner), "{err:?}");
    assert_eq!(opened, 0);
}

#[test]
fn key_file_with_two_keys_gives_one_message_both_open() {
    let sender = Home::with(&["sender.sec.asc"]);
    let mut two = read("openpgp/alice.asc");
    two.extend(read("openpgp/bob-rsa.asc"));
    let p = MessagePlan {
        label: "pair".into(),
        format: Format::OpenPgp,
        keys: vec![Recipient::OpenPgp(OpenPgpCert::new(two).unwrap())],
    };
    let ct = encrypt_to(&p, &sender.opts(false));
    let mut ids = packet_keyids(&ct);
    ids.sort();
    let mut want = vec![enc_keyid("alice.asc"), enc_keyid("bob-rsa.asc")];
    want.sort();
    assert_eq!(ids, want);
    for home in [
        Home::with(&["alice.sec.asc"]),
        Home::with(&["bob-rsa.sec.asc"]),
    ] {
        assert_eq!(open(&ct, &home).unwrap().0, MSG);
    }
    assert!(matches!(open(&ct, &sender), Err(Error::NoMatchingKey)));
    // Nothing was imported into the sender's keyring.
    let listed = String::from_utf8(sender.gpg(&["--with-colons", "--list-keys"])).unwrap();
    assert!(!listed.contains(&fpr("alice.asc")) && !listed.contains(&fpr("bob-rsa.asc")));
}

#[test]
fn key_file_with_an_unusable_key_is_refused_before_output() {
    let sender = Home::with(&["sender.sec.asc"]);
    let signonly = Home::with(&[]);
    signonly.gpg(&[
        "--quick-gen-key",
        "Sign Only (test fixture) <signonly@example.org>",
        "ed25519",
        "sign",
        "1y",
    ]);
    let mut two = read("openpgp/alice.asc");
    two.extend(signonly.gpg(&["--armor", "--export"]));
    let p = MessagePlan {
        label: "pair".into(),
        format: Format::OpenPgp,
        keys: vec![Recipient::OpenPgp(OpenPgpCert::new(two).unwrap())],
    };
    let err = encrypt_each(
        || -> std::io::Result<&[u8]> { panic!("input opened") },
        |_| -> std::io::Result<Vec<u8>> { panic!("output opened") },
        &[p],
        &sender.opts(true),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::BadKey { label, .. } if label == "pair"),
        "{err:?}"
    );
}

/// Signatures gpg finds in `ct`, as the fingerprints of VALIDSIG lines.
fn valid_signers(ct: &[u8], home: &Home) -> Vec<String> {
    let path = home.path().join("signed.msg");
    std::fs::write(&path, ct).unwrap();
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--status-fd", "1", "--decrypt"])
        .arg(&path)
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&out.stdout).into_owned();
    let sigs = status.lines().filter(|l| l.contains("NEWSIG")).count();
    let valid: Vec<String> = status
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] VALIDSIG "))
        .map(|l| l.split(' ').next().unwrap().to_string())
        .collect();
    assert_eq!(sigs, valid.len(), "{status}");
    valid
}

#[test]
fn explicit_signer_wins_over_default_key() {
    let sender = Home::with(&["bob-rsa.sec.asc", "sender.sec.asc"]);
    std::fs::write(
        sender.path().join("gpg.conf"),
        format!("default-key {}\n", fpr("bob-rsa.asc")),
    )
    .unwrap();
    let opts = EncryptOpts {
        signer: Some(fpr("sender.asc")),
        ..sender.opts(false)
    };
    let ct = encrypt_to(&alice_plan(), &opts);
    let alice = Home::with(&["alice.sec.asc", "sender.asc", "bob-rsa.asc"]);
    assert_eq!(valid_signers(&ct, &alice), [fpr("sender.asc")]);
}

#[test]
fn gpg_conf_options_that_add_keys_are_refused() {
    let sender = Home::with(&["sender.sec.asc", "bob-rsa.sec.asc"]);
    let me = fpr("sender.asc");
    let file = fixture("openpgp/sender.asc");
    let file = file.to_str().unwrap();
    for (conf, option) in [
        (format!("recipient {me}"), "recipient"),
        (format!("  hidden-recipient\t{me}"), "hidden-recipient"),
        (format!("recipient-file {file}"), "recipient-file"),
        (
            format!("hidden-recipient-file {file}"),
            "hidden-recipient-file",
        ),
        (format!("local-user {}", fpr("bob-rsa.asc")), "local-user"),
    ] {
        // gpg reads gpg.conf-2 before gpg.conf; the check reads the same.
        for name in ["gpg.conf", "gpg.conf-2"] {
            let _ = std::fs::remove_file(sender.path().join("gpg.conf"));
            let _ = std::fs::remove_file(sender.path().join("gpg.conf-2"));
            std::fs::write(sender.path().join(name), format!("# x\n{conf}\n")).unwrap();
            let err = encrypt_each(
                || -> std::io::Result<&[u8]> { panic!("input opened") },
                |_| -> std::io::Result<Vec<u8>> { panic!("output opened") },
                &[alice_plan()],
                &sender.opts(true),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::GpgConf { option: o, .. } if o == option),
                "{conf} in {name}: {err:?}"
            );
            assert!(err.to_string().contains(name), "{err}");
        }
    }
    // local-user only matters when signing, and comments do not count.
    std::fs::write(
        sender.path().join("gpg.conf-2"),
        format!("local-user {}\n# recipient {me}\n", fpr("bob-rsa.asc")),
    )
    .unwrap();
    let opts = EncryptOpts {
        sign: false,
        ..sender.opts(false)
    };
    assert_eq!(
        packet_keyids(&encrypt_to(&alice_plan(), &opts)),
        [enc_keyid("alice.asc")]
    );
}

#[test]
fn self_copy_opens_with_sender_key() {
    let sender = Home::with(&["sender.sec.asc"]);
    let user = openpgp_user(Some(sender.path())).unwrap();
    let me = crypto::Sender {
        openpgp: user.self_key,
        age: None,
    };
    let (self_copy, note) = self_plan(&me, None).unwrap();
    assert_eq!((self_copy.format, note), (Format::OpenPgp, None));
    let ct = encrypt_to(&self_copy, &sender.opts(true));
    let (plain, found) = open(&ct, &sender).unwrap();
    assert_eq!(plain, MSG);
    assert_eq!(found.signer.unwrap().status, SignatureStatus::Good);
    assert_eq!(packet_keyids(&ct), [enc_keyid("sender.asc")]);
    let alice = Home::with(&["alice.sec.asc"]);
    assert!(matches!(open(&ct, &alice), Err(Error::NoMatchingKey)));
}

#[test]
fn recipient_message_has_no_sender_key() {
    let sender = Home::with(&["sender.sec.asc"]);
    let ct = encrypt_to(&alice_plan(), &sender.opts(false));
    assert_eq!(packet_keyids(&ct), [enc_keyid("alice.asc")]);
    assert!(matches!(open(&ct, &sender), Err(Error::NoMatchingKey)));
}

#[test]
fn encrypt_to_in_gpg_conf_ignored() {
    let sender = Home::with(&["sender.sec.asc"]);
    let me = fpr("sender.asc");
    std::fs::write(
        sender.path().join("gpg.conf"),
        format!("encrypt-to {me}\nhidden-encrypt-to {me}\ndefault-recipient-self\n"),
    )
    .unwrap();
    for armor in [true, false] {
        let ct = encrypt_to(&alice_plan(), &sender.opts(armor));
        assert_eq!(
            packet_keyids(&ct),
            [enc_keyid("alice.asc")],
            "armor {armor}"
        );
        assert!(matches!(open(&ct, &sender), Err(Error::NoMatchingKey)));
    }
}

#[test]
fn recipient_key_is_not_imported() {
    let sender = Home::with(&["sender.sec.asc"]);
    encrypt_to(&alice_plan(), &sender.opts(true));
    let listed = String::from_utf8(sender.gpg(&["--with-colons", "--list-keys"])).unwrap();
    assert!(!listed.contains(&fpr("alice.asc")));
}

#[test]
fn encrypt_each_mixed_openpgp_and_age() {
    let sender = Home::with(&["sender.sec.asc"]);
    let alice = Home::with(&["alice.sec.asc", "sender.asc"]);
    let erin_line = String::from_utf8(read("ssh/erin_ed25519.pub")).unwrap();
    let erin = Person {
        label: "erin".into(),
        keys: vec![Recipient::Age(crypto::AgeKey::Ssh(
            erin_line.trim().parse().unwrap(),
        ))],
    };
    let alice_person = Person {
        label: "alice".into(),
        keys: alice_plan().keys,
    };
    let plans = plan(&[alice_person, erin], None).unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let results = encrypt_each(
        || Ok(MSG),
        |p| std::fs::File::create(out_dir.path().join(&p.label)),
        &plans,
        &sender.opts(true),
    );
    let outputs: Vec<Vec<u8>> = ["alice", "erin"]
        .iter()
        .map(|l| std::fs::read(out_dir.path().join(l)).unwrap())
        .collect();
    let sent: Vec<_> = results
        .unwrap()
        .into_iter()
        .map(|r| r.unwrap().format)
        .collect();
    assert_eq!(sent, [Format::OpenPgp, Format::Age]);
    assert_eq!(open(&outputs[0], &alice).unwrap().0, MSG);
    let mut ctx = DecryptCtx::new();
    ctx.add_ssh_identity(&read("ssh/erin_ed25519"), age::NoCallbacks)
        .unwrap();
    let mut plain = Vec::new();
    decrypt(&outputs[1][..], &mut plain, &ctx).unwrap();
    assert_eq!(plain, MSG);
}
