//! ssh config `IdentityFile` update, pure and apply (T14).

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rotation::{
    ConfigError, LineChange, apply_config_update, backup_path, plan_config_update, restore_config,
    update_text,
};
use test_support::TempHome;

const BASE: &str = env!("CARGO_TARGET_TMPDIR");
const HOME: &str = "/home/t";

fn old() -> PathBuf {
    PathBuf::from("/home/t/.ssh/id_work")
}
fn new() -> PathBuf {
    PathBuf::from("/home/t/.ssh/id_work-20261112")
}

#[test]
fn config_update_replaces_only_matching_value() {
    let text = "\
Host a
    IdentityFile ~/.ssh/id_work
Host b
  identityfile=/home/t/.ssh/id_work # work key
Host c
\tIdentityFile = \"%d/.ssh/id_work\"
Host d
    IdentityFile ~/.ssh/id_work_old
    IdentityFile ~/.ssh/id_work.pub
    IdentityFile /other/.ssh/id_work
    # IdentityFile ~/.ssh/id_work
    CertificateFile ~/.ssh/id_work
    IdentityFileX ~/.ssh/id_work
";
    let u = update_text(text, &old(), &new(), Path::new(HOME));
    assert_eq!(
        u.changes,
        vec![
            LineChange {
                line: 2,
                before: "    IdentityFile ~/.ssh/id_work".into(),
                after: "    IdentityFile ~/.ssh/id_work-20261112".into(),
            },
            LineChange {
                line: 4,
                before: "  identityfile=/home/t/.ssh/id_work # work key".into(),
                after: "  identityfile=/home/t/.ssh/id_work-20261112 # work key".into(),
            },
            LineChange {
                line: 6,
                before: "\tIdentityFile = \"%d/.ssh/id_work\"".into(),
                after: "\tIdentityFile = \"/home/t/.ssh/id_work-20261112\"".into(),
            },
        ]
    );
    let want = text
        .replace(
            "IdentityFile ~/.ssh/id_work\nHost b",
            "IdentityFile ~/.ssh/id_work-20261112\nHost b",
        )
        .replace(
            "identityfile=/home/t/.ssh/id_work #",
            "identityfile=/home/t/.ssh/id_work-20261112 #",
        )
        .replace("\"%d/.ssh/id_work\"", "\"/home/t/.ssh/id_work-20261112\"");
    assert_eq!(u.updated, want);
    assert!(u.listed.is_empty());

    // A new path with a space gets quotes.
    let u = update_text(
        "IdentityFile ~/.ssh/id_work\n",
        &old(),
        Path::new("/home/t/.ssh/my key"),
        Path::new(HOME),
    );
    assert_eq!(u.updated, "IdentityFile \"~/.ssh/my key\"\n");
}

#[test]
fn config_update_keeps_other_bytes() {
    let text = "# top\r\n\r\nHost a\r\n  IdentityFile ~/.ssh/id_work   \r\n\tUser me\nHost *\n  IdentityFile ~/.ssh/id_work";
    let u = update_text(text, &old(), &new(), Path::new(HOME));
    assert_eq!(
        u.updated,
        "# top\r\n\r\nHost a\r\n  IdentityFile ~/.ssh/id_work-20261112   \r\n\tUser me\nHost *\n  IdentityFile ~/.ssh/id_work-20261112"
    );
    assert_eq!(u.changes.len(), 2);

    // No match: byte-identical.
    let none = "Host x\n  IdentityFile ~/.ssh/other\r\n";
    assert_eq!(
        update_text(none, &old(), &new(), Path::new(HOME)).updated,
        none
    );
}

#[test]
fn config_update_lists_unknown_tokens() {
    let text = "Host a\n  IdentityFile ~/.ssh/id_%h\n  IdentityFile %d/.ssh/%r_key\n  IdentityFile ~/.ssh/id_work\n  IdentityFile ~/.ssh/100%%\n  IdentityFile ${HOME}/.ssh/id_work\n";
    let u = update_text(text, &old(), &new(), Path::new(HOME));
    assert_eq!(u.listed, vec![2, 3, 6]);
    assert_eq!(u.changes.len(), 1);
    assert_eq!(u.changes[0].line, 4);

    let home = TempHome::new(BASE);
    let cfg = home.ssh_dir().join("config");
    fs::write(&cfg, text).unwrap();
    let plan = plan_config_update(
        std::slice::from_ref(&cfg),
        &old(),
        &new(),
        Path::new(HOME),
        "r1",
    )
    .unwrap();
    let real = fs::canonicalize(&cfg).unwrap();
    assert_eq!(plan.listed.len(), 3);
    assert_eq!(plan.listed[0].path, real);
    assert_eq!(plan.listed[0].line, 2);
    assert_eq!(plan.listed[0].text, "  IdentityFile ~/.ssh/id_%h");
    assert!(
        plan.diff()
            .contains("-  IdentityFile ~/.ssh/id_work\n+  IdentityFile ~/.ssh/id_work-20261112\n")
    );
}

#[test]
fn config_apply_backs_up_keeps_mode_and_restores() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let old = ssh.join("id_work");
    let new = ssh.join("id_work-20261112");
    let cfg = ssh.join("config");
    let inc = ssh.join("work.conf");
    let untouched = ssh.join("other.conf");
    let cfg_text = "Include work.conf other.conf\nHost a\n  IdentityFile ~/.ssh/id_work\n";
    let inc_text = "Host b\n  IdentityFile ~/.ssh/id_work\r\n";
    fs::write(&cfg, cfg_text).unwrap();
    fs::write(&inc, inc_text).unwrap();
    fs::write(&untouched, "Host c\n  User x\n").unwrap();
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&inc, fs::Permissions::from_mode(0o600)).unwrap();

    // The file list comes from the M1 config scan.
    let files = inventory::scan_config(&cfg, home.path()).unwrap().files;
    assert_eq!(files, vec![cfg.clone(), inc.clone(), untouched.clone()]);

    let plan = plan_config_update(&files, &old, &new, home.path(), "r7").unwrap();
    assert_eq!(plan.files.len(), 2);
    let before_plan = fs::read_to_string(&cfg).unwrap();
    assert_eq!(before_plan, cfg_text, "planning writes nothing");
    assert!(!backup_path(&cfg, "r7").exists());

    let written = apply_config_update(&plan, "r7").unwrap();
    assert_eq!(written.len(), 2);
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        cfg_text.replace("id_work\n", "id_work-20261112\n")
    );
    assert_eq!(
        fs::read_to_string(&inc).unwrap(),
        "Host b\n  IdentityFile ~/.ssh/id_work-20261112\r\n"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().mode() & 0o7777;
    assert_eq!(mode(&cfg), 0o644);
    assert_eq!(mode(&inc), 0o600);
    assert_eq!(
        fs::read_to_string(backup_path(&cfg, "r7")).unwrap(),
        cfg_text
    );
    assert_eq!(
        fs::read_to_string(backup_path(&inc, "r7")).unwrap(),
        inc_text
    );
    assert_eq!(mode(&backup_path(&cfg, "r7")), 0o600);
    assert!(!backup_path(&untouched, "r7").exists());
    let leftovers: Vec<_> = fs::read_dir(&ssh)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("keysteward-tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // Resume: planning again finds the backups, applying again is a no-op.
    let again = plan_config_update(&files, &old, &new, home.path(), "r7").unwrap();
    assert_eq!(again, plan);
    assert!(apply_config_update(&again, "r7").unwrap().is_empty());

    // Rollback restores from the backups; a second restore does nothing.
    let restored = restore_config(&files, &old, &new, home.path(), "r7").unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(fs::read_to_string(&cfg).unwrap(), cfg_text);
    assert_eq!(fs::read_to_string(&inc).unwrap(), inc_text);
    assert_eq!(mode(&cfg), 0o644);
    assert!(
        restore_config(&files, &old, &new, home.path(), "r7")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn config_apply_refuses_changed_file_and_follows_symlink() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let old = ssh.join("id_work");
    let new = ssh.join("id_work-2");
    let real = home.path().join("dotfiles-config");
    let cfg = ssh.join("config");
    fs::write(&real, "IdentityFile ~/.ssh/id_work\n").unwrap();
    std::os::unix::fs::symlink(&real, &cfg).unwrap();

    let plan =
        plan_config_update(std::slice::from_ref(&cfg), &old, &new, home.path(), "s").unwrap();
    // The user edits the file after the plan: nothing is written.
    fs::write(&real, "IdentityFile ~/.ssh/id_work\nUser me\n").unwrap();
    let err = apply_config_update(&plan, "s").unwrap_err();
    assert!(matches!(err, ConfigError::Changed(_)), "{err}");
    assert_eq!(
        fs::read_to_string(&real).unwrap(),
        "IdentityFile ~/.ssh/id_work\nUser me\n"
    );
    assert!(!backup_path(&real, "s").exists());

    // A fresh plan works and keeps the symlink.
    let plan =
        plan_config_update(std::slice::from_ref(&cfg), &old, &new, home.path(), "s").unwrap();
    apply_config_update(&plan, "s").unwrap();
    assert!(fs::symlink_metadata(&cfg).unwrap().file_type().is_symlink());
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        "IdentityFile ~/.ssh/id_work-2\nUser me\n"
    );

    // Restore refuses a file edited after the update.
    fs::write(&real, "edited\n").unwrap();
    let err = restore_config(std::slice::from_ref(&cfg), &old, &new, home.path(), "s").unwrap_err();
    assert!(
        matches!(&err, ConfigError::RestoreIncomplete { restored, failed }
            if restored.is_empty() && failed.len() == 1),
        "{err}"
    );
    assert_eq!(fs::read_to_string(&real).unwrap(), "edited\n");

    assert!(matches!(
        plan_config_update(&[cfg], &old, &new, home.path(), "../x"),
        Err(ConfigError::BadStamp(_))
    ));
}

#[test]
fn restore_goes_on_after_a_changed_file() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let old = ssh.join("id_work");
    let new = ssh.join("id_work-2");
    let a = ssh.join("a.conf");
    let b = ssh.join("b.conf");
    let c = ssh.join("c.conf");
    let text = "IdentityFile ~/.ssh/id_work\n";
    for f in [&a, &b, &c] {
        fs::write(f, text).unwrap();
    }
    let files = vec![a.clone(), b.clone(), c.clone()];
    let plan = plan_config_update(&files, &old, &new, home.path(), "r").unwrap();
    assert_eq!(apply_config_update(&plan, "r").unwrap().len(), 3);

    // The user edits the first file after the update.
    fs::write(&a, "mine\n").unwrap();
    let err = restore_config(&files, &old, &new, home.path(), "r").unwrap_err();
    let ConfigError::RestoreIncomplete { restored, failed } = &err else {
        panic!("{err}");
    };
    let real = |p: &Path| fs::canonicalize(p).unwrap();
    assert_eq!(restored, &vec![real(&b), real(&c)]);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, real(&a));
    let msg = err.to_string();
    assert!(msg.contains("b.conf") && msg.contains("a.conf"), "{msg}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "mine\n");
    assert_eq!(fs::read_to_string(&b).unwrap(), text);
    assert_eq!(fs::read_to_string(&c).unwrap(), text);
}
