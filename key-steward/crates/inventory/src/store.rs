use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use identity_core::Fingerprint;
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::location::{
    Location, LocationId, LocationKind, NewLocation, Purpose, SshHost, Status, Target,
};

/// Store errors. The text never holds a token: the store has none (S-4).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("the database has schema version {found}, this build knows up to {known}")]
    TooNew { found: u32, known: u32 },
    #[error("location {kind} does not take a target of this type")]
    TargetMismatch { kind: LocationKind },
    #[error("bad value in the database: {0}")]
    Corrupt(String),
    #[error("cannot prepare the database file {path}: {reason}")]
    Io { path: String, reason: String },
    /// S-8: the database dir must be 0700.
    #[error("{path} is open to other users (mode {mode:o}); it must be 0700")]
    SharedDir { path: String, mode: u32 },
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Schema migrations, in order. Index `i` brings the schema to version
/// `i + 1` (kept in `PRAGMA user_version`). Never edit a released entry;
/// add a new one.
///
/// Keys are not stored, only where they are installed. There is no token
/// column, and there must never be one (S-4).
const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE locations (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL,
    ssh_alias       TEXT,
    ssh_hostname    TEXT,
    ssh_user        TEXT,
    ssh_port        INTEGER,
    base_url        TEXT,
    account         TEXT,
    key_kind        TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    status          TEXT NOT NULL,
    status_reason   TEXT,
    last_checked    INTEGER,
    CHECK ((ssh_alias IS NULL) <> (base_url IS NULL AND account IS NULL))
);
CREATE UNIQUE INDEX locations_unique ON locations (
    kind, ifnull(ssh_alias, ''), ifnull(base_url, ''), ifnull(account, ''),
    key_fingerprint, purpose
);
"#];

/// Result of [`Store::add`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    New(LocationId),
    /// The same kind, target, key and purpose was already stored.
    Existing(LocationId),
}

impl Added {
    pub fn id(self) -> LocationId {
        match self {
            Added::New(id) | Added::Existing(id) => id,
        }
    }
}

/// SQLite store for locations and their check results.
pub struct Store {
    conn: Connection,
}

const COLUMNS: &str = "id, kind, ssh_alias, ssh_hostname, ssh_user, ssh_port, base_url, \
                       account, key_kind, key_fingerprint, purpose, status, status_reason, \
                       last_checked";

impl Store {
    /// Opens or creates the database file and applies pending migrations.
    /// The caller picks the path (the app uses `$XDG_DATA_HOME/key-steward/`).
    /// A missing dir is made 0700 and a new file 0600 (S-8). A dir that
    /// other users can open is refused; an existing file is set to 0600.
    pub fn open(path: &Path) -> Result<Store> {
        prepare_path(path)?;
        Store::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Store> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store> {
        conn.pragma_update(None, "foreign_keys", true)?;
        let mut store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    fn migrate(&mut self) -> Result<()> {
        let known = MIGRATIONS.len() as u32;
        let found = self.schema_version()?;
        if found > known {
            return Err(StoreError::TooNew { found, known });
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(found as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i as u32 + 1)?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Adds a location as `unverified`, or returns the id of the same one.
    pub fn add(&mut self, loc: &NewLocation) -> Result<Added> {
        check_target(loc.kind, &loc.target)?;
        let (alias, hostname, user, port, base_url, account) = target_columns(&loc.target);
        let (key_kind, fpr) = fingerprint_columns(&loc.key);
        let tx = self.conn.transaction()?;
        let existing: Option<LocationId> = tx
            .query_row(
                "SELECT id FROM locations WHERE kind = ?1 AND ifnull(ssh_alias, '') = ?2 \
                 AND ifnull(base_url, '') = ?3 AND ifnull(account, '') = ?4 \
                 AND key_fingerprint = ?5 AND purpose = ?6",
                params![
                    loc.kind.as_str(),
                    alias.unwrap_or(""),
                    base_url.unwrap_or(""),
                    account.unwrap_or(""),
                    fpr,
                    loc.purpose.as_str()
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(Added::Existing(id));
        }
        tx.execute(
            "INSERT INTO locations (kind, ssh_alias, ssh_hostname, ssh_user, ssh_port, \
             base_url, account, key_kind, key_fingerprint, purpose, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                loc.kind.as_str(),
                alias,
                hostname,
                user,
                port,
                base_url,
                account,
                key_kind,
                fpr,
                loc.purpose.as_str(),
                Status::Unverified.as_str()
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(Added::New(id))
    }

    pub fn get(&self, id: LocationId) -> Result<Option<Location>> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM locations WHERE id = ?1"),
                [id],
                read_row,
            )
            .optional()?
            .transpose()
    }

    /// All locations, oldest first.
    pub fn list(&self) -> Result<Vec<Location>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM locations ORDER BY id"))?;
        let rows = stmt.query_map([], read_row)?;
        rows.map(|r| r?).collect()
    }

    /// Locations that hold the key with this fingerprint.
    pub fn list_for_key(&self, key: &Fingerprint) -> Result<Vec<Location>> {
        let (key_kind, fpr) = fingerprint_columns(key);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM locations WHERE key_kind = ?1 AND key_fingerprint = ?2 \
             ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![key_kind, fpr], read_row)?;
        rows.map(|r| r?).collect()
    }

    /// Writes a check result. Returns false if there is no such location.
    pub fn set_status(
        &mut self,
        id: LocationId,
        status: &Status,
        checked: SystemTime,
    ) -> Result<bool> {
        let reason = match status {
            Status::Error(r) => Some(r.as_str()),
            _ => None,
        };
        let n = self.conn.execute(
            "UPDATE locations SET status = ?1, status_reason = ?2, last_checked = ?3 \
             WHERE id = ?4",
            params![status.as_str(), reason, to_unix(checked), id],
        )?;
        Ok(n == 1)
    }

    #[cfg(test)]
    fn conn(&self) -> &Connection {
        &self.conn
    }
}

fn prepare_path(path: &Path) -> Result<()> {
    let io = |p: &Path, e: std::io::Error| StoreError::Io {
        path: p.display().to_string(),
        reason: e.to_string(),
    };
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io(dir, e))?;
    }
    let mode = fs::metadata(dir)
        .map_err(|e| io(dir, e))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(StoreError::SharedDir {
            path: dir.display().to_string(),
            mode,
        });
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = fs::metadata(path).map_err(|e| io(path, e))?;
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .map_err(|e| io(path, e))?;
            }
            Ok(())
        }
        Err(e) => Err(io(path, e)),
    }
}

fn check_target(kind: LocationKind, target: &Target) -> Result<()> {
    match (kind, target) {
        (LocationKind::SshServer, Target::Ssh(_)) => Ok(()),
        (LocationKind::SshServer, _) | (_, Target::Ssh(_)) => {
            Err(StoreError::TargetMismatch { kind })
        }
        _ => Ok(()),
    }
}

type TargetColumns<'a> = (
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<u16>,
    Option<&'a str>,
    Option<&'a str>,
);

fn target_columns(target: &Target) -> TargetColumns<'_> {
    match target {
        Target::Ssh(h) => (
            Some(&h.alias),
            h.hostname.as_deref(),
            h.user.as_deref(),
            h.port,
            None,
            None,
        ),
        Target::Account { base_url, account } => {
            (None, None, None, None, Some(base_url), Some(account))
        }
    }
}

fn fingerprint_columns(fpr: &Fingerprint) -> (&'static str, &str) {
    let kind = match fpr {
        Fingerprint::Ssh(_) => "ssh",
        Fingerprint::OpenPgp(_) => "openpgp",
        Fingerprint::Age(_) => "age",
    };
    (kind, fpr.as_str())
}

fn to_unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

fn from_unix(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

fn read_row(r: &Row<'_>) -> rusqlite::Result<Result<Location>> {
    let kind: String = r.get("kind")?;
    let alias: Option<String> = r.get("ssh_alias")?;
    let hostname: Option<String> = r.get("ssh_hostname")?;
    let user: Option<String> = r.get("ssh_user")?;
    let port: Option<u16> = r.get("ssh_port")?;
    let base_url: Option<String> = r.get("base_url")?;
    let account: Option<String> = r.get("account")?;
    let key_kind: String = r.get("key_kind")?;
    let fpr: String = r.get("key_fingerprint")?;
    let purpose: String = r.get("purpose")?;
    let status: String = r.get("status")?;
    let reason: Option<String> = r.get("status_reason")?;
    let last_checked: Option<i64> = r.get("last_checked")?;
    let id: LocationId = r.get("id")?;

    let corrupt = |what: &str, v: &str| StoreError::Corrupt(format!("location {id}: {what} {v:?}"));
    let build = || -> Result<Location> {
        let kind = LocationKind::parse(&kind).ok_or_else(|| corrupt("kind", &kind))?;
        let target = match (alias, base_url, account) {
            (Some(alias), None, None) => Target::Ssh(SshHost {
                alias,
                hostname,
                user,
                port,
            }),
            (None, Some(base_url), Some(account)) => Target::Account { base_url, account },
            _ => return Err(corrupt("target", "")),
        };
        let key = match key_kind.as_str() {
            "ssh" => Fingerprint::Ssh(fpr),
            "openpgp" => Fingerprint::OpenPgp(fpr),
            "age" => Fingerprint::Age(fpr),
            other => return Err(corrupt("key kind", other)),
        };
        let purpose = Purpose::parse(&purpose).ok_or_else(|| corrupt("purpose", &purpose))?;
        let status = match status.as_str() {
            "verified" => Status::Verified,
            "unverified" => Status::Unverified,
            "missing" => Status::Missing,
            "error" => Status::Error(reason.unwrap_or_default()),
            other => return Err(corrupt("status", other)),
        };
        Ok(Location {
            id,
            kind,
            target,
            key,
            purpose,
            status,
            last_checked: last_checked.map(from_unix),
        })
    };
    Ok(build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn ssh_loc(alias: &str) -> NewLocation {
        NewLocation {
            kind: LocationKind::SshServer,
            target: Target::Ssh(SshHost {
                alias: alias.into(),
                hostname: Some("build.example.com".into()),
                user: Some("me".into()),
                port: Some(2222),
            }),
            key: Fingerprint::Ssh("SHA256:abc".into()),
            purpose: Purpose::SshAuth,
        }
    }

    fn forge_loc() -> NewLocation {
        NewLocation {
            kind: LocationKind::GitLab,
            target: Target::Account {
                base_url: "https://gitlab.example.org".into(),
                account: "me".into(),
            },
            key: Fingerprint::OpenPgp("0123456789ABCDEF0123456789ABCDEF01234567".into()),
            purpose: Purpose::OpenPgp,
        }
    }

    #[test]
    fn migrations_apply_on_empty_db() {
        let dir = private_dir();
        let path = dir.path().join("inventory.sqlite");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), MIGRATIONS.len() as u32);
        drop(store);
        // Opening again applies nothing and keeps the data.
        let mut store = Store::open(&path).unwrap();
        store.add(&ssh_loc("build")).unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), MIGRATIONS.len() as u32);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn database_is_private() {
        use std::os::unix::fs::MetadataExt;
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("data/key-steward/inventory.sqlite");
        let mut store = Store::open(&path).unwrap();
        store.add(&ssh_loc("build")).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        drop(store);

        // An existing file that is too open is fixed.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        Store::open(&path).unwrap();
        assert_eq!(mode(&path), 0o600);

        // A dir other users can open is refused, and nothing is created.
        let shared = base.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        let err = Store::open(&shared.join("inventory.sqlite")).err().unwrap();
        assert!(
            matches!(err, StoreError::SharedDir { mode: 0o755, .. }),
            "{err}"
        );
        assert!(!shared.join("inventory.sqlite").exists());
    }

    /// S-8: locations name keys by fingerprint only. No column may hold key
    /// material (public or private) or a token.
    #[test]
    fn schema_has_no_key_material() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.conn();
        let mut stmt = conn
            .prepare(
                "SELECT m.name, p.name, p.type FROM sqlite_master m \
                 JOIN pragma_table_info(m.name) p WHERE m.type = 'table'",
            )
            .unwrap();
        let cols: Vec<(String, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!cols.is_empty());
        for (table, col, ty) in cols {
            let c = col.to_lowercase();
            assert_ne!(ty.to_uppercase(), "BLOB", "{table}.{col} is a BLOB");
            for bad in [
                "public", "private", "blob", "material", "pem", "armor", "encoded",
            ] {
                assert!(!c.contains(bad), "{table}.{col} could hold key material");
            }
            if c.contains("key") {
                assert!(
                    ["key_kind", "key_fingerprint"].contains(&c.as_str()),
                    "{table}.{col}: keys are referenced by fingerprint only"
                );
            }
        }
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = private_dir();
        let path = dir.path().join("inventory.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        drop(conn);
        let err = Store::open(&path).err().unwrap();
        assert!(matches!(err, StoreError::TooNew { found: 99, .. }), "{err}");
    }

    #[test]
    fn location_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store.add(&ssh_loc("build")).unwrap();
        let b = store.add(&forge_loc()).unwrap();
        assert!(matches!(a, Added::New(_)));
        assert_eq!(
            store.add(&ssh_loc("build")).unwrap(),
            Added::Existing(a.id())
        );

        let got = store.get(a.id()).unwrap().unwrap();
        let want = ssh_loc("build");
        assert_eq!(got.kind, want.kind);
        assert_eq!(got.target, want.target);
        assert_eq!(got.key, want.key);
        assert_eq!(got.purpose, want.purpose);
        assert_eq!(got.status, Status::Unverified);
        assert_eq!(got.last_checked, None);

        let got = store.get(b.id()).unwrap().unwrap();
        assert_eq!(got.target, forge_loc().target);
        assert_eq!(got.key, forge_loc().key);

        let t = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let err = Status::Error("Host key verification failed".into());
        assert!(store.set_status(a.id(), &err, t).unwrap());
        let got = store.get(a.id()).unwrap().unwrap();
        assert_eq!(got.status, err);
        assert_eq!(got.last_checked, Some(t));
        assert!(store.set_status(a.id(), &Status::Verified, t).unwrap());
        assert_eq!(store.get(a.id()).unwrap().unwrap().status, Status::Verified);
        assert!(!store.set_status(999, &Status::Missing, t).unwrap());

        assert_eq!(store.list().unwrap().len(), 2);
        assert_eq!(store.list_for_key(&ssh_loc("x").key).unwrap().len(), 1);
        assert!(
            store
                .list_for_key(&Fingerprint::OpenPgp("SHA256:abc".into()))
                .unwrap()
                .is_empty()
        );
        assert!(store.get(999).unwrap().is_none());
    }

    #[test]
    fn target_must_match_kind() {
        let mut store = Store::open_in_memory().unwrap();
        let mut loc = forge_loc();
        loc.kind = LocationKind::SshServer;
        assert!(matches!(
            store.add(&loc),
            Err(StoreError::TargetMismatch { .. })
        ));
        let mut loc = ssh_loc("build");
        loc.kind = LocationKind::GitHub;
        assert!(matches!(
            store.add(&loc),
            Err(StoreError::TargetMismatch { .. })
        ));
    }

    #[test]
    fn schema_has_no_token_column() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.conn();
        let mut tables = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let tables: Vec<String> = tables
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!tables.is_empty());
        for table in tables {
            let mut cols = conn
                .prepare("SELECT name FROM pragma_table_info(?1)")
                .unwrap();
            let cols: Vec<String> = cols
                .query_map([&table], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            for col in cols {
                let c = col.to_lowercase();
                for bad in ["token", "secret", "password", "credential", "auth"] {
                    assert!(!c.contains(bad), "column {table}.{col} looks like a secret");
                }
            }
        }
    }
}
