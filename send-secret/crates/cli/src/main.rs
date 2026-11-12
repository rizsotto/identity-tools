//! `send-secret`: encrypt and decrypt with OpenPGP and age (M1). A thin
//! layer over the `crypto` crate. Exit codes: 0 ok, 1 error, 2 usage.
//! Messages never hold plaintext (S-5).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use crypto::{
    DecryptCtx, Decrypted, EncryptOpts, Format, MessagePlan, OpenPgpCert, OpenPgpSelf, Person,
    Recipient, SelfIdentity, Sender, SignatureStatus, SignerValidity,
};
use identity_core::KeyError;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "send-secret",
    version,
    about = "Encrypt a secret for someone, or open one"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt for one or more recipients, one message each.
    Encrypt(EncryptArgs),
    /// Decrypt an OpenPGP or age message.
    Decrypt(DecryptArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// A recipient's public key file (OpenPGP, age or SSH keys). One file
    /// per recipient.
    #[arg(long = "to-key", value_name = "FILE", required = true)]
    to_key: Vec<PathBuf>,
    /// Input file (default: stdin).
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    input: Option<PathBuf>,
    /// Output file; with several recipients the BASE of the file names
    /// (default: stdout).
    #[arg(short = 'o', long = "output", value_name = "OUT")]
    output: Option<PathBuf>,
    /// Text output (ASCII armor).
    #[arg(short = 'a', long)]
    armor: bool,
    /// Do not add your own key to the messages (you can not read them back).
    #[arg(long)]
    no_self: bool,
    /// Do not sign OpenPGP messages.
    #[arg(long)]
    no_sign: bool,
    /// Use this format for every recipient.
    #[arg(long, value_enum)]
    format: Option<FormatArg>,
}

#[derive(Args)]
struct DecryptArgs {
    /// Input file (default: stdin).
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    input: Option<PathBuf>,
    /// Output file, created new with mode 0600 (default: stdout).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,
    /// An age identity file or SSH private key. Replaces the default age
    /// and SSH identities; gpg keys are always tried.
    #[arg(long = "identity", value_name = "FILE")]
    identity: Vec<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Openpgp,
    Age,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Openpgp => Format::OpenPgp,
            FormatArg::Age => Format::Age,
        }
    }
}

enum Fail {
    Usage(String),
    Error(String),
}

fn error(e: impl std::fmt::Display) -> Fail {
    Fail::Error(e.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Encrypt(args) => encrypt(args),
        Cmd::Decrypt(args) => decrypt(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Usage(msg)) => {
            eprintln!("send-secret: {msg}");
            ExitCode::from(2)
        }
        Err(Fail::Error(msg)) => {
            eprintln!("send-secret: error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn note(msg: impl std::fmt::Display) {
    eprintln!("send-secret: note: {msg}");
}

/// The key file name without its extension; characters outside
/// `[A-Za-z0-9._-]` become `_`.
fn label_for(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn encrypt(args: EncryptArgs) -> Result<(), Fail> {
    let mut labels = HashSet::new();
    let mut files = Vec::new();
    for path in &args.to_key {
        let label = label_for(path);
        if label.is_empty() {
            return Err(Fail::Usage(format!(
                "{}: can not make a label from this file name",
                path.display()
            )));
        }
        if !labels.insert(label.clone()) {
            return Err(Fail::Usage(format!(
                "two key files have the label \"{label}\"; rename one"
            )));
        }
        files.push((label, path));
    }
    let several = files.len() > 1;
    if several && args.output.is_none() {
        return Err(Fail::Usage(
            "several recipients need -o BASE (one output file each)".into(),
        ));
    }
    if several && args.input.is_none() {
        return Err(Fail::Usage(
            "several recipients need -i FILE (stdin can not be read twice)".into(),
        ));
    }

    let people = files
        .into_iter()
        .map(|(label, path)| load_person(label, path))
        .collect::<Result<Vec<_>, _>>()?;
    let force = args.format.map(Format::from);
    let mut plans = crypto::plan(&people, force).map_err(error)?;

    let sign = !args.no_sign;
    let has_openpgp = plans.iter().any(|p| p.format == Format::OpenPgp);
    let user = if has_openpgp && (sign || !args.no_self) {
        Some(crypto::openpgp_user(None).map_err(error)?)
    } else {
        None
    };
    let signer = user.as_ref().and_then(|u| u.signer.clone());

    // Your own key goes into every message, so you can read it back
    // (FR-12). Notes are printed only once every message is checked, so a
    // failing run does not first talk about them.
    let mut notes = Vec::new();
    if !args.no_self {
        let age = if plans.iter().any(|p| p.format == Format::Age) {
            let path = crypto::self_identity_path(&config_home()?);
            Some(
                SelfIdentity::load_or_create(&path)
                    .map_err(error)?
                    .recipient(),
            )
        } else {
            None
        };
        let sender = Sender {
            openpgp: user.map_or(OpenPgpSelf::NoSecretKey, |u| u.self_key),
            age,
        };
        crypto::add_sender(&mut plans, &sender);
        let why = match sender.openpgp {
            OpenPgpSelf::CannotEncrypt => "your default OpenPGP key cannot encrypt",
            _ => "you have no OpenPGP secret key",
        };
        for plan in plans.iter().filter(|p| p.sender.is_none()) {
            notes.push(format!(
                "{}: your own key is not in this message, so you can not read it back ({why})",
                plan.label
            ));
        }
    }

    let paths: HashMap<String, Option<PathBuf>> = plans
        .iter()
        .map(|p| (p.label.clone(), output_path(p, &args, several)))
        .collect();
    for path in paths.values().flatten() {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Fail::Error(format!(
                "{}: file exists; nothing was written",
                path.display()
            )));
        }
    }

    let opts = EncryptOpts {
        armor: args.armor,
        sign,
        gnupg_home: None,
        signer,
    };
    let mut created: Vec<PathBuf> = Vec::new();
    let results = crypto::encrypt_each(
        || -> io::Result<Box<dyn Read + Send>> {
            Ok(match &args.input {
                Some(path) => Box::new(File::open(path)?),
                None => Box::new(io::stdin()),
            })
        },
        |plan| -> io::Result<Box<dyn Write + Send>> {
            Ok(match &paths[&plan.label] {
                Some(path) => {
                    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
                    created.push(path.clone());
                    Box::new(file)
                }
                None => Box::new(io::stdout()),
            })
        },
        &plans,
        &opts,
    )
    .map_err(encrypt_error)?;
    for msg in notes {
        note(msg);
    }

    let mut written = Vec::new();
    let mut failed = false;
    for (plan, result) in plans.iter().zip(results) {
        let place = match &paths[&plan.label] {
            Some(path) => path.display().to_string(),
            None => "stdout".into(),
        };
        match result {
            Ok(sent) => {
                eprintln!("{}: {place} ({})", sent.label, describe(plan, &opts));
                written.push(place);
            }
            Err(e) => {
                failed = true;
                eprintln!("{}: failed: {}", plan.label, encrypt_error_text(&e));
                if let Some(path) = &paths[&plan.label]
                    && created.contains(path)
                {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
    if failed {
        let list = if written.is_empty() {
            "none".to_string()
        } else {
            written.join(", ")
        };
        return Err(Fail::Error(format!(
            "not every message was written; written: {list}"
        )));
    }
    Ok(())
}

fn describe(plan: &MessagePlan, opts: &EncryptOpts) -> String {
    match plan.format {
        Format::OpenPgp if opts.sign => "OpenPGP, signed".into(),
        Format::OpenPgp => "OpenPGP, not signed".into(),
        Format::Age => "age".into(),
    }
}

fn encrypt_error_text(e: &crypto::Error) -> String {
    match e {
        crypto::Error::NoSigner => format!("{e}; use --no-sign to send it unsigned"),
        e => e.to_string(),
    }
}

fn encrypt_error(e: crypto::Error) -> Fail {
    Fail::Error(format!("{}; nothing was written", encrypt_error_text(&e)))
}

/// One recipient: exact `-o OUT` (or stdout). Several: `BASE.<label>.<ext>`.
fn output_path(plan: &MessagePlan, args: &EncryptArgs, several: bool) -> Option<PathBuf> {
    let out = args.output.as_ref()?;
    if !several {
        return Some(out.clone());
    }
    let ext = match (plan.format, args.armor) {
        (Format::OpenPgp, true) => "asc",
        (Format::OpenPgp, false) => "gpg",
        (Format::Age, _) => "age",
    };
    let mut name = out.clone().into_os_string();
    name.push(format!(".{}.{ext}", plan.label));
    Some(PathBuf::from(name))
}

/// Reads one `--to-key` file. OpenPGP keys (armored or binary) become one
/// key; other files are read as SSH and age key lines, and keys age can
/// not use are skipped with a note (FR-4).
fn load_person(label: String, path: &Path) -> Result<Person, Fail> {
    let in_file = |e: &dyn std::fmt::Display| Fail::Error(format!("{}: {e}", path.display()));
    let bytes = identity_core::read_key_file(path).map_err(|e| in_file(&e))?;
    let lines = match identity_core::parse_public_keys(&bytes) {
        Ok(lines) => lines,
        Err(KeyError::UnsupportedFormat("OpenPGP") | KeyError::NotText) => {
            let cert = OpenPgpCert::new(bytes).map_err(|e| in_file(&e))?;
            return Ok(Person {
                label,
                keys: vec![Recipient::OpenPgp(cert)],
            });
        }
        Err(e) => return Err(in_file(&e)),
    };
    let mut keys = Vec::new();
    for line in lines {
        match line.key {
            Ok(key) => match crypto::age_key(&key) {
                Ok(key) => keys.push(Recipient::Age(key)),
                Err(skipped) => note(format!("{label}: {skipped}")),
            },
            Err(e) => note(format!("{label}: line {} skipped: {e}", line.line)),
        }
    }
    Ok(Person { label, keys })
}

/// `$XDG_CONFIG_HOME` if it is an absolute path, else `$HOME/.config`. The
/// XDG spec says relative paths are invalid.
fn config_home() -> Result<PathBuf, Fail> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
        && dir.is_absolute()
    {
        return Ok(dir);
    }
    Ok(home()?.join(".config"))
}

fn home() -> Result<PathBuf, Fail> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| Fail::Error("HOME is not set to an absolute path".into()))
}

/// Largest private key file we read.
const MAX_IDENTITY: u64 = 64 * 1024;

fn read_secret(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY as usize + 1));
    File::open(path)?
        .take(MAX_IDENTITY + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IDENTITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large for a key",
        ));
    }
    Ok(bytes)
}

fn add_identity(ctx: &mut DecryptCtx, path: &Path) -> Result<(), String> {
    let bytes = read_secret(path).map_err(|e| e.to_string())?;
    let is_age = bytes
        .windows(b"AGE-SECRET-KEY-".len())
        .any(|w| w == b"AGE-SECRET-KEY-");
    if is_age {
        ctx.add_age_identity_file(&bytes)
    } else {
        ctx.add_ssh_identity(&bytes, TtyPrompt)
    }
    .map_err(|e| e.to_string())
}

/// Asks for SSH key passphrases on the terminal (`/dev/tty`).
#[derive(Clone)]
struct TtyPrompt;

impl age::Callbacks for TtyPrompt {
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        let typed = Zeroizing::new(rpassword::prompt_password(format!("{description}: ")).ok()?);
        Some(age::secrecy::SecretString::from(typed.as_str()))
    }
}

fn decrypt(args: DecryptArgs) -> Result<(), Fail> {
    let mut ctx = DecryptCtx::new();
    if args.identity.is_empty() {
        let ssh = home()?.join(".ssh");
        for name in ["id_ed25519", "id_rsa"] {
            let path = ssh.join(name);
            if path.exists()
                && let Err(e) = add_identity(&mut ctx, &path)
            {
                note(format!("{}: not used: {e}", path.display()));
            }
        }
        let path = crypto::self_identity_path(&config_home()?);
        match SelfIdentity::load(&path) {
            Ok(Some(me)) => ctx.add_self_identity(me),
            Ok(None) => {}
            Err(e) => note(format!("{}: not used: {e}", path.display())),
        }
    } else {
        for path in &args.identity {
            add_identity(&mut ctx, path)
                .map_err(|e| Fail::Error(format!("{}: {e}", path.display())))?;
        }
    }

    let input: Box<dyn Read + Send> = match &args.input {
        Some(path) => {
            Box::new(File::open(path).map_err(|e| Fail::Error(format!("{}: {e}", path.display())))?)
        }
        None => Box::new(io::stdin()),
    };
    let found = match &args.output {
        Some(path) => {
            // No temp file: plaintext goes only to the file the user named.
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| Fail::Error(format!("{}: {e}", path.display())))?;
            match crypto::decrypt(input, &file, &ctx) {
                Ok(found) => found,
                Err(e) => {
                    let _ = file.set_len(0);
                    drop(file);
                    let _ = fs::remove_file(path);
                    return Err(Fail::Error(format!("{e}; no output file was kept")));
                }
            }
        }
        None => crypto::decrypt(input, io::stdout(), &ctx)
            .map_err(|e| Fail::Error(format!("{e}; output incomplete, discard it")))?,
    };
    report(&found);
    Ok(())
}

fn report(found: &Decrypted) {
    if found.format == Format::OpenPgp {
        match &found.signer {
            None => note("the message is not signed"),
            Some(s) => {
                let validity = match s.validity {
                    SignerValidity::Ultimate => "ultimate",
                    SignerValidity::Full => "full",
                    SignerValidity::Marginal => "marginal",
                    SignerValidity::Never => "never",
                    SignerValidity::Unknown => "unknown",
                };
                let status = match s.status {
                    SignatureStatus::Good => format!("good signature, key validity {validity}"),
                    SignatureStatus::UnknownKey => {
                        "public key not in your keyring, signature not checked".into()
                    }
                    SignatureStatus::KeyExpired => "good signature, but the key has expired".into(),
                    SignatureStatus::KeyRevoked => {
                        "the key is revoked, do not trust this signature".into()
                    }
                    SignatureStatus::SignatureExpired => "the signature has expired".into(),
                    _ => "signature not checked".into(),
                };
                eprintln!("send-secret: signed by {} ({status})", s.fingerprint);
            }
        }
    }
    if found.more_messages {
        note("another message follows this one; only the first was decrypted");
    }
}
