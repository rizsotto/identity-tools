use ssh_key::public::KeyData;
use ssh_key::{HashAlg, Mpint};

use crate::error::LineError;
use crate::key::{Fingerprint, KeyAlgo, SshPublicKey};

const KNOWN_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Parse one OpenSSH public key line (`<type> <base64> [comment]`). Fields
/// may be split by any run of spaces or tabs. The comment is kept as found.
pub(crate) fn parse_line(line: &str) -> Result<SshPublicKey, LineError> {
    let (key_type, rest) = split_field(line);
    let (blob, comment) = split_field(rest);
    if !KNOWN_TYPES.contains(&key_type) {
        return Err(if key_type.ends_with("-cert-v01@openssh.com") {
            LineError::Certificate
        } else if line.split_whitespace().any(|f| KNOWN_TYPES.contains(&f)) {
            LineError::Options
        } else {
            LineError::UnknownType
        });
    }
    let key = ssh_key::PublicKey::from_openssh(&format!("{key_type} {blob}"))
        .map_err(|_| LineError::Malformed)?;
    if key.algorithm().as_str() != key_type {
        return Err(LineError::Malformed);
    }
    let encoded = key.to_openssh().map_err(|_| LineError::Malformed)?;
    Ok(SshPublicKey {
        algo: algo(key.key_data()),
        fingerprint: Fingerprint::Ssh(key.fingerprint(HashAlg::Sha256).to_string()),
        comment: Some(comment.to_string()).filter(|c| !c.is_empty()),
        encoded,
    })
}

/// Split off the first field. The rest has its leading whitespace removed.
fn split_field(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn algo(data: &KeyData) -> KeyAlgo {
    match data {
        KeyData::Ed25519(_) => KeyAlgo::Ed25519,
        KeyData::Ecdsa(k) => KeyAlgo::Ecdsa(k.curve().as_str().to_string()),
        KeyData::Rsa(k) => KeyAlgo::Rsa(bits(&k.n)),
        KeyData::Dsa(k) => KeyAlgo::Dsa(bits(&k.p)),
        KeyData::SkEd25519(_) => KeyAlgo::SkEd25519,
        KeyData::SkEcdsaSha2NistP256(_) => KeyAlgo::SkEcdsa("nistp256".to_string()),
        other => KeyAlgo::Other(other.algorithm().as_str().to_string()),
    }
}

/// Bit length of a positive integer, as `ssh-keygen -l` reports key sizes.
fn bits(n: &Mpint) -> u32 {
    let bytes = n.as_positive_bytes().unwrap_or(&[]);
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => (bytes.len() - i - 1) as u32 * 8 + (8 - bytes[i].leading_zeros()),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_counts_from_the_top_set_bit() {
        assert_eq!(bits(&Mpint::from_positive_bytes(&[0x01]).unwrap()), 1);
        assert_eq!(bits(&Mpint::from_positive_bytes(&[0x80, 0]).unwrap()), 16);
        assert_eq!(
            bits(&Mpint::from_positive_bytes(&[0x7f, 0, 0]).unwrap()),
            23
        );
    }

    #[test]
    fn dsa_key_is_listed_with_its_size() {
        // OpenSSH 10 can not make DSA keys, so build one from parts. The
        // numbers are not a valid DSA key; only the sizes matter here.
        let p = Mpint::from_positive_bytes(&[0x80; 128]).unwrap();
        let q = Mpint::from_positive_bytes(&[0x80; 20]).unwrap();
        let dsa = ssh_key::public::DsaPublicKey {
            p,
            q,
            g: Mpint::from_positive_bytes(&[2]).unwrap(),
            y: Mpint::from_positive_bytes(&[3]).unwrap(),
        };
        let line = ssh_key::PublicKey::new(KeyData::Dsa(dsa), "old@example.org")
            .to_openssh()
            .unwrap();
        let key = parse_line(&line).unwrap();
        assert_eq!(key.algo, KeyAlgo::Dsa(1024));
        assert!(key.encoded.starts_with("ssh-dss "));
    }
}
