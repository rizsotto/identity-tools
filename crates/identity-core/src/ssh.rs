use ssh_key::public::KeyData;
use ssh_key::{HashAlg, Mpint};

use crate::key::{Fingerprint, KeyAlgo, KeyKind, PublicKey};

/// Parse one OpenSSH public key line (`<type> <base64> [comment]`).
/// Lines with `authorized_keys` options are not accepted here.
pub(crate) fn parse_line(line: &str) -> Result<PublicKey, String> {
    let mut key = ssh_key::PublicKey::from_openssh(line).map_err(|e| e.to_string())?;
    let comment = Some(key.comment().to_string()).filter(|c| !c.is_empty());
    key.set_comment("");
    let encoded = key.to_openssh().map_err(|e| e.to_string())?;
    Ok(PublicKey {
        kind: KeyKind::Ssh,
        algo: algo(key.key_data()),
        fingerprint: Fingerprint::Ssh(key.fingerprint(HashAlg::Sha256).to_string()),
        comment,
        created: None,
        expiry: None,
        encoded,
    })
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
        assert!(!key.is_age_recipient());
    }
}
