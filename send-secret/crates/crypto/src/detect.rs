//! Find out what kind of message an input holds, from its first bytes.

/// How many leading bytes `detect_format` needs at most. Pass fewer only
/// when the input is shorter.
pub const DETECT_LEN: usize = 1024;

const OPENPGP_ARMOR: &[u8] = b"-----BEGIN PGP MESSAGE-----";
const AGE_ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_BINARY: &[u8] = b"age-encryption.org/v1\n";

/// What `detect_format` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    OpenPgpArmor,
    AgeArmor,
    OpenPgpBinary,
    AgeBinary,
    Unknown,
}

/// Detects the format from the start of the input (FR-7).
///
/// Armor may follow leading ASCII whitespace, as `gpg` and `age` accept it.
/// Binary OpenPGP is recognized by its first packet: a public-key or
/// symmetric-key encrypted session key, or a marker packet. Those are the
/// packets an encrypted message starts with (RFC 9580, sections 4.2, 5.1,
/// 5.3, 5.8). Anything else is `Unknown`.
pub fn detect_format(head: &[u8]) -> Detected {
    if head.starts_with(AGE_BINARY) {
        return Detected::AgeBinary;
    }
    if let Some(tag) = head.first().and_then(|&b| openpgp_packet_tag(b)) {
        return if matches!(tag, 1 | 3 | 10) {
            Detected::OpenPgpBinary
        } else {
            Detected::Unknown
        };
    }
    let text = trim_ascii_start(head);
    if starts_with_armor_line(text, OPENPGP_ARMOR) {
        Detected::OpenPgpArmor
    } else if starts_with_armor_line(text, AGE_ARMOR) {
        Detected::AgeArmor
    } else {
        Detected::Unknown
    }
}

/// The packet tag of an OpenPGP packet header byte, if bit 7 is set.
fn openpgp_packet_tag(byte: u8) -> Option<u8> {
    if byte & 0x80 == 0 {
        None
    } else if byte & 0x40 != 0 {
        Some(byte & 0x3f)
    } else {
        Some((byte >> 2) & 0x0f)
    }
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// The marker must end the line, so `-----BEGIN PGP MESSAGE-----X` is not armor.
fn starts_with_armor_line(text: &[u8], marker: &[u8]) -> bool {
    match text.strip_prefix(marker) {
        Some(rest) => matches!(rest.first(), None | Some(b'\r' | b'\n')),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(rel: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/ciphertext")
            .join(rel);
        let mut bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        bytes.truncate(DETECT_LEN);
        bytes
    }

    #[test]
    fn detects_gpg_armored_fixture() {
        assert_eq!(
            detect_format(&fixture("openpgp-armored.asc")),
            Detected::OpenPgpArmor
        );
    }

    #[test]
    fn detects_gpg_binary_fixture() {
        assert_eq!(
            detect_format(&fixture("openpgp-binary.gpg")),
            Detected::OpenPgpBinary
        );
    }

    #[test]
    fn detects_age_armored_fixture() {
        assert_eq!(
            detect_format(&fixture("age-armored.age")),
            Detected::AgeArmor
        );
    }

    #[test]
    fn detects_age_binary_fixture() {
        assert_eq!(
            detect_format(&fixture("age-binary.age")),
            Detected::AgeBinary
        );
    }

    #[test]
    fn armor_after_leading_whitespace() {
        let mut input = b"\n \r\n\t".to_vec();
        input.extend(fixture("openpgp-armored.asc"));
        assert_eq!(detect_format(&input), Detected::OpenPgpArmor);
        let mut input = b"\n\n".to_vec();
        input.extend(fixture("age-armored.age"));
        assert_eq!(detect_format(&input), Detected::AgeArmor);
    }

    #[test]
    fn armor_with_crlf() {
        assert_eq!(
            detect_format(b"-----BEGIN PGP MESSAGE-----\r\n\r\nhQ"),
            Detected::OpenPgpArmor
        );
    }

    #[test]
    fn junk_is_unknown() {
        for junk in [
            &b""[..],
            b"   \n",
            b"hello world",
            b"Encrypted for Alice\n-----BEGIN PGP MESSAGE-----\n",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            b"-----BEGIN PGP MESSAGE-----X\n",
            b"-----BEGIN PGP SIGNED MESSAGE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE",
            b"age-encryption.org/v2\n",
            b"age-encryption.org/v1",
            b"\x00\x01\x02",
        ] {
            assert_eq!(detect_format(junk), Detected::Unknown, "{junk:?}");
        }
    }

    #[test]
    fn binary_openpgp_by_first_packet() {
        // New format headers: PKESK (1), SKESK (3), marker (10).
        assert_eq!(detect_format(&[0xc1, 0x5e]), Detected::OpenPgpBinary);
        assert_eq!(detect_format(&[0xc3, 0x0d]), Detected::OpenPgpBinary);
        assert_eq!(detect_format(&[0xca, 0x03]), Detected::OpenPgpBinary);
        // Old format header for PKESK: 0b1000_0100.
        assert_eq!(detect_format(&[0x84, 0x5e]), Detected::OpenPgpBinary);
        // A public key packet (6) or a literal data packet (11) is not an
        // encrypted message.
        assert_eq!(detect_format(&[0xc6, 0x33]), Detected::Unknown);
        assert_eq!(detect_format(&[0x99, 0x01]), Detected::Unknown);
        assert_eq!(detect_format(&[0xcb, 0x10]), Detected::Unknown);
    }
}
