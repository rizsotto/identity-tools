//! Find out what kind of message an input holds, from its first bytes.

use std::io::{self, Read};

/// How many leading bytes `detect_format` looks at. Pass fewer only when
/// the input is shorter.
pub const DETECT_LEN: usize = 1024;

const OPENPGP_ARMOR: &[u8] = b"-----BEGIN PGP MESSAGE-----";
const AGE_ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_BINARY: &[u8] = b"age-encryption.org/v1\n";
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// The input from the start of the message on: the rest of the head, then
/// the rest of the input.
pub type MessageReader<R> = io::Chain<io::Cursor<Vec<u8>>, R>;

/// Reads the first bytes of `input`, detects the format and returns a reader
/// that starts at the message (`Detection::start`), so text before the
/// armor is skipped.
pub fn open_message<R: Read>(mut input: R) -> io::Result<(Detection, MessageReader<R>)> {
    let mut head = Vec::with_capacity(DETECT_LEN);
    (&mut input)
        .take(DETECT_LEN as u64)
        .read_to_end(&mut head)?;
    let detection = detect_format(&head);
    let mut head = io::Cursor::new(head);
    head.set_position(detection.start as u64);
    Ok((detection, head.chain(input)))
}

/// The kind of message `detect_format` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    OpenPgpArmor,
    AgeArmor,
    OpenPgpBinary,
    AgeBinary,
    Unknown,
}

/// What `detect_format` found, and where the message starts in the input.
/// Decryption must start reading at `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    pub format: Detected,
    pub start: usize,
}

/// Detects the format from the start of the input (FR-7).
///
/// Binary age starts with its header line. Binary OpenPGP is recognized by
/// its first packet: a public-key encrypted session key (version 3 or 6), a
/// symmetric-key encrypted session key (version 4 or 6), or a marker packet.
/// Those are the packets an encrypted message starts with (RFC 9580,
/// sections 4.2, 5.1, 5.3, 5.8).
///
/// Armor is found at the start of any line in `head` (leading spaces or
/// tabs allowed), so a UTF-8 BOM, blank lines, triple backticks or a header
/// line before it do not matter. `start` then points at the BEGIN marker.
pub fn detect_format(head: &[u8]) -> Detection {
    let found = |format, start| Detection { format, start };
    if head.starts_with(AGE_BINARY) {
        return found(Detected::AgeBinary, 0);
    }
    if is_openpgp_message_start(head) {
        return found(Detected::OpenPgpBinary, 0);
    }
    let body_start = if head.starts_with(UTF8_BOM) {
        UTF8_BOM.len()
    } else {
        0
    };
    let line_starts = std::iter::once(body_start).chain(
        head.iter()
            .enumerate()
            .filter(|&(i, &b)| b == b'\n' && i >= body_start)
            .map(|(i, _)| i + 1),
    );
    for line in line_starts {
        let indent = head[line..]
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        let at = line + indent;
        if is_armor_line(&head[at..], OPENPGP_ARMOR) {
            return found(Detected::OpenPgpArmor, at);
        }
        if is_armor_line(&head[at..], AGE_ARMOR) {
            return found(Detected::AgeArmor, at);
        }
    }
    found(Detected::Unknown, 0)
}

/// True if `head` starts with an OpenPGP packet that can begin an encrypted
/// message, checked by its tag and its version byte (or marker body).
fn is_openpgp_message_start(head: &[u8]) -> bool {
    let Some(&first) = head.first() else {
        return false;
    };
    if first & 0x80 == 0 {
        return false;
    }
    let (tag, header_len) = if first & 0x40 != 0 {
        let len_bytes = match head.get(1) {
            Some(0..=191) => 1,
            Some(192..=223) => 2,
            Some(255) => 5,
            // Partial body lengths are not allowed for these packets.
            _ => return false,
        };
        (first & 0x3f, 1 + len_bytes)
    } else {
        let len_bytes = match first & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return false,
        };
        ((first >> 2) & 0x0f, 1 + len_bytes)
    };
    let body = head.get(header_len..).unwrap_or_default();
    match tag {
        1 => matches!(body.first(), Some(3 | 6)),
        3 => matches!(body.first(), Some(4 | 6)),
        10 => body.starts_with(b"PGP"),
        _ => false,
    }
}

/// The marker must end the line, so `-----BEGIN PGP MESSAGE-----X` is not armor.
fn is_armor_line(text: &[u8], marker: &[u8]) -> bool {
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

    fn format(head: &[u8]) -> Detected {
        detect_format(head).format
    }

    fn with_prefix(prefix: &[u8], rel: &str) -> Vec<u8> {
        let mut input = prefix.to_vec();
        input.extend(fixture(rel));
        input
    }

    #[test]
    fn open_message_starts_at_the_armor() {
        let mut input = b"\xef\xbb\xbf```\n".to_vec();
        input.extend(vec![b'a'; DETECT_LEN]);
        input[7..34].copy_from_slice(b"-----BEGIN PGP MESSAGE-----");
        input[34] = b'\n';
        let (d, mut reader) = open_message(&input[..]).unwrap();
        assert_eq!(d.format, Detected::OpenPgpArmor);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, &input[7..]);
    }

    #[test]
    fn detects_gpg_armored_fixture() {
        let d = detect_format(&fixture("openpgp-armored.asc"));
        assert_eq!(
            d,
            Detection {
                format: Detected::OpenPgpArmor,
                start: 0
            }
        );
    }

    #[test]
    fn detects_gpg_binary_fixture() {
        let d = detect_format(&fixture("openpgp-binary.gpg"));
        assert_eq!(
            d,
            Detection {
                format: Detected::OpenPgpBinary,
                start: 0
            }
        );
    }

    #[test]
    fn detects_age_armored_fixture() {
        let d = detect_format(&fixture("age-armored.age"));
        assert_eq!(
            d,
            Detection {
                format: Detected::AgeArmor,
                start: 0
            }
        );
    }

    #[test]
    fn detects_age_binary_fixture() {
        let d = detect_format(&fixture("age-binary.age"));
        assert_eq!(
            d,
            Detection {
                format: Detected::AgeBinary,
                start: 0
            }
        );
    }

    #[test]
    fn armor_after_leading_blank_lines() {
        let input = with_prefix(b"\n \r\n\t", "openpgp-armored.asc");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::OpenPgpArmor,
                start: 5
            }
        );
        let input = with_prefix(b"\n\n", "age-armored.age");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::AgeArmor,
                start: 2
            }
        );
    }

    #[test]
    fn armor_inside_triple_backticks() {
        let mut input = with_prefix(b"```\n", "age-armored.age");
        input.extend(b"```\n");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::AgeArmor,
                start: 4
            }
        );
        let input = with_prefix(b"```\r\n", "openpgp-armored.asc");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::OpenPgpArmor,
                start: 5
            }
        );
    }

    #[test]
    fn armor_after_utf8_bom() {
        let input = with_prefix(UTF8_BOM, "openpgp-armored.asc");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::OpenPgpArmor,
                start: 3
            }
        );
        let input = with_prefix(b"\xef\xbb\xbf\n```\n", "age-armored.age");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::AgeArmor,
                start: 8
            }
        );
    }

    #[test]
    fn armor_after_header_line() {
        let prefix = b"Encrypted for Alice (github:alice) with age.\n\n";
        let input = with_prefix(prefix, "age-armored.age");
        assert_eq!(
            detect_format(&input),
            Detection {
                format: Detected::AgeArmor,
                start: prefix.len()
            }
        );
    }

    #[test]
    fn armor_with_crlf() {
        assert_eq!(
            format(b"-----BEGIN PGP MESSAGE-----\r\n\r\nhQ"),
            Detected::OpenPgpArmor
        );
    }

    #[test]
    fn junk_is_unknown() {
        for junk in [
            &b""[..],
            b"   \n",
            b"hello world",
            b"```\nhello\n```\n",
            b"\xef\xbb\xbfhello",
            b"see -----BEGIN PGP MESSAGE-----\n",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            b"-----BEGIN PGP MESSAGE-----X\n",
            b"-----BEGIN PGP SIGNED MESSAGE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE",
            b"age-encryption.org/v2\n",
            b"age-encryption.org/v1",
            b"\x00\x01\x02",
        ] {
            assert_eq!(detect_format(junk).format, Detected::Unknown, "{junk:?}");
        }
    }

    #[test]
    fn armor_beyond_head_is_unknown() {
        let mut input = vec![b'x'; DETECT_LEN];
        input.push(b'\n');
        let head = &input[..DETECT_LEN];
        assert_eq!(format(head), Detected::Unknown);
    }

    #[test]
    fn binary_openpgp_by_first_packet() {
        // New format: PKESK v3, PKESK v6, SKESK v4, SKESK v6, marker.
        assert_eq!(format(&[0xc1, 0x5e, 0x03]), Detected::OpenPgpBinary);
        assert_eq!(format(&[0xc1, 0x5e, 0x06]), Detected::OpenPgpBinary);
        assert_eq!(format(&[0xc3, 0x0d, 0x04]), Detected::OpenPgpBinary);
        assert_eq!(format(&[0xc3, 0xc0, 0x10, 0x06]), Detected::OpenPgpBinary);
        assert_eq!(format(b"\xca\x03PGP"), Detected::OpenPgpBinary);
        // Old format PKESK with a one byte length: 0b1000_0100.
        assert_eq!(format(&[0x84, 0x5e, 0x03]), Detected::OpenPgpBinary);
        // Old format PKESK with a two byte length: 0b1000_0101.
        assert_eq!(format(&[0x85, 0x01, 0x0c, 0x03]), Detected::OpenPgpBinary);
    }

    #[test]
    fn other_packets_are_unknown() {
        // Public key (6), literal data (11), bad versions, short input.
        assert_eq!(format(&[0xc6, 0x33, 0x04]), Detected::Unknown);
        assert_eq!(format(&[0x99, 0x01, 0x0d, 0x04]), Detected::Unknown);
        assert_eq!(format(&[0xcb, 0x10, 0x62]), Detected::Unknown);
        assert_eq!(format(&[0xc1, 0x5e, 0x04]), Detected::Unknown);
        assert_eq!(format(&[0xc3, 0x0d, 0x03]), Detected::Unknown);
        assert_eq!(format(&[0xc1]), Detected::Unknown);
        assert_eq!(format(b"\xca\x03XYZ"), Detected::Unknown);
    }

    #[test]
    fn utf8_text_is_not_binary_openpgp() {
        // "é" is C3 A9: new format tag 3 with length 169, but the next byte
        // is not a SKESK version.
        assert_eq!(format("école".as_bytes()), Detected::Unknown);
        assert_eq!(
            format("é\n-----BEGIN PGP MESSAGE-----\n".as_bytes()),
            Detected::OpenPgpArmor
        );
        // "Á" (C3 81) and "Ä" (C3 84) likewise.
        assert_eq!(format("Ácido".as_bytes()), Detected::Unknown);
        assert_eq!(format("Äpfel".as_bytes()), Detected::Unknown);
    }
}
