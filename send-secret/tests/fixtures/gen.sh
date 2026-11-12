#!/usr/bin/env bash
# Generates every Send Secret test key and sample ciphertext in this
# directory. Run it inside the devcontainer (needs gpg, age, age-keygen,
# ssh-keygen and base64). The output is committed; regenerate only with
# this script. Fake names and example.org addresses only.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

work="$(mktemp -d)"
trap 'gpgconf --homedir "$work/gnupg" --kill all 2>/dev/null || true; rm -rf "$work"' EXIT
export HOME="$work/home"
export GNUPGHOME="$work/gnupg"
mkdir -p "$HOME" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

PASSPHRASE="fixture-passphrase"
MESSAGE="Send Secret fixture message"

rm -rf openpgp age ssh ciphertext
mkdir openpgp age ssh ciphertext

gpg_q() {
    gpg --batch --quiet --pinentry-mode loopback "$@"
}

# name, primary algo, encryption subkey algo, passphrase
gen_openpgp() {
    local name="$1" primary="$2" sub="$3" pass="$4"
    local uid="${name^} Example (test fixture) <${name%%-*}@example.org>"
    gpg_q --passphrase "$pass" --quick-gen-key "$uid" "$primary" sign,cert never
    local fpr
    fpr="$(gpg --batch --with-colons --list-keys "$uid" | awk -F: '$1 == "fpr" { print $10; exit }')"
    gpg_q --passphrase "$pass" --quick-add-key "$fpr" "$sub" encr never
    gpg_q --armor --export "$fpr" > "openpgp/$name.asc"
    gpg_q --passphrase "$pass" --armor --export-secret-keys "$fpr" > "openpgp/$name.sec.asc"
}

gen_openpgp alice ed25519 cv25519 ""
gen_openpgp bob-rsa rsa3072 rsa3072 ""
gen_openpgp sender ed25519 cv25519 ""
gen_openpgp carol-pw ed25519 cv25519 "$PASSPHRASE"

# age x25519
age-keygen -o age/dave.txt 2> /dev/null
age-keygen -y age/dave.txt > age/dave.pub

# SSH keys
ssh-keygen -q -t ed25519 -N "" -C "erin@example.org" -f ssh/erin_ed25519
ssh-keygen -q -t rsa -b 3072 -N "" -C "frank@example.org" -f ssh/frank_rsa
ssh-keygen -q -t ed25519 -N "$PASSPHRASE" -C "grace@example.org" -f ssh/grace_ed25519_pw
ssh-keygen -q -t ecdsa -b 256 -N "" -C "heidi@example.org" -f ssh/heidi_ecdsa
# Valid SSH RSA key that the age crate rejects (over 4096 bits).
ssh-keygen -q -t rsa -b 8192 -N "" -C "ivan@example.org" -f "$work/ivan_rsa8192"
cp "$work/ivan_rsa8192.pub" ssh/ivan_rsa8192.pub
# Valid SSH RSA key that the age crate rejects (under 2048 bits).
ssh-keygen -q -t rsa -b 1024 -N "" -C "kim@example.org" -f "$work/kim_rsa1024"
cp "$work/kim_rsa1024.pub" ssh/kim_rsa1024.pub

# Fake security key line (sk-ssh-ed25519): well-formed wire format,
# random point, no private key exists.
{
    printf '\x00\x00\x00\x1ask-ssh-ed25519@openssh.com'
    printf '\x00\x00\x00\x20'
    head -c 32 /dev/urandom
    printf '\x00\x00\x00\x04ssh:'
} > "$work/sk.bin"
echo "sk-ssh-ed25519@openssh.com $(base64 -w0 "$work/sk.bin") judy@example.org" > ssh/judy_sk.pub

# A GitHub style .keys list: two usable keys, then ECDSA, sk- and two RSA
# keys of a size the age crate rejects.
cat ssh/erin_ed25519.pub ssh/frank_rsa.pub ssh/heidi_ecdsa.pub ssh/judy_sk.pub \
    ssh/ivan_rsa8192.pub ssh/kim_rsa1024.pub > ssh/multi.keys

# Sample ciphertexts made by the reference tools.
printf '%s' "$MESSAGE" | gpg_q --trust-model always --armor -r alice@example.org -e > ciphertext/openpgp-armored.asc
printf '%s' "$MESSAGE" | gpg_q --trust-model always -r alice@example.org -e > ciphertext/openpgp-binary.gpg
printf '%s' "$MESSAGE" | age -a -R age/dave.pub > ciphertext/age-armored.age
printf '%s' "$MESSAGE" | age -R age/dave.pub > ciphertext/age-binary.age

chmod 644 openpgp/* age/* ssh/* ciphertext/*
echo "fixtures written to $here"
