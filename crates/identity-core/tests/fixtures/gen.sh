#!/bin/bash
# Makes the public key fixtures for identity-core tests. Run it in the
# devcontainer from this directory. Only public keys are kept; the private
# halves go to a temp dir and are deleted. Fake names only.
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ssh_key() { # name type bits
    ssh-keygen -q -N '' -t "$2" ${3:+-b "$3"} -C "$1@example.org" -f "$tmp/$1"
    cp "$tmp/$1.pub" "$1.pub"
}
ssh_key ed25519 ed25519
ssh_key rsa3072 rsa 3072
ssh_key rsa2048 rsa 2048
ssh_key ecdsa256 ecdsa 256
ssh_key ecdsa384 ecdsa 384

# Security key (sk-) public keys need a token to make. Build them from a
# normal key: the sk- blob is the sk- type name, the same key fields, then
# the application string "ssh:".
ssh_string() { printf '%08x' "${#1}" | sed 's/../\\x&/g' | xargs -0 printf; printf '%s' "$1"; }
sk_key() { # name sk-type from-key
    local blob="$tmp/$3.blob" type_len
    cut -d' ' -f2 "$3.pub" | base64 -d >"$blob"
    type_len=$(cut -d' ' -f1 "$3.pub" | tr -d '\n' | wc -c)
    { ssh_string "$2"; tail -c +$((4 + type_len + 1)) "$blob"; ssh_string "ssh:"; } \
        | base64 -w0 >"$tmp/$1.b64"
    printf '%s %s %s@example.org\n' "$2" "$(cat "$tmp/$1.b64")" "$1" >"$1.pub"
}
sk_key sk-ed25519 sk-ssh-ed25519@openssh.com ed25519
sk_key sk-ecdsa sk-ecdsa-sha2-nistp256@openssh.com ecdsa256

age-keygen -o "$tmp/age.key" 2>/dev/null
age-keygen -y "$tmp/age.key" >age.txt

# A forge style key list (like github.com/<user>.keys): several keys.
cat ed25519.pub rsa3072.pub ecdsa256.pub sk-ed25519.pub >keys-list.txt
