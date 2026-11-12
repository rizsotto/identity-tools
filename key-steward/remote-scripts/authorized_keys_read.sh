#!/bin/sh
# Key Steward: print ~/.ssh/authorized_keys (SPEC 9.1). A static script,
# run through the bootstrap command; it reads no input.
#
# Output: the marker line "key-steward-read v1", then one status line:
#   ok <cksum> <size>   then the file bytes
#   absent | symlink | notfile | toolarge (over 1000000 bytes)
#   error <what>        (exit 2)
main() {
	IFS=' 	
'
	set -f
	printf '%s\n' 'key-steward-read v1'
	cd || { printf 'error cd\n'; return 2; }
	f=.ssh/authorized_keys
	if [ -L "$f" ]; then printf 'symlink\n'; return 0; fi
	if [ ! -e "$f" ]; then printf 'absent\n'; return 0; fi
	if [ ! -f "$f" ]; then printf 'notfile\n'; return 0; fi
	sum=$(cksum < "$f") || { printf 'error cksum\n'; return 2; }
	set -- $sum
	if [ "$2" -gt 1000000 ]; then printf 'toolarge\n'; return 0; fi
	printf 'ok %s %s\n' "$1" "$2"
	cat "$f" || return 2
}
main; exit $?
