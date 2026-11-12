#!/bin/sh
# Key Steward: replace ~/.ssh/authorized_keys (SPEC 9.1). A static script,
# run through the bootstrap command. User data comes only on stdin:
#   <old cksum> <old size> <new cksum> <new size>
#   <new content>
#
# Writes nothing unless the file still has the old checksum and the whole
# new content arrived. Backup: authorized_keys.keysteward-<UTC time>-<pid>.
# Output: the marker line "key-steward-apply v1", then one status line:
#   done <cksum> <size>          exit 0
#   badinput | error <what>      exit 2
#   changed                      exit 3
#   symlink | absent | notfile   exit 4
#   notmp | error <what>         exit 5
#   short                        exit 6 (new content incomplete)
main() {
	IFS=' 	
'
	umask 077
	printf '%s\n' 'key-steward-apply v1'
	cd || { printf 'error cd\n'; return 2; }
	f=.ssh/authorized_keys
	IFS= read -r header || { printf 'badinput\n'; return 2; }
	set -- $header
	if [ $# -ne 4 ]; then printf 'badinput\n'; return 2; fi
	for n in "$@"; do
		case $n in ''|*[!0-9]*) printf 'badinput\n'; return 2 ;; esac
	done
	old="$1 $2"
	new="$3 $4"
	if [ -L "$f" ]; then printf 'symlink\n'; return 4; fi
	if [ ! -e "$f" ]; then printf 'absent\n'; return 4; fi
	if [ ! -f "$f" ]; then printf 'notfile\n'; return 4; fi
	sum=$(cksum < "$f") || { printf 'error cksum\n'; return 5; }
	set -- $sum
	if [ "$1 $2" != "$old" ]; then printf 'changed\n'; return 3; fi
	tmp=$f.keysteward-tmp.$$
	(set -C; : > "$tmp") 2>/dev/null || { printf 'notmp\n'; return 5; }
	cat > "$tmp" || { rm -f "$tmp"; printf 'error write\n'; return 5; }
	set -- $(cksum < "$tmp")
	if [ "$1 $2" != "$new" ]; then rm -f "$tmp"; printf 'short\n'; return 6; fi
	backup=$f.keysteward-$(date -u +%Y%m%dT%H%M%SZ)-$$
	(set -C; cat "$f" > "$backup") 2>/dev/null || {
		rm -f "$tmp"; printf 'error backup\n'; return 5
	}
	set -- $(cksum < "$backup")
	if [ "$1 $2" != "$old" ]; then
		rm -f "$tmp" "$backup"; printf 'changed\n'; return 3
	fi
	mv -f "$tmp" "$f" || { rm -f "$tmp"; printf 'error mv\n'; return 5; }
	set -- $(cksum < "$f")
	printf 'done %s %s\n' "$1" "$2"
}
main; exit $?
