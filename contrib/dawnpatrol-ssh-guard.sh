#!/bin/bash
# dawnpatrol-ssh-guard.sh - forced command for DawnPatrol's SSH key.
#
# Install on the server being read, then put this in front of DawnPatrol's
# key in ~/.ssh/authorized_keys (one line):
#
#   command="/home/you/bin/dawnpatrol-ssh-guard.sh",restrict ssh-ed25519 AAAA... dawnpatrol-logs
#
# Every login with that key then runs this script instead of a shell. It runs
# the requested command only if it is exactly one of the read-only commands
# the ssh_host source sends, and every path in it is under LOG_ROOTS below.
# Anything else - a shell, a write, a path elsewhere - is refused and logged.
#
# Set LOG_ROOTS to the same folders as DAWNPATROL_SOURCE_SSH_<NAME>_HTTP_ROOTS.
# Test without running anything: DAWNPATROL_GUARD_DRYRUN=1 SSH_ORIGINAL_COMMAND='...' ./dawnpatrol-ssh-guard.sh
set -u

LOG_ROOTS=("${DAWNPATROL_GUARD_ROOTS:-$HOME/logs}")
DENY_LOG="${HOME}/.dawnpatrol-guard-denied.log"

cmd="${SSH_ORIGINAL_COMMAND:-}"

deny() {
    printf '%s denied: %s\n' "$(date -u +%FT%TZ)" "${cmd:0:300}" >> "$DENY_LOG" 2>/dev/null
    echo "dawnpatrol-ssh-guard: command not allowed" >&2
    exit 126
}

allow() {
    if [[ -n "${DAWNPATROL_GUARD_DRYRUN:-}" ]]; then echo "ALLOW"; exit 0; fi
    exec /bin/sh -c "$cmd"
}

# A path token as Python's shlex.quote writes it: bare safe characters, or a
# single-quoted string without embedded quotes.
P="([A-Za-z0-9@%+=:,./_-]+|'[^']*')"
N="[0-9]+"

under_roots() {   # every path token in $1 must be under a LOG_ROOT, with no ..
    local text="$1" tok path root ok
    [[ "$text" == *..* ]] && return 1
    while read -r tok; do
        path="${tok#\'}"; path="${path%\'}"
        ok=1
        for root in "${LOG_ROOTS[@]}"; do
            root="${root%/}"
            [[ "$path" == "$root" || "$path" == "$root"/* ]] && ok=0
        done
        [[ $ok -eq 0 ]] || return 1
    done < <(grep -oE "(^| )(/[^ ']*|'/[^']*')" <<< "$text" | sed 's/^ //')
    return 0
}

# 1. connection probe
[[ "$cmd" == "echo dawnpatrol-ok; id -nG" ]] && allow

# 2. journal probe and journal read (no paths involved)
[[ "$cmd" == "journalctl -n 1 -o json --no-pager" ]] && allow
re="^journalctl --utc --no-pager -o json --output-fields=[A-Z_,]+ --since @$N --until @$N( -u [A-Za-z0-9@._-]+)* *\| head -n $N$"
[[ "$cmd" =~ $re ]] && allow

# 3. log listing
re="^find (-L )?$P( $P)* -maxdepth $N -type f -name $P (-newermt @$N )?-printf '%s %p\\\\n' 2>&1 \| sed 's/\^find: /! /'( \| head -n $N)?$"
if [[ "$cmd" =~ $re ]]; then
    under_roots "${cmd%% -maxdepth*}" && allow
    deny
fi

# 4. log read: marker line + zcat|tail, repeated per file
part="echo @@DAWNPATROL-[0-9a-f]+@@ $P; zcat -f -- $P 2>/dev/null \| tail -n $N"
re="^$part(; $part)*$"
if [[ "$cmd" =~ $re ]]; then
    under_roots "$cmd" && allow
    deny
fi

deny
