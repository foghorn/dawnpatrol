# Reading a remote server over SSH (journal and nginx logs)

The `ssh_host` source reads a server you can only reach by SSH: its systemd
journal (SSH logons, sudo, service errors) and its nginx access logs, from any
number of site folders. This guide sets up one server. Repeat steps 1–4 per
server, then list every server name in step 5.

What DawnPatrol runs on the server, each run:

- `journalctl --utc -o json --since @<start> --until @<end> | head -n <cap>`;
- `find <roots> -maxdepth <n> -type f -name '<pattern>' -newermt @<start>`
  to list access logs changed during the window;
- `zcat -f <file> | tail -n <cap>` for each of those files, gzipped or not.

All three are read-only. Nothing is installed on the server, nothing runs
there between DawnPatrol runs, and the account never needs sudo.

**No root on the server?** You can still read whatever your own account can:
on shared or managed hosting, that usually means every site's access logs, but
not the system journal. Skip step 1, use your own username as `USER`, set
`JOURNAL=false`, and do step 3 in your own `~/.ssh/authorized_keys`, **with the
guard script from step 3a**. The key then logs in as you, so locking it to
DawnPatrol's read commands is what keeps a stolen key from being a stolen account.

## 1. A read-only account on the server

On the server, as root:

```bash
useradd --system --create-home --shell /bin/bash dawnlogs
usermod -aG systemd-journal,adm dawnlogs   # journal, and nginx logs (Debian/Ubuntu: group adm)
```

- `systemd-journal` lets the account read the whole journal. Without it,
  `journalctl` shows only the account's own entries.
- nginx's logs are usually `root:adm` with mode `640` on Debian and Ubuntu,
  so `adm` covers them. Elsewhere, give the account read access to each site's
  log folder: for example `setfacl -R -m u:dawnlogs:rX /var/www/*/logs`, plus
  a default ACL (`-d -m u:dawnlogs:r`) so rotated files stay readable.

Check as the account:

```bash
sudo -u dawnlogs journalctl -n 3 --no-pager
sudo -u dawnlogs find /var/www /var/log/nginx -maxdepth 4 -name '*access*.log*'
```

## 2. A key for DawnPatrol

On the DawnPatrol host, in the DawnPatrol folder:

```bash
mkdir -p config/ssh
ssh-keygen -t ed25519 -N '' -C dawnpatrol-logs -f config/ssh/web1_ed25519
```

The container runs as uid 10001, and `ssh` refuses a private key other users
can read. So give the key to that uid with owner-only access:

```bash
sudo chown 10001:10001 config/ssh/web1_ed25519
sudo chmod 600 config/ssh/web1_ed25519
```

`config/ssh/` is gitignored; keep it that way.

## 3. Authorize the key, restricted

On the server, put the public key (`config/ssh/web1_ed25519.pub`) in
`/home/dawnlogs/.ssh/authorized_keys` with restrictions in front of it:

```
restrict,from="203.0.113.7" ssh-ed25519 AAAA... dawnpatrol-logs
```

- `restrict` turns off port forwarding, agent forwarding, X11 and the PTY, so
  the key can only run commands.
- `from=` limits the key to DawnPatrol's public address. With a dynamic home
  address, leave `from=` out or list a range, and rely on the key alone.

```bash
chown -R dawnlogs:dawnlogs /home/dawnlogs/.ssh
chmod 700 /home/dawnlogs/.ssh && chmod 600 /home/dawnlogs/.ssh/authorized_keys
```

### 3a. Lock the key to DawnPatrol's commands (recommended; essential without root)

`contrib/dawnpatrol-ssh-guard.sh` is a forced command: every login with the
key runs it instead of a shell. It runs the request only if it is exactly one of
the read-only commands DawnPatrol sends, with every path under the log folders
you name, and refuses and logs anything else (`~/.dawnpatrol-guard-denied.log`).
Copy it to the server, set its folders, and point the key at it:

```bash
mkdir -p ~/bin
# copy contrib/dawnpatrol-ssh-guard.sh to ~/bin/ on the server, then:
chmod 755 ~/bin/dawnpatrol-ssh-guard.sh
```

Edit its `LOG_ROOTS` line to the same folders as `HTTP_ROOTS`, then change the
key's line in `authorized_keys` to:

```
command="/home/you/bin/dawnpatrol-ssh-guard.sh",restrict ssh-ed25519 AAAA... dawnpatrol-logs
```

Check it refuses everything else, without running anything:

```bash
DAWNPATROL_GUARD_DRYRUN=1 SSH_ORIGINAL_COMMAND='cat ~/.ssh/authorized_keys' \
  ~/bin/dawnpatrol-ssh-guard.sh; echo "exit $?"     # prints the refusal, exit 126
```

A test in DawnPatrol's suite runs the guard against every command the source
generates, so the two can't drift apart unnoticed.

## 4. Pin the server's host key

DawnPatrol never accepts a host key on first use: an unknown or changed key
fails the run for that server, which is what a man-in-the-middle looks like.
Record the key once, from a machine you trust, and compare its fingerprint
with the server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on
the server):

```bash
ssh-keyscan -t ed25519 -p 22 web.example.org >> config/ssh/known_hosts
ssh-keygen -lf config/ssh/known_hosts
chmod 644 config/ssh/known_hosts
```

If the server's host key is ever legitimately replaced (a rebuild), delete
its line from `config/ssh/known_hosts` and repeat this step.

## 5. Configure DawnPatrol

In `.env`:

```bash
DAWNPATROL_SOURCE_SSH_HOSTS=web1          # comma-separated server names; enables the source

DAWNPATROL_SOURCE_SSH_WEB1_HOST=web.example.org
DAWNPATROL_SOURCE_SSH_WEB1_USER=dawnlogs
#DAWNPATROL_SOURCE_SSH_WEB1_PORT=22
DAWNPATROL_SOURCE_SSH_WEB1_KEY_FILE=/etc/dawnpatrol/ssh/web1_ed25519
#DAWNPATROL_SOURCE_SSH_WEB1_KNOWN_HOSTS=/etc/dawnpatrol/ssh/known_hosts
DAWNPATROL_SOURCE_SSH_WEB1_IP=203.0.113.20   # its public address: kept as each request's destination
DAWNPATROL_SOURCE_SSH_WEB1_HTTP_ROOTS=/var/www,/var/log/nginx
#DAWNPATROL_SOURCE_SSH_WEB1_HTTP_PATTERN=*access*.log*
#DAWNPATROL_SOURCE_SSH_WEB1_HTTP_MAX_DEPTH=4
#DAWNPATROL_SOURCE_SSH_WEB1_HTTP_FOLLOW_SYMLINKS=false  # true where live logs are symlinked in (DreamHost)
#DAWNPATROL_SOURCE_SSH_WEB1_JOURNAL=true
#DAWNPATROL_SOURCE_SSH_WEB1_JOURNAL_UNITS=        # e.g. ssh.service,nginx.service; empty = everything
#DAWNPATROL_SOURCE_SSH_WEB1_MAX_LINES=300000      # per journal and per log file
#DAWNPATROL_SOURCE_SSH_WEB1_TIMEOUT=300
```

**How site names are worked out.** Each log file is named after where it sits
under its root:

| Log file | Site |
|---|---|
| `/var/www/shop.example.org/logs/access.log` | `shop.example.org` (first folder under the root) |
| `/var/log/nginx/api.example.org.access.log` | `api.example.org` (file in the root: name minus the access/log suffix) |
| `/var/log/nginx/access.log` | `default` |

Rotated files (`access.log.1`, `access.log.2.gz`) belong to the same site.
Where a host keeps one rotated log under two names (`access.log.0` and
`access.log.2026-11-20`, as DreamHost does), each line is counted once per
folder. Folders the account can't read are named in the run's notes and in
`probe`, so a site that can't be read isn't silently missing.

Some hosts link each site's live logs in from elsewhere. DreamHost, for one:
`~/logs/<site>/https -> /home/_domain_logs/<you>/<site>/https.<id>`. `find`
doesn't follow links by default, so set `HTTP_FOLLOW_SYMLINKS=true` there.
Only files modified during the run's window are read, and each line is kept
only if its own timestamp falls inside the window.

Mount the key folder into the container, read-only, next to the profile:

```bash
-v /home/<you>/docker/dawnpatrol/config/ssh:/etc/dawnpatrol/ssh:ro
```

Then describe the server in `profile.yml`: a `hosts` entry with its public
address, the sites it serves, the addresses you administer it from, and any
monitor or crawler that hits it every few minutes. The model reads this every
run, and it is what lets "admin pages served to 203.0.113.7" read as you
rather than an intruder.

## 6. Test

```bash
docker exec dawnpatrol dawnpatrol probe
```

Each server reports three checks:
- `web1-ssh`: connected, and which groups the account has;
- `web1-journal`: the journal is readable;
- `web1-http-logs`: access logs were found, and which sites they belong to.

Then `dawnpatrol run --dry-run --print` shows the Web block in the statistics,
and any web findings alongside the rest.

## What it looks for

- **SSH logons on the server:** the same checks as for the router's SSH:
  failure bursts, logons from new addresses, and new accounts.
- **Web requests (`http_activity`):**
  - scanners;
  - a sensitive file such as `.env` or `.git` actually served (HIGH);
  - injection attempts, rated higher when one reached the application (2xx/5xx);
  - web-shell-shaped scripts answering from upload folders (HIGH);
  - login brute force, server-error spikes and very large responses;
  - WordPress password sprays across many addresses, and successful logins
    from addresses not in `DAWNPATROL_WEB_TRUSTED_CLIENTS`;
  - fake Googlebots/Bingbots and user-agent rotation;
  - scripts running for the first time (from the second run on);
  - admin pages served, per client.
- **IoC lists:** client addresses, plus user agents and URL markers, are
  checked against your lists. The ARTEX pack's fork user agents and
  web-shell markers such as `k=x9f3c2b7e` are matched in every request.

## Things to know

- Request URLs are stored and can appear in reports. Applications that put
  secrets in query strings (tokens, password-reset links) will have them
  copied into DawnPatrol's database and reports; fix those in the
  application.
- A busy server can produce a lot: the journal and each log file are capped at
  `MAX_LINES` per run, and hitting the cap marks the source DEGRADED rather
  than truncating silently. Raise it, or narrow `JOURNAL_UNITS`.
- Only nginx's default "combined" log format is parsed; lines in other formats
  are counted and skipped.
