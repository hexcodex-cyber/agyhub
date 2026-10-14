# agyhub

Phone and browser page for [Antigravity CLI](https://antigravity.google/docs/cli/install/) (`agy`). The browser talks only to this process. A chat is one long-running `agy` process. Login is a password plus TOTP.

This repository has no host names, addresses, or site configuration. The steps below are the whole install. They were tested on Ubuntu 24.04 with Python 3.12 and `agy` 1.2.2.

## Requirements

- Linux, x86_64 or aarch64, with systemd. glibc 2.28 or newer. musl systems such as Alpine will not run `agy`.
- Python 3.12, `python3-venv`, and the packages in `requirements.txt` (`aiohttp` 3.14.3).
- `curl` and CA certificates, to install `agy`.
- `chattr` (package `e2fsprogs`) to lock the policy file.
- A Google account. Sign-in is done once in the page after the service is up. Do not copy an OAuth token from another user.

Commands below are run as root, from a checkout of this repository. Package names are Debian and Ubuntu. On another systemd distribution, install the same software under its own names.

## Install

```bash
apt-get update
apt-get install -y python3 python3-venv python3-pip curl ca-certificates e2fsprogs

id agyhub >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/agyhub --shell /usr/sbin/nologin agyhub
passwd -l agyhub

install -d -o root -g root -m 0755 /opt/agyhub
cp -a server.py requirements.txt static deploy /opt/agyhub/
python3 -m venv /opt/agyhub/.venv
/opt/agyhub/.venv/bin/pip install -r /opt/agyhub/requirements.txt
chown -R root:root /opt/agyhub

install -d -o agyhub -g agyhub -m 0700 /var/lib/agyhub /var/lib/agyhub/hub /var/lib/agyhub/work
install -d -o root -g root -m 0755 /var/lib/agyhub/status

sudo -u agyhub -H bash -lc 'curl -fsSL https://antigravity.google/cli/install.sh | bash'
ln -sfn /home/agyhub/.local/bin/agy /usr/local/bin/agy
agy --version

install -d -o agyhub -g agyhub -m 0700 /home/agyhub/.gemini /home/agyhub/.gemini/antigravity-cli
install -m 0644 -o root -g root /opt/agyhub/deploy/antigravity-settings.json /home/agyhub/.gemini/antigravity-cli/settings.json
chattr +i /home/agyhub/.gemini/antigravity-cli/settings.json
```

Create the login secret as the service user. If the environment variable named `AGYHUB_PASSWORD` is set, `setup` uses it and does not prompt. Otherwise it asks twice. The password must be 8 to 256 characters. Unset that variable when `setup` returns. Do not write it into a file in this repository, and do not put it in the systemd unit.

```bash
sudo -u agyhub env AGYHUB_ROOT=/var/lib/agyhub/hub HOME=/home/agyhub \
  /opt/agyhub/.venv/bin/python /opt/agyhub/server.py setup
```

`setup` prints the TOTP secret once. Put it in an authenticator. It is stored only in `/var/lib/agyhub/hub/secrets.json`, mode 600. To replace it, run `setup` again with `--force`.

```bash
install -m 0644 /opt/agyhub/deploy/agyhub.service /etc/systemd/system/agyhub.service
install -m 0644 /opt/agyhub/deploy/agyhub-status.service /etc/systemd/system/agyhub-status.service
install -m 0644 /opt/agyhub/deploy/agyhub-status.timer /etc/systemd/system/agyhub-status.timer
install -m 0755 /opt/agyhub/deploy/agyhub-status /usr/local/sbin/agyhub-status
systemctl daemon-reload
systemctl enable --now agyhub.service agyhub-status.timer
```

The service is up when both of these succeed:

```bash
systemctl is-active agyhub.service
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2432/login
```

The second command prints `200`. Open that URL, log in, and use the page's Google sign-in once. The token is written under `/home/agyhub/.gemini/` for this user only.

## What the unit does

`deploy/agyhub.service` runs as `agyhub`, with no login shell. It binds `127.0.0.1:2432`. This process refuses `0.0.0.0` and `::`. It does not pass `--yolo` (`--dangerously-skip-permissions`). Do not add that flag.

The shipped `agy` policy turns the terminal sandbox off and sets tool permission to `always-proceed`, so `agy` can run commands and edit files as the `agyhub` user. Do not give that user sudo, and do not put SSH private keys or other accounts' secrets in its home. The `read_file` denies in `deploy/antigravity-settings.json` do not stop a shell command: `agyhub` can read any file the operating system allows, including its own `secrets.json` and OAuth token. `chattr +i` stops the service user from replacing the policy file. The status directory is root-owned; `agyhub-status.timer` rewrites `/var/lib/agyhub/status/snapshot.txt` every five minutes, and the policy allows `agy` to read that file.

Workspace for chats and attachments is `/var/lib/agyhub/work`, mode 700.

## Reaching it from another machine

Edit `--bind` in the unit to one address on this host. Then limit that port to the clients that should see it.

For HTTPS, terminate TLS at a reverse proxy and add `--trusted-proxy` set to the address this host sees the proxy connect from. The proxy must send `X-Forwarded-Proto`. `--secure-cookie` marks the cookie Secure on real HTTPS and on that forwarded HTTPS. A direct HTTP client does not get the Secure flag, so the browser keeps the cookie.

## Tests

From a checkout, without root and without a Google account:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_agyhub.py
sh deploy/ready.sh
```

The tests use `tests/fake_agy.py`. `deploy/ready.sh` exits 0 only when no secret file is tracked, no secret-shaped line is in a tracked file, and the `origin` URL has no credentials.
