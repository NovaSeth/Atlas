# Quickstart: from a blank server to Atlas and Claude on your phone

This guide takes you from "I have a fresh Debian or Ubuntu server and an SSH login" to this:

- Atlas watches the server and tells you by mail when something changes that you did not approve.
- Claude Code runs on the server under your own Claude subscription (Pro or Max), in a session that survives
  closing your SSH window.
- You talk to that session from the Claude app on your phone, and Claude is woken by Atlas within seconds of an
  alarm.

Take it slowly, one step at a time. Every step says what to type, what you should see, and how to check it worked.
Where a step often fails there is an "If something goes wrong" line. Text in `<angle brackets>` is for you to
replace; everything else can be copied as it is. Commands that start with `sudo` ask for your account password the
first time.

Atlas itself needs no AI and no Claude account: steps 1 to 3 give you a working watchdog on their own. Steps 4 to 10
add the AI resident. Background: [README](../README.md), [docs/resident.md](resident.md).

## Before you start

You need:

- **A server**: Debian 12+ or Ubuntu 24.04+ with systemd, 1 vCPU, and at least 4 GB of RAM if you want Claude Code
  on the same machine (Atlas alone runs in 768 MB). You reach it over SSH.
- **sudo**: a login that can run `sudo`. This guide calls that account `ops`; use your own name if you already
  have one, and replace `ops` everywhere below.
- **A Claude Pro or Max account** (claude.ai). Remote Control, the feature that lets your phone talk to the server's
  session, works with these subscriptions, not with an API key. On Team or Enterprise plans an Owner has to
  enable it.
- **The Claude app** on your phone (iOS or Android), signed in to the same account.
- **Access to the Atlas repository**: the repository is public on GitHub; a private fork or mirror needs access (see step 2).
- **A mailbox** for alerts, for example `you@example.com`.

Cost and data, in plain words. Atlas never contacts an AI provider. Claude Code does: while the resident session
runs, the conversation (what Atlas reports, what Claude reads from the server and types) is sent to Anthropic and,
with Remote Control, stored there while the session is connected. The files and the commands stay on your server.
Atlas shows Claude text written by strangers (web paths, user names) only in cleaned form, and Claude reads raw logs
only through a restricted helper, but you should still read the "Threat model" section of
[docs/security.md](security.md) before you attach an AI to a server that holds anything sensitive. Usage counts
against your subscription limits.

## 1. Prepare the server

Log in over SSH as your sudo account and install what Atlas and this guide need:

```bash
sudo apt-get update
sudo apt-get install -y git python3 sudo cron iproute2 curl tmux
```

`tmux` keeps the Claude session alive when you disconnect. Sending mail is set up in step 3, where you choose how alerts reach you.

You should see apt finish without errors. Check:

```bash
python3 --version      # 3.11 or newer
sudo --version | head -1   # 1.9.10 or newer
```

There are two accounts in this setup:

1. **`atlas`**, an unprivileged system account that runs Atlas. The installer creates it in step 3; you do not do
   anything for it.
2. **Your login account (`ops`)**, which runs Claude. If you only have `root` today, create it:

```bash
sudo adduser ops               # asks for a password; the other questions can stay empty
sudo usermod -aG sudo ops      # on Debian/Ubuntu this is the group that may use sudo
```

Then open a new SSH session as `ops` and check `sudo -v` works. Claude runs as `ops`, never as `root`.

If something goes wrong: `Python 3.10` on Ubuntu 22.04 or older means the server is too old for Atlas; use a newer
image. In recipe (a) of step 3, `Unable to locate package bsd-mailx` on Ubuntu: use `mailutils` instead.

## 2. Get Atlas

As `ops`:

```bash
git clone <atlas repository URL> atlas
cd atlas
```

**Private fork or mirror?** The Atlas repository itself is public and clones without credentials. A private copy needs them, and `git clone` fails otherwise. Either sign in with the GitHub CLI
(`sudo apt-get install -y gh`, then `gh auth login` and `gh auth setup-git`), or add an SSH key of this server to
your GitHub account and clone with the SSH address shown on the repository page. Or ask the maintainer for an archive, unpack it, and
`cd` into it; then skip the verification below.

**Verify the release before you run anything as root.** Releases are signed tags; the repository carries the allowed
signers in `.github/allowed_signers`. Replace `<tag>` with the release you want (`git tag --list` shows them):

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag <tag>   # must say: Good "git" signature
git checkout <tag>
```

You should see `Good "git" signature`. If it says anything else, stop and do not install.

## 3. Install Atlas

Look at what the installer would do first. It changes nothing in this mode:

```bash
sudo ./install.sh --dry-run
```

You should see a list of lines starting with `[dry-run]`: create the `atlas` user, copy the code to `/opt/atlas`,
create `/var/lib/atlas`, install the systemd units and a sudoers drop-in that allows only read-only commands. Now
the real run with the defaults (code in `/opt/atlas`, state in `/var/lib/atlas`, user `atlas`):

```bash
sudo ./install.sh --install-cron
```

At the end the installer takes a first snapshot of the machine and asks:

```
Accept this snapshot as the baseline now (atlas.py bless)? [y/N]
```

This question is the heart of Atlas. The *baseline* is "what this server should look like" (packages, users, open
ports, services, SSH keys, cron). From now on every difference from it is reported as drift. Answer `y` only on a
server you have just set up yourself and trust; on a server that might already be compromised the baseline would
bless the compromise. If you answer `n` you can do it later (below).

To keep the first minutes quiet, the installer then does three more things:

- **Your SSH address.** If you run it inside an SSH session it offers to add your client address to
  `known-ips.txt` (it asks `y/N`; with `--yes` it adds it, with a dated comment). Without that, your own login would be
  the first alarm. The address is checked (IPv4 or IPv6 only) before it is written. Outside SSH it prints how to add one.
- **HTTP expectations.** With `--with-apache`, on a fresh state, it records today's first status code of each enabled
  vhost in `http-expected.json` and prints them. Review that file: it holds what the sites answer now, which is not
  necessarily what they should answer. An existing file is never overwritten.
- **A first patrol.** It runs one patrol as the Atlas user, and only then starts the escalation timer, so escalation
  does not mail "patrol missing" before the first heartbeat exists.

Look at what Atlas saw, and accept it if it is right:

```bash
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas python3 /opt/atlas/atlas/atlas.py show
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas python3 /opt/atlas/atlas/atlas.py bless
```

`show` prints the machine's identity and vitals. `bless` stores it as the baseline and mails you a notice with the
user and time (it also needs the mail setup below to be useful). Without a baseline Atlas reports `UNKNOWN`; it never
makes one by itself.

**Tell Atlas how to reach you.** Open the config and set a recipient:

```bash
sudo nano /var/lib/atlas/sentinel.env
```

The file already contains empty `SENTINEL_EMAIL=` and `SENTINEL_AGENT_SUDO_USERS=` lines: **edit those existing
lines** (do not add duplicates). Use your own address, and tell Atlas which account is the AI's, so Claude's routine
`sudo` is not an alarm:

```
SENTINEL_EMAIL=you@example.com
SENTINEL_AGENT_SUDO_USERS=ops
```

The next part sets up how alerts reach you. See [docs/configuration.md](configuration.md) for every key. Then restart the stream and give `ops` read access to Atlas state:

```bash
sudo systemctl restart sentinel-stream.service
sudo usermod -aG atlas ops      # takes effect only at your next SSH login; `exec bash -l` does NOT refresh groups
```

### Make sure alerts reach you

A fresh server usually cannot deliver mail to large providers directly, and an alert nobody receives is worth
nothing. Pick one recipe (about 5 minutes) and finish it with a real test message.

**Recipe (a): mail through an external SMTP relay with msmtp.** You need an account at a mail provider that offers
SMTP, and an **app password** for it (never your main password). Replace the example values:

```bash
sudo apt-get install -y msmtp msmtp-mta bsd-mailx
sudo install -m 0600 -o atlas -g atlas /dev/null /etc/atlas-smtp-pass
sudo nano /etc/atlas-smtp-pass        # the app password on one line, nothing else
sudo nano /etc/msmtprc
sudo chown atlas:atlas /etc/msmtprc && sudo chmod 0600 /etc/msmtprc
```

Put this in `/etc/msmtprc` (host, port, user and addresses are examples):

```
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account relay
host smtp.example.com
port 587
tls_starttls on
user alerts@example.com
from alerts@example.com
passwordeval cat /etc/atlas-smtp-pass

account default : relay
```

Set `SENTINEL_EMAIL=you@example.com` in `sentinel.env`, and test as the Atlas account, which is who sends the alerts:

```bash
echo "Atlas mail test" | sudo -u atlas mail -s "atlas test" you@example.com
```

You should receive the message within a minute or two (check spam). If not, `sudo -u atlas msmtp --debug
you@example.com < /dev/null` shows where the SMTP conversation fails: usually a wrong password, a provider that
needs an app password, or a blocked port 587.

**Recipe (b): phone push with ntfy.** Install the ntfy app on your phone and subscribe to a topic with a long random
name that only you know, for example `atlas-` followed by 24 random letters and digits. The topic name is the
only secret: anyone who knows it can read and send. The notices travel through the public service ntfy.sh (what an
outside service sees is discussed under "Threat model" in [docs/security.md](security.md)); keep subjects and bodies
short. Create `/usr/local/bin/atlas-ntfy` (replace the topic):

```bash
sudo tee /usr/local/bin/atlas-ntfy > /dev/null <<'EOF'
#!/bin/sh
# Atlas calls: atlas-ntfy "<subject>" "<body>"
curl -fsS -m 10 -H "Title: $1" -d "$2" https://ntfy.sh/atlas-REPLACE-WITH-YOUR-RANDOM-TOPIC
EOF
sudo chmod 0755 /usr/local/bin/atlas-ntfy
```

In `sentinel.env` set `SENTINEL_NOTIFY_CMD=/usr/local/bin/atlas-ntfy` (Atlas calls it as `<cmd> "<subject>" "<body>"`).
Test it exactly as Atlas runs it, as the Atlas account:

```bash
sudo -u atlas /usr/local/bin/atlas-ntfy "atlas test" "hello from the server"
echo "exit $?"
```

You should see a JSON reply from ntfy, `exit 0`, and the notification on your phone within seconds. `exit 6` or
`22` means no network or a wrong URL.
Atlas has no separate test command; calling the notify command directly, as the Atlas account, is the test.

You can use both recipes. Whichever you use, a test message must have reached you before you go on.

**After any change to `sentinel.env`, restart the stream.** The escalation timer re-reads the file on every run, but
the real-time stream reads it only when it starts:

```bash
sudo systemctl restart sentinel-stream.service
systemctl is-active sentinel-stream.service    # must print: active
```

**Check that the three watchers are alive:**

```bash
systemctl is-active sentinel-stream.service      # active
systemctl is-active sentinel-escalation.timer    # active
sudo crontab -u atlas -l | grep atlas-managed    # the patrol line, every 30 minutes
```

Run the patrol once by hand and look at its heartbeat. Read the state **as the Atlas account**: `ops` cannot read it
until its next login, and a check that fails for lack of permission must not look like an all-clear:

```bash
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas /opt/atlas/atlas/patrol.sh
sudo -u atlas tail -n 3 /var/lib/atlas/heartbeat.log
sudo -u atlas sh -c 'test -e /var/lib/atlas/ALERT && cat /var/lib/atlas/ALERT || echo "no ALERT file"'
```

A fresh heartbeat line with the current time means the patrol runs. If you did not bless, an `ALERT` saying
`UNKNOWN` is expected.

If something goes wrong: `run as root` means you forgot `sudo`. `missing prerequisite` lines name the package to
install. If `sentinel-stream.service` is not active, `systemctl status --lines=0 sentinel-stream.service` says why.
`Permission denied` reading `/var/lib/atlas` as `ops` means you have not logged in again since `usermod`: log out and
back in over SSH (a new login, not `exec bash -l`) before step 7, then check with `id` that `atlas` is in your groups.

## 4. Install Claude Code

As `ops` (not root, not sudo):

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Open a new shell, or run `exec bash -l`, so the new `PATH` applies, then check:

```bash
claude --version
claude doctor
```

You should see a version number, and `claude doctor` should list no errors. The native install updates itself.
This is Anthropic's installer; see their setup page (code.claude.com/docs/en/setup) for alternatives such as the apt
repository.

If something goes wrong: `claude: command not found` means `~/.local/bin` is not on your `PATH`. Run
`echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc` and then `exec bash -l`. If the installer complains about
memory or the platform, check that the server has 4 GB of RAM and is x64 or ARM64.

## 5. Log in with your subscription

The server has no browser, so Claude Code gives you a link to open on your laptop or phone. Run:

```bash
claude auth login
```

Then:

1. Press `c` to copy the login URL (or select it with the mouse) and open it in a browser **on your own computer or
   phone**.
2. Sign in with the Claude account that has Pro or Max, and approve.
3. The page shows a code. Paste it into the terminal at `Paste code here` and press Enter.
4. You should see `Login successful`.

Check:

```bash
claude auth status --text
echo "exit $?"        # 0 means logged in
```

Do **not** use `claude setup-token` for this: the token it makes cannot start Remote Control sessions.

If something goes wrong: if `ANTHROPIC_API_KEY` is set in your environment, Claude Code may bill the API instead
of using your subscription, and Remote Control will refuse it. Check with `env | grep ANTHROPIC` and run
`unset ANTHROPIC_API_KEY` (remove it from `~/.bashrc` or `~/.profile` too, then log in again). Your credentials are
stored in `~/.claude/.credentials.json`, readable only by you.

## 6. Add the Atlas resident plugin

The plugin gives Claude the Atlas alert procedure and a restricted log reader. The installer copied the plugin
marketplace to `/opt/atlas/agent`; its name is `atlas` and the plugin is `atlas-resident`:

```bash
claude plugin marketplace add /opt/atlas/agent
claude plugin marketplace list
claude plugin install atlas-resident@atlas --scope user
claude plugin list
```

You should see the marketplace `atlas` listed, and `atlas-resident@atlas` in the plugin list as enabled. (Instead of
the local path you can use `owner/repo` of the Atlas repository on GitHub; for a private fork Claude Code uses
the git credentials already on this server and never asks, so `gh auth login` from step 2 must have been done.)

If something goes wrong: `marketplace not found` or a clone error for a private fork `owner/repo` means the server has no
credentials for it; use the local path above. If the plugin does not show in `claude plugin list`, run
`claude plugin marketplace list` and use the exact marketplace name it prints after the `@`.

## 7. Start the resident session with Remote Control

Create a working directory for the session. It must **not** be your home directory itself (Claude Code does not
remember trust for `$HOME`):

```bash
mkdir -p ~/resident && cd ~/resident
```

**First time, interactively**, to answer the one-time questions:

```bash
claude --remote-control "atlas-server"
```

Answer `y` to `Trust <directory>? [y/N]` (if asked) and `y` to `Enable Remote Control? (y/n)`. Then stop the
session with `Ctrl+C` (press it twice if it does not stop). Answer them here, once: inside tmux or a service nobody sees the prompt, and the session would wait forever.

**Now the real session, inside tmux**, so it survives SSH logout:

```bash
tmux new -s claude
cd ~/resident
claude --remote-control "atlas-server"
```

You should see the Claude Code prompt and a line saying Remote Control is active with the session name
`atlas-server`; pressing the spacebar shows a QR code you can scan with your phone.

**First message to the session**, so it listens for Atlas. Paste this (it is the instruction from AGENTS.md):

```text
You are the resident of this host, watched by Atlas (code /opt/atlas, state /var/lib/atlas). Follow
/opt/atlas/AGENTS.md. Now arm your Monitor tool once on this command, with the longest timeout it allows,
and re-arm it when it expires. Never run a polling loop.
SENTINEL_ATLAS=/var/lib/atlas /opt/atlas/sentinel/session-sensor.sh
```

Claude starts the Monitor and replies that it is armed. Claude Code may ask your permission before it uses a tool (for example the Monitor, or reading files under
`/opt/atlas`, outside this directory). Approve at the terminal, or from the phone in the same session. An unanswered
question stalls Claude, though not the alarm path: Atlas still mails you. Silence from then on is normal: the sensor prints a line only
when something changes.

Now detach from tmux without stopping Claude: press `Ctrl+b`, release, then `d`.

If something goes wrong: `Remote Control is not available` or no such option means your plan does not include it
(Pro and Max do; Team and Enterprise need an Owner to switch it on), you are logged in with an API key (see step 5),
or Claude Code is outdated (`claude update`). If you are asked to trust the folder every time, you are in `$HOME`;
`cd ~/resident` first. If the session cannot read Atlas files, you have not logged in again since step 3.

## 8. Talk to it from your phone

1. Open the Claude app, tap **Code**.
2. Find the session named `atlas-server` (it has a computer icon and a green dot) and open it.
3. The same list is in a browser at claude.ai/code.

You should see the conversation from step 7. Try: "What does Atlas see on this server right now?" or "Show me the
Atlas alert state and the last patrol heartbeat." Claude runs `atlas.py show` and reads the state directory for
you. You can ask it to investigate, restart a failed service, or explain an alert. Expect it to ask your approval for risky actions; Atlas's rules for the agent are in [docs/resident.md](resident.md), section 7.

Cloud sessions you may also see in the Code tab are a different thing: they run on Anthropic's machines and cannot
see this server. Open the one with your server's name.

If something goes wrong: no session in the list means the process is not running (reattach with
`tmux attach -t claude`) or it is signed in to another account. A greyed-out session is offline: see step 9.

## 9. Keep it running

- Detach (leave it running): `Ctrl+b`, then `d`. Closing the SSH window does the same.
- Come back: `tmux attach -t claude`.
- The session lives in that one process. If the process or the server stops, the session is gone and does not come
  back by itself. After a reboot, log in and start it again: `tmux new -s claude`, `cd ~/resident`,
  `claude --remote-control "atlas-server"`, and give the first message of step 7 again.
- Some systems end your user processes at logout (`KillUserProcesses=yes` in `/etc/systemd/logind.conf`). Check
  with `grep -i KillUserProcesses /etc/systemd/logind.conf`; the default is `no`.
- While the resident is off on purpose, tell Atlas: `sudo touch /var/lib/atlas/RESIDENT-OFF` (remove the file when it
  is back). Otherwise escalation tells you the resident is dead.
- Atlas cannot see a `tmux` session. With `SENTINEL_RESIDENT_UNIT` and `SENTINEL_RESIDENT_SCREEN` empty (the default)
  it assumes there is no resident and sends every critical event straight to you as well, which is the safe setting.
  The systemd pattern below lets you set `SENTINEL_RESIDENT_UNIT` (see [docs/resident.md](resident.md), section 3).

**Optional: start it at boot with systemd. This is not an official Claude Code feature.** It is a pattern that works
on a reference host, using `screen`. Risk: a service that starts an AI with shell access at boot, with nobody
watching, is a standing privilege; the account's rights are what limits it. Give `ops` narrow sudo rights (see
docs/resident.md), keep Atlas's escalation running, and be ready to stop it.

The installer can do the file work for you: `sudo ./install.sh --resident-user ops --permission-mode default` (the trust
level is required, see below) renders `/etc/atlas/resident.env` and the unit and does not enable it. The manual steps
follow. Atlas ships the pieces: `examples/systemd/atlas-resident.service` (unit template), `examples/resident/resident.env`
(settings) and `examples/resident/start-resident.sh` (checks the network and the logins, then starts the session).
Install them from the checkout of step 2, with the same placeholders the installer fills in:

```bash
sudo apt-get install -y screen
sudo install -d -m 0755 /etc/atlas
sudo install -m 0644 examples/resident/resident.env /etc/atlas/resident.env
sudo nano /etc/atlas/resident.env      # set RESIDENT_PERMISSION_MODE (the trust level, see below), check RESIDENT_DIR, RESIDENT_NAME, RESIDENT_CLAUDE
sed -e "s|@ATLAS_CODE@|/opt/atlas|g" -e "s|@ATLAS_STATE@|/var/lib/atlas|g" -e "s|@RESIDENT_USER@|ops|g" \
  -e "s|@RESIDENT_HOME@|/home/ops|g" \
  examples/systemd/atlas-resident.service | sudo tee /etc/systemd/system/atlas-resident.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now atlas-resident.service
```

`resident.env` is sourced as shell code: it must stay `root:root 0644` (the script refuses otherwise): the human owns the trust level, and the agent account must not be able to raise its own.
**Choose the trust level before the enable line above.** Set `RESIDENT_PERMISSION_MODE` in `/etc/atlas/resident.env` to `default` (asks you before
risky actions, answered from the Claude app), `acceptEdits`, `plan` or `bypassPermissions` (acts without asking; also
needs `--allow-dangerously-skip-permissions` in `RESIDENT_EXTRA_ARGS`). It is empty on purpose: the service refuses to
start until you choose (see [docs/resident.md](resident.md#choose-the-trust-level)). The installer does not set
`SENTINEL_RESIDENT_UNIT` (the unit is not running yet, so Atlas would report the resident dead at once). After
`systemctl enable --now atlas-resident.service` set it in `/var/lib/atlas/sentinel.env`, so Atlas reports the resident
dead when the unit fails:

```bash
sudo sed -i 's|^SENTINEL_RESIDENT_UNIT=.*|SENTINEL_RESIDENT_UNIT=atlas-resident.service|' /var/lib/atlas/sentinel.env
```
 The service sends the first message of step 7 by itself (a generic version). Attach with
`screen -r claude`.

**Test it without a reboot.** Stop your manual session, then:

```bash
sudo systemctl start atlas-resident.service
systemctl is-active atlas-resident.service     # active
screen -ls                                     # as ops: a session named claude
```

The session appears in the Claude app under the name from `RESIDENT_NAME`. If the unit is `failed`, the script says
why in `sudo journalctl -u atlas-resident.service -n 20`: most likely the login is gone (see
[Logins and restarts](resident.md#logins-and-restarts)).

## 10. Test that the alarm path works

Do this once, now, while you are watching. A small package is a harmless change that Atlas treats as drift:

```bash
sudo apt-get install -y cowsay
```

Do not bless anything yet. Wait for the patrol (it runs every 30 minutes), or run it now:

```bash
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas /opt/atlas/atlas/patrol.sh
sudo -u atlas cat /var/lib/atlas/ALERT
```

You should see an `ALERT` file that mentions the package change. Within a minute or two you should also see:

- in the Claude session (look at it from the phone), a line starting `ATLAS ALERT:` and Claude investigating: it finds
  the apt history entry, the package, and your account;
- a mail or notification to you, if the alert stays unacknowledged: escalation mails an unacknowledged alert after 45
  minutes, whatever Claude does.

Because you installed the package, accept it. Tell Claude "I installed cowsay, bless it" or do it yourself:

```bash
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas python3 /opt/atlas/atlas/atlas.py check
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas python3 /opt/atlas/atlas/atlas.py bless
sudo -u atlas env SENTINEL_ATLAS=/var/lib/atlas python3 /opt/atlas/atlas/atlas.py ack
```

`check` shows the difference (exit code 1 = changes). `bless` accepts the new state as baseline. `ack` acknowledges
the current alert content, which stops escalation for that alert. **Both `bless` and `ack` send you a notice with the
user and the time**, so the agent cannot quietly accept a change; if you did not expect one of those mails, treat it
as an incident. Never acknowledge by creating the `ALERT.acked` file by hand: Atlas reports that as unrecorded.

Finally remove the test package, and bless that too: `sudo apt-get remove -y cowsay`, then patrol, `check`, `bless`
as above. Atlas is now tested end to end: detection, the AI woken, the human told.

## Uninstall

Stop and remove the resident first. As `ops`:

```bash
tmux kill-session -t claude                 # or: sudo systemctl disable --now atlas-resident.service
```

Remove the `atlas-resident` plugin and the `atlas` marketplace from the `/plugin` menu inside a Claude Code session
(Anthropic's page: code.claude.com/docs/en/plugins/install), and check with `claude plugin list`. To log out of
Claude on this server, delete its stored login: `rm ~/.claude/.credentials.json`. To end it for good, uninstall
Claude Code the way its setup page describes.

Then remove Atlas. From your `atlas` checkout:

```bash
sudo ./uninstall.sh --dry-run
sudo ./uninstall.sh
```

This removes the units, the sudoers drop-in and the crontab lines. The state directory (`/var/lib/atlas`, baseline
and logs) is kept; add `--purge` to delete it too. The code in `/opt/atlas` and the accounts stay: remove them by
hand (`sudo rm -r /opt/atlas`, `sudo userdel atlas`) if you want. If you created the systemd unit, delete
`/etc/systemd/system/atlas-resident.service`.
