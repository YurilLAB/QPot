package instance

// cowriefs.go builds each persona login user's home directory in Cowrie's fake
// filesystem - real dotfiles, a populated ~/.bash_history and a believable
// ~/.ssh - and patches the fake-fs pickle at container start so all of it is
// actually SERVED.
//
// Why this matters for the mission (keep the attacker engaged so we capture more
// TTP): after identity/credential/honeyfs work, the dominant remaining Cowrie
// tell is that a user you just logged in as has NO usable home - `cat
// ~/.bash_history` is empty, `ls -la ~` shows nothing, `cd ~` may error. A real
// account always has a populated home. Giving the account a believable home
// (standard dotfiles + a history of plausible prior admin activity + an ~/.ssh
// that corroborates the history) makes the box look genuinely used.
//
// CRITICAL mechanism note (verified against the pinned Cowrie's shell/fs.py):
// Cowrie's file_contents() serves a file's bytes ONLY from the node's A_REALFILE
// field (index 9) or, via init_honeyfs(), from a matching file in the honeyfs
// directory - it NEVER reads content stored inline in the pickle node. So
// content baked into a node's contents field is invisible: `cat` returns empty.
// The previous approach embedded each ~/.bash_history's bytes inline in the
// node, so it was a silent no-op (empty history, while `ls -la` showed a
// non-zero size - itself a contradiction). We therefore write every file to a
// real file on the container's writable tmpfs (/tmp/cowrie/qpotfs/<path>) and
// point the node's realfile at it; we set the realfile ourselves BEFORE Cowrie's
// init_honeyfs runs (which only fills EMPTY realfiles), so our content wins.
//
// Two stock facts the old code got wrong (verified by loading the pinned
// fs.pickle): the base image's only home is /home/phil (NOT /home/debian), so
// the old "clone debian's dotfiles" step silently produced empty homes; and
// /home/phil has no matching entry once QPot rewrites /etc/passwd, so `ls /home`
// showed a user absent from passwd - we remove it.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// embeddedFile is one file the fs-patch script materialises: it writes Content
// to a real file on the container's writable tmpfs and points the fake-fs node's
// realfile at it so `cat`/`head`/`grep` actually return the bytes. Path is
// absolute in the fake filesystem (e.g. "/etc/machine-id" or
// "/home/jmartin/.bash_history"); Mode is the full st_mode int (e.g. 0o100644).
type embeddedFile struct {
	Path    string
	UID     int
	GID     int
	Mode    int
	Content string
}

// homeUser is a persona login account that gets a real /home/<name> in the fake
// filesystem. UID MUST equal the account's uid in the generated /etc/passwd
// (etcPasswd), or `id` and `ls -la ~` ownership disagree - itself a tell.
type homeUser struct {
	Name    string
	UID     int
	History string
}

// cowrieHomeUsers returns the persona's human login users (the accounts that get
// a /home/<name> shell in /etc/passwd) with the SAME uids etcPasswd assigns, plus
// a believable per-user shell history. It mirrors etcPasswd's iteration exactly -
// same skip rules, same uid counter advancing for every included account - so the
// home directories, their ownership and /etc/passwd stay perfectly consistent.
func cowrieHomeUsers(t credentialTemplate, seed string) []homeUser {
	var out []homeUser
	uid := 1000
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		thisUID := uid
		uid++ // advance for EVERY account (service too) to match etcPasswd's uids
		if _, isService := serviceAccounts[name]; isService {
			continue // service accounts are nologin with a system home, no /home/<name>
		}
		out = append(out, homeUser{Name: name, UID: thisUID, History: bashHistoryFor(name, seed)})
	}
	return out
}

// historyBlocks are sequences of plausible prior admin/dev activity. A real
// user's ~/.bash_history is a stream of ordinary operational commands; these read
// like genuine sysadmin work (deploys, log checks, package updates, ssh hops).
// The commands need not be ones Cowrie implements - a history records PAST input,
// it is never executed - so referencing df/top/ssh/etc. is fine and realistic.
// The ssh/scp lines deliberately match the hosts planted in ~/.ssh/known_hosts
// and ~/.ssh/config so the breadcrumbs corroborate one another.
var historyBlocks = [][]string{
	{"ls -la", "cd /var/www", "git status", "git pull", "sudo systemctl restart nginx"},
	{"df -h", "free -m", "sudo apt update", "sudo apt upgrade -y", "sudo reboot"},
	{"tail -n 100 /var/log/syslog", "sudo journalctl -u ssh --no-pager", "netstat -tlnp"},
	{"vim ~/.ssh/config", "ssh deploy@10.0.0.5", "scp backup.tar.gz db01:/srv/backups/"},
	{"docker ps", "docker logs --tail 50 app", "docker compose up -d", "docker image prune -f"},
	{"cd /opt", "wget https://releases.example.net/app-2.4.1.tar.gz", "tar xzf app-2.4.1.tar.gz", "./configure && make -j2"},
	{"crontab -l", "sudo systemctl status cron", "ps aux | grep -v grep | grep python"},
	{"htop", "iostat -x 2 3", "sudo du -sh /var/log/*", "sudo find / -name '*.log' -size +100M"},
}

// bashHistoryFor builds a deterministic-but-varied ~/.bash_history for a user.
// Two differently-salted block picks plus a couple of recent commands give a
// believable, per-user history that differs across users and instances.
func bashHistoryFor(name, seed string) string {
	b1 := historyBlocks[seededIndex("hist1:"+name+":"+seed, len(historyBlocks))]
	b2 := historyBlocks[seededIndex("hist2:"+name+":"+seed, len(historyBlocks))]
	lines := append([]string{}, b1...)
	if &b2[0] != &b1[0] { // include a second, different block
		lines = append(lines, b2...)
	}
	lines = append(lines, "cd ~", "ls", "exit")
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

// --- standard dotfile content (Debian/Ubuntu /etc/skel and root defaults). A
// real account's dotfiles are these near-universal files; an empty ~/.bashrc on
// a box that obviously uses bash is a tell. These are static (they come from
// /etc/skel on a real box, identical across users) on purpose. ---

const skelBashrc = `# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Alias definitions.
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
`

const skelProfile = `# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
`

const skelBashLogout = `# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
`

const rootBashrc = `# ~/.bashrc: executed by bash(1) for non-login shells.

# Note: PS1 and umask are already set in /etc/profile. You should not
# need this unless you want different defaults for root.
# PS1='${debian_chroot:+($debian_chroot)}\h:\w\$ '
# umask 022

# You may uncomment the following lines if you want ` + "`ls'" + ` to be colorized:
# export LS_OPTIONS='--color=auto'
# eval "$(dircolors)"
# alias ls='ls $LS_OPTIONS'
# alias ll='ls $LS_OPTIONS -l'
# alias l='ls $LS_OPTIONS -lA'
#
# Some more alias to avoid making mistakes:
# alias rm='rm -i'
# alias cp='cp -i'
# alias mv='mv -i'
`

const rootProfile = `# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true
`

// sshEd25519Pub returns a valid, per-instance ssh-ed25519 public key line
// ("ssh-ed25519 <base64>") derived deterministically from seed. Real: it is a
// genuine ed25519 key in OpenSSH wire format, so its shape and length are
// correct for authorized_keys / known_hosts.
func sshEd25519Pub(seed string) string {
	h := sha256.Sum256([]byte("ssh-ed25519-key:" + seed))
	pub := ed25519.NewKeyFromSeed(h[:]).Public().(ed25519.PublicKey)
	var buf []byte
	appendStr := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	appendStr([]byte("ssh-ed25519"))
	appendStr(pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(buf)
}

// authorizedKeysFor is the account's ~/.ssh/authorized_keys: the admin key(s)
// this box trusts for that account. A real, valid ed25519 key with a plausible
// comment.
func authorizedKeysFor(user, seed string) string {
	return sshEd25519Pub("authkey:"+user+":"+seed) + " " + user + "@workstation\n"
}

// knownHostsFor is ~/.ssh/known_hosts: the internal hosts this box has SSH'd to,
// matching the hosts referenced in the planted ~/.bash_history and ~/.ssh/config.
// Only internal/private hosts (whose real keys an attacker cannot know) are used,
// so there is no public host key to contradict.
func knownHostsFor(seed string) string {
	return "10.0.0.5 " + sshEd25519Pub("host:10.0.0.5:"+seed) + "\n" +
		"db01,10.0.0.11 " + sshEd25519Pub("host:db01:"+seed) + "\n"
}

// sshClientConfig is ~/.ssh/config: host aliases corroborating the history's ssh
// hops (ssh deploy@10.0.0.5, scp ... db01:...). No IdentityFile references so it
// stays consistent with an ~/.ssh that has no private key (the admin's private
// key lives on their workstation, not on this server - which is why only
// authorized_keys is present).
func sshClientConfig() string {
	return "Host deploy\n    HostName 10.0.0.5\n    User deploy\n\n" +
		"Host db01\n    HostName 10.0.0.11\n    User deploy\n"
}

// cowrieHomeFiles returns every embedded file that makes up the persona's login
// home directories: dotfiles, a populated ~/.bash_history and a believable
// ~/.ssh for each human user, plus /root's equivalents when root is an accepted
// login. UIDs match etcPasswd (via cowrieHomeUsers) so ownership is consistent.
func cowrieHomeFiles(t credentialTemplate, seed string) []embeddedFile {
	var files []embeddedFile
	add := func(home string, uid int, name string) {
		if uid == 0 {
			files = append(files,
				embeddedFile{Path: home + "/.bashrc", UID: uid, GID: uid, Mode: 0o100644, Content: rootBashrc},
				embeddedFile{Path: home + "/.profile", UID: uid, GID: uid, Mode: 0o100644, Content: rootProfile},
			)
		} else {
			files = append(files,
				embeddedFile{Path: home + "/.bashrc", UID: uid, GID: uid, Mode: 0o100644, Content: skelBashrc},
				embeddedFile{Path: home + "/.profile", UID: uid, GID: uid, Mode: 0o100644, Content: skelProfile},
				embeddedFile{Path: home + "/.bash_logout", UID: uid, GID: uid, Mode: 0o100644, Content: skelBashLogout},
			)
		}
		files = append(files,
			embeddedFile{Path: home + "/.bash_history", UID: uid, GID: uid, Mode: 0o100600, Content: bashHistoryFor(name, seed)},
			embeddedFile{Path: home + "/.ssh/authorized_keys", UID: uid, GID: uid, Mode: 0o100600, Content: authorizedKeysFor(name, seed)},
			embeddedFile{Path: home + "/.ssh/known_hosts", UID: uid, GID: uid, Mode: 0o100644, Content: knownHostsFor(seed)},
			embeddedFile{Path: home + "/.ssh/config", UID: uid, GID: uid, Mode: 0o100600, Content: sshClientConfig()},
		)
	}
	for _, hu := range cowrieHomeUsers(t, seed) {
		add("/home/"+hu.Name, hu.UID, hu.Name)
	}
	for _, u := range t.Users {
		if sanitizeConfigValue(u.Username) == "root" {
			add("/root", 0, "root")
			break
		}
	}
	return files
}

// personaHomeNames returns the /home/<name> directories that SHOULD exist on
// this box - the human login users - so the patch can strip any stock home
// (e.g. /home/phil from the base image) that has no matching /etc/passwd entry.
func personaHomeNames(t credentialTemplate, seed string) []string {
	var names []string
	for _, hu := range cowrieHomeUsers(t, seed) {
		names = append(names, hu.Name)
	}
	return names
}

// cowrieFsPatchScript renders the Python script (run inside the cowrie image at
// container start) that (a) removes stock home dirs absent from /etc/passwd,
// and (b) materialises every embedded file - persona home content AND
// per-instance system files - by writing it to the writable tmpfs and pointing
// the fake-fs node's realfile at it (the only content path Cowrie actually
// serves). The payload is base64-encoded JSON so arbitrary content cannot break
// the script's syntax (injection-safe), and the base pickle is copied through
// unchanged on ANY error so Cowrie's shell always loads.
func cowrieFsPatchScript(files []embeddedFile, keepHomes []string) string {
	type jf struct {
		Path    string `json:"path"`
		UID     int    `json:"uid"`
		GID     int    `json:"gid"`
		Mode    int    `json:"mode"`
		Content string `json:"content"`
	}
	arr := make([]jf, 0, len(files))
	for _, f := range files {
		arr = append(arr, jf(f)) // identical fields; the json tags only affect output
	}
	fdata, _ := json.Marshal(arr)
	if keepHomes == nil {
		keepHomes = []string{}
	}
	kdata, _ := json.Marshal(keepHomes)
	fenc := base64.StdEncoding.EncodeToString(fdata)
	kenc := base64.StdEncoding.EncodeToString(kdata)
	return fmt.Sprintf(`#!/usr/bin/env python3
# QPot: build persona home directories and per-instance system files in Cowrie's
# fake filesystem at container start. Content is served via each node's realfile
# pointer (Cowrie's file_contents reads A_REALFILE or the honeyfs dir, NEVER
# inline node content), so every file is written to the writable tmpfs and the
# node points at it. On ANY error the base pickle is copied through unchanged so
# Cowrie's shell always has a valid filesystem to load.
import base64, json, os, pickle, shutil, sys, time

BASE = "/home/cowrie/cowrie/src/cowrie/data/fs.pickle"
OUT = "/tmp/cowrie/fs.pickle"
REALDIR = "/tmp/cowrie/qpotfs"
FILES = json.loads(base64.b64decode("%s").decode("ascii"))
KEEP_HOMES = set(json.loads(base64.b64decode("%s").decode("ascii")))

T_DIR, T_FILE = 1, 2
N, T, U, G, SZ, M, C, CONT, TGT, RF = range(10)
NOW = int(time.time())


def children(node):
    return node[CONT] if len(node) > CONT and isinstance(node[CONT], list) else []


def find_child(node, name):
    for c in children(node):
        if c[N] == name:
            return c
    return None


def ensure_dir(fs, parts, uid, gid):
    cur = fs
    for p in parts:
        nxt = find_child(cur, p)
        if nxt is None:
            nxt = [p, T_DIR, uid, gid, 4096, 0o40755, NOW, [], None, None]
            cur[CONT].append(nxt)
        cur = nxt
    return cur


def put_file(fs, path, uid, gid, mode, content):
    parts = [x for x in path.split("/") if x]
    dirparts, fname = parts[:-1], parts[-1]
    parent = ensure_dir(fs, dirparts, uid, gid)
    # a real ~/.ssh is 0700 and owned by the user
    if dirparts and dirparts[-1] == ".ssh":
        parent[M] = 0o40700
        parent[U] = uid
        parent[G] = gid
    rf = REALDIR + "/" + "/".join(parts)
    os.makedirs(os.path.dirname(rf), exist_ok=True)
    with open(rf, "wb") as fp:
        fp.write(content)
    # /proc files report size 0 in ls -l (they are virtual); everything else
    # reports its real length. file_contents checks A_REALFILE before A_SIZE, so
    # size 0 does not suppress the served content.
    size = 0 if path.startswith("/proc/") else len(content)
    node = [fname, T_FILE, uid, gid, size, mode, NOW, [], None, rf]
    existing = find_child(parent, fname)
    if existing is not None:
        parent[CONT][parent[CONT].index(existing)] = node
    else:
        parent[CONT].append(node)


def patch():
    fs = pickle.load(open(BASE, "rb"))
    # Strip stock home dirs (e.g. /home/phil) that have no /etc/passwd account.
    home = find_child(fs, "home")
    if home is not None and isinstance(home[CONT], list):
        home[CONT][:] = [c for c in home[CONT] if c[N] in KEEP_HOMES]
    for f in FILES:
        put_file(fs, f["path"], int(f["uid"]), int(f["gid"]), int(f["mode"]),
                 f["content"].encode("utf-8", "replace"))
    data = pickle.dumps(fs, protocol=2)
    pickle.loads(data)  # validate the patched tree round-trips before committing
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fp:
        fp.write(data)


try:
    patch()
except Exception as e:  # never let a patch bug break Cowrie's filesystem
    sys.stderr.write("qpot fs patch failed, using base pickle: %%r\n" %% (e,))
    shutil.copy(BASE, OUT)
`, fenc, kenc)
}
