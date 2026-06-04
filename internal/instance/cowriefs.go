package instance

// cowriefs.go gives each persona's human login users a real home directory in
// Cowrie's fake filesystem (/home/<user> with dotfiles and a populated
// ~/.bash_history).
//
// Why this matters for the mission (keep the attacker engaged so we capture more
// TTP): after identity/credential/honeyfs work, the dominant remaining Cowrie
// tell is that a user you just logged in as has NO home directory - `cd ~` errors
// with "No such file or directory", `ls -la ~` fails, `cat ~/.bash_history` is
// empty. A real account always has a home. That single inconsistency tips off a
// human operator early and they disconnect. Giving the account a believable home
// (standard dotfiles + a history of plausible prior admin activity) makes the box
// look genuinely used, so the attacker keeps exploring.
//
// Mechanism: Cowrie's filesystem STRUCTURE comes from a pickled tree
// (fs.pickle); honeyfs only supplies content for paths already in that tree. The
// stock tree has only /home/debian, so persona users are absent. We therefore
// patch the pickle at container start: a tiny generated Python script
// (cowrieFsPatchScript) loads the image's base pickle, appends a /home/<user>
// node per persona human user - cloning debian's dotfiles and embedding a
// per-user ~/.bash_history directly in the node's content bytes - validates it by
// round-trip, and writes it to the writable tmpfs at /tmp/cowrie/fs.pickle, which
// cowrie.cfg points `filesystem` at. On ANY error it copies the base pickle
// through unchanged, so a patch bug degrades to "no home dirs" rather than ever
// breaking Cowrie's shell. The script runs inside the cowrie image (which has
// Python and the base pickle) right before twistd, so it needs nothing pulled or
// generated on the host.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

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

// cowrieFsPatchScript renders the Python script (run inside the cowrie image at
// container start) that appends the persona home directories to a copy of the
// base fs.pickle. The user list is embedded as base64-encoded JSON so arbitrary
// usernames/history text cannot break the script's syntax (injection-safe), and
// the script copies the base pickle through unchanged on any failure.
func cowrieFsPatchScript(users []homeUser) string {
	type ju struct {
		Name    string `json:"name"`
		UID     int    `json:"uid"`
		History string `json:"history"`
	}
	arr := make([]ju, 0, len(users))
	for _, u := range users {
		arr = append(arr, ju(u)) // identical fields; tags only affect JSON output
	}
	data, _ := json.Marshal(arr)
	enc := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf(`#!/usr/bin/env python3
# QPot: add persona home directories to Cowrie's fake filesystem at startup.
# Generated per instance. On any error the base pickle is passed through unchanged
# so Cowrie's shell always has a valid filesystem to load.
import base64, json, pickle, copy, time, shutil, sys

BASE = "/home/cowrie/cowrie/src/cowrie/data/fs.pickle"
OUT = "/tmp/cowrie/fs.pickle"
USERS = json.loads(base64.b64decode("%s").decode("ascii"))

T_DIR, T_FILE = 1, 2
N, T, U, G, SZ, M, C, CONT, TGT, RF = range(10)


def find(node, parts):
    cur = node
    for p in parts:
        ks = cur[CONT] if len(cur) > CONT and isinstance(cur[CONT], list) else []
        cur = next((c for c in ks if c[N] == p), None)
        if cur is None:
            return None
    return cur


def patch():
    fs = pickle.load(open(BASE, "rb"))
    home = find(fs, ["home"])
    if home is None:
        raise RuntimeError("no /home in base fs")
    debian = find(fs, ["home", "debian"])
    existing = {c[N] for c in home[CONT]}
    now = int(time.time())
    for u in USERS:
        name = u["name"]
        uid = int(u["uid"])
        if not name or name in existing:
            continue
        kids = []
        if debian is not None:
            for c in debian[CONT]:
                nc = copy.deepcopy(c)
                nc[U] = uid
                nc[G] = uid
                kids.append(nc)
        hb = u["history"].encode("utf-8", "replace")
        kids.append([".bash_history", T_FILE, uid, uid, len(hb), 0o100600, now, hb, None, None])
        home[CONT].append([name, T_DIR, uid, uid, 4096, 0o40755, now, kids, None, None])
    data = pickle.dumps(fs, protocol=2)
    pickle.loads(data)  # validate the patched tree round-trips before committing
    with open(OUT, "wb") as f:
        f.write(data)


try:
    patch()
except Exception as e:  # never let a patch bug break Cowrie's filesystem
    sys.stderr.write("qpot fs patch failed, using base pickle: %%r\n" %% (e,))
    shutil.copy(BASE, OUT)
`, enc)
}
