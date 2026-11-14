package instance

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// huntAnswer is what one command of the hunt client answered.
type huntAnswer struct {
	Out    string `json:"out"`
	Status int    `json:"status"`
}

// cowrieHunt runs the commands over one SSH connection to the real image's
// service (patched: with QPot's patch layer over it) and returns their
// answers and the fingerprint of the host key the service presented. The
// image as shipped ends a connection with the first command it is given, so
// there the commands are typed at a login shell and the one answer is what
// the terminal showed.
func cowrieHunt(t *testing.T, patched bool, commands []string) ([]huntAnswer, string) {
	t.Helper()
	name := cowrieStatefulService(t, "hunt/cowrie_hunt_client.go", patched)
	args := []string{"exec", name, "/qpot-stateful-test/ssh-client"}
	want := len(commands)
	if !patched {
		args, want = append(args, "--shell"), 1
	}
	out, err := conpotLiveDocker(2*time.Minute, append(args, commands...)...)
	var got struct {
		HostKey string       `json:"host_key"`
		Answers []huntAnswer `json:"answers"`
	}
	if err != nil || json.Unmarshal([]byte(strings.TrimSpace(out)), &got) != nil || len(got.Answers) != want {
		logs, _ := conpotLiveDocker(10*time.Second, "logs", "--tail", "60", name)
		t.Fatalf("hunt client (patched %v): %v\n%s\n%s", patched, err, out, logs)
	}
	return got.Answers, got.HostKey
}

// TestCowrieStatefulHunt: what someone who has a shell and looks for secrets
// runs answers on the real image as it answers on a Linux server: a recursive
// grep, find with -o, -exec and its tests, xargs grep, source, the shell's
// ${...} operators, sh -c with arguments, cut -c, tar that packs and unpacks,
// ssh-keygen. The host key files are the keys the service presents, and
// /proc/1/cgroup is a systemd host's. The image as shipped is run with a few
// of the same commands and must still show the faults: when it no longer
// does, the patch has nothing left to fix there.
func TestCowrieStatefulHunt(t *testing.T) {
	if os.Getenv("QPOT_TEST_COWRIE_STATEFUL") != "1" {
		t.Skip("set QPOT_TEST_COWRIE_STATEFUL=1 for the actual-image attacker path")
	}
	env := "DB_PASS=s3cret\nAWS_KEY=AKIAEXAMPLE\n"
	steps := []struct {
		command, want string
		status        int
	}{
		{`mkdir -p /srv/app/conf /srv/app/logs && printf 'DB_PASS=s3cret\nAWS_KEY=AKIAEXAMPLE\n' > /srv/app/.env && ` +
			`printf 'x=1\n' > /srv/app/conf/a.conf && printf 'export QQ=42\nPLAIN=7\n' > /srv/app/env.sh; echo made`, "made\n", 0},
		{`grep -rn AKIA /srv/app`, "/srv/app/.env:2:AWS_KEY=AKIAEXAMPLE\n", 0},
		{`grep -rl --include='*.conf' x /srv`, "/srv/app/conf/a.conf\n", 0},
		{`cd /srv/app && grep -r QQ`, "env.sh:export QQ=42\n", 0},
		{`grep -r NOTHERE /srv/app; echo $?`, "1\n", 0},
		{`find /srv/app -type f | xargs grep -l DB_PASS`, "/srv/app/.env\n", 0},
		{`find /srv/app -name '*.conf' -o -name '.env'`, "/srv/app/conf/a.conf\n/srv/app/.env\n", 0},
		{`find /srv/app \( -name '*.sh' -o -name '*.conf' \) -type f -size -2k`, "/srv/app/conf/a.conf\n/srv/app/env.sh\n", 0},
		{`find /srv/app -type f -exec grep -q AKIA {} \; -print`, "/srv/app/.env\n", 0},
		{`find /srv/app -maxdepth 1 -name .env -exec cat {} +`, env, 0},
		{`find /srv/app -name a.conf -exec sh -c 'echo "${1##*/} in ${1%/*}"' _ {} \;`, "a.conf in /srv/app/conf\n", 0},
		{`find /srv/app -bogus`, "find: unknown predicate `-bogus'\n", 1},
		{`. /srv/app/env.sh; echo "QQ=$QQ PLAIN=$PLAIN"`, "QQ=42 PLAIN=7\n", 0},
		{`source /srv/app/env.sh && echo ${QQ:-none} ${NOPE:-none}`, "42 none\n", 0},
		{`F=/srv/app/conf/a.conf; echo ${F##*/} ${F%.*} ${#F} ${F/conf/CONF} "${NOPE:-a b}"`, "a.conf /srv/app/conf/a 20 /srv/app/CONF/a.conf a b\n", 0},
		{`echo ${NOPE:?gone}; echo after`, "bash: line 1: NOPE: gone\n", 127},
		{`sh -c 'echo "$0|$1|$#"' x y z`, "x|y|2\n", 0},
		{`echo abcdefghij | cut -c2-4`, "bcd\n", 0},
		{`tar czf /tmp/k.tgz /srv/app 2>/dev/null; tar tzf /tmp/k.tgz`,
			"srv/app/\nsrv/app/conf/\nsrv/app/conf/a.conf\nsrv/app/logs/\nsrv/app/.env\nsrv/app/env.sh\n", 0},
		{`mkdir /tmp/x && tar xzf /tmp/k.tgz -C /tmp/x && cat /tmp/x/srv/app/.env`, env, 0},
		{`tar czf - /srv/app/conf 2>/dev/null | tar tzf - 2>&1 | head -1; tar cf /tmp/n.tar /nosuch; echo $?`,
			"", 0},
		{`ssh-keygen -q -t ed25519 -N '' -C probe -f /tmp/k && ssh-keygen -lf /tmp/k.pub | cut -d' ' -f1,3,4`, "256 probe (ED25519)\n", 0},
		{`[ "$(ssh-keygen -y -f /tmp/k)" = "$(cat /tmp/k.pub)" ] && head -1 /tmp/k`, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 0},
		{`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1,2,4`, "", 0},
		{`cat /proc/1/cgroup; ls -l /proc/1/cgroup | cut -d' ' -f5`, "0::/init.scope\n0\n", 0},
		// a .env holds plain NAME=value lines: they are the caller's after it is read
		{`cd /srv/app && . ./.env && echo "$DB_PASS ${AWS_KEY:0:4}"`, "s3cret AKIA\n", 0},
		{`echo $((${NOPE:-4} + ${#HOME}))`, "9\n", 0},
	}
	commands := make([]string, len(steps))
	for i, s := range steps {
		commands[i] = s.command
	}
	got, hostKey := cowrieHunt(t, true, commands)
	for i, s := range steps {
		switch i {
		case 20:
			// an archive on the output is the image's to list; packing a file that is not there fails as tar does
			if !strings.HasSuffix(got[i].Out, "tar: /nosuch: Cannot stat: No such file or directory\n"+
				"tar: Exiting with failure status due to previous errors\n2\n") {
				t.Errorf("%s:\n%q", s.command, got[i].Out)
			}
		case 23:
			// the file holds the key the service presented when this client connected
			if got[i].Out != "256 "+hostKey+" (ED25519)\n" || !strings.HasPrefix(hostKey, "SHA256:") {
				t.Errorf("%s: %q, the service presented %s", s.command, got[i].Out, hostKey)
			}
		default:
			if got[i].Out != s.want || got[i].Status != s.status {
				t.Errorf("%s:\n%q (status %d)\nwant\n%q (status %d)", s.command, got[i].Out, got[i].Status, s.want, s.status)
			}
		}
	}

	stock, _ := cowrieHunt(t, false, []string{
		`mkdir -p /srv/app && echo AWS_KEY=AKIAEXAMPLE > /srv/app/.env; grep -rn AKIA /srv/app`,
		`echo ${NOPE:-none}`,
		`echo abcdefghij | cut -c2-4`,
		`find /srv/app -name x -o -name .env`,
		`cat /etc/ssh/ssh_host_ed25519_key.pub | wc -c`,
	})
	// what the terminal showed, without the insert-mode switches the image's line editor writes
	shown := strings.NewReplacer("\x1b[4h", "", "\x1b[4l", "").Replace(stock[0].Out)
	for _, fault := range []string{"\ngrep: /srv/app: Is a directory\n", "syntax error: unexpected end of file\n",
		"\nabcdefghij\n", "\nfind: unknown argument '-o'\n", "\n0\n"} {
		if !strings.Contains(shown, fault) {
			t.Errorf("the image as shipped does not answer %q: it no longer has the fault the patch layer is there for\n%q", fault, shown)
		}
	}
}
