package engagement

import "strings"

// maxParse is how much of an input line is parsed for its stem and for the
// probe test. A longer line is never a probe.
const maxParse = 4096

// maxStem is the longest command stem kept.
const maxStem = 64

// probeKind says whether an input line only looks at the environment.
// The order matters: when several lines share the last timestamp of a session
// the weakest answer wins.
type probeKind uint8

const (
	probeNo          probeKind = iota // does something else
	probeIfNoPayload                  // ls: a probe only in a session without a payload
	probeYes                          // an environment or fingerprint probe
)

// probeAlways are the commands that only report on the host, whatever their
// arguments.
var probeAlways = map[string]bool{
	"uname": true, "nproc": true, "free": true, "lscpu": true, "id": true,
	"whoami": true, "w": true, "ps": true, "dmesg": true, "df": true,
}

// probeBare are probes only without an operand: "mount" lists, "mount /dev/x
// /mnt" acts; "hostname" prints, "hostname x" sets.
var probeBare = map[string]bool{"mount": true, "hostname": true}

// probeFiles are the files whose reading with cat is a probe.
var probeFiles = map[string]bool{
	"/proc/cpuinfo": true, "/proc/version": true, "/proc/meminfo": true,
	"/etc/issue": true, "/etc/os-release": true, "/etc/passwd": true,
}

// probeFilters may follow a probe in a pipeline ("cat /proc/cpuinfo | grep
// name | wc -l") without changing what it is.
var probeFilters = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true, "head": true, "tail": true,
	"wc": true, "awk": true, "cut": true, "sort": true, "uniq": true,
	"tr": true, "sed": true, "cat": true, "more": true, "less": true,
}

// sudoValueFlags are the sudo options followed by a value.
var sudoValueFlags = map[string]bool{
	"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true,
	"-R": true, "-T": true, "-U": true, "-r": true, "-t": true,
}

// stage is one command of a pipeline.
type stage struct {
	words []string
	// writes: output goes to a file, or input comes from a file or a
	// here-document. Redirections to /dev/null and to another descriptor
	// (2>&1) do not count.
	writes bool
	// hidden: the line uses command substitution, so what runs is not what
	// the words say.
	hidden bool
}

// NormalizeCommand is the form two input lines are compared in: surrounding
// white space removed and every run of white space made one space.
func NormalizeCommand(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// Stem is the command name of an input line: the first word of its first
// command after leading VAR=value assignments, sudo and its options, and the
// directory part are removed, in lower case. Bytes outside printable ASCII
// become "?", and it is cut to 64 bytes. A line with no command word gives
// "(none)".
func Stem(line string) string {
	if len(line) > maxParse {
		line = line[:maxParse]
	}
	cmds := parseLine(line)
	if len(cmds) == 0 {
		return "(none)"
	}
	name, _ := commandName(cmds[0][0].words)
	if name == "" {
		return "(none)"
	}
	return name
}

// classifyProbe says whether an input line is an environment or fingerprint
// probe. Every command on the line must be one; in a pipeline the first
// command must be one and the rest must be text filters. A command that
// writes to a file or uses command substitution is not a probe.
func classifyProbe(line string) probeKind {
	if len(line) > maxParse {
		return probeNo
	}
	cmds := parseLine(line)
	if len(cmds) == 0 {
		return probeNo
	}
	kind := probeYes
	for _, pipeline := range cmds {
		for i, st := range pipeline {
			if st.writes || st.hidden {
				return probeNo
			}
			name, args := commandName(st.words)
			if i > 0 {
				if !probeFilters[name] {
					return probeNo
				}
				continue
			}
			k := probeCommand(name, args)
			if k == probeNo {
				return probeNo
			}
			if k < kind {
				kind = k
			}
		}
	}
	return kind
}

// probeCommand classifies one command by its name and arguments.
func probeCommand(name string, args []string) probeKind {
	switch {
	case probeAlways[name]:
		return probeYes
	case probeBare[name]:
		if len(operands(args)) > 0 {
			return probeNo
		}
		return probeYes
	case name == "ls":
		return probeIfNoPayload
	case name == "echo":
		// Printing a literal back ("echo ok", echo -e "\x6F\x6B") tests the
		// shell. An echo into a file was refused before this point.
		return probeYes
	case name == "cat":
		files := operands(args)
		if len(files) == 0 {
			return probeNo
		}
		for _, f := range files {
			if !probeFiles[f] {
				return probeNo
			}
		}
		return probeYes
	case name == "busybox":
		// "busybox" alone lists the applets; "busybox XYZZY" asks for an
		// applet that cannot exist, to see the "applet not found" answer.
		if len(args) == 0 || (len(args) == 1 && isAppletToken(args[0])) {
			return probeYes
		}
		n, a := commandName(args)
		return probeCommand(n, a)
	}
	return probeNo
}

// operands are the arguments that are not options.
func operands(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// isAppletToken reports whether s looks like a made-up applet name: 2 to 32
// upper-case letters and digits with at least one letter.
func isAppletToken(s string) bool {
	if len(s) < 2 || len(s) > 32 {
		return false
	}
	letter := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return letter
}

// commandName skips leading assignments and sudo, and returns the command's
// stem and its arguments.
func commandName(words []string) (string, []string) {
	i := 0
	for i < len(words) {
		w := words[i]
		if isAssignment(w) {
			i++
			continue
		}
		if cleanStem(w) != "sudo" {
			break
		}
		i++
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			if sudoValueFlags[words[i]] {
				i++
			}
			i++
		}
	}
	if i >= len(words) {
		return "", nil
	}
	return cleanStem(words[i]), words[i+1:]
}

// isAssignment reports whether w is a shell VAR=value word.
func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		letter := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// cleanStem drops the directory part of a command word, lower-cases it,
// replaces bytes outside printable ASCII with "?" and cuts it to maxStem.
func cleanStem(w string) string {
	if i := strings.LastIndexByte(w, '/'); i >= 0 && i+1 < len(w) {
		w = w[i+1:]
	}
	if len(w) > maxStem {
		w = w[:maxStem]
	}
	b := []byte(w)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 'a' - 'A'
		case c < 0x21 || c > 0x7e:
			b[i] = '?'
		}
	}
	return string(b)
}

// parseLine splits a shell input line into commands (separated by ";", "&&",
// "||", "&" and newlines), each a pipeline of stages. It follows quotes and
// backslashes well enough to find the command words; it does not expand
// anything.
func parseLine(line string) [][]stage {
	var (
		cmds   [][]stage
		pipe   []stage
		cur    stage
		word   []byte
		inWord bool
	)
	flushWord := func() {
		if inWord {
			cur.words = append(cur.words, string(word))
			word = word[:0]
			inWord = false
		}
	}
	endStage := func() {
		flushWord()
		if len(cur.words) > 0 || cur.writes || cur.hidden {
			pipe = append(pipe, cur)
		}
		cur = stage{}
	}
	endCommand := func() {
		endStage()
		if len(pipe) > 0 {
			cmds = append(cmds, pipe)
		}
		pipe = nil
	}
	next := func(i int) byte {
		if i+1 < len(line) {
			return line[i+1]
		}
		return 0
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			inWord = true
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				word = append(word, line[i+1:]...)
				i = len(line)
			} else {
				word = append(word, line[i+1:i+1+end]...)
				i += end + 1
			}
		case '"':
			inWord = true
			for i++; i < len(line) && line[i] != '"'; i++ {
				d := line[i]
				if d == '\\' && strings.IndexByte("\"\\$`", next(i)) >= 0 && i+1 < len(line) {
					i++
					d = line[i]
				} else if d == '`' || (d == '$' && next(i) == '(') {
					cur.hidden = true
				}
				word = append(word, d)
			}
		case '\\':
			if i+1 < len(line) {
				i++
				inWord = true
				word = append(word, line[i])
			}
		case '`':
			cur.hidden = true
			inWord = true
			word = append(word, c)
		case '$':
			if next(i) == '(' {
				cur.hidden = true
			}
			inWord = true
			word = append(word, c)
		case ' ', '\t', '\r':
			flushWord()
		case '\n', ';':
			endCommand()
		case '&':
			switch next(i) {
			case '&':
				i++
				endCommand()
			case '>':
				flushWord() // "&> file": the redirection is read next
			default:
				endCommand()
			}
		case '|':
			if next(i) == '|' {
				i++
				endCommand()
			} else {
				endStage()
			}
		case '>', '<':
			// A number stuck to the operator is a descriptor, not a word.
			if inWord && allDigits(word) {
				word = word[:0]
				inWord = false
			}
			flushWord()
			if next(i) == c {
				i++
			}
			j := i + 1
			toFD := false
			if j < len(line) && line[j] == '&' {
				toFD = true
				j++
			}
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			k := j
			for k < len(line) && strings.IndexByte(" \t\n;|&<>", line[k]) < 0 {
				k++
			}
			target := line[j:k]
			i = k - 1
			harmless := target == "/dev/null" || (toFD && allDigits([]byte(target)))
			if c == '<' || !harmless {
				cur.writes = true
			}
		default:
			inWord = true
			word = append(word, c)
		}
	}
	endCommand()
	return cmds
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
