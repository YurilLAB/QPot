package intelligence

import (
	"math/rand/v2"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"testing"
)

// kelvin and longS are the two non-ASCII runes that fold to an ASCII letter;
// eAcute and eAcuteUpper fold only to each other.
var (
	kelvin      = string(rune(0x212a))
	longS       = string(rune(0x017f))
	eAcute      = string(rune(0x00e9))
	eAcuteUpper = string(rune(0x00c9))
)

// literalsFunc derives a pattern's literals; the tests swap in broken ones
// to show the checks catch them.
type literalsFunc func(re *regexp.Regexp) *catLiterals

func literalsFrom(derive func(*syntax.Regexp) literalSet) literalsFunc {
	return func(re *regexp.Regexp) *catLiterals {
		tree, err := syntax.Parse(re.String(), syntax.Perl)
		if err != nil {
			return nil
		}
		if l := derive(tree.Simplify()); l.ok {
			return &catLiterals{exact: l.exact, folded: l.folded}
		}
		return nil
	}
}

// unsound returns a text the pattern matches that its literals rule out.
func unsound(re *regexp.Regexp, lits *catLiterals, lower func(string) string, texts []string) (string, bool) {
	for _, s := range texts {
		if re.MatchString(s) && !lits.may(s, lower(s)) {
			return s, true
		}
	}
	return "", false
}

// genRegexp builds a random pattern over a tiny alphabet, so random texts
// match it often.
func genRegexp(r *rand.Rand, depth int) string {
	atoms := []string{"a", "b", "k", "s", "K", "ab", "ks", "sa", "[ab]", "[ks]", ".", `\bk`, "a" + eAcute + "b", eAcute}
	if depth <= 0 || r.IntN(3) == 0 {
		return atoms[r.IntN(len(atoms))]
	}
	sub := func() string { return genRegexp(r, depth-1) }
	switch r.IntN(10) {
	case 0, 1:
		return "(?:" + sub() + sub() + ")"
	case 2:
		return "(?:" + sub() + sub() + sub() + ")"
	case 3, 4:
		return "(?:" + sub() + "|" + sub() + ")"
	case 5:
		return "(?:" + sub() + ")*"
	case 6:
		return "(?:" + sub() + ")+"
	case 7:
		return "(?:" + sub() + ")?"
	case 8:
		return "(?:" + sub() + "){" + []string{"1,2", "0,2", "2"}[r.IntN(3)] + "}"
	default:
		return "(?i:" + sub() + ")"
	}
}

func genText(r *rand.Rand) string {
	runes := []string{"a", "b", "k", "s", "A", "B", "K", "S", kelvin, longS, eAcute, eAcuteUpper, "x", " "}
	var b strings.Builder
	for n := r.IntN(8); n > 0; n-- {
		b.WriteString(runes[r.IntN(len(runes))])
	}
	return b.String()
}

// randomUnsound runs random patterns against random texts and returns the
// first unsound case, with how many patterns had literals and how many
// matches were checked.
func randomUnsound(lits literalsFunc, lower func(string) string) (bad string, withLits, matches int) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 4000; i++ {
		re, err := regexp.Compile(genRegexp(r, 3))
		if err != nil {
			continue
		}
		l := lits(re)
		if l == nil {
			continue
		}
		withLits++
		texts := make([]string, 40)
		for j := range texts {
			texts[j] = genText(r)
		}
		for _, s := range texts {
			if re.MatchString(s) {
				matches++
			}
		}
		if s, ok := unsound(re, l, lower, texts); ok {
			return re.String() + " on " + strings.ToValidUTF8(s, "?"), withLits, matches
		}
	}
	return "", withLits, matches
}

// asciiLower lower-cases ASCII only: the Kelvin sign and the long s stay.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// TestPrefilterRandomPatternsSound checks the literal derivation on random
// patterns: whatever a pattern matches holds one of its literals.
func TestPrefilterRandomPatternsSound(t *testing.T) {
	bad, withLits, matches := randomUnsound(literalsFrom(requiredLiterals), catLower)
	if bad != "" {
		t.Fatalf("unsound literals: %s", bad)
	}
	// The run must not pass by testing nothing.
	if withLits < 1000 || matches < 10000 {
		t.Fatalf("random run too thin: %d patterns with literals, %d matches", withLits, matches)
	}
	t.Logf("%d patterns with literals, %d matches checked", withLits, matches)
}

// TestPrefilterRandomCatchesBrokenLiterals is the negative control: the same
// random run finds the holes in two broken derivations.
func TestPrefilterRandomCatchesBrokenLiterals(t *testing.T) {
	// An optional part is not required: claiming its literals is wrong.
	optionalRequired := func(re *syntax.Regexp) literalSet {
		if (re.Op == syntax.OpStar || re.Op == syntax.OpQuest) && len(re.Sub) == 1 {
			return requiredLiterals(re.Sub[0])
		}
		return requiredLiterals(re)
	}
	if bad, _, _ := randomUnsound(literalsFrom(optionalRequired), catLower); bad == "" {
		t.Error("the random run missed literals taken from an optional part")
	}
	// Folding ASCII only misses the Kelvin sign and the long s.
	if bad, _, _ := randomUnsound(literalsFrom(requiredLiterals), asciiLower); bad == "" {
		t.Error("the random run missed an ASCII-only fold")
	}
	// A case-insensitive literal with a non-ASCII letter is not folded by
	// catLower: keeping the whole literal is wrong.
	wholeFolded := func(re *syntax.Regexp) literalSet {
		if re.Op == syntax.OpLiteral && re.Flags&syntax.FoldCase != 0 {
			return literalSet{folded: []string{strings.ToLower(string(re.Rune))}, ok: true}
		}
		return requiredLiterals(re)
	}
	if bad, _, _ := randomUnsound(literalsFrom(wholeFolded), catLower); bad == "" {
		t.Error("the random run missed a folded non-ASCII literal")
	}
}

func TestRequiredLiterals(t *testing.T) {
	cases := []struct {
		re          string
		exact, fold []string
		none        bool
	}{
		{re: `wget`, exact: []string{"wget"}},
		{re: `(?i)WGET`, fold: []string{"wget"}},
		{re: `(?i)kill`, fold: []string{"kill"}},
		{re: `a?bcd`, exact: []string{"bcd"}},
		{re: `x*`, none: true},
		{re: `(?:curl|wget)\s+http`, exact: []string{"http"}},
		{re: `\b(?:curl|wget)\b`, exact: []string{"curl", "wget"}},
		{re: `curl|[a-z]+`, none: true},
		{re: `(?:ab)+`, exact: []string{"ab"}},
		{re: `(?:ab){0,3}`, none: true},
		{re: `(?i)caf` + "\u00e9", fold: []string{"caf"}},
		{re: `.*`, none: true},
	}
	for _, c := range cases {
		got := literalsOf(regexp.MustCompile(c.re))
		if c.none {
			if got != nil {
				t.Errorf("%s: literals %v %v, want none", c.re, got.exact, got.folded)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: no literals", c.re)
			continue
		}
		if strings.Join(got.exact, ",") != strings.Join(c.exact, ",") || strings.Join(got.folded, ",") != strings.Join(c.fold, ",") {
			t.Errorf("%s: literals %q %q, want %q %q", c.re, got.exact, got.folded, c.exact, c.fold)
		}
	}
}

func TestCatLower(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"plain text":        "plain text",
		"WGET http://X":     "wget http://x",
		kelvin + "ILL -9":   "kill -9",
		"pa" + longS + "wd": "paswd",
		"caf\u00c9 \xff":    "caf\u00c9 \xff",
	} {
		if got := catLower(in); got != want {
			t.Errorf("catLower(%q) = %q, want %q", in, got, want)
		}
	}
	// Already-folded text is returned as it is, without a copy.
	if s := "nothing to fold"; catLower(s) != s {
		t.Error("catLower changed folded text")
	}
}

// prefilterCorpusTexts is every shell and web text of the attack corpus, with
// its case and k/s folds varied.
var prefilterCorpusTexts = sync.OnceValues(func() ([]string, error) {
	files, err := filepath.Glob(filepath.Join("testdata", "attack_corpus", "*.jsonl"))
	if err != nil || len(files) == 0 {
		return nil, err
	}
	var out []string
	for _, f := range files {
		samples, err := catReadCorpus(f)
		if err != nil {
			return nil, err
		}
		for _, s := range samples {
			in := newCatInput(s.event())
			for _, txt := range []string{in.shell, in.web, in.webRaw, in.redis, in.any} {
				if txt == "" {
					continue
				}
				out = append(out, txt, strings.ToUpper(txt),
					strings.ReplaceAll(strings.ReplaceAll(txt, "k", kelvin), "s", longS),
					strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(txt), "K", kelvin), "S", longS))
			}
		}
	}
	return out, nil
})

// prefilteredPatterns is every pattern categorisation runs through the
// prefilter: those the corpus reaches (literalsOf caches each one it is
// asked about) and every exploit pattern.
func prefilteredPatterns(t testing.TB) []*regexp.Regexp {
	texts, err := prefilterCorpusTexts()
	if err != nil || len(texts) == 0 {
		t.Fatalf("corpus texts: %v (%d)", err, len(texts))
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "attack_corpus", "*.jsonl"))
	for _, f := range files {
		samples, err := catReadCorpus(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range samples {
			Categorize(s.event())
		}
	}
	seen := map[*regexp.Regexp]bool{}
	var out []*regexp.Regexp
	catLiteralsOf.Range(func(k, _ any) bool {
		re := k.(*regexp.Regexp)
		seen[re] = true
		out = append(out, re)
		return true
	})
	for _, e := range catExploits {
		if !seen[e.re] {
			out = append(out, e.re)
		}
	}
	return out
}

// TestPrefilterSoundOnCorpus checks every prefiltered pattern against the
// corpus texts and their case and fold variants.
func TestPrefilterSoundOnCorpus(t *testing.T) {
	patterns := prefilteredPatterns(t)
	texts, _ := prefilterCorpusTexts()
	if len(patterns) < 60 {
		t.Fatalf("only %d prefiltered patterns reached", len(patterns))
	}
	matched := 0
	for _, re := range patterns {
		if s, bad := unsound(re, literalsOf(re), catLower, texts); bad {
			t.Errorf("%s: matches %q but its literals rule it out", re, s)
		}
		for _, s := range texts {
			if re.MatchString(s) {
				matched++
				break
			}
		}
	}
	if matched < len(patterns)/2 {
		t.Errorf("only %d of %d patterns match any corpus text", matched, len(patterns))
	}
	// Negative control: the same check catches a literal a pattern does not
	// need.
	wrong := &catLiterals{exact: []string{"never-in-a-command"}}
	if _, bad := unsound(catRecon, wrong, catLower, texts); !bad {
		t.Error("the corpus check missed a wrong literal on catRecon")
	}
}

// FuzzPrefilterSound checks the prefiltered patterns on fuzzed texts.
func FuzzPrefilterSound(f *testing.F) {
	patterns := prefilteredPatterns(f)
	texts, _ := prefilterCorpusTexts()
	for i, s := range texts {
		if i%4 == 0 {
			f.Add(s)
		}
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, txt := range []string{s, strings.ToLower(s)} {
			for _, re := range patterns {
				if re.MatchString(txt) && !literalsOf(re).may(txt, catLower(txt)) {
					t.Fatalf("%s: matches %q but its literals rule it out", re, txt)
				}
			}
		}
	})
}
