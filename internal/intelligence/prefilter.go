package intelligence

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode/utf8"
)

// catLiterals is a quick test of whether a pattern can match a text at all.
// Every match of the pattern contains one of its literals: an exact one as it
// is, a case-insensitive one (ASCII only) in the lower-cased text. A text
// that holds none of them cannot match, and the pattern is not run on it;
// most commands name none of the tools a given pattern looks for, and a
// strings.Contains is far cheaper than a backtracking regexp.
type catLiterals struct {
	exact, folded []string
}

// may reports whether the pattern can match text; lower is text lower-cased
// with catLower.
func (l *catLiterals) may(text, lower string) bool {
	if l == nil {
		return true
	}
	for _, s := range l.exact {
		if strings.Contains(text, s) {
			return true
		}
	}
	for _, s := range l.folded {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// catLower folds s the way a case-insensitive ASCII literal matches: ASCII
// letters to lower case, and the only non-ASCII runes that fold to an ASCII
// letter, the Kelvin sign (U+212A) and the long s (U+017F), to k and s.
// Every other byte is kept as it is.
func catLower(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' || c >= utf8.RuneSelf {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := make([]byte, i, len(s))
	copy(b, s[:i])
	for i < len(s) {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b = append(b, c)
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\u212a':
			b = append(b, 'k')
		case '\u017f':
			b = append(b, 's')
		default:
			b = append(b, s[i:i+n]...)
		}
		i += n
	}
	return string(b)
}

type literalSet struct {
	exact, folded []string
	ok            bool
}

// score prefers the set whose shortest literal is longest, then the smaller.
func (l literalSet) score() int {
	shortest := 1 << 20
	for _, s := range append(append([]string(nil), l.exact...), l.folded...) {
		shortest = min(shortest, len(s))
	}
	return shortest*1000 - len(l.exact) - len(l.folded)
}

// requiredLiterals returns literals one of which every match of re contains,
// or ok=false when it cannot tell.
func requiredLiterals(re *syntax.Regexp) literalSet {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return literalSet{}
		}
		s := string(re.Rune)
		if re.Flags&syntax.FoldCase == 0 {
			return literalSet{exact: []string{s}, ok: true}
		}
		// Only ASCII folds as catLower folds it: keep the longest ASCII run,
		// which every match also holds.
		run := ""
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r >= utf8.RuneSelf }) {
			if len(part) > len(run) {
				run = part
			}
		}
		if run == "" {
			return literalSet{}
		}
		return literalSet{folded: []string{catLower(run)}, ok: true}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
		return literalSet{}
	case syntax.OpConcat:
		var best literalSet
		for _, sub := range re.Sub {
			if l := requiredLiterals(sub); l.ok && (!best.ok || l.score() > best.score()) {
				best = l
			}
		}
		return best
	case syntax.OpAlternate:
		out := literalSet{ok: true}
		for _, sub := range re.Sub {
			l := requiredLiterals(sub)
			if !l.ok {
				return literalSet{}
			}
			out.exact = append(out.exact, l.exact...)
			out.folded = append(out.folded, l.folded...)
		}
		return out
	default:
		return literalSet{}
	}
}

// catLiteralsOf caches each pattern's literals; nil when it has none.
var catLiteralsOf sync.Map // *regexp.Regexp -> *catLiterals

func literalsOf(re *regexp.Regexp) *catLiterals {
	if v, ok := catLiteralsOf.Load(re); ok {
		return v.(*catLiterals)
	}
	var lit *catLiterals
	if tree, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		if l := requiredLiterals(tree.Simplify()); l.ok {
			lit = &catLiterals{exact: l.exact, folded: l.folded}
		}
	}
	v, _ := catLiteralsOf.LoadOrStore(re, lit)
	return v.(*catLiterals)
}

// catMatch is re.MatchString(text) that skips the regexp when text holds
// none of its literals; lower is catLower(text).
func catMatch(re *regexp.Regexp, text, lower string) bool {
	return literalsOf(re).may(text, lower) && re.MatchString(text)
}
