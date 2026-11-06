package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/qpot/qpot/internal/hostsetup"
)

// maxAnswerLen bounds one typed answer; the rest of a longer line is dropped.
const maxAnswerLen = 4096

// maxAttempts is how many invalid answers a question takes before setup
// gives up on it (a script feeding garbage must not loop for ever).
const maxAttempts = 8

type lineMsg struct {
	s   string
	eof bool
}

// prompter asks questions on a terminal. Every question has a default
// (Enter takes it), every answer is checked, and a wrong answer is asked
// again with the reason. Ctrl-C (the context) and end of input stop it with
// a coded error.
type prompter struct {
	ctx   context.Context
	out   io.Writer
	req   chan<- struct{}
	lines <-chan lineMsg
	eof   bool
}

// newPrompter starts a reader that reads one line of in per request, so it
// never reads standard input while setup is not asking (an installer that
// asks its own questions gets the keyboard to itself), and a blocked read
// cannot hold up Ctrl-C.
func newPrompter(ctx context.Context, in io.Reader, out io.Writer) *prompter {
	req := make(chan struct{})
	ch := make(chan lineMsg, 1)
	go func() {
		r := bufio.NewReaderSize(in, maxAnswerLen)
		for range req {
			line, err := readBoundedLine(r)
			if err != nil && line == "" {
				ch <- lineMsg{eof: true}
				return
			}
			ch <- lineMsg{s: line, eof: err != nil}
		}
	}()
	return &prompter{ctx: ctx, out: out, req: req, lines: ch}
}

// readBoundedLine reads one line, keeping at most maxAnswerLen bytes of it.
func readBoundedLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		frag, isPrefix, err := r.ReadLine()
		if b.Len() < maxAnswerLen {
			rest := maxAnswerLen - b.Len()
			if len(frag) > rest {
				frag = frag[:rest]
			}
			b.Write(frag)
		}
		if err != nil {
			return b.String(), err
		}
		if !isPrefix {
			return strings.TrimRight(b.String(), "\r"), nil
		}
	}
}

func (p *prompter) readLine() (string, *hostsetup.Error) {
	if p.eof {
		return "", hostsetup.E("QP-INPUT-009")
	}
	select {
	case <-p.ctx.Done():
		fmt.Fprintln(p.out)
		return "", hostsetup.E("QP-INT-001")
	case p.req <- struct{}{}:
	}
	select {
	case <-p.ctx.Done():
		fmt.Fprintln(p.out)
		return "", hostsetup.E("QP-INT-001")
	case m := <-p.lines:
		if m.eof {
			p.eof = true
			if m.s == "" {
				fmt.Fprintln(p.out)
				return "", hostsetup.E("QP-INPUT-009")
			}
		}
		return m.s, nil
	}
}

// ask asks a free-text question. parse checks the answer (the default when
// the answer is empty) and returns a coded error whose reason is shown
// before the question is asked again.
func (p *prompter) ask(question, def string, parse func(string) *hostsetup.Error) (string, *hostsetup.Error) {
	for attempt := 1; ; attempt++ {
		if def != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", termSafe(question), termSafe(def))
		} else {
			fmt.Fprintf(p.out, "%s: ", termSafe(question))
		}
		line, err := p.readLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = def
		}
		perr := parse(line)
		if perr == nil {
			return line, nil
		}
		fmt.Fprintf(p.out, "  %s %s\n", termSafe(perr.Cause()), "Please try again.")
		if attempt >= maxAttempts {
			return "", perr.WithFix("Too many answers were not accepted. %s", perr.Entry().Fix)
		}
	}
}

// confirm asks a yes/no question.
func (p *prompter) confirm(question string, def bool) (bool, *hostsetup.Error) {
	hint := "Y/n"
	if !def {
		hint = "y/N"
	}
	for attempt := 1; ; attempt++ {
		fmt.Fprintf(p.out, "%s [%s]: ", termSafe(question), hint)
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		if v, ok := parseYesNo(line, def); ok {
			return v, nil
		}
		fmt.Fprintln(p.out, "  Please answer y (yes) or n (no).")
		if attempt >= maxAttempts {
			return false, hostsetup.E("QP-INPUT-012").WithWhy("The answer to %q was not yes or no.", question)
		}
	}
}

// choice is one option of a numbered menu.
type choice struct {
	key, label string
}

// choose shows a numbered menu; the answer may be the number or the key.
func (p *prompter) choose(question string, opts []choice, def string) (string, *hostsetup.Error) {
	fmt.Fprintln(p.out, termSafe(question))
	for i, o := range opts {
		fmt.Fprintf(p.out, "  %d) %-10s %s\n", i+1, termSafe(o.key), termSafe(o.label))
	}
	var picked string
	_, err := p.ask("Your choice", def, func(s string) *hostsetup.Error {
		s = strings.ToLower(strings.TrimSpace(s))
		for i, o := range opts {
			if s == o.key || s == fmt.Sprint(i+1) {
				picked = o.key
				return nil
			}
		}
		return hostsetup.E("QP-INPUT-012").WithWhy("%q is not one of the choices: type its number or its name.", truncRunes(s, 30))
	})
	return picked, err
}
