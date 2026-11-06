package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/hostsetup"
)

func portParse(s string) *hostsetup.Error { _, e := parsePortAnswer(s); return e }

func TestPrompterReasksUntilValid(t *testing.T) {
	var out bytes.Buffer
	p := newPrompter(context.Background(), strings.NewReader("abc\n70000\n\r\n"), &out)
	got, err := p.ask("Web UI port", "8080", portParse)
	if err != nil || got != "8080" {
		t.Fatalf("got %q, %v", got, err)
	}
	if strings.Count(out.String(), "Please try again.") != 2 || strings.Count(out.String(), "Web UI port [8080]: ") != 3 {
		t.Fatalf("output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `"abc" is not a port number`) {
		t.Fatalf("the reason was not shown:\n%s", out.String())
	}
}

func TestPrompterEndOfInput(t *testing.T) {
	var out bytes.Buffer
	p := newPrompter(context.Background(), strings.NewReader("abc"), &out)
	if _, err := p.ask("Port", "", portParse); err == nil || err.Code != "QP-INPUT-009" {
		t.Fatalf("EOF after a bad answer: %v", err)
	}
	// Further questions fail the same way instead of hanging.
	if _, err := p.confirm("Again?", true); err == nil || err.Code != "QP-INPUT-009" {
		t.Fatalf("second question after EOF: %v", err)
	}
	p = newPrompter(context.Background(), strings.NewReader("y"), &out)
	if v, err := p.confirm("Last line without a newline?", false); err != nil || !v {
		t.Fatalf("unterminated last line: %v %v", v, err)
	}
}

func TestPrompterGivesUpAfterManyBadAnswers(t *testing.T) {
	var out bytes.Buffer
	p := newPrompter(context.Background(), strings.NewReader(strings.Repeat("nope\n", 50)), &out)
	_, err := p.ask("Port", "", portParse)
	if err == nil || err.Code != "QP-INPUT-004" || strings.Count(out.String(), "Please try again.") != maxAttempts {
		t.Fatalf("err %v after %d tries", err, strings.Count(out.String(), "Please try again."))
	}
	if _, err := newPrompter(context.Background(), strings.NewReader(strings.Repeat("maybe\n", 50)), &out).confirm("Sure?", true); err == nil {
		t.Fatal("endless invalid yes/no accepted")
	}
}

// Ctrl-C while setup waits for an answer ends the question at once, even
// though the read itself is still blocked.
func TestPrompterCtrlC(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	p := newPrompter(ctx, pr, &out)
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := p.ask("Instance name", "default", func(string) *hostsetup.Error { return nil }); err == nil || err.Code != "QP-INT-001" {
		t.Fatalf("Ctrl-C: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("took too long")
	}
}

// The reader only reads when asked, so standard input stays free for an
// installer that asks its own questions between setup's.
func TestPrompterReadsOnlyWhenAsked(t *testing.T) {
	pr, pw := io.Pipe()
	var out bytes.Buffer
	p := newPrompter(context.Background(), pr, &out)
	read := make(chan struct{})
	go func() {
		_, _ = pw.Write([]byte("first\n"))
		close(read)
	}()
	if v, err := p.ask("Q", "", func(string) *hostsetup.Error { return nil }); err != nil || v != "first" {
		t.Fatalf("%q %v", v, err)
	}
	<-read
	written := make(chan struct{})
	go func() {
		_, _ = pw.Write([]byte("second\n")) // blocks until someone reads
		close(written)
	}()
	select {
	case <-written:
		t.Fatal("the prompter read standard input without being asked")
	case <-time.After(200 * time.Millisecond):
	}
	if v, err := p.ask("Q", "", func(string) *hostsetup.Error { return nil }); err != nil || v != "second" {
		t.Fatalf("%q %v", v, err)
	}
	pw.Close()
}

func TestPrompterChooseAndHostileText(t *testing.T) {
	var out bytes.Buffer
	p := newPrompter(context.Background(), strings.NewReader("9\nhifi\n"), &out)
	got, err := p.choose("Pick \x1b]0;evil\x07", []choice{{"minimal", "a"}, {"hifi", "b\x1b[2J"}}, "minimal")
	if err != nil || got != "hifi" {
		t.Fatalf("%q %v", got, err)
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
	p = newPrompter(context.Background(), strings.NewReader("2\n"), &out)
	if got, _ := p.choose("Pick", []choice{{"minimal", "a"}, {"hifi", "b"}}, "minimal"); got != "hifi" {
		t.Fatalf("by number: %q", got)
	}
}

// FuzzPrompter feeds arbitrary keyboard input to a run of questions: it must
// end (answers, a coded error or end of input), never panic, and never echo
// a control character.
func FuzzPrompter(f *testing.F) {
	f.Add([]byte("\n\n\n\n"))
	f.Add([]byte("abc\n8080\ny\n2\n"))
	f.Add([]byte("\x1b[2J\x07\r\n\x00\xff\n"))
	f.Add([]byte(strings.Repeat("x", 9000) + "\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var out bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p := newPrompter(ctx, bytes.NewReader(input), &out)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if _, err := p.ask("Instance name", "default", func(s string) *hostsetup.Error { _, e := parseInstanceAnswer(s); return e }); err != nil {
				return
			}
			if _, err := p.ask("Web UI port", "8080", portParse); err != nil {
				return
			}
			if _, err := p.confirm("Go ahead?", true); err != nil {
				return
			}
			_, _ = p.choose("Pick", []choice{{"a", "x"}, {"b", "y"}}, "a")
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the questions did not end")
		}
		for _, r := range out.String() {
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("control character %U in prompt output", r)
			}
		}
	})
}
