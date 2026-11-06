package hostsetup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Docker Desktop's terms, shown before setup installs it. Setup never
// accepts them for the owner: Docker Desktop asks when it first opens.
var desktopLicenceNotes = []string{
	"Docker Desktop has its own licence (the Docker Subscription Service Agreement):",
	"it is free for personal use, education, non-commercial open source and small",
	"businesses (under 250 employees AND under $10 million yearly revenue); larger",
	"organisations need a paid subscription. Docker Desktop shows the agreement the",
	"first time it opens, and you decide there; setup does not accept it for you.",
	"Details: https://www.docker.com/legal/docker-subscription-service-agreement/",
}

func (in *Installer) planMac(need Need) (*Plan, *Error) {
	p := &Plan{Title: "Start Docker Desktop", Method: "Docker Desktop", Desktop: true}
	open := Step{Title: "Open Docker Desktop and wait for it to start (accept its terms there if it asks)", Kind: KindDesktop,
		Cmds:  []Command{{Args: []string{"open", "-a", "Docker"}, Timeout: time.Minute}},
		After: in.waitDesktop}
	switch {
	case need.Engine || need.Upgrade:
		if _, err := in.LookPath("brew"); err != nil {
			return nil, E("QP-DOCKER-008").WithWhy("Homebrew is not installed, so setup cannot install Docker Desktop for you.").
				WithFix("Install Docker Desktop from https://docs.docker.com/desktop/setup/install/mac-install/ , open it once, then run qpot setup again.")
		}
		p.Title = "Install Docker Desktop"
		p.Method = "Homebrew (brew install --cask docker-desktop)"
		args := []string{"brew", "install", "--cask", "docker-desktop"}
		if need.Upgrade && !need.Engine {
			p.Title, args = "Update Docker Desktop", []string{"brew", "upgrade", "--cask", "docker-desktop"}
		}
		p.Notes = append(p.Notes, desktopLicenceNotes...)
		p.Steps = []Step{{Title: p.Title + " (Homebrew may ask for your password)", Kind: KindDesktop,
			Cmds: []Command{{Args: args, Interactive: true, Timeout: 30 * time.Minute}}}, open}
	case need.Compose:
		return nil, E("QP-COMPOSE-001").WithWhy("Docker Desktop includes Compose, but it is missing here.").
			WithFix("Update Docker Desktop (brew upgrade --cask docker-desktop, or its own updater), then run qpot setup again.")
	default:
		p.Steps = []Step{open}
	}
	return p, nil
}

// desktopExe is where Docker Desktop's installer puts it on Windows.
func desktopExe() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Docker", "Docker", "Docker Desktop.exe")
}

func (in *Installer) planWindows(need Need) (*Plan, *Error) {
	p := &Plan{Title: "Start Docker Desktop", Method: "Docker Desktop", Desktop: true}
	switch {
	case need.Engine || need.Upgrade:
		if _, err := in.LookPath("winget"); err != nil {
			return nil, E("QP-DOCKER-008").WithWhy("winget is not available, so setup cannot install Docker Desktop for you.").
				WithFix("Install Docker Desktop from https://docs.docker.com/desktop/setup/install/windows-install/ , open it once, then run qpot setup again.")
		}
		p.Title = "Install Docker Desktop"
		p.Method = "winget (Docker.DockerDesktop)"
		verb := "install"
		if need.Upgrade && !need.Engine {
			p.Title, verb = "Update Docker Desktop", "upgrade"
		}
		p.Notes = append(p.Notes, desktopLicenceNotes...)
		p.Notes = append(p.Notes, "winget shows its own agreement prompts; answer them yourself. Windows may",
			"ask to restart or to install WSL 2 afterwards.")
		p.Steps = []Step{{Title: p.Title, Kind: KindDesktop,
			Cmds: []Command{{Args: []string{"winget", verb, "-e", "--id", "Docker.DockerDesktop"}, Interactive: true, Timeout: 45 * time.Minute}},
			After: func(context.Context) *Error {
				return E("QP-DOCKER-007").WithFix("Restart Windows if the installer asked you to, open Docker Desktop from the Start menu, accept its terms if you agree, wait until it says the engine is running, then run qpot setup again.")
			}}}
	case need.Compose:
		return nil, E("QP-COMPOSE-001").WithWhy("Docker Desktop includes Compose, but it is missing here.").
			WithFix("Update Docker Desktop (winget upgrade -e --id Docker.DockerDesktop, or its own updater), then run qpot setup again.")
	default:
		p.Steps = []Step{{Title: "Open Docker Desktop and wait for it to start (accept its terms there if it asks)", Kind: KindDesktop,
			Cmds:  []Command{{Args: []string{"cmd", "/c", "start", "", desktopExe()}, Timeout: time.Minute}},
			After: in.waitDesktop}}
	}
	return p, nil
}

func (in *Installer) waitDesktop(ctx context.Context) *Error {
	wait := in.DaemonWait
	if wait <= 0 {
		wait = 3 * time.Minute
	}
	in.say("      Waiting up to %s for Docker Desktop to start...", wait.Round(time.Second))
	if _, ok := in.WaitDaemon(ctx, wait); ok {
		return nil
	}
	if ctx.Err() != nil {
		return E("QP-INT-001").Wrap(ctx.Err())
	}
	return E("QP-DOCKER-007")
}

var userNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

// GroupPlan adds the user to the docker group.
func (in *Installer) GroupPlan() (*Plan, *Error) {
	if !userNameRe.MatchString(in.P.User) {
		return nil, E("QP-PERM-004").WithWhy("Setup could not work out a usable name for your user (%q).", truncate(in.P.User, 32)).
			WithFix("Add yourself to the docker group by hand (sudo usermod -aG docker <your user name>), log in again and run qpot setup again.")
	}
	return &Plan{Title: "Let " + in.P.User + " use Docker through the docker group", Root: true,
		Steps: []Step{{Title: "Add " + in.P.User + " to the docker group", Kind: KindGroup,
			Cmds: []Command{{Args: []string{"usermod", "-aG", "docker", in.P.User}, Root: true, Timeout: time.Minute}}}}}, nil
}

// Describe writes the plan with every command exactly as it will run.
func (in *Installer) Describe(w io.Writer, p *Plan) {
	if p.Method == "" {
		fmt.Fprintf(w, "%s:\n\n", p.Title)
	} else {
		fmt.Fprintf(w, "%s, using %s:\n\n", p.Title, p.Method)
	}
	for i, st := range p.Steps {
		fmt.Fprintf(w, "  %d. %s\n", i+1, st.Title)
		for _, l := range st.Info {
			fmt.Fprintf(w, "       %s\n", l)
		}
		if st.Done != nil && st.Done(context.Background()) {
			fmt.Fprintf(w, "       (already done; skipped)\n")
			continue
		}
		if len(st.Show) > 0 {
			for _, l := range st.Show {
				fmt.Fprintf(w, "       $ %s\n", l)
			}
			continue
		}
		for _, c := range st.Cmds {
			fmt.Fprintf(w, "       $ %s\n", ShellJoin(in.R.Argv(c)))
		}
	}
	if len(p.Notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range p.Notes {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}

// EnsureRoot checks that the root commands of a plan can run: as root, or
// through sudo. With a terminal it asks sudo for the password once up front
// (sudo -v); without one it checks that sudo works without a password.
func (in *Installer) EnsureRoot(ctx context.Context, interactive bool) *Error {
	if in.P.EUID == 0 || in.P.GOOS != "linux" {
		return nil
	}
	if _, err := in.LookPath("sudo"); err != nil {
		return E("QP-PERM-001")
	}
	if interactive {
		in.say("Setup needs administrator rights for the commands above; sudo may ask for your password.")
		res := in.R.Run(ctx, Command{Args: []string{"sudo", "-v"}, Interactive: true, Timeout: 5 * time.Minute})
		if res.Canceled {
			return E("QP-INT-001")
		}
		if !res.OK() {
			return E("QP-PERM-003").WithDetails("sudo -v exited with status %d", res.Exit)
		}
		return nil
	}
	res := in.R.Run(ctx, Command{Args: []string{"sudo", "-n", "true"}, Timeout: 30 * time.Second})
	if res.OK() {
		return nil
	}
	if res.Canceled {
		return E("QP-INT-001")
	}
	lower := strings.ToLower(res.Combined())
	if strings.Contains(lower, "password") || strings.Contains(lower, "terminal") || strings.Contains(lower, "tty") {
		return E("QP-PERM-002").WithDetails("%s", LastLines(res.Combined(), 3))
	}
	return E("QP-PERM-003").WithDetails("%s", LastLines(res.Combined(), 3))
}

// Execute runs the plan's steps in order, skipping those already done. It
// stops at the first failure with a coded error.
func (in *Installer) Execute(ctx context.Context, p *Plan) *Error {
	n := len(p.Steps)
	for i, st := range p.Steps {
		if ctx.Err() != nil {
			return E("QP-INT-001").Wrap(ctx.Err())
		}
		if st.Done != nil && st.Done(ctx) {
			in.say("  [%d/%d] %s: already done", i+1, n, st.Title)
			continue
		}
		in.say("  [%d/%d] %s...", i+1, n, st.Title)
		if st.Prepare != nil {
			if err := st.Prepare(ctx); err != nil {
				return err
			}
		}
		cmds := st.Cmds
		if st.Dynamic != nil {
			dc, err := st.Dynamic(ctx)
			if err != nil {
				return err
			}
			cmds = dc
		}
		for _, c := range cmds {
			if c.Root && (st.Kind == KindInstall || st.Kind == KindUpdate || st.Kind == KindRemove) {
				wait := in.LockWait
				if wait <= 0 {
					wait = 2 * time.Minute
				}
				if err := WaitForPackageManager(ctx, in.P, c.Args[0], wait, func(s string) { in.say("        %s", s) }); err != nil {
					return err
				}
			}
			res := in.R.Run(ctx, c)
			if !res.OK() {
				if res.Canceled || ctx.Err() != nil {
					return E("QP-INT-001").WithWhy("Setup was stopped while it ran: %s", ShellJoin(in.R.Argv(c))).
						WithFix("Run qpot setup again; it checks what is already done. If it reports an interrupted installation, run: sudo dpkg --configure -a")
				}
				return ClassifyFailure(st.Kind, ShellJoin(in.R.Argv(c)), res)
			}
		}
		if st.After != nil {
			if err := st.After(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}
