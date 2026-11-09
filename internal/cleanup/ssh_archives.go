package cleanup

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/vectorstate"
)

// Bound metadata work even if an attacker generated a large directory tree.
const maxSSHArchiveEntries = 8192

type sshArchive struct {
	service, name, rel string
	created            time.Time
}

func sshArchiveName(name string) bool {
	tail, ok := strings.CutPrefix(name, "archive-g")
	if !ok {
		return false
	}
	generation, nonce, ok := strings.Cut(tail, "-")
	if !ok || generation == "" || nonce == "" {
		return false
	}
	for _, part := range []string{generation, nonce} {
		if len(part) > 20 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// Only the trusted archive parent timestamp determines retention. A prior
// visitor could forge file timestamps, but never mounts this archive parent.
func expiredSSHArchives(ctx context.Context, root *os.Root, cutoff time.Time, dataPaths ...string) []sshArchive {
	info, err := root.Lstat("logs/cells")
	if err != nil || !info.IsDir() {
		return nil
	}
	cells, err := root.OpenRoot("logs/cells")
	if err != nil {
		return nil
	}
	defer cells.Close()
	type cellScan struct {
		service, leaf string
		directory     *os.File
	}
	services := instance.SSHCellLogServices()
	scans := make([]cellScan, 0, len(services))
	// Hold each finite cell's read position through all turns. Every handle
	// closes on return before pruning, including early errors/cancellation.
	for _, service := range services {
		if ctx.Err() != nil {
			break
		}
		leaf := service
		if len(dataPaths) > 0 {
			leaf, err = instance.SSHRuntimeCellID(dataPaths[0], service)
			if err != nil {
				return nil
			}
		}
		info, err := cells.Lstat(leaf)
		if err != nil || !info.IsDir() {
			continue
		}
		directory, err := cells.Open(leaf)
		if err != nil {
			continue
		}
		defer directory.Close()
		scans = append(scans, cellScan{service, leaf, directory})
	}
	budget := maxSSHArchiveEntries
	turn := max(1, maxSSHArchiveEntries/len(services))
	var archives []sshArchive
	// A first turn for every cell preserves cross-cell fairness. Later turns
	// reuse the remaining global budget rather than repeatedly starving an
	// acknowledged archive behind a retained prefix in a single busy cell.
	for len(scans) > 0 && ctx.Err() == nil && budget > 0 {
		active := scans[:0]
		for _, scan := range scans {
			if ctx.Err() != nil || budget <= 0 {
				break
			}
			entries, readErr := scan.directory.ReadDir(min(budget, turn, 256))
			budget -= len(entries) // includes current and unknown entries too
			for _, entry := range entries {
				if !entry.IsDir() || !sshArchiveName(entry.Name()) {
					continue
				}
				info, err := entry.Info()
				if err == nil && info.IsDir() && info.ModTime().Before(cutoff) {
					archives = append(archives, sshArchive{scan.service, entry.Name(), path.Join("logs/cells", scan.leaf, entry.Name()), info.ModTime()})
				}
			}
			if readErr == nil && len(entries) > 0 {
				active = append(active, scan)
			}
		}
		scans = active
	}
	return archives
}

// removeSSHArchive removes only closed, expired evidence. Unlike active logs,
// it is safe to remove symlinks themselves and private UID directories. All
// path resolution is inside one archive, and every operation checks a bound.
func removeSSHArchive(ctx context.Context, root *os.Root, rel string, budget *int, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if *budget <= 0 || depth > maxDepth {
		return errors.New("SSH archive cleanup work limit reached")
	}
	*budget--
	info, err := root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return root.Remove(rel) // includes a symlink itself, never its target
	}
	// An empty private UID directory can be removed without listing its contents.
	if err := root.Remove(rel); err == nil {
		return nil
	}
	directory, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		if *budget <= 0 {
			return errors.New("SSH archive cleanup work limit reached")
		}
		entries, readErr := directory.ReadDir(min(*budget, 256))
		for _, entry := range entries {
			if err := removeSSHArchive(ctx, root, path.Join(rel, entry.Name()), budget, depth+1); err != nil {
				return err
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return readErr
			}
			break
		}
		if *budget <= 0 {
			return errors.New("SSH archive cleanup work limit reached")
		}
	}
	return root.Remove(rel)
}

func pruneSSHArchives(ctx context.Context, rep *Report, area *Area, root *os.Root, dir string, archives []sshArchive, opt Options, delivered ...vectorstate.Delivered) {
	if len(archives) == 0 {
		return
	}
	waiting := 0
	defer func() {
		if waiting > 0 {
			rep.note("%d SSH closed archives retained until their JSON logs have complete unambiguous delivery checkpoints.", waiting)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var got vectorstate.Delivered
	if len(delivered) == 1 {
		got = delivered[0]
	}
	inventory, scanErr := readSSHInventory(ctx, root, dir, opt.Helper)
	if scanErr != nil {
		rep.note("SSH closed archives retained: delivery inventory unavailable (%v).", scanErr)
		return
	}
	shared := map[uint64]int{}
	for _, entry := range inventory {
		if entry.hasFP {
			shared[entry.fp]++
		}
	}
	budgets := map[string]int{}
	for _, archive := range archives {
		if ctx.Err() != nil {
			break
		}
		budget, seen := budgets[archive.service]
		if !seen {
			budget = maxSSHArchiveEntries / len(instance.SSHCellLogServices())
		}
		if budget <= 0 {
			continue
		}
		if !sshArchiveDelivered(archive, inventory, shared, got) {
			waiting++
			continue
		}
		// Delivery eligibility was bounded by the complete inventory above.
		// Retained, unacknowledged headers must not consume deletion work and
		// permanently hide a later eligible archive in the same cell.
		budget-- // include each authorized archive/header/helper attempt
		budgets[archive.service] = budget
		var freed int64
		for _, entry := range inventory {
			if strings.HasPrefix(entry.rel, archive.rel+"/") {
				freed += entry.disk
			}
		}
		if opt.DryRun {
			area.Removed++
			area.Freed += freed
			area.Bytes = max(0, area.Bytes-freed)
			continue
		}
		info, err := root.Lstat(archive.rel)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || !info.ModTime().Equal(archive.created) {
			continue
		}
		archived, err := root.OpenRoot(archive.rel)
		if err == nil {
			err = removeSSHArchive(ctx, archived, "logs", &budget, 0)
			_ = archived.Close()
		}
		budgets[archive.service] = budget
		if err != nil && opt.Helper != nil && ctx.Err() == nil {
			// Mount only this immutable archive, never a current guest log tree.
			err = opt.Helper.Remove(ctx, filepath.Join(dir, filepath.FromSlash(archive.rel)), []string{"logs"})
		}
		if err == nil {
			err = root.Remove(archive.rel)
		}
		if err != nil {
			rep.fail(err)
			continue
		}
		area.Removed++
		area.Freed += freed
		area.Bytes = max(0, area.Bytes-freed)
	}
}

// isSSHArchiveFile protects every syntactically trusted closed tree, including
// fresh archives and archives with forged file timestamps, from generic prune.
func isSSHArchiveFile(rel string) bool {
	parts := strings.SplitN(rel, "/", 5)
	return len(parts) == 5 && parts[0] == "logs" && parts[1] == "cells" && sshArchiveName(parts[3])
}

type sshEvidenceFile struct {
	rel        string
	size, disk int64
	fp         uint64
	hasFP      bool
}

// sshInventoryHelper is optional so existing helper implementations remain
// compatible. The summary covers all cells to reject fingerprint collisions
// with another closed or active log. Incomplete inventories never authorize
// evidence deletion.
type sshInventoryHelper interface {
	SSHInventory(context.Context, string) ([]sshEvidenceFile, error)
}

func readSSHInventory(ctx context.Context, root *os.Root, dir string, helper Helper) ([]sshEvidenceFile, error) {
	var files []sshEvidenceFile
	budget := maxSSHArchiveEntries
	var visit func(string, int) error
	visit = func(rel string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxDepth || budget <= 0 {
			return errors.New("SSH evidence inventory work limit reached")
		}
		budget--
		info, err := root.Lstat(rel)
		if errors.Is(err, fs.ErrNotExist) && rel == "logs/cells" {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.IsDir() {
			d, err := root.Open(rel)
			if err != nil {
				return err
			}
			defer d.Close()
			for {
				entries, err := d.ReadDir(min(max(budget, 1), 256))
				for _, entry := range entries {
					if err := visit(path.Join(rel, entry.Name()), depth+1); err != nil {
						return err
					}
				}
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					return err
				}
			}
		}
		if !info.Mode().IsRegular() || !singleEvidenceLink(root, rel, info) {
			return errors.New("SSH evidence contains an unsupported object or hard link")
		}
		entry := sshEvidenceFile{rel: rel, size: info.Size(), disk: onDisk(info)}
		if strings.HasSuffix(rel, ".json") {
			f, err := root.OpenFile(rel, os.O_RDONLY|noFollow|evidenceNonBlock, 0)
			if err != nil {
				return err
			}
			actual, err := f.Stat()
			if err != nil || !actual.Mode().IsRegular() || !os.SameFile(info, actual) || actual.Size() != info.Size() || !actual.ModTime().Equal(info.ModTime()) {
				f.Close()
				return errors.New("SSH evidence changed during inventory")
			}
			entry.fp, entry.hasFP = vectorstate.Fingerprint(f)
			after, statErr := f.Stat()
			f.Close()
			if statErr != nil || after.Size() != actual.Size() || !after.ModTime().Equal(actual.ModTime()) {
				return errors.New("SSH evidence changed during inventory")
			}
		}
		files = append(files, entry)
		return nil
	}
	err := visit("logs/cells", 0)
	if err == nil {
		return files, nil
	}
	if h, ok := helper.(sshInventoryHelper); ok {
		return h.SSHInventory(ctx, filepath.Join(dir, "logs", "cells"))
	}
	return nil, err
}

func sshArchiveDelivered(archive sshArchive, files []sshEvidenceFile, shared map[uint64]int, got vectorstate.Delivered) bool {
	jsonLogs, captures := 0, false
	for _, entry := range files {
		if !strings.HasPrefix(entry.rel, archive.rel+"/") {
			continue
		}
		if !strings.HasSuffix(entry.rel, ".json") {
			captures = captures || entry.size > 0
			continue
		}
		if entry.size == 0 {
			continue
		}
		jsonLogs++
		if !entry.hasFP || shared[entry.fp] != 1 {
			return false
		}
		if position, ok := got[entry.fp]; !ok || position < entry.size {
			return false
		}
	}
	return jsonLogs > 0 || !captures
}

func decodeSSHInventory(output []byte) ([]sshEvidenceFile, error) {
	lines := bytes.Split(bytes.TrimSuffix(output, []byte("\n")), []byte("\n"))
	if len(lines) == 0 || string(lines[len(lines)-1]) != "complete" {
		return nil, errors.New("incomplete SSH evidence helper inventory")
	}
	if len(lines) > maxSSHArchiveEntries+1 {
		return nil, errors.New("SSH evidence helper entry limit reached")
	}
	files := make([]sshEvidenceFile, 0, len(lines)-1)
	seen := map[string]bool{}
	for _, line := range lines[:len(lines)-1] {
		fields := bytes.Split(line, []byte(" "))
		if len(fields) != 4 {
			return nil, errors.New("invalid SSH evidence inventory record")
		}
		name, err := hex.DecodeString(string(fields[0]))
		if err != nil {
			return nil, err
		}
		rel := string(name)
		if !filepath.IsLocal(filepath.FromSlash(rel)) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel))) != rel || strings.ContainsRune(rel, 0) || seen[rel] {
			return nil, errors.New("invalid SSH evidence inventory path")
		}
		seen[rel] = true
		size, err := strconv.ParseInt(string(fields[1]), 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("invalid SSH evidence size")
		}
		blocks, err := strconv.ParseInt(string(fields[2]), 10, 64)
		if err != nil || blocks < 0 || blocks > (1<<63-1)/512 {
			return nil, errors.New("invalid SSH evidence blocks")
		}
		entry := sshEvidenceFile{rel: path.Join("logs/cells", rel), size: size, disk: blocks * 512}
		if string(fields[3]) != "-" {
			first, err := hex.DecodeString(string(fields[3]))
			if err != nil || len(first) > vectorstate.MaxLine+1 {
				return nil, fmt.Errorf("invalid SSH evidence first line")
			}
			entry.fp, entry.hasFP = vectorstate.Fingerprint(bytes.NewReader(first))
		}
		files = append(files, entry)
	}
	return files, nil
}
