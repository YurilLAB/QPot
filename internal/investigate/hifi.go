package investigate

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/qpot/qpot/internal/database"
)

// HiFiOutput reads what a command printed in a HiFi SSH cell. The cell's
// OpenSSH capture is written by the control plane into the cell's record
// folder, outside the database: the stored event names the file, and the
// file is read from there.
//
// The names come from stored events, which a visitor's input shaped. Each is
// checked against the one form the capture writer uses, and the file is
// opened inside the cell's own folder only.
type HiFiOutput struct {
	// Cells is the folder that holds one folder per cell.
	Cells string
	// Slot maps a cell service ("ssh-backend-3", "ssh-backend-3-backup") to
	// its folder name under Cells.
	Slot func(service string) (string, error)
}

var (
	reHiFiCell    = regexp.MustCompile(`^ssh-backend-(?:[1-9]|1[0-6])$`)
	reHiFiUID     = regexp.MustCompile(`^[0-9]{1,10}$`)
	reHiFiStream  = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.(?:out|err)$`)
	reHiFiArchive = regexp.MustCompile(`^archive-g[0-9]{1,20}-[A-Za-z0-9_-]{1,20}$`)
	reHiFiSlot    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Output implements OutputReader.
func (h *HiFiOutput) Output(e *database.Event, stream string) (data []byte, cut, found bool, err error) {
	if h == nil || h.Cells == "" || h.Slot == nil || e == nil {
		return nil, false, false, nil
	}
	md := e.Metadata
	key, ext := "stdout_file", ".out"
	if stream == "stderr" {
		key, ext = "stderr_file", ".err"
	} else if stream != "stdout" {
		return nil, false, false, nil
	}
	name, cell, uid := md[key], md["cell"], md["uid"]
	if !reHiFiStream.MatchString(name) || filepath.Ext(name) != ext || !reHiFiCell.MatchString(cell) || !reHiFiUID.MatchString(uid) {
		return nil, false, false, nil
	}
	service := cell
	switch md["role"] {
	case "", "app":
	case "backup":
		service += "-backup"
	default:
		return nil, false, false, nil // a database cell runs no shell
	}
	slot, err := h.Slot(service)
	if err != nil || !reHiFiSlot.MatchString(slot) {
		return nil, false, false, nil
	}
	root, err := os.OpenRoot(filepath.Join(h.Cells, slot))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, false, nil
		}
		return nil, false, false, err
	}
	defer root.Close()

	// The live folder first, then the closed generations, newest name first.
	places := []string{"current"}
	if entries, err := fs.ReadDir(root.FS(), "."); err == nil {
		var archives []string
		for _, entry := range entries {
			if entry.IsDir() && reHiFiArchive.MatchString(entry.Name()) {
				archives = append(archives, entry.Name()+"/logs")
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(archives)))
		places = append(places, archives...)
	}
	for _, place := range places {
		f, err := root.Open(place + "/uid-" + uid + "/" + name)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			continue
		}
		data, err = io.ReadAll(io.LimitReader(f, MaxOutput+1))
		_ = f.Close()
		if err != nil {
			return nil, false, false, err
		}
		if len(data) > MaxOutput {
			return data[:MaxOutput], true, true, nil
		}
		return data, md["truncated"] == "true", true, nil
	}
	return nil, false, false, nil
}
