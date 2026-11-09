// Package sshbackend initializes and records disposable real-SSH backends.
package sshbackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	// MaxManifestBytes bounds the complete scene passed to the backend.
	MaxManifestBytes = 1 << 20
	maxSceneFiles    = 64
	maxSceneDirs     = 64
	maxFileBytes     = 128 << 10
	maxSceneBytes    = 512 << 10
)

// Manifest describes local files for one role in an isolated organization.
// It never contains destinations the initialization process should contact.
type Manifest struct {
	Version      int         `json:"version"`
	Role         string      `json:"role"`
	Organization string      `json:"organization"`
	Database     Database    `json:"database"`
	Backup       Backup      `json:"backup"`
	Files        []File      `json:"files"`
	Directories  []Directory `json:"directories"`
}

// Database identifies the decoy database referenced by a scene's local files.
type Database struct {
	Host     string `json:"host"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// Backup identifies the decoy backup account referenced by local files.
type Backup struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// File is an ordinary text file to install before any SSH session is admitted.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    uint32 `json:"mode"`
	Owner   string `json:"owner"`
}

// Directory is a local scene directory and its real Unix ownership/mode.
type Directory struct {
	Path  string `json:"path"`
	Mode  uint32 `json:"mode"`
	Owner string `json:"owner"`
}

// DecodeManifest validates the whole input before initialization mutates files.
func DecodeManifest(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return m, errors.New("scene manifest is empty or exceeds the size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("decode scene manifest: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("scene manifest contains trailing data")
	}
	return m, m.Validate()
}

// Validate checks bounded local scene data. Credentials are used only as file
// contents; the bootstrap never interprets them as commands or connection URLs.
func (m Manifest) Validate() error {
	if m.Version != 1 || (m.Role != "app" && m.Role != "backup") {
		return errors.New("unsupported scene version or role")
	}
	if m.Organization == "" || len(m.Organization) > 128 || strings.ContainsAny(m.Organization, "\x00\r\n") {
		return errors.New("invalid scene organization")
	}
	if len(m.Files) > maxSceneFiles || len(m.Directories) > maxSceneDirs {
		return errors.New("scene has too many files or directories")
	}
	seen := make(map[string]bool)
	total := 0
	for _, dir := range m.Directories {
		if err := validatePath(dir.Path, true); err != nil {
			return err
		}
		if seen[dir.Path] || dir.Mode == 0 || dir.Mode&^0o777 != 0 || !accountName(dir.Owner) {
			return fmt.Errorf("invalid or duplicate scene directory %q", dir.Path)
		}
		seen[dir.Path] = true
	}
	filePaths := make(map[string]bool)
	for _, file := range m.Files {
		if err := validatePath(file.Path, false); err != nil {
			return err
		}
		if seen[file.Path] || file.Mode == 0 || file.Mode&^0o777 != 0 || !accountName(file.Owner) || len(file.Content) > maxFileBytes {
			return fmt.Errorf("invalid or duplicate scene file %q", file.Path)
		}
		seen[file.Path] = true
		filePaths[file.Path] = true
		total += len(file.Content)
	}
	if total > maxSceneBytes {
		return errors.New("scene contents exceed the size limit")
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "/"; parent = path.Dir(parent) {
			if filePaths[parent] {
				return fmt.Errorf("scene file %q cannot contain child paths", parent)
			}
		}
	}
	return nil
}

func validatePath(name string, directory bool) error {
	if len(name) > 1024 || name == "" || path.Clean(name) != name || !strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\r\n") {
		return fmt.Errorf("invalid scene path %q", name)
	}
	for _, component := range strings.Split(name, "/") {
		if len(component) > 200 {
			return fmt.Errorf("scene path component is too long")
		}
	}
	allowed := false
	for _, prefix := range []string{"/srv/", "/home/", "/root/", "/opt/", "/usr/local/bin/", "/etc/ssh/ssh_config.d/"} {
		if strings.HasPrefix(name, prefix) || (directory && name == strings.TrimSuffix(prefix, "/")) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("scene path %q is outside scene directories", name)
	}
	return nil
}

func accountName(name string) bool {
	if name == "" || len(name) > 32 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return name[0] != '-'
}
