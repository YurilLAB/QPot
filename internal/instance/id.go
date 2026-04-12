// Package instance provides QPot ID management
package instance

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	QPOT_ID_PREFIX = "qp_"
	ID_LENGTH      = 24 // After prefix
)

// QPotID represents a unique QPot instance ID
type QPotID struct {
	ID       string `json:"id"`
	Instance string `json:"instance"`
	DataPath string `json:"data_path"`
}

// GenerateID generates a new unique QPot ID with qp_ prefix
func GenerateID(instanceName string) (*QPotID, error) {
	// Generate random bytes
	bytes := make([]byte, 15)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %w", err)
	}

	// Encode to base32 (alphanumeric, URL-safe)
	encoded := base32.StdEncoding.EncodeToString(bytes)
	encoded = strings.ToLower(encoded)
	encoded = strings.ReplaceAll(encoded, "=", "")

	// Ensure it starts with qp_ prefix
	id := QPOT_ID_PREFIX + encoded[:ID_LENGTH]

	return &QPotID{
		ID:       id,
		Instance: instanceName,
	}, nil
}

// LoadID loads the QPot ID from disk
func LoadID(instanceName string) (*QPotID, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	idPath := filepath.Join(homeDir, ".qpot", "instances", instanceName, "qpot.id")
	data, err := os.ReadFile(idPath)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(string(data))
	dataPath := filepath.Join(homeDir, ".qpot", "instances", instanceName)

	return &QPotID{
		ID:       id,
		Instance: instanceName,
		DataPath: dataPath,
	}, nil
}

// Save saves the QPot ID to disk. Creates the DataPath directory if needed.
func (q *QPotID) Save() error {
	if err := os.MkdirAll(q.DataPath, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	idPath := filepath.Join(q.DataPath, "qpot.id")
	return os.WriteFile(idPath, []byte(q.ID), 0600)
}

// String returns the ID string
func (q *QPotID) String() string {
	return q.ID
}

// ValidateID validates a QPot ID format
func ValidateID(id string) bool {
	if !strings.HasPrefix(id, QPOT_ID_PREFIX) {
		return false
	}

	// Check length
	if len(id) != len(QPOT_ID_PREFIX)+ID_LENGTH {
		return false
	}

	// Check valid characters (base32)
	validChars := "abcdefghijklmnopqrstuvwxyz234567"
	for _, ch := range id[len(QPOT_ID_PREFIX):] {
		if !strings.ContainsRune(validChars, ch) {
			return false
		}
	}

	return true
}
