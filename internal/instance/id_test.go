package instance

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateIDFormat(t *testing.T) {
	id, err := GenerateID("testinstance")
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}
	if id == nil {
		t.Fatal("GenerateID returned nil")
	}
	if !strings.HasPrefix(id.ID, QPOT_ID_PREFIX) {
		t.Errorf("ID %q should start with %q", id.ID, QPOT_ID_PREFIX)
	}
	expectedLen := len(QPOT_ID_PREFIX) + ID_LENGTH
	if len(id.ID) != expectedLen {
		t.Errorf("ID length = %d, want %d", len(id.ID), expectedLen)
	}
	if id.Instance != "testinstance" {
		t.Errorf("Instance = %q, want testinstance", id.Instance)
	}
}

func TestGenerateIDIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateID("testinstance")
		if err != nil {
			t.Fatalf("iteration %d: GenerateID failed: %v", i, err)
		}
		if seen[id.ID] {
			t.Errorf("duplicate ID generated: %q", id.ID)
		}
		seen[id.ID] = true
	}
}

func TestGenerateIDOnlyBase32Chars(t *testing.T) {
	validChars := "abcdefghijklmnopqrstuvwxyz234567"
	id, err := GenerateID("testinstance")
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}
	suffix := id.ID[len(QPOT_ID_PREFIX):]
	for _, ch := range suffix {
		if !strings.ContainsRune(validChars, ch) {
			t.Errorf("ID contains invalid base32 character %q", ch)
		}
	}
}

func TestValidateIDAcceptsValid(t *testing.T) {
	id, err := GenerateID("test")
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}
	if !ValidateID(id.ID) {
		t.Errorf("ValidateID rejected a freshly generated ID: %q", id.ID)
	}
}

func TestValidateIDRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"no prefix", "abcdefghijklmnopqrstuvwx"},
		{"wrong prefix", "xx_abcdefghijklmnopqrstuvwx"},
		{"too short", "qp_abc"},
		{"too long", "qp_" + strings.Repeat("a", ID_LENGTH+1)},
		{"invalid char", "qp_abcdefghijklmnopqrstu!"},
		{"uppercase I", "qp_ABCDEFGHIJKLMNOPQRSTU1"},
	}
	for _, tc := range cases {
		if ValidateID(tc.id) {
			t.Errorf("ValidateID(%q) = true, want false (%s)", tc.id, tc.name)
		}
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	// Use a non-existent subdirectory — Save should create it.
	dataPath := dir + "/subdir/deep"
	qid := &QPotID{
		ID:       "qp_abcdefghijklmnopqrstuvwx",
		Instance: "test",
		DataPath: dataPath,
	}
	if err := qid.Save(); err != nil {
		t.Fatalf("Save with non-existent directory failed: %v", err)
	}
	// Verify the file was written into the created directory.
	idPath := dataPath + "/qpot.id"
	data, err := os.ReadFile(idPath)
	if err != nil {
		t.Fatalf("qpot.id file not found after Save: %v", err)
	}
	if string(data) != qid.ID {
		t.Errorf("qpot.id content = %q, want %q", string(data), qid.ID)
	}
}
