package cleanup

import (
	"encoding/hex"
	"path"
	"strings"
	"testing"
)

// FuzzDecodeSSHInventory: the helper's inventory names files a HiFi guest
// created, and cleanup removes archives by those names. Whatever the helper
// printed, an inventory is either refused whole or names only paths inside
// the cells' record tree, each once, with sizes no file can lack.
func FuzzDecodeSSHInventory(f *testing.F) {
	name := func(s string) string { return hex.EncodeToString([]byte(s)) }
	f.Add([]byte(name("ssh-backend-1/current/a.json") + " 10 8 " + hex.EncodeToString([]byte("{}\n")) + "\ncomplete\n"))
	f.Add([]byte(name("ssh-backend-1/current/a.json") + " 10 8 -\ncomplete\n"))
	f.Add([]byte(name("../escape") + " 1 1 -\ncomplete\n"))
	f.Add([]byte(name("a//b") + " 1 1 -\ncomplete\n"))
	f.Add([]byte(name("a") + " 1 1 -\n" + name("a") + " 1 1 -\ncomplete\n"))
	f.Add([]byte(name("a") + " -1 99999999999999999999 zz\ncomplete\n"))
	f.Add([]byte(name("a") + " 1 1 -\n"))
	f.Add([]byte("complete\n"))
	f.Fuzz(func(t *testing.T, output []byte) {
		files, err := decodeSSHInventory(output)
		if err != nil {
			if files != nil {
				t.Fatalf("a refused inventory still returned %d files", len(files))
			}
			return
		}
		seen := map[string]bool{}
		for _, file := range files {
			rel := file.rel
			if !strings.HasPrefix(rel, "logs/cells/") || path.Clean(rel) != rel || strings.Contains(rel, "\x00") ||
				strings.HasPrefix(rel, "/") || rel == "logs/cells" {
				t.Fatalf("the inventory names %q", rel)
			}
			for _, part := range strings.Split(rel, "/") {
				if part == ".." || part == "." || part == "" {
					t.Fatalf("the inventory names %q", rel)
				}
			}
			if seen[rel] {
				t.Fatalf("the inventory names %q twice", rel)
			}
			seen[rel] = true
			if file.size < 0 || file.disk < 0 || file.disk%512 != 0 {
				t.Fatalf("%q has size %d and %d bytes on disk", rel, file.size, file.disk)
			}
		}
	})
}

// An empty record file has an empty first line in the helper's inventory and
// is listed; the record tree itself ("."), which the helper never prints, is
// refused (the fuzzer found it accepted).
func TestDecodeSSHInventoryEdges(t *testing.T) {
	name := func(s string) string { return hex.EncodeToString([]byte(s)) }
	files, err := decodeSSHInventory([]byte(name("ssh-backend-1/current/empty.json") + " 0 0 \ncomplete\n"))
	if err != nil || len(files) != 1 || files[0].rel != "logs/cells/ssh-backend-1/current/empty.json" || files[0].hasFP {
		t.Fatalf("an empty record file: %+v, %v", files, err)
	}
	for _, bad := range []string{".", "./a", "a/.", "a/../b", "/a", ""} {
		if files, err := decodeSSHInventory([]byte(name(bad) + " 0 0 -\ncomplete\n")); err == nil {
			t.Errorf("the name %q was accepted: %+v", bad, files)
		}
	}
}
