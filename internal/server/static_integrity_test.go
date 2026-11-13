package server

import (
	"crypto/sha512"
	"encoding/base64"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

// reIntegrity finds a tag's local resource and the hash the page pins it to.
var reIntegrity = regexp.MustCompile(`<(?:link|script)\b[^>]*?\b(?:href|src)="(/[^"?#]*)(?:\?[^"]*)?"[^>]*?\bintegrity="([^"]*)"`)

// A page pins its stylesheets and scripts to a hash, and the browser refuses
// a file that does not match: a stylesheet edited without its hash leaves
// the page unstyled, with only a console message to say why. Every hash in
// the embedded pages is that of the embedded file it names.
func TestStaticPagesPinTheFilesTheyShip(t *testing.T) {
	checked := 0
	err := fs.WalkDir(staticFS, "static", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(name, ".html") {
			return err
		}
		page, err := staticFS.ReadFile(name)
		if err != nil {
			return err
		}
		for _, m := range reIntegrity.FindAllStringSubmatch(string(page), -1) {
			file, pinned := path.Join("static", m[1]), m[2]
			data, err := staticFS.ReadFile(file)
			if err != nil {
				t.Errorf("%s pins %s, which is not shipped: %v", name, m[1], err)
				continue
			}
			sum := sha512.Sum384(data)
			if want := "sha384-" + base64.StdEncoding.EncodeToString(sum[:]); pinned != want {
				t.Errorf("%s pins %s to %s; the file shipped is %s", name, m[1], pinned, want)
			}
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 5 {
		t.Fatalf("only %d pinned files were found: the pages' tags are no longer read", checked)
	}
}
