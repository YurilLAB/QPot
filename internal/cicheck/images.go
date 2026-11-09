package cicheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const imageIndexLimit = 512 << 10

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type publishedImageIndex struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		Platform  struct {
			OS           string   `json:"os"`
			Architecture string   `json:"architecture"`
			Variant      string   `json:"variant"`
			OSFeatures   []string `json:"os.features"`
		} `json:"platform"`
	} `json:"manifests"`
}

// CheckImageIndex requires a real OCI/Docker multi-platform index with exactly
// the two generic Linux architectures shipped and tested by the HiFi workflow.
// The release job obtains each index from its exact commit-specific image ref;
// this check never replaces a missing registry image with a source rebuild.
func CheckImageIndex(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > imageIndexLimit {
		return errors.New("published image index must be a regular file no larger than 512 KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open published image index: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, imageIndexLimit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("cannot read published image index")
	}
	return checkImageIndex(data)
}

func checkImageIndex(data []byte) error {
	if len(data) == 0 || len(data) > imageIndexLimit {
		return errors.New("published image index is empty or exceeds 512 KiB")
	}
	// Duplicate JSON keys are ambiguous across consumers. Reject them before
	// interpreting platform and digest metadata; bound nesting independently.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := imageIndexJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("invalid published image index: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("published image index must contain exactly one JSON document")
	}
	root, err := imageIndexObject(data, []string{"schemaVersion", "mediaType", "manifests"})
	if err != nil {
		return err
	}
	var manifests []json.RawMessage
	if err := json.Unmarshal(root["manifests"], &manifests); err != nil || len(manifests) != 2 {
		return errors.New("published image index must contain two manifest descriptors")
	}
	for _, raw := range manifests {
		descriptor, err := imageIndexObject(raw, []string{"mediaType", "digest", "size", "platform"})
		if err != nil {
			return err
		}
		if _, err := imageIndexObject(descriptor["platform"], []string{"os", "architecture"}, "variant", "os.features"); err != nil {
			return err
		}
	}
	var index publishedImageIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return errors.New("published image index has invalid metadata types")
	}
	if index.SchemaVersion != 2 || (index.MediaType != "application/vnd.oci.image.index.v1+json" && index.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json") || len(index.Manifests) != 2 {
		return errors.New("expected an OCI/Docker index with exactly two tested platforms")
	}
	platforms, digests := map[string]bool{}, map[string]bool{}
	for _, descriptor := range index.Manifests {
		p := descriptor.Platform
		if p.OS != "linux" || (p.Architecture != "amd64" && p.Architecture != "arm64") || platforms[p.Architecture] || len(p.OSFeatures) != 0 {
			return errors.New("published image index is missing a generic tested Linux platform")
		}
		if (p.Architecture == "amd64" && p.Variant != "" && p.Variant != "v1") || (p.Architecture == "arm64" && p.Variant != "" && p.Variant != "v8") {
			return errors.New("published image index requires an unsupported CPU variant")
		}
		if (descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" && descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json") || !imageDigestPattern.MatchString(descriptor.Digest) || digests[descriptor.Digest] || descriptor.Size <= 0 || descriptor.Size > 4<<20 {
			return errors.New("published image index has an invalid or duplicate immutable image descriptor")
		}
		platforms[p.Architecture], digests[descriptor.Digest] = true, true
	}
	return nil
}

// OCI field names are case-sensitive. encoding/json's struct matching is not;
// check canonical names before decoding so an alias cannot override metadata.
func imageIndexObject(raw []byte, required []string, optional ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("published image metadata must be a JSON object")
	}
	for _, field := range required {
		if _, present := object[field]; !present {
			return nil, errors.New("published image metadata is missing a canonical field")
		}
	}
	known := append(append([]string{}, required...), optional...)
	for key := range object {
		for _, field := range known {
			if key != field && strings.EqualFold(key, field) {
				return nil, errors.New("published image metadata contains an ambiguous field alias")
			}
		}
	}
	return object, nil
}

func imageIndexJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds 32 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || keys[key] {
				return errors.New("invalid or duplicate JSON object key")
			}
			keys[key] = true
			if err := imageIndexJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := imageIndexJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
