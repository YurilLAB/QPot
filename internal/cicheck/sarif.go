package cicheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CodeQLSummary describes the reports accepted by the release security gate.
type CodeQLSummary struct {
	Reports  int
	Rules    int
	Results  int
	Reviewed int
}

type codeQLDocument struct {
	Version string      `json:"version"`
	Runs    []codeQLRun `json:"runs"`
}

type codeQLRun struct {
	Tool struct {
		Driver     codeQLComponent   `json:"driver"`
		Extensions []codeQLComponent `json:"extensions"`
	} `json:"tool"`
	Invocations []codeQLInvocation `json:"invocations"`
	Results     *[]json.RawMessage `json:"results"`
	Artifacts   []struct {
		Location map[string]json.RawMessage `json:"location"`
	} `json:"artifacts"`
}

type codeQLInvocation struct {
	ExecutionSuccessful            *bool           `json:"executionSuccessful"`
	ExitCode                       json.RawMessage `json:"exitCode"`
	ToolExecutionNotifications     json.RawMessage `json:"toolExecutionNotifications"`
	ToolConfigurationNotifications json.RawMessage `json:"toolConfigurationNotifications"`
}

type codeQLNotification struct {
	Level      *string `json:"level"`
	Descriptor struct {
		ID string `json:"id"`
	} `json:"descriptor"`
}

type codeQLComponent struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	SemanticVersion string       `json:"semanticVersion"`
	Rules           []codeQLRule `json:"rules"`
}

type codeQLRule struct {
	ID                   string `json:"id"`
	DefaultConfiguration struct {
		Level *string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]json.RawMessage `json:"properties"`
}

type codeQLResult struct {
	RuleID    string  `json:"ruleId"`
	RuleIndex *int    `json:"ruleIndex"`
	Level     *string `json:"level"`
	Rule      *struct {
		ID            string `json:"id"`
		Index         *int   `json:"index"`
		ToolComponent *struct {
			Index *int   `json:"index"`
			Name  string `json:"name"`
		} `json:"toolComponent"`
	} `json:"rule"`
}

// CheckCodeQLReports requires actual, successful CodeQL SARIF reports and fails
// on error/warning findings or any positive security severity, including notes.
// SARIF suppressions do not automatically waive a release-blocking finding.
func CheckCodeQLReports(dir string) (CodeQLSummary, error) {
	return checkCodeQLReports(dir, nil)
}

// CheckReviewedCodeQLReports additionally accepts individually reviewed findings
// whose full result and referenced source bytes still match the approved record.
func CheckReviewedCodeQLReports(root, dir, reviewFile string) (CodeQLSummary, error) {
	reviews, err := loadCodeQLReviews(root, reviewFile)
	if err != nil {
		return CodeQLSummary{}, err
	}
	defer reviews.root.Close()
	summary, err := checkCodeQLReports(dir, reviews)
	if err != nil {
		return summary, err
	}
	for i, used := range reviews.used {
		if !used {
			return summary, fmt.Errorf("reviewed CodeQL finding %q is stale or no longer reported", reviews.entries[i].RuleID)
		}
	}
	return summary, nil
}

func checkCodeQLReports(dir string, reviews *codeQLReviews) (CodeQLSummary, error) {
	var total CodeQLSummary
	entries, err := os.ReadDir(dir)
	if err != nil {
		return total, fmt.Errorf("read CodeQL output: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sarif") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return total, fmt.Errorf("inspect CodeQL report: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<20 {
			return total, fmt.Errorf("CodeQL report %q must be a regular file no larger than 128 MiB", entry.Name())
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			return total, fmt.Errorf("open CodeQL report: %w", err)
		}
		limited := &io.LimitedReader{R: f, N: (128 << 20) + 1}
		summary, checkErr := checkCodeQLReportReviewed(limited, reviews)
		closeErr := f.Close()
		if limited.N == 0 {
			return total, fmt.Errorf("CodeQL report %q exceeds 128 MiB", entry.Name())
		}
		if checkErr != nil {
			return total, fmt.Errorf("CodeQL report %q: %w", entry.Name(), checkErr)
		}
		if closeErr != nil {
			return total, fmt.Errorf("close CodeQL report: %w", closeErr)
		}
		total.Reports++
		total.Rules += summary.Rules
		total.Results += summary.Results
		total.Reviewed += summary.Reviewed
	}
	if total.Reports == 0 {
		return total, fmt.Errorf("no CodeQL SARIF report was produced")
	}
	return total, nil
}

func checkCodeQLReport(r io.Reader) (CodeQLSummary, error) {
	return checkCodeQLReportReviewed(r, nil)
}

func checkCodeQLReportReviewed(r io.Reader, reviews *codeQLReviews) (CodeQLSummary, error) {
	var summary CodeQLSummary
	data, err := io.ReadAll(io.LimitReader(r, (128<<20)+1))
	if err != nil || len(data) > 128<<20 {
		return summary, fmt.Errorf("CodeQL report could not be read within its size limit")
	}
	if err := codeQLJSONKeys(data, reflect.TypeFor[codeQLDocument]()); err != nil {
		return summary, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document codeQLDocument
	if err := decoder.Decode(&document); err != nil {
		return summary, fmt.Errorf("decode SARIF: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return summary, fmt.Errorf("SARIF must contain exactly one JSON document")
	}
	if document.Version != "2.1.0" || len(document.Runs) == 0 {
		return summary, fmt.Errorf("expected SARIF 2.1.0 with a completed CodeQL run")
	}
	for _, run := range document.Runs {
		driver := run.Tool.Driver
		if driver.Name != "CodeQL" || (driver.Version == "" && driver.SemanticVersion == "") {
			return summary, fmt.Errorf("missing CodeQL tool, version or query metadata")
		}
		if len(run.Invocations) == 0 || run.Results == nil {
			return summary, fmt.Errorf("missing CodeQL execution or result metadata")
		}
		for _, invocation := range run.Invocations {
			if invocation.ExecutionSuccessful == nil || !*invocation.ExecutionSuccessful {
				return summary, fmt.Errorf("CodeQL execution was not successful")
			}
			if len(invocation.ExitCode) > 0 {
				var exit int
				if bytes.Equal(bytes.TrimSpace(invocation.ExitCode), []byte("null")) || json.Unmarshal(invocation.ExitCode, &exit) != nil || exit != 0 {
					return summary, fmt.Errorf("CodeQL invocation has an invalid or failing exit code")
				}
			}
			for _, notifications := range []json.RawMessage{invocation.ToolExecutionNotifications, invocation.ToolConfigurationNotifications} {
				if err := checkCodeQLNotifications(notifications); err != nil {
					return summary, err
				}
			}
		}
		components := append([]codeQLComponent{driver}, run.Tool.Extensions...)
		queryRules := 0
		for _, component := range components {
			if component.Name == "" || (component.Version == "" && component.SemanticVersion == "") {
				return summary, fmt.Errorf("missing CodeQL component metadata")
			}
			seen := map[string]bool{}
			for _, rule := range component.Rules {
				if rule.ID == "" || seen[rule.ID] {
					return summary, fmt.Errorf("missing or duplicate CodeQL rule identifier")
				}
				seen[rule.ID] = true
				if rule.DefaultConfiguration.Level != nil && !sarifLevel(*rule.DefaultConfiguration.Level) {
					return summary, fmt.Errorf("unsupported CodeQL rule level")
				}
				if _, err := securitySeverity(rule.Properties["security-severity"]); err != nil {
					return summary, err
				}
			}
			queryRules += len(component.Rules)
		}
		if queryRules == 0 {
			return summary, fmt.Errorf("missing CodeQL query metadata")
		}
		for _, raw := range *run.Results {
			if err := codeQLJSONKeys(raw, reflect.TypeFor[codeQLResult]()); err != nil {
				return summary, err
			}
			var result codeQLResult
			if err := json.Unmarshal(raw, &result); err != nil {
				return summary, fmt.Errorf("invalid CodeQL result metadata: %w", err)
			}
			rule, err := codeQLResultRule(run, result)
			if err != nil {
				return summary, err
			}
			id := rule.ID
			severity, _ := securitySeverity(rule.Properties["security-severity"])
			level := "warning" // SARIF reportingConfiguration default.
			if rule.DefaultConfiguration.Level != nil {
				level = *rule.DefaultConfiguration.Level
			}
			if result.Level != nil {
				level = *result.Level
			}
			if !sarifLevel(level) {
				return summary, fmt.Errorf("unsupported CodeQL result level")
			}
			if level == "error" || level == "warning" || severity > 0 {
				if reviews == nil {
					return summary, fmt.Errorf("blocking CodeQL finding %q (level %s, security severity %g)", id, level, severity)
				}
				if err := reviews.accept(run, id, raw); err != nil {
					return summary, err
				}
				summary.Reviewed++
			}
		}
		summary.Rules += queryRules
		summary.Results += len(*run.Results)
	}
	return summary, nil
}

func checkCodeQLNotifications(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("invalid CodeQL notification metadata")
	}
	if err := codeQLJSONKeys(raw, reflect.TypeFor[[]codeQLNotification]()); err != nil {
		return err
	}
	var notifications []codeQLNotification
	if err := json.Unmarshal(raw, &notifications); err != nil {
		return fmt.Errorf("invalid CodeQL notification metadata: %w", err)
	}
	for _, notification := range notifications {
		level := "warning" // SARIF notification default.
		if notification.Level != nil {
			level = *notification.Level
			if !sarifLevel(level) {
				return fmt.Errorf("invalid CodeQL notification level")
			}
		}
		if level == "error" || notification.Descriptor.ID == "go/diagnostics/extraction-errors" {
			return fmt.Errorf("CodeQL reported failed or incomplete analysis")
		}
	}
	return nil
}

func codeQLResultRule(run codeQLRun, result codeQLResult) (codeQLRule, error) {
	component := run.Tool.Driver
	id, index := result.RuleID, result.RuleIndex
	if reference := result.Rule; reference != nil {
		if reference.ID != "" {
			if id != "" && id != reference.ID {
				return codeQLRule{}, fmt.Errorf("inconsistent CodeQL result rule identifiers")
			}
			id = reference.ID
		}
		if reference.Index != nil {
			if index != nil && *index != *reference.Index {
				return codeQLRule{}, fmt.Errorf("inconsistent CodeQL result rule indexes")
			}
			index = reference.Index
		}
		if ref := reference.ToolComponent; ref != nil {
			if ref.Index == nil || *ref.Index < 0 || *ref.Index >= len(run.Tool.Extensions) {
				return codeQLRule{}, fmt.Errorf("invalid CodeQL tool component reference")
			}
			component = run.Tool.Extensions[*ref.Index]
			if ref.Name != "" && ref.Name != component.Name {
				return codeQLRule{}, fmt.Errorf("inconsistent CodeQL tool component name")
			}
		}
	}
	if index != nil {
		i := *index
		if i < 0 || i >= len(component.Rules) || (id != "" && id != component.Rules[i].ID) {
			return codeQLRule{}, fmt.Errorf("invalid CodeQL result rule reference")
		}
		return component.Rules[i], nil
	}
	for _, rule := range component.Rules {
		if rule.ID == id {
			return rule, nil
		}
	}
	return codeQLRule{}, fmt.Errorf("CodeQL result references an unknown rule")
}

type codeQLReview struct {
	RuleID        string                         `json:"ruleId"`
	URI           string                         `json:"uri"`
	ResultSHA256  string                         `json:"resultSHA256"`
	SourceSHA256  map[string]codeQLSourceBinding `json:"sourceSHA256"`
	Disposition   string                         `json:"disposition"`
	Justification string                         `json:"justification"`
}

// codeQLSourceBinding labels public digests explicitly instead of treating a
// source filename as the name of a credential-shaped string value.
type codeQLSourceBinding struct {
	SHA256 string `json:"sha256"`
}

type codeQLReviews struct {
	root    *os.Root
	entries []codeQLReview
	byKey   map[string]int
	used    []bool
}

func loadCodeQLReviews(root, reviewFile string) (*codeQLReviews, error) {
	name, err := codeQLSourcePath(reviewFile)
	if err != nil {
		return nil, fmt.Errorf("invalid CodeQL review path: %w", err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open reviewed source root: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = r.Close()
		}
	}()
	data, err := readCodeQLSource(r, name, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("read CodeQL review manifest: %w", err)
	}
	var manifest struct {
		Version             int            `json:"version"`
		SourceCatalogSHA256 string         `json:"sourceCatalogSHA256"`
		Findings            []codeQLReview `json:"findings"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := codeQLJSONKeys(data, reflect.TypeOf(manifest)); err != nil {
		return nil, fmt.Errorf("ambiguous CodeQL review manifest: %w", err)
	}
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("invalid CodeQL review manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || manifest.Version != 2 || manifest.Findings == nil || !codeQLSHA(manifest.SourceCatalogSHA256) {
		return nil, fmt.Errorf("invalid CodeQL review manifest version or structure")
	}
	catalog, err := codeQLSourceCatalog(r)
	if err != nil {
		return nil, fmt.Errorf("fingerprint reviewed program: %w", err)
	}
	if catalog != manifest.SourceCatalogSHA256 {
		return nil, fmt.Errorf("CodeQL review manifest has a stale program source catalog")
	}
	reviews := &codeQLReviews{root: r, entries: manifest.Findings, byKey: map[string]int{}, used: make([]bool, len(manifest.Findings))}
	for i, review := range reviews.entries {
		if review.RuleID == "" || review.URI == "" || !codeQLSHA(review.ResultSHA256) || len(review.SourceSHA256) == 0 || strings.TrimSpace(review.Justification) == "" || (review.Disposition != "false-positive" && review.Disposition != "intentional-decoy") {
			return nil, fmt.Errorf("CodeQL review %d lacks a specific disposition, justification or fingerprint", i)
		}
		if _, err := codeQLSourcePath(review.URI); err != nil {
			return nil, fmt.Errorf("CodeQL review %d has an invalid relative URI", i)
		}
		for source, binding := range review.SourceSHA256 {
			if _, err := codeQLSourcePath(source); err != nil || !codeQLSHA(binding.SHA256) {
				return nil, fmt.Errorf("CodeQL review %d has invalid source fingerprints", i)
			}
		}
		key := review.RuleID + "\x00" + review.URI + "\x00" + review.ResultSHA256
		if _, duplicate := reviews.byKey[key]; duplicate {
			return nil, fmt.Errorf("duplicate CodeQL review entry")
		}
		reviews.byKey[key] = i
	}
	complete = true
	return reviews, nil
}

// CodeQLSourceCatalogSHA256 fingerprints the complete production Go source path
// set and contents, including platform files and module manifests. Test files
// and Git metadata are excluded; the review JSON cannot include its own hash.
func CodeQLSourceCatalogSHA256(root string) (string, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer r.Close()
	return codeQLSourceCatalog(r)
}

func codeQLSourceCatalog(root *os.Root) (string, error) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "qpot-codeql-production-source-v1\n")
	var names []string
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source catalog contains a symlink at %q", name)
		}
		if entry.IsDir() {
			return nil
		}
		base := filepath.Base(name)
		if !(strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")) && base != "go.mod" && base != "go.sum" {
			return nil
		}
		names = append(names, name)
		if len(names) > 10000 {
			return fmt.Errorf("source catalog exceeds 10000 files")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("source catalog contains no production Go inputs")
	}
	sort.Strings(names)
	var total int64
	for _, name := range names {
		data, err := readCodeQLSource(root, name, 16<<20)
		if err != nil {
			return "", fmt.Errorf("read source catalog entry %q: %w", name, err)
		}
		total += int64(len(data))
		if total > 128<<20 {
			return "", fmt.Errorf("source catalog exceeds 128 MiB")
		}
		sum := sha256.Sum256(data)
		// Length framing makes the sorted path and content-fingerprint
		// stream unambiguous even for unusual filenames.
		_, _ = fmt.Fprintf(hash, "%d:%s:%x\n", len(name), name, sum)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (reviews *codeQLReviews) accept(run codeQLRun, id string, raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid CodeQL result: %w", err)
	}
	digest, err := codeQLResultSHA256(run, value)
	if err != nil {
		return fmt.Errorf("canonicalize CodeQL result: %w", err)
	}
	locations, ok := value["locations"].([]any)
	if !ok || len(locations) == 0 {
		return fmt.Errorf("blocking CodeQL finding %q lacks a source location", id)
	}
	primary, ok := locations[0].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid CodeQL primary location")
	}
	physical, ok := primary["physicalLocation"].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid CodeQL physical location")
	}
	artifact, ok := physical["artifactLocation"].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid CodeQL artifact location")
	}
	uri, err := codeQLArtifactURI(run, artifact)
	if err != nil {
		return err
	}
	key := id + "\x00" + uri + "\x00" + digest
	i, ok := reviews.byKey[key]
	if !ok {
		return fmt.Errorf("blocking CodeQL finding %q at %q has no exact reviewed disposition", id, uri)
	}
	review := reviews.entries[i]
	sources := map[string]bool{}
	var collect func(any) error
	collect = func(node any) error {
		switch n := node.(type) {
		case map[string]any:
			for key, child := range n {
				if key == "artifactLocation" {
					location, ok := child.(map[string]any)
					if !ok {
						return fmt.Errorf("invalid referenced CodeQL artifact")
					}
					uri, err := codeQLArtifactURI(run, location)
					if err != nil {
						return err
					}
					path, err := codeQLSourcePath(uri)
					if err != nil {
						return err
					}
					sources[path] = true
				}
				if err := collect(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range n {
				if err := collect(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := collect(value); err != nil {
		return fmt.Errorf("CodeQL finding %q has unsupported source references: %w", id, err)
	}
	for source := range sources {
		if _, covered := review.SourceSHA256[source]; !covered {
			return fmt.Errorf("CodeQL review for %q omits referenced source %q", id, source)
		}
	}
	for source, expected := range review.SourceSHA256 {
		data, err := readCodeQLSource(reviews.root, source, 16<<20)
		if err != nil {
			return fmt.Errorf("read reviewed source %q: %w", source, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected.SHA256 {
			return fmt.Errorf("CodeQL review for %q has stale source %q", id, source)
		}
	}
	reviews.used[i] = true
	return nil
}

// codeQLResultSHA256 digests a result with every artifact named by its path
// alone, rewriting value in place. CodeQL lists a run's artifacts in no fixed
// order, so an index into that list differs between two analyses of the same
// code, while the path it names does not.
func codeQLResultSHA256(run codeQLRun, value map[string]any) (string, error) {
	var resolve func(any) error
	resolve = func(node any) error {
		switch n := node.(type) {
		case map[string]any:
			for key, child := range n {
				if location, ok := child.(map[string]any); ok && key == "artifactLocation" {
					if _, indexed := location["index"]; indexed {
						uri, err := codeQLArtifactURI(run, location)
						if err != nil {
							return err
						}
						location["uri"] = uri
						delete(location, "index")
					}
				}
				if err := resolve(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range n {
				if err := resolve(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := resolve(value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func codeQLArtifactURI(run codeQLRun, location map[string]any) (string, error) {
	if base, ok := location["uriBaseId"]; ok && base != "%SRCROOT%" {
		return "", fmt.Errorf("unsupported CodeQL URI base")
	}
	uri, _ := location["uri"].(string)
	if rawIndex, indexed := location["index"]; indexed {
		index, ok := rawIndex.(json.Number)
		if !ok {
			return "", fmt.Errorf("invalid CodeQL artifact index")
		}
		i, err := strconv.Atoi(string(index))
		if err != nil || i < 0 || i >= len(run.Artifacts) {
			return "", fmt.Errorf("invalid CodeQL artifact index")
		}
		var indexedURI string
		if err := json.Unmarshal(run.Artifacts[i].Location["uri"], &indexedURI); err != nil {
			return "", fmt.Errorf("missing indexed CodeQL artifact URI")
		}
		var indexedBase string
		if rawBase, present := run.Artifacts[i].Location["uriBaseId"]; present {
			if err := json.Unmarshal(rawBase, &indexedBase); err != nil || indexedBase != "%SRCROOT%" {
				return "", fmt.Errorf("unsupported indexed CodeQL URI base")
			}
		}
		if uri != "" && uri != indexedURI {
			return "", fmt.Errorf("inconsistent CodeQL artifact URI and index")
		}
		uri = indexedURI
	}
	if _, err := codeQLSourcePath(uri); err != nil {
		return "", err
	}
	return uri, nil
}

func codeQLSourcePath(uri string) (string, error) {
	name, err := url.PathUnescape(uri)
	if err != nil || !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00:#?") || filepath.ToSlash(filepath.Clean(name)) != name {
		return "", fmt.Errorf("expected a canonical repository-relative CodeQL source path")
	}
	return name, nil
}

func codeQLSHA(hash string) bool {
	_, err := hex.DecodeString(hash)
	return err == nil && len(hash) == 64 && strings.ToLower(hash) == hash
}

func readCodeQLSource(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("reviewed input is not a bounded regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("reviewed input is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded reviewed input: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("reviewed input exceeds its size limit")
	}
	return data, nil
}

// codeQLJSONKeys rejects ambiguous JSON before encoding/json can overwrite a
// finding through duplicate fields or its case-insensitive struct matching.
// Free-form producer maps keep their normal case-sensitive keys.
func codeQLJSONKeys(data []byte, schema reflect.Type) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("CodeQL JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := codeQLJSONValue(decoder, schema, 0); err != nil {
		return fmt.Errorf("invalid or ambiguous CodeQL JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("CodeQL JSON must contain exactly one document")
	}
	return nil
}

func codeQLJSONValue(decoder *json.Decoder, schema reflect.Type, depth int) error {
	if depth > 512 {
		return fmt.Errorf("unsupported JSON nesting")
	}
	for schema != nil && schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	if schema == reflect.TypeFor[json.RawMessage]() {
		schema = nil
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if schema != nil {
		valid := true
		switch schema.Kind() {
		case reflect.Struct, reflect.Map:
			valid = token == json.Delim('{')
		case reflect.Slice, reflect.Array:
			valid = token == json.Delim('[')
		case reflect.String:
			_, valid = token.(string)
		case reflect.Bool:
			_, valid = token.(bool)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			_, valid = token.(json.Number)
		}
		if !valid {
			return fmt.Errorf("unsupported CodeQL JSON field type")
		}
	}
	switch token {
	case json.Delim('{'):
		fields := map[string]reflect.Type{}
		if schema != nil && schema.Kind() == reflect.Struct {
			for i := range schema.NumField() {
				field := schema.Field(i)
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				if name != "-" && field.PkgPath == "" {
					if name == "" {
						name = field.Name
					}
					fields[name] = field.Type
				}
			}
		}
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON object key")
			}
			seen[key] = true
			child, exact := fields[key]
			if !exact {
				for canonical := range fields {
					if strings.EqualFold(key, canonical) {
						return fmt.Errorf("non-canonical JSON field spelling")
					}
				}
				if schema != nil && schema.Kind() == reflect.Map {
					child = schema.Elem()
				}
			}
			if err := codeQLJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return fmt.Errorf("invalid JSON object end")
		}
	case json.Delim('['):
		var child reflect.Type
		if schema != nil && (schema.Kind() == reflect.Array || schema.Kind() == reflect.Slice) {
			child = schema.Elem()
		}
		for decoder.More() {
			if err := codeQLJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return fmt.Errorf("invalid JSON array end")
		}
	}
	return nil
}

func sarifLevel(level string) bool {
	return level == "none" || level == "note" || level == "warning" || level == "error"
}

func securitySeverity(raw json.RawMessage) (float64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("unsupported CodeQL security severity metadata")
	}
	severity, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(severity) || math.IsInf(severity, 0) || severity < 0 || severity > 10 {
		return 0, fmt.Errorf("invalid CodeQL security severity metadata")
	}
	return severity, nil
}
