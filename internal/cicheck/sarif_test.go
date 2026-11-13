package cicheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const successfulCodeQLReport = `{
  "version":"2.1.0",
  "runs":[{
    "tool":{"driver":{"name":"CodeQL","semanticVersion":"2.27.4","rules":[{
      "id":"go/test-security-rule","defaultConfiguration":{"level":"warning"},
      "properties":{"security-severity":"8.1"}
    }]}},
    "invocations":[{"executionSuccessful":true}],
    "results":[]
  }]
}`

func TestCodeQLReportRequiresSuccessfulAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  string
		new  string
	}{
		{"empty report", successfulCodeQLReport, ""},
		{"old SARIF", `"2.1.0"`, `"2.0.0"`},
		{"no tool", `"CodeQL"`, `"some other tool"`},
		{"no version", `"semanticVersion":"2.27.4"`, `"semanticVersion":""`},
		{"failed analysis", `"executionSuccessful":true`, `"executionSuccessful":false`},
		{"missing success", `"executionSuccessful":true`, `"other":true`},
		{"missing invocations", `"invocations":[{"executionSuccessful":true}]`, `"invocations":[]`},
		{"missing results", `"results":[]`, `"notResults":[]`},
		{"null results", `"results":[]`, `"results":null`},
		{"duplicate hides finding", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule"}],"results":[]`},
		{"case alias hides finding", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule"}],"Results":[]`},
		{"single case alias", `"results":[]`, `"Results":[]`},
		{"duplicate success", `"executionSuccessful":true`, `"executionSuccessful":false,"executionSuccessful":true`},
		{"case alias success", `"executionSuccessful":true`, `"executionSuccessful":false,"ExecutionSuccessful":true`},
		{"failing exit status", `"executionSuccessful":true`, `"executionSuccessful":true,"exitCode":2`},
		{"invalid exit status", `"executionSuccessful":true`, `"executionSuccessful":true,"exitCode":"0"`},
		{"null exit status", `"executionSuccessful":true`, `"executionSuccessful":true,"exitCode":null`},
		{"execution error notification", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]`},
		{"configuration error notification", `"executionSuccessful":true`, `"executionSuccessful":true,"toolConfigurationNotifications":[{"level":"error"}]`},
		{"invalid notification level", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[{"level":"critical"}]`},
		{"null notification level", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[{"level":null}]`},
		{"null notification object", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[null]`},
		{"case alias notification level", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[{"Level":"error"}]`},
		{"null notification metadata", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":null`},
		{"warning extraction error", `"executionSuccessful":true`, `"executionSuccessful":true,"toolExecutionNotifications":[{"level":"warning","descriptor":{"id":"go/diagnostics/extraction-errors"}}]`},
		{"invalid severity", `"security-severity":"8.1"`, `"security-severity":"NaN"`},
		{"invalid level", `"level":"warning"`, `"level":"critical"`},
		{"empty level", `"level":"warning"`, `"level":""`},
		{"null level", `"level":"warning"`, `"level":null`},
		{"unknown rule", `"results":[]`, `"results":[{"ruleId":"go/unknown"}]`},
		{"invalid index", `"results":[]`, `"results":[{"ruleIndex":-1}]`},
		{"mismatched rule", `"results":[]`, `"results":[{"ruleId":"go/other","ruleIndex":0}]`},
		{"warning finding", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule","level":"warning"}]`},
		{"error finding", `"results":[]`, `"results":[{"ruleIndex":0,"level":"error"}]`},
		{"default-level finding", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule"}]`},
		{"security note", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule","level":"note"}]`},
		{"security none", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule","level":"none"}]`},
		{"suppression is not approval", `"results":[]`, `"results":[{"ruleId":"go/test-security-rule","suppressions":[{"kind":"inSource","status":"accepted","justification":"unreviewed claim"}]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := strings.Replace(successfulCodeQLReport, tc.old, tc.new, 1)
			if _, err := checkCodeQLReport(strings.NewReader(report)); err == nil {
				t.Fatal("incomplete analysis or a blocking finding passed the release gate")
			}
		})
	}
	if _, err := checkCodeQLReport(strings.NewReader(successfulCodeQLReport + successfulCodeQLReport)); err == nil {
		t.Fatal("multiple JSON documents passed")
	}
	if _, err := checkCodeQLReport(strings.NewReader(successfulCodeQLReport + "invalid")); err == nil {
		t.Fatal("trailing garbage passed")
	}
	invalidUTF8 := strings.Replace(successfulCodeQLReport, `"version":`, "\"unknown\":\"\xff\",\"version\":", 1)
	if _, err := checkCodeQLReport(strings.NewReader(invalidUTF8)); err == nil {
		t.Fatal("invalid UTF-8 was silently replaced in a report")
	}
}

func TestCodeQLReviewRejectsAmbiguousJSON(t *testing.T) {
	for _, scenario := range []string{"duplicate version", "case alias findings", "duplicate findings", "case alias disposition"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			writeCodeQLReviewFixture(t, root, reports, document, []codeQLReview{review})
			path := filepath.Join(root, ".github/reviews.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			switch scenario {
			case "duplicate version":
				text = strings.Replace(text, `"version":2`, `"version":0,"version":2`, 1)
			case "case alias findings":
				text = strings.Replace(text, `"findings":`, `"Findings":`, 1)
			case "duplicate findings":
				text = strings.Replace(text, `"findings":`, `"findings":[],"findings":`, 1)
			case "case alias disposition":
				text = strings.Replace(text, `"disposition":`, `"Disposition":`, 1)
			}
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json"); err == nil {
				t.Fatal("ambiguous review JSON passed")
			}
		})
	}
}

func codeQLReviewFixture(t testing.TB) (string, string, map[string]any, codeQLReview) {
	t.Helper()
	root, reports := t.TempDir(), t.TempDir()
	for _, dir := range []string{"internal", ".github"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sources := map[string]codeQLSourceBinding{}
	for _, name := range []string{"internal/source.go", "internal/helper.go"} {
		data := []byte("package fixture\n// " + name + "\n")
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		sources[name] = codeQLSourceBinding{SHA256: hex.EncodeToString(sum[:])}
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(successfulCodeQLReport), &document); err != nil {
		t.Fatal(err)
	}
	location := func(uri string) map[string]any {
		return map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": map[string]any{"startLine": 1}}}
	}
	result := map[string]any{
		"ruleId": "go/test-security-rule", "ruleIndex": 0,
		"locations":           []any{location("internal/source.go")},
		"partialFingerprints": map[string]any{"primaryLocationLineHash": "line-v1"},
		"codeFlows":           []any{map[string]any{"threadFlows": []any{map[string]any{"locations": []any{map[string]any{"location": location("internal/helper.go")}}}}}},
	}
	document["runs"].([]any)[0].(map[string]any)["results"] = []any{result}
	review := codeQLReview{RuleID: "go/test-security-rule", URI: "internal/source.go", ResultSHA256: codeQLTestDigest(t, result), SourceSHA256: sources, Disposition: "false-positive", Justification: "Fixture review proves this exact result and both unchanged source files."}
	return root, reports, document, review
}

// codeQLTestDigest digests a fixture result as the gate does: with its rule
// named by ruleId, not by a place in the rule list.
func codeQLTestDigest(t testing.TB, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var named map[string]any
	if err := json.Unmarshal(data, &named); err != nil {
		t.Fatal(err)
	}
	delete(named, "ruleIndex")
	if data, err = json.Marshal(named); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeCodeQLReviewFixture(t testing.TB, root, reports string, document any, entries []codeQLReview) {
	t.Helper()
	catalog, err := CodeQLSourceCatalogSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]any{
		filepath.Join(reports, "go.sarif"):             document,
		filepath.Join(root, ".github", "reviews.json"): map[string]any{"version": 2, "sourceCatalogSHA256": catalog, "findings": entries},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCodeQLReviewedFindingRequiresExactEvidence(t *testing.T) {
	for _, scenario := range []string{"accepted", "no justification", "accepted risk", "duplicate entry", "stale source", "omitted flow source", "changed trace", "changed fingerprint", "moved result", "new result", "removed result", "unsafe source", "unsafe review path"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			run := document["runs"].([]any)[0].(map[string]any)
			result := run["results"].([]any)[0].(map[string]any)
			entries := []codeQLReview{review}
			reviewPath := ".github/reviews.json"
			switch scenario {
			case "no justification":
				entries[0].Justification = " "
			case "accepted risk":
				entries[0].Disposition = "accepted-risk"
			case "duplicate entry":
				entries = append(entries, review)
			case "stale source":
				if err := os.WriteFile(filepath.Join(root, "internal/helper.go"), []byte("changed source"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "omitted flow source":
				delete(review.SourceSHA256, "internal/helper.go")
			case "changed trace":
				result["codeFlows"] = []any{}
			case "changed fingerprint":
				result["partialFingerprints"] = map[string]any{"primaryLocationLineHash": "line-v2"}
			case "moved result":
				result["locations"] = []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "internal/helper.go"}}}}
			case "new result":
				run["results"] = append(run["results"].([]any), map[string]any{"ruleId": "go/test-security-rule", "message": map[string]any{"text": "new finding"}})
			case "removed result":
				run["results"] = []any{}
			case "unsafe source":
				review.SourceSHA256["../outside.go"] = codeQLSourceBinding{SHA256: strings.Repeat("0", 64)}
			case "unsafe review path":
				reviewPath = "../reviews.json"
			}
			writeCodeQLReviewFixture(t, root, reports, document, entries)
			summary, err := CheckReviewedCodeQLReports(root, reports, reviewPath)
			if scenario == "accepted" {
				if err != nil || summary.Reviewed != 1 || summary.Results != 1 {
					t.Fatalf("exact reviewed evidence failed: %+v %v", summary, err)
				}
				if _, err := CheckCodeQLReports(reports); err == nil {
					t.Fatal("a finding passed without its explicit review manifest")
				}
			} else if err == nil {
				t.Fatal("altered or unreviewed evidence passed the release gate")
			}
		})
	}
}

// CodeQL lists a run's artifacts in no fixed order, and its locations point
// into that list: the reviewed finding is the same whichever way round its
// files are listed, while an index that disagrees with its path is refused.
func TestCodeQLReviewIgnoresArtifactOrder(t *testing.T) {
	for _, scenario := range []string{"listed in order", "listed reversed", "index disagrees"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			run := document["runs"].([]any)[0].(map[string]any)
			files := []string{"internal/source.go", "internal/helper.go"}
			if scenario == "listed reversed" {
				files = []string{"internal/helper.go", "internal/source.go"}
			}
			index := map[string]int{}
			var artifacts []any
			for i, file := range files {
				index[file] = i
				artifacts = append(artifacts, map[string]any{"location": map[string]any{"uri": file, "uriBaseId": "%SRCROOT%"}})
			}
			if scenario == "index disagrees" {
				index["internal/helper.go"] = index["internal/source.go"]
			}
			run["artifacts"] = artifacts
			var point func(any)
			point = func(node any) {
				switch n := node.(type) {
				case map[string]any:
					for key, child := range n {
						if location, ok := child.(map[string]any); ok && key == "artifactLocation" {
							location["index"] = index[location["uri"].(string)]
						}
						point(child)
					}
				case []any:
					for _, child := range n {
						point(child)
					}
				}
			}
			point(run["results"])
			writeCodeQLReviewFixture(t, root, reports, document, []codeQLReview{review})
			_, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json")
			if accepted := err == nil; accepted != (scenario != "index disagrees") {
				t.Fatalf("accepted %v: %v", accepted, err)
			}
		})
	}
}

// CodeQL lists a component's rules, and the components, in no fixed order
// either. Two analyses of one commit listed the query pack's rules in
// different orders, and the second one's gate refused every reviewed finding
// because the digest covered the rule's place in the list. The reviewed
// finding is the same wherever its rule is listed and however the result
// refers to it, while a place that names another rule is refused.
func TestCodeQLReviewIgnoresRuleOrder(t *testing.T) {
	other := func(id string) map[string]any {
		return map[string]any{"id": id, "defaultConfiguration": map[string]any{"level": "warning"}, "properties": map[string]any{"security-severity": "5.0"}}
	}
	for _, scenario := range []string{"first of one", "last of three", "in a query pack", "in a query pack listed second", "place names another rule", "pack place names another pack"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			run := document["runs"].([]any)[0].(map[string]any)
			tool := run["tool"].(map[string]any)
			driver := tool["driver"].(map[string]any)
			reviewed := driver["rules"].([]any)[0]
			result := run["results"].([]any)[0].(map[string]any)
			pack := func(rules ...any) map[string]any {
				return map[string]any{"name": "codeql/go-queries", "semanticVersion": "1.6.14", "rules": rules}
			}
			empty := map[string]any{"name": "codeql/go-all", "semanticVersion": "7.0.0"}
			byPack := func(component, index int) {
				driver["rules"] = []any{}
				delete(result, "ruleIndex")
				result["rule"] = map[string]any{"id": "go/test-security-rule", "index": index, "toolComponent": map[string]any{"index": component}}
				// The pin is taken from the result with the rule and its pack
				// named, so both orders below are held to one digest.
				named := maps.Clone(result)
				named["rule"] = map[string]any{"id": "go/test-security-rule", "toolComponent": map[string]any{"name": "codeql/go-queries"}}
				review.ResultSHA256 = codeQLTestDigest(t, named)
			}
			switch scenario {
			case "last of three":
				driver["rules"] = []any{other("go/first"), other("go/second"), reviewed}
				result["ruleIndex"] = 2
			case "in a query pack":
				tool["extensions"] = []any{pack(other("go/first"), reviewed), empty}
				byPack(0, 1)
			case "in a query pack listed second":
				tool["extensions"] = []any{empty, pack(reviewed, other("go/first"), other("go/second"))}
				byPack(1, 0)
			case "place names another rule":
				driver["rules"] = []any{other("go/first"), reviewed}
				result["ruleIndex"] = 0
			case "pack place names another pack":
				tool["extensions"] = []any{pack(reviewed), empty}
				byPack(1, 0)
			}
			writeCodeQLReviewFixture(t, root, reports, document, []codeQLReview{review})
			_, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json")
			refused := scenario == "place names another rule" || scenario == "pack place names another pack"
			if accepted := err == nil; accepted == refused {
				t.Fatalf("accepted %v: %v", accepted, err)
			}
			if refused && !strings.Contains(err.Error(), "rule") {
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}

func TestCodeQLReviewRequiresTypedSourceBindings(t *testing.T) {
	for _, scenario := range []string{"valid", "legacy version", "legacy string", "mixed record formats", "null record", "array record", "number record", "boolean record", "empty sources", "null sources", "duplicate source path", "missing digest", "empty digest", "short digest", "nonhex digest", "uppercase digest", "null digest", "numeric digest", "object digest", "unknown digest field", "case alias", "duplicate digest", "conflicting case alias"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			writeCodeQLReviewFixture(t, root, reports, document, []codeQLReview{review})
			path := filepath.Join(root, ".github/reviews.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			bindings := manifest["findings"].([]any)[0].(map[string]any)["sourceSHA256"].(map[string]any)
			const source = "internal/helper.go"
			hash := review.SourceSHA256[source].SHA256
			switch scenario {
			case "legacy version":
				manifest["version"] = 1
			case "legacy string":
				for name := range bindings {
					bindings[name] = review.SourceSHA256[name].SHA256
				}
			case "mixed record formats":
				bindings[source] = hash
			case "null record":
				bindings[source] = nil
			case "array record":
				bindings[source] = []any{hash}
			case "number record":
				bindings[source] = 123
			case "boolean record":
				bindings[source] = true
			case "empty sources":
				manifest["findings"].([]any)[0].(map[string]any)["sourceSHA256"] = map[string]any{}
			case "null sources":
				manifest["findings"].([]any)[0].(map[string]any)["sourceSHA256"] = nil
			case "missing digest":
				bindings[source] = map[string]any{}
			case "empty digest":
				bindings[source] = map[string]any{"sha256": ""}
			case "short digest":
				bindings[source] = map[string]any{"sha256": hash[:63]}
			case "nonhex digest":
				bindings[source] = map[string]any{"sha256": strings.Repeat("g", 64)}
			case "uppercase digest":
				bindings[source] = map[string]any{"sha256": strings.ToUpper(hash)}
			case "null digest":
				bindings[source] = map[string]any{"sha256": nil}
			case "numeric digest":
				bindings[source] = map[string]any{"sha256": 123}
			case "object digest":
				bindings[source] = map[string]any{"sha256": map[string]any{"value": hash}}
			case "unknown digest field":
				bindings[source] = map[string]any{"sha256": hash, "extra": "unreviewed"}
			case "case alias":
				bindings[source] = map[string]any{"SHA256": hash}
			}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			field := `"sha256":"` + hash + `"`
			if scenario == "duplicate source path" {
				record := `"` + source + `":{"sha256":"` + hash + `"}`
				data = []byte(strings.Replace(string(data), record, record+","+record, 1))
			}
			if scenario == "duplicate digest" {
				data = []byte(strings.Replace(string(data), field, field+","+field, 1))
			}
			if scenario == "conflicting case alias" {
				data = []byte(strings.Replace(string(data), field, field+`,"SHA256":"`+hash+`"`, 1))
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			summary, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json")
			if scenario == "valid" {
				if err != nil || summary.Reviewed != 1 {
					t.Fatalf("typed source binding failed: %+v %v", summary, err)
				}
			} else if err == nil {
				t.Fatal("malformed or legacy source binding passed")
			}
		})
	}
}

func TestCodeQLReviewBindsCompleteProductionSourceCatalog(t *testing.T) {
	for _, scenario := range []string{"unchanged", "readme only", "test source only", "new production file", "changed unreferenced file", "renamed unreferenced file", "changed module", "source symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root, reports, document, review := codeQLReviewFixture(t)
			unreferenced := filepath.Join(root, "internal/unreferenced.go")
			if err := os.WriteFile(unreferenced, []byte("package fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeCodeQLReviewFixture(t, root, reports, document, []codeQLReview{review})
			var path string
			switch scenario {
			case "readme only":
				path = filepath.Join(root, "README.md")
			case "test source only":
				path = filepath.Join(root, "internal/only_test.go")
			case "new production file":
				path = filepath.Join(root, "internal/new.go")
			case "changed unreferenced file":
				path = unreferenced
			case "renamed unreferenced file":
				if err := os.Rename(unreferenced, filepath.Join(root, "internal/moved.go")); err != nil {
					t.Fatal(err)
				}
			case "changed module":
				path = filepath.Join(root, "go.mod")
			case "source symlink":
				outside := filepath.Join(t.TempDir(), "outside.go")
				if err := os.WriteFile(outside, []byte("package outside\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "internal/linked.go")); err != nil {
					t.Skipf("source symlink unavailable on this host: %v", err)
				}
			}
			if path != "" {
				if err := os.WriteFile(path, []byte("changed content\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json")
			unchanged := scenario == "unchanged" || scenario == "readme only" || scenario == "test source only"
			if (err == nil) != unchanged {
				t.Fatalf("source catalog policy incorrect for %s: %v", scenario, err)
			}
		})
	}
}

func TestCodeQLGroupedRulesMatchActionOutput(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal([]byte(successfulCodeQLReport), &document); err != nil {
		t.Fatal(err)
	}
	run := document["runs"].([]any)[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	tool["extensions"] = []any{map[string]any{"name": "codeql/go-queries", "semanticVersion": "1.6.14", "rules": driver["rules"]}, map[string]any{"name": "codeql/go-all", "semanticVersion": "8.1.0"}}
	driver["rules"] = []any{}
	for _, scenario := range []string{"empty successful analysis", "blocking grouped finding", "missing component", "wrong component", "wrong component name"} {
		t.Run(scenario, func(t *testing.T) {
			result := map[string]any{"ruleId": "go/test-security-rule", "rule": map[string]any{"id": "go/test-security-rule", "index": 0, "toolComponent": map[string]any{"index": 0}}}
			reference := result["rule"].(map[string]any)["toolComponent"].(map[string]any)
			switch scenario {
			case "missing component":
				delete(result["rule"].(map[string]any), "toolComponent")
			case "wrong component":
				reference["index"] = 1
			case "wrong component name":
				reference["name"] = "different-package"
			}
			run["results"] = []any{result}
			if scenario == "empty successful analysis" {
				run["results"] = []any{}
			}
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := checkCodeQLReport(strings.NewReader(string(data)))
			if scenario == "empty successful analysis" {
				if err != nil || summary.Rules != 1 {
					t.Fatalf("actual action schema not supported: %+v %v", summary, err)
				}
			} else if err == nil {
				t.Fatal("blocking or malformed grouped result passed")
			}
		})
	}
}

func FuzzCodeQLReviewManifest(f *testing.F) {
	root, reports, document, review := codeQLReviewFixture(f)
	writeCodeQLReviewFixture(f, root, reports, document, []codeQLReview{review})
	seed, err := os.ReadFile(filepath.Join(root, ".github/reviews.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(seed))
	f.Add(`{"version":2,"findings":[]}`)
	f.Add(`{"version":1,"findings":[]}`)
	f.Add("")
	f.Fuzz(func(t *testing.T, manifest string) {
		if len(manifest) > 64<<10 {
			return
		}
		if err := os.WriteFile(filepath.Join(root, ".github/reviews.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		summary, err := CheckReviewedCodeQLReports(root, reports, ".github/reviews.json")
		if err == nil && (summary.Reviewed != 1 || summary.Results != 1 || !json.Valid([]byte(manifest))) {
			t.Fatal("invalid manifest or an unreviewed finding passed")
		}
	})
}

func TestCodeQLReportsAcceptCompletedEmptyResults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sarif"), []byte(successfulCodeQLReport), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := CheckCodeQLReports(dir)
	if err != nil || summary.Reports != 1 || summary.Rules != 1 || summary.Results != 0 {
		t.Fatalf("completed analysis not accepted: %+v %v", summary, err)
	}
	// A non-security informational result is not silently promoted into a
	// security finding; positive security severity is covered above.
	report := strings.Replace(successfulCodeQLReport, `"security-severity":"8.1"`, `"precision":"high"`, 1)
	report = strings.Replace(report, `"results":[]`, `"results":[{"ruleIndex":0,"level":"note"}]`, 1)
	if _, err := checkCodeQLReport(strings.NewReader(report)); err != nil {
		t.Fatalf("non-security note was rejected: %v", err)
	}
	unknown := strings.Replace(successfulCodeQLReport, `"version":`, `"properties":{"Name":"one","name":"two"},"version":`, 1)
	if _, err := checkCodeQLReport(strings.NewReader(unknown)); err != nil {
		t.Fatalf("free-form producer property keys lost case sensitivity: %v", err)
	}
}

func TestCodeQLReportsRequireActualRegularFiles(t *testing.T) {
	if _, err := CheckCodeQLReports(t.TempDir()); err == nil {
		t.Fatal("missing report passed")
	}
	if _, err := CheckCodeQLReports(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing output directory passed")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "go.sarif"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCodeQLReports(dir); err == nil {
		t.Fatal("directory masquerading as report passed")
	}
	large := t.TempDir()
	f, err := os.Create(filepath.Join(large, "go.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((128 << 20) + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCodeQLReports(large); err == nil {
		t.Fatal("oversized report passed")
	}
}

func FuzzCodeQLReport(f *testing.F) {
	f.Add(successfulCodeQLReport)
	f.Add(`{"version":"2.1.0","runs":[]}`)
	f.Add("")
	f.Fuzz(func(t *testing.T, report string) {
		if len(report) > 128<<10 {
			return
		}
		summary, err := checkCodeQLReport(strings.NewReader(report))
		if err == nil {
			if !json.Valid([]byte(report)) || summary.Rules == 0 {
				t.Fatal("accepted an invalid or query-free analysis")
			}
		}
	})
}
