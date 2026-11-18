package libgobuster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type sarifTestResult struct {
	finding SARIFFinding
}

func (r sarifTestResult) ResultToString() (string, error) {
	return r.finding.Message, nil
}

func (r sarifTestResult) ToSARIF() SARIFFinding {
	return r.finding
}

type decodedSARIFReport struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID              string            `json:"ruleId"`
			Level               string            `json:"level"`
			Message             sarifMessage      `json:"message"`
			Locations           []sarifLocation   `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			BaselineState       string            `json:"baselineState"`
		} `json:"results"`
		Invocations []sarifInvocation `json:"invocations"`
	} `json:"runs"`
}

func TestSARIFWriterMultiResultAndOfficialSchema(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "gobuster.sarif")
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nmissing\napi\n"), 0o600); err != nil {
		t.Fatalf("could not create wordlist: %v", err)
	}

	writer, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: wordlist,
	})
	if err != nil {
		t.Fatalf("could not create SARIF writer: %v", err)
	}
	writer.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "found admin",
			LogicalLocation: "admin",
		}},
		word: "admin",
		line: 1,
	})
	writer.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPServerErrorRuleID,
			Message:         "found api",
			LogicalLocation: "api",
		}},
		word: "api",
		line: 3,
	})
	writer.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "found admin backup",
			LogicalLocation: "admin.bak",
		}},
		word: "admin.bak",
		line: 7,
	})
	if err := writer.Close(nil); err != nil {
		t.Fatalf("could not close SARIF writer: %v", err)
	}

	document := validateOfficialSARIFSchema(t, output)
	if document.Version != SARIFVersion {
		t.Fatalf("version = %q, want %q", document.Version, SARIFVersion)
	}
	run := document.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("unexpected invocation: %#v", run.Invocations)
	}
	if len(run.Tool.Driver.Rules) != len(SARIFRules) {
		t.Fatalf("rules = %d, want %d", len(run.Tool.Driver.Rules), len(SARIFRules))
	}

	assertResult(t, run.Results[0], SARIFHTTPSuccessRuleID, "note", 1, "admin")
	assertResult(t, run.Results[1], SARIFHTTPServerErrorRuleID, "error", 3, "api")
	assertResult(t, run.Results[2], SARIFHTTPSuccessRuleID, "note", 7, "admin.bak")

	artifactURI := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.HasPrefix(artifactURI, "wordlists/") {
		t.Fatalf("artifact URI %q is not a sanitized relative path", artifactURI)
	}
	assertSafeRelativeURI(t, artifactURI)
	if strings.Contains(artifactURI, filepath.Base(wordlist)) {
		// The basename is allowed, but the temporary directory must never be.
		assertNoTemporaryPath(t, artifactURI)
	}

	firstFingerprint := run.Results[0].PartialFingerprints["gobuster/v1"]
	if firstFingerprint == "" {
		t.Fatal("missing stable fingerprint")
	}

	secondWriter, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: wordlist,
	})
	if err != nil {
		t.Fatalf("could not create second SARIF writer: %v", err)
	}
	secondWriter.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "found admin",
			LogicalLocation: "admin",
		}},
		word: "admin",
		line: 1,
	})
	secondWriter.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "new endpoint",
			LogicalLocation: "new-endpoint",
		}},
		word: "new-endpoint",
		line: 2,
	})
	if err := secondWriter.Close(nil); err != nil {
		t.Fatalf("could not close second SARIF writer: %v", err)
	}
	secondDocument := validateOfficialSARIFSchema(t, output)
	if secondDocument.Runs[0].Results[0].PartialFingerprints["gobuster/v1"] != firstFingerprint {
		t.Fatal("fingerprint changed between identical findings")
	}
	if secondDocument.Runs[0].Results[0].BaselineState != "unchanged" {
		t.Fatalf("existing result baselineState = %q, want unchanged", secondDocument.Runs[0].Results[0].BaselineState)
	}
	if secondDocument.Runs[0].Results[1].BaselineState != "new" {
		t.Fatalf("new result baselineState = %q, want new", secondDocument.Runs[0].Results[1].BaselineState)
	}
}

func TestSARIFWriterZeroResultsOfficialSchema(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "empty.sarif")
	writer, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: filepath.Join(t.TempDir(), "words.txt"),
	})
	if err != nil {
		t.Fatalf("could not create SARIF writer: %v", err)
	}
	if err := writer.Close(nil); err != nil {
		t.Fatalf("could not close SARIF writer: %v", err)
	}

	document := validateOfficialSARIFSchema(t, output)
	if len(document.Runs[0].Results) != 0 {
		t.Fatalf("results = %d, want 0", len(document.Runs[0].Results))
	}
	if !document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("zero-result scan must still report a successful invocation")
	}
}

func TestSARIFWriterFailureOfficialSchema(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "failed.sarif")
	writer, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: filepath.Join(t.TempDir(), "words.txt"),
	})
	if err != nil {
		t.Fatalf("could not create SARIF writer: %v", err)
	}
	writer.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "partial result",
			LogicalLocation: "admin",
		}},
		word: "admin",
		line: 1,
	})
	if err := writer.Close(errors.New("failed in /home/example/tmp-work and /tmp/scan")); err != nil {
		t.Fatalf("failed scan should still produce valid SARIF: %v", err)
	}

	document := validateOfficialSARIFSchema(t, output)
	invocation := document.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("failed scan reported executionSuccessful=true")
	}
	if len(invocation.ToolExecutionNotifications) != 1 {
		t.Fatalf("notifications = %d, want 1", len(invocation.ToolExecutionNotifications))
	}
	notification := invocation.ToolExecutionNotifications[0].Message.Text
	if strings.Contains(notification, "/home/") || strings.Contains(notification, "/tmp/") {
		t.Fatalf("failure message leaked an absolute path: %q", notification)
	}
	assertNoTemporaryPath(t, mustReadFile(t, output))
	temporaryFiles, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".failed.sarif.tmp-*"))
	if err != nil {
		t.Fatalf("could not inspect temporary files: %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("failure path left temporary files behind: %v", temporaryFiles)
	}
}

func TestSARIFArtifactURIEscaping(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	invalid := string([]byte{'w', 'o', 'r', 'd', 0xff, '.', 't', 'x', 't'})
	uri := sarifArtifactURI(filepath.Join(cwd, invalid), cwd)
	if !utf8.ValidString(uri) {
		t.Fatalf("escaped URI is not valid UTF-8: %q", uri)
	}
	if !strings.Contains(uri, "%FF") {
		t.Fatalf("invalid byte was not percent-escaped: %q", uri)
	}
	assertSafeRelativeURI(t, uri)

	symlinkPath := filepath.Join(cwd, "links", "wordlist.txt")
	if uri := sarifArtifactURI(symlinkPath, cwd); uri != "links/wordlist.txt" {
		t.Fatalf("symlink path URI = %q, want links/wordlist.txt", uri)
	}

	longPath := filepath.Join(cwd, strings.Repeat("a", 10000), "words.txt")
	longURI := sarifArtifactURI(longPath, cwd)
	assertSafeRelativeURI(t, longURI)
	if len(longURI) < 10000 {
		t.Fatalf("long path was unexpectedly truncated: %d", len(longURI))
	}

	outsideURI := sarifArtifactURI(filepath.Join(t.TempDir(), "words.txt"), cwd)
	assertSafeRelativeURI(t, outsideURI)
	if !strings.HasPrefix(outsideURI, "wordlists/") {
		t.Fatalf("outside path URI = %q, want wordlists/ prefix", outsideURI)
	}
}

func TestSARIFWriterLargeStreamAndCleanup(t *testing.T) {
	t.Parallel()

	const resultCount = 20000
	dir := t.TempDir()
	output := filepath.Join(dir, "large.sarif")
	writer, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: filepath.Join(t.TempDir(), "words.txt"),
	})
	if err != nil {
		t.Fatalf("could not create SARIF writer: %v", err)
	}
	for i := range resultCount {
		writer.WriteResult(&sarifLocatedResult{
			Result: sarifTestResult{finding: SARIFFinding{
				RuleID:          SARIFHTTPSuccessRuleID,
				Message:         "found endpoint",
				LogicalLocation: fmt.Sprintf("endpoint-%d", i),
			}},
			word: fmt.Sprintf("endpoint-%d", i),
			line: i + 1,
		})
	}
	if err := writer.Close(nil); err != nil {
		t.Fatalf("could not close large SARIF writer: %v", err)
	}
	if writer.resultCount != resultCount {
		t.Fatalf("resultCount = %d, want %d", writer.resultCount, resultCount)
	}

	count := countSARIFResults(t, output)
	if count != resultCount {
		t.Fatalf("streamed results = %d, want %d", count, resultCount)
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(dir, ".large.sarif.tmp-*"))
	if err != nil {
		t.Fatalf("could not inspect temporary files: %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", temporaryFiles)
	}
}

func TestSARIFWriterWriteFailureLeavesNoPartialFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	output := filepath.Join(dir, "broken.sarif")
	writer, err := NewSARIFWriter(output, SARIFRunInfo{
		Mode:     "directory enumeration",
		Target:   "http://example.test",
		Wordlist: filepath.Join(t.TempDir(), "words.txt"),
	})
	if err != nil {
		t.Fatalf("could not create SARIF writer: %v", err)
	}
	writer.WriteResult(&sarifLocatedResult{
		Result: sarifTestResult{finding: SARIFFinding{
			RuleID:          SARIFHTTPSuccessRuleID,
			Message:         "found admin",
			LogicalLocation: "admin",
		}},
		word: "admin",
		line: 1,
	})
	if err := writer.file.Close(); err != nil {
		t.Fatalf("could not close test file handle: %v", err)
	}
	if err := writer.Close(nil); err == nil {
		t.Fatal("write failure unexpectedly produced a report")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output exists after write failure: %v", err)
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(dir, ".broken.sarif.tmp-*"))
	if err != nil {
		t.Fatalf("could not inspect temporary files: %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("write failure left temporary files behind: %v", temporaryFiles)
	}
}

func TestSARIFSeverityMappingIsExplicit(t *testing.T) {
	t.Parallel()

	tests := map[SARIFSeverity]string{
		SARIFSeverityHigh:   "error",
		SARIFSeverityMedium: "warning",
		SARIFSeverityHint:   "note",
	}
	for severity, want := range tests {
		if got := SARIFSeverityLevels[severity]; got != want {
			t.Fatalf("severity %q maps to %q, want %q", severity, got, want)
		}
	}

	if SARIFRuleForStatus(503) != SARIFHTTPServerErrorRuleID {
		t.Fatal("5xx status no longer maps to the high-severity rule")
	}
	if SARIFRuleForStatus(403) != SARIFHTTPAccessRuleID {
		t.Fatal("403 status no longer maps to the medium-severity rule")
	}
	if SARIFRuleForStatus(200) != SARIFHTTPSuccessRuleID {
		t.Fatal("200 status no longer maps to the hint rule")
	}
}

func BenchmarkSARIFWriterStreaming(b *testing.B) {
	const results = 1000

	b.ReportAllocs()
	for b.Loop() {
		output := filepath.Join(b.TempDir(), "benchmark.sarif")
		writer, err := NewSARIFWriter(output, SARIFRunInfo{
			Mode:     "directory enumeration",
			Target:   "http://example.test",
			Wordlist: filepath.Join(b.TempDir(), "words.txt"),
		})
		if err != nil {
			b.Fatalf("could not create SARIF writer: %v", err)
		}
		for i := range results {
			word := fmt.Sprintf("endpoint-%d", i)
			writer.WriteResult(&sarifLocatedResult{
				Result: sarifTestResult{finding: SARIFFinding{
					RuleID:          SARIFHTTPSuccessRuleID,
					Message:         "found endpoint",
					LogicalLocation: word,
				}},
				word: word,
				line: i + 1,
			})
		}
		if err := writer.Close(nil); err != nil {
			b.Fatalf("could not close SARIF writer: %v", err)
		}
	}
}

func validateOfficialSARIFSchema(t *testing.T, filename string) decodedSARIFReport {
	t.Helper()

	schemaFile, err := os.Open("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("could not open official SARIF schema: %v", err)
	}
	defer schemaFile.Close()

	schemaDocument, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatalf("could not parse official SARIF schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sarif-schema-2.1.0.json", schemaDocument); err != nil {
		t.Fatalf("could not register official SARIF schema: %v", err)
	}
	compiled, err := compiler.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("could not compile official SARIF schema: %v", err)
	}

	reportFile, err := os.Open(filename)
	if err != nil {
		t.Fatalf("could not open SARIF output: %v", err)
	}
	defer reportFile.Close()
	reportDocument, err := jsonschema.UnmarshalJSON(reportFile)
	if err != nil {
		t.Fatalf("could not parse SARIF output: %v", err)
	}
	if err := compiled.Validate(reportDocument); err != nil {
		t.Fatalf("official SARIF schema validation failed: %v", err)
	}

	var report decodedSARIFReport
	if err := json.Unmarshal([]byte(mustReadFile(t, filename)), &report); err != nil {
		t.Fatalf("could not decode SARIF output: %v", err)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(report.Runs))
	}
	return report
}

func assertResult(t *testing.T, result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	BaselineState       string            `json:"baselineState"`
}, ruleID, level string, line int, logicalLocation string,
) {
	t.Helper()

	if result.RuleID != ruleID {
		t.Fatalf("ruleId = %q, want %q", result.RuleID, ruleID)
	}
	if result.Level != level {
		t.Fatalf("level = %q, want %q", result.Level, level)
	}
	if result.Message.Text == "" {
		t.Fatal("message text is empty")
	}
	region := result.Locations[0].PhysicalLocation.Region
	if region.StartLine != line || region.EndLine != line {
		t.Fatalf("region lines = %d-%d, want %d-%d", region.StartLine, region.EndLine, line, line)
	}
	if len(result.Locations[0].LogicalLocations) != 1 {
		t.Fatalf("logical locations = %d, want 1", len(result.Locations[0].LogicalLocations))
	}
	if result.Locations[0].LogicalLocations[0].Name != logicalLocation {
		t.Fatalf("logical location = %q, want %q", result.Locations[0].LogicalLocations[0].Name, logicalLocation)
	}
}

func assertSafeRelativeURI(t *testing.T, uri string) {
	t.Helper()

	if err := sarifValidateURI(uri); err != nil {
		t.Fatalf("unsafe artifact URI %q: %v", uri, err)
	}
	for _, forbidden := range []string{"/home/", "/tmp/", `C:\`, "file://"} {
		if strings.Contains(uri, forbidden) {
			t.Fatalf("artifact URI %q contains forbidden path fragment %q", uri, forbidden)
		}
	}
}

func assertNoTemporaryPath(t *testing.T, value string) {
	t.Helper()

	for _, forbidden := range []string{"/home/", "/tmp/", `C:\`} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("output contains forbidden path fragment %q", forbidden)
		}
	}
}

func countSARIFResults(t *testing.T, filename string) int {
	t.Helper()

	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("could not open SARIF output: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("could not scan SARIF output: %v", err)
		}
		if token == "results" {
			break
		}
	}
	token, err := decoder.Token()
	if err != nil {
		t.Fatalf("could not find results array: %v", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		t.Fatalf("results is not an array: %#v", token)
	}

	count := 0
	for decoder.More() {
		var result json.RawMessage
		if err := decoder.Decode(&result); err != nil {
			t.Fatalf("could not decode result %d: %v", count, err)
		}
		count++
	}
	return count
}

func mustReadFile(t *testing.T, filename string) string {
	t.Helper()

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("could not read %s: %v", filename, err)
	}
	return string(content)
}
