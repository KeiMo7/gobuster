package dir

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalcli "github.com/OJ/gobuster/v3/cli"
	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"
)

func TestDirSARIFOutputTracksWordlistLines(t *testing.T) {
	server := newSARIFTestServer(t)
	defer server.Close()

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nmissing\napi\n"), 0o600); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}
	output := filepath.Join(t.TempDir(), "results.sarif")

	_, err := runDirScan(t, server.URL, wordlist, output)
	if err != nil {
		t.Fatalf("gobuster returned an error: %v", err)
	}

	var report struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("could not read SARIF output: %v", err)
	}
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatalf("could not decode SARIF output: %v", err)
	}

	run := report.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	if !run.Invocations[0].ExecutionSuccessful {
		t.Fatal("successful scan reported executionSuccessful=false")
	}

	found := map[int]string{}
	for _, result := range run.Results {
		location := result.Locations[0].PhysicalLocation
		found[location.Region.StartLine] = result.RuleID + "/" + result.Level
		if location.Region.EndLine != location.Region.StartLine {
			t.Fatalf("result spans lines %d-%d, want a single line", location.Region.StartLine, location.Region.EndLine)
		}
		if location.ArtifactLocation.URI == "" || filepath.IsAbs(location.ArtifactLocation.URI) {
			t.Fatalf("invalid artifact URI %q", location.ArtifactLocation.URI)
		}
	}
	if found[1] != libgobuster.SARIFHTTPSuccessRuleID+"/note" {
		t.Fatalf("line 1 result = %q, want success/note", found[1])
	}
	if found[3] != libgobuster.SARIFHTTPServerErrorRuleID+"/error" {
		t.Fatalf("line 3 result = %q, want server-error/error", found[3])
	}
	if strings.Contains(string(content), filepath.Dir(wordlist)) {
		t.Fatal("SARIF output leaked the temporary wordlist directory")
	}
}

func TestDirDefaultOutputUnchanged(t *testing.T) {
	server := newSARIFTestServer(t)
	defer server.Close()

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}

	output, err := runDirScan(t, server.URL, wordlist, "")
	if err != nil {
		t.Fatalf("gobuster returned an error: %v", err)
	}
	want := fmt.Sprintf("%-20s (Status: %d) [Size: %d]\n", "admin", http.StatusOK, len("admin body"))
	if output != want {
		t.Fatalf("default output changed:\n got: %q\nwant: %q", output, want)
	}
}

func TestDirSARIFScanFailureWritesValidInvocation(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	serverURL := server.URL
	server.Close()

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}
	output := filepath.Join(t.TempDir(), "failed.sarif")

	_, err := runDirScan(t, serverURL, wordlist, output)
	if err == nil {
		t.Fatal("gobuster unexpectedly succeeded against a closed server")
	}

	var report struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	content, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatalf("failed scan did not leave a SARIF report: %v", readErr)
	}
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatalf("could not decode failure SARIF output: %v", err)
	}
	if report.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("failed scan reported executionSuccessful=true")
	}
}

func newSARIFTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "admin body")
		case "/api":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "api error")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func runDirScan(t *testing.T, rawURL, wordlist, sarifOutput string) (string, error) {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("could not parse test server URL: %v", err)
	}
	pluginOpts := gobusterdir.NewOptions()
	pluginOpts.URL = parsedURL
	pluginOpts.Timeout = 5 * time.Second
	pluginOpts.StatusCodesBlacklist = "404"
	pluginOpts.StatusCodesBlacklistParsed.Add(http.StatusNotFound)

	globalOpts := libgobuster.Options{
		Threads:     1,
		Wordlist:    wordlist,
		Quiet:       true,
		NoProgress:  true,
		NoError:     true,
		SARIFOutput: sarifOutput,
	}
	log := libgobuster.NewLogger(false)
	plugin, err := gobusterdir.New(&globalOpts, pluginOpts, log)
	if err != nil {
		t.Fatalf("could not create directory plugin: %v", err)
	}

	return captureStdout(t, func() error {
		return internalcli.Gobuster(t.Context(), &globalOpts, plugin, log)
	})
}

func captureStdout(t *testing.T, run func() error) (string, error) {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("could not create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	runErr := run()
	if err := writer.Close(); err != nil {
		t.Fatalf("could not close stdout pipe: %v", err)
	}
	content, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("could not read stdout: %v", readErr)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("could not close stdout reader: %v", err)
	}
	return string(content), runErr
}
