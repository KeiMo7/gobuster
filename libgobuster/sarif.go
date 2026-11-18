package libgobuster

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	SARIFVersion         = "2.1.0"
	SARIFSchemaURI       = "https://json.schemastore.org/sarif-2.1.0.json"
	SARIFToolName        = "gobuster"
	SARIFToolInformation = "https://github.com/OJ/gobuster"
	SARIFRulePrefix      = "gobuster/"
)

type SARIFSeverity string

const (
	SARIFSeverityHigh   SARIFSeverity = "high"
	SARIFSeverityMedium SARIFSeverity = "medium"
	SARIFSeverityHint   SARIFSeverity = "hint"
)

// SARIFSeverityLevels is the single source of truth for SARIF result levels.
var SARIFSeverityLevels = map[SARIFSeverity]string{
	SARIFSeverityHigh:   "error",
	SARIFSeverityMedium: "warning",
	SARIFSeverityHint:   "note",
}

const (
	SARIFFallbackRuleID        = "gobuster/result"
	SARIFHTTPSuccessRuleID     = "gobuster/http/success"
	SARIFHTTPRedirectRuleID    = "gobuster/http/redirect"
	SARIFHTTPAccessRuleID      = "gobuster/http/access-control"
	SARIFHTTPServerErrorRuleID = "gobuster/http/server-error"
	SARIFHTTPOtherRuleID       = "gobuster/http/other"
	SARIFDNSSubdomainRuleID    = "gobuster/dns/subdomain"
	SARIFTFTPSuccessRuleID     = "gobuster/tftp/file"
	SARIFS3BucketRuleID        = "gobuster/s3/bucket"
	SARIFGCSBucketRuleID       = "gobuster/gcs/bucket"
)

// SARIFRuleDefinition describes a stable reporting rule.
type SARIFRuleDefinition struct {
	ID          string
	Name        string
	Description string
	Severity    SARIFSeverity
	Tags        []string
}

var SARIFRules = []SARIFRuleDefinition{
	{
		ID:          SARIFHTTPSuccessRuleID,
		Name:        "HTTP resource discovered",
		Description: "gobuster found a resource that returned a successful HTTP status code.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "http"},
	},
	{
		ID:          SARIFHTTPRedirectRuleID,
		Name:        "HTTP redirect discovered",
		Description: "gobuster found a resource that returned an HTTP redirect status code.",
		Severity:    SARIFSeverityMedium,
		Tags:        []string{"discovery", "http", "redirect"},
	},
	{
		ID:          SARIFHTTPAccessRuleID,
		Name:        "Access-controlled HTTP resource discovered",
		Description: "gobuster found a resource that returned an HTTP authentication or authorization status code.",
		Severity:    SARIFSeverityMedium,
		Tags:        []string{"discovery", "http", "access-control"},
	},
	{
		ID:          SARIFHTTPServerErrorRuleID,
		Name:        "HTTP server error discovered",
		Description: "gobuster found a resource that returned an HTTP server error status code.",
		Severity:    SARIFSeverityHigh,
		Tags:        []string{"discovery", "http", "server-error"},
	},
	{
		ID:          SARIFHTTPOtherRuleID,
		Name:        "HTTP response discovered",
		Description: "gobuster found a resource that returned an HTTP status code outside the standard discovery categories.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "http"},
	},
	{
		ID:          SARIFDNSSubdomainRuleID,
		Name:        "DNS subdomain discovered",
		Description: "gobuster resolved a subdomain for the target domain.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "dns"},
	},
	{
		ID:          SARIFTFTPSuccessRuleID,
		Name:        "TFTP file discovered",
		Description: "gobuster found a file exposed by the target TFTP service.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "tftp"},
	},
	{
		ID:          SARIFS3BucketRuleID,
		Name:        "S3 bucket discovered",
		Description: "gobuster found an S3 bucket.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "s3"},
	},
	{
		ID:          SARIFGCSBucketRuleID,
		Name:        "GCS bucket discovered",
		Description: "gobuster found a Google Cloud Storage bucket.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery", "gcs"},
	},
	{
		ID:          SARIFFallbackRuleID,
		Name:        "gobuster result",
		Description: "gobuster produced a result that does not have a specialized SARIF rule.",
		Severity:    SARIFSeverityHint,
		Tags:        []string{"discovery"},
	},
}

// SARIFFinding is the stable, output-format-neutral representation of one result.
type SARIFFinding struct {
	RuleID          string
	Message         string
	LogicalLocation string
	Properties      map[string]string
}

// SARIFResult can be implemented by result types that provide structured SARIF data.
type SARIFResult interface {
	Result
	ToSARIF() SARIFFinding
}

// SARIFTargetProvider exposes a stable target identity for fingerprints and baselines.
type SARIFTargetProvider interface {
	SARIFTarget() string
}

// SARIFRuleForStatus maps an HTTP status to a stable, mode-independent rule.
func SARIFRuleForStatus(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return SARIFHTTPSuccessRuleID
	case statusCode >= 300 && statusCode < 400:
		return SARIFHTTPRedirectRuleID
	case statusCode == 401 || statusCode == 403:
		return SARIFHTTPAccessRuleID
	case statusCode >= 500 && statusCode < 600:
		return SARIFHTTPServerErrorRuleID
	default:
		return SARIFHTTPOtherRuleID
	}
}

// SARIFLevelForRule returns the configured SARIF level for a rule ID.
func SARIFLevelForRule(ruleID string) string {
	rule, _, ok := sarifRuleByID(ruleID)
	if !ok {
		rule, _, _ = sarifRuleByID(SARIFFallbackRuleID)
	}
	return SARIFSeverityLevels[rule.Severity]
}

func sarifRuleByID(ruleID string) (SARIFRuleDefinition, int, bool) {
	for i := range SARIFRules {
		if SARIFRules[i].ID == ruleID {
			return SARIFRules[i], i, true
		}
	}
	return SARIFRuleDefinition{}, 0, false
}

func sarifFingerprint(target, ruleID, logicalLocation string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + ruleID + "\x00" + logicalLocation))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sarifAutomationID(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "gobuster/" + hex.EncodeToString(sum[:8])
}

func sarifArtifactURI(path, cwd string) string {
	if path == "" || path == "-" {
		return "stdin"
	}

	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Join(cwd, cleaned)
	}

	relative, err := filepath.Rel(cwd, cleaned)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		sum := sha256.Sum256([]byte(cleaned))
		relative = filepath.Join("wordlists", hex.EncodeToString(sum[:8]), filepath.Base(cleaned))
	}

	relative = filepath.ToSlash(relative)
	relative = strings.TrimPrefix(relative, "./")
	return sarifEscapeURI(relative)
}

func sarifEscapeURI(value string) string {
	const upperHex = "0123456789ABCDEF"

	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		b := value[i]
		if isSARIFURIUnreserved(b) || b == '/' {
			builder.WriteByte(b)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(upperHex[b>>4])
		builder.WriteByte(upperHex[b&0x0f])
	}
	return builder.String()
}

func isSARIFURIUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' ||
		b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func sarifText(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	return ansiEscapePattern.ReplaceAllString(value, "")
}

func sarifErrorText(err error, cwd string) string {
	if err == nil {
		return ""
	}
	return sarifSanitizeText(err.Error(), cwd)
}

func sarifSanitizeText(value, cwd string) string {
	message := value
	for _, prefix := range []string{cwd, filepath.ToSlash(cwd), os.TempDir(), filepath.ToSlash(os.TempDir())} {
		if prefix != "" && prefix != "." {
			message = strings.ReplaceAll(message, prefix, "<path>")
		}
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
		message = strings.ReplaceAll(message, home, "<home>")
	}
	message = sarifAbsolutePathPattern.ReplaceAllString(message, "<path>")
	return sarifText(message)
}

func sarifColumnEnd(value string) int {
	columns := utf8.RuneCountInString(value) + 1
	if columns < 2 {
		return 2
	}
	return columns
}

func sarifValidateURI(uri string) error {
	if uri == "" {
		return errors.New("uri is empty")
	}
	if strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, `\\`) {
		return fmt.Errorf("uri %q must be relative", uri)
	}
	if len(uri) >= 2 && uri[1] == ':' {
		return fmt.Errorf("uri %q must not contain a drive letter", uri)
	}
	if parsed, err := url.Parse(uri); err == nil && parsed.IsAbs() {
		return fmt.Errorf("uri %q must not be absolute", uri)
	}
	return nil
}

var (
	ansiEscapePattern        = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	sarifAbsolutePathPattern = regexp.MustCompile(`(?i)(?:[a-z]:[\\/][^\s"']*|/(?:home|tmp|var/folders|private/var|users|root)/[^\s"']*)`)
)
