package libgobuster

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const sarifWriteBufferSize = 64 * 1024

// SARIFRunInfo contains the per-invocation metadata needed by the SARIF writer.
type SARIFRunInfo struct {
	Mode      string
	Target    string
	Wordlist  string
	StartTime time.Time
}

// SARIFWriter streams one SARIF 2.1.0 run to a temporary file and atomically
// publishes it when Close succeeds.
type SARIFWriter struct {
	filename     string
	tempFilename string
	file         *os.File
	buffer       *bufio.Writer
	cwd          string
	artifactURI  string
	automationID string
	startTime    time.Time
	baseline     map[string]struct{}
	resultCount  int
	writeErr     error
	closed       bool
}

type sarifLocatedResult struct {
	Result
	word string
	line int
}

func (r *sarifLocatedResult) sarifContext() (string, int) {
	return r.word, r.line
}

// NewSARIFWriter creates a SARIF writer. If filename already contains a
// matching SARIF run, its fingerprints are used to emit baselineState.
func NewSARIFWriter(filename string, info SARIFRunInfo) (*SARIFWriter, error) {
	if filename == "" {
		return nil, errors.New("SARIF output filename is empty")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory for SARIF output: %w", err)
	}

	startTime := info.StartTime
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	automationID := sarifAutomationID(info.Mode + "\x00" + info.Target)
	baseline := loadSARIFBaseline(filename, automationID)

	tempFile, err := os.CreateTemp(filepath.Dir(filename), "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary SARIF output: %w", err)
	}

	writer := &SARIFWriter{
		filename:     filename,
		tempFilename: tempFile.Name(),
		file:         tempFile,
		buffer:       bufio.NewWriterSize(tempFile, sarifWriteBufferSize),
		cwd:          cwd,
		artifactURI:  sarifArtifactURI(info.Wordlist, cwd),
		automationID: automationID,
		startTime:    startTime,
		baseline:     baseline,
	}
	if err := writer.writePreamble(info); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
		return nil, err
	}
	return writer, nil
}

func (w *SARIFWriter) writePreamble(info SARIFRunInfo) error {
	driver := sarifDriver{
		Name:            SARIFToolName,
		Version:         VERSION,
		SemanticVersion: VERSION,
		InformationURI:  SARIFToolInformation,
		Rules:           sarifRuleDescriptors(),
	}
	driverJSON, err := json.Marshal(driver)
	if err != nil {
		return fmt.Errorf("failed to encode SARIF driver: %w", err)
	}
	automationID, err := json.Marshal(w.automationID)
	if err != nil {
		return fmt.Errorf("failed to encode SARIF automation id: %w", err)
	}

	_, _ = w.buffer.WriteString(`{"$schema":`)
	schemaJSON, err := json.Marshal(SARIFSchemaURI)
	if err != nil {
		return fmt.Errorf("failed to encode SARIF schema URI: %w", err)
	}
	_, _ = w.buffer.Write(schemaJSON)
	_, _ = w.buffer.WriteString(`,"version":"` + SARIFVersion + `","runs":[{"tool":{"driver":`)
	_, _ = w.buffer.Write(driverJSON)
	_, _ = w.buffer.WriteString(`},"automationDetails":{"id":`)
	_, _ = w.buffer.Write(automationID)
	_, _ = w.buffer.WriteString(`},"columnKind":"unicodeCodePoints","results":[`)
	return nil
}

// WriteResult appends one result without retaining prior results in memory.
func (w *SARIFWriter) WriteResult(result Result) {
	if w.writeErr != nil || w.closed {
		return
	}

	word, line := "", 1
	baseResult := result
	if located, ok := result.(*sarifLocatedResult); ok {
		word, line = located.sarifContext()
		baseResult = located.Result
	}

	finding, ok := sarifFindingForResult(baseResult)
	if !ok {
		text, err := baseResult.ResultToString()
		if err != nil {
			text = "gobuster result"
		}
		finding = SARIFFinding{
			RuleID:  SARIFFallbackRuleID,
			Message: sarifText(strings.TrimSpace(text)),
		}
	}

	rule, ruleIndex, ruleFound := sarifRuleByID(finding.RuleID)
	if !ruleFound {
		rule, ruleIndex, _ = sarifRuleByID(SARIFFallbackRuleID)
		finding.RuleID = SARIFFallbackRuleID
	}
	if finding.Message == "" {
		finding.Message = rule.Description
	}

	fingerprint := sarifFingerprint(w.automationID, finding.RuleID, finding.LogicalLocation)
	baselineState := "new"
	if _, exists := w.baseline[fingerprint]; exists {
		baselineState = "unchanged"
	}

	resultJSON := sarifResult{
		RuleID:    finding.RuleID,
		RuleIndex: ruleIndex,
		Level:     SARIFSeverityLevels[rule.Severity],
		Message:   sarifMessage{Text: sarifSanitizeText(finding.Message, w.cwd)},
		Locations: []sarifLocation{newSARIFLocation(w.artifactURI, word, line, finding.LogicalLocation)},
		PartialFingerprints: map[string]string{
			"gobuster/v1": fingerprint,
		},
		BaselineState: baselineState,
		Properties:    sanitizedSARIFProperties(finding.Properties, w.cwd),
	}
	if err := validateSARIFResult(resultJSON, w.resultCount); err != nil {
		w.writeErr = err
		return
	}
	resultBytes, err := json.Marshal(resultJSON)
	if err != nil {
		w.writeErr = fmt.Errorf("runs[0].results[%d]: failed to encode result: %w", w.resultCount, err)
		return
	}

	if w.resultCount > 0 {
		if _, err := w.buffer.WriteString(","); err != nil {
			w.writeErr = fmt.Errorf("runs[0].results[%d]: failed to write separator: %w", w.resultCount, err)
			return
		}
	}
	if _, err := w.buffer.Write(resultBytes); err != nil {
		w.writeErr = fmt.Errorf("runs[0].results[%d]: failed to write result: %w", w.resultCount, err)
		return
	}
	w.resultCount++

	if w.buffer.Buffered() >= sarifWriteBufferSize {
		if err := w.buffer.Flush(); err != nil {
			w.writeErr = fmt.Errorf("runs[0].results[%d]: failed to flush result chunk: %w", w.resultCount-1, err)
		}
	}
}

// Close finishes the JSON document and publishes it only after a self-check.
// A scan error is represented by invocation.executionSuccessful=false.
func (w *SARIFWriter) Close(runErr error) error {
	if w.closed {
		return w.writeErr
	}
	w.closed = true

	if w.writeErr != nil {
		w.cleanup()
		return w.writeErr
	}

	endTime := time.Now().UTC()
	invocation := sarifInvocation{
		ExecutionSuccessful: runErr == nil,
		StartTimeUTC:        w.startTime.Format(time.RFC3339Nano),
		EndTimeUTC:          endTime.Format(time.RFC3339Nano),
	}
	if runErr != nil {
		invocation.ToolExecutionNotifications = []sarifNotification{{
			Level:   "error",
			Message: sarifMessage{Text: "gobuster scan failed: " + sarifErrorText(runErr, w.cwd)},
		}}
	}

	invocationJSON, err := json.Marshal(invocation)
	if err != nil {
		w.cleanup()
		return fmt.Errorf("failed to encode SARIF invocation: %w", err)
	}

	if _, err := w.buffer.WriteString(`],"invocations":[`); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to finish SARIF results: %w", err)
	}
	if _, err := w.buffer.Write(invocationJSON); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to write SARIF invocation: %w", err)
	}
	if _, err := w.buffer.WriteString(`],"properties":{"resultCount":` + strconv.Itoa(w.resultCount) + `}}]}`); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to finish SARIF document: %w", err)
	}
	if err := w.buffer.Flush(); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to flush SARIF document: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to sync SARIF document: %w", err)
	}
	if err := w.file.Close(); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to close SARIF document: %w", err)
	}

	if err := validateSARIFJSON(w.tempFilename); err != nil {
		w.cleanup()
		return err
	}
	if err := publishSARIF(w.tempFilename, w.filename); err != nil {
		w.cleanup()
		return fmt.Errorf("failed to publish SARIF output: %w", err)
	}
	w.tempFilename = ""
	return nil
}

func publishSARIF(tempFilename, filename string) error {
	err := os.Rename(tempFilename, filename)
	if err == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return err
	}
	// Windows does not replace an existing destination atomically.
	if removeErr := os.Remove(filename); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return err
	}
	return os.Rename(tempFilename, filename)
}

func (w *SARIFWriter) cleanup() {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if w.tempFilename != "" {
		_ = os.Remove(w.tempFilename)
		w.tempFilename = ""
	}
}

func sarifFindingForResult(result Result) (SARIFFinding, bool) {
	sarifResult, ok := result.(SARIFResult)
	if !ok {
		return SARIFFinding{}, false
	}
	return sarifResult.ToSARIF(), true
}

func newSARIFLocation(artifactURI, word string, line int, logicalLocation string) sarifLocation {
	if line < 1 {
		line = 1
	}
	region := sarifRegion{
		StartLine:   line,
		StartColumn: 1,
		EndLine:     line,
		EndColumn:   sarifColumnEnd(word),
	}
	if word != "" {
		region.Snippet = &sarifArtifactContent{Text: sarifText(word)}
	}
	location := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
			Region:           region,
		},
	}
	if logicalLocation != "" {
		safeLogicalLocation := sarifSanitizeText(logicalLocation, "")
		location.LogicalLocations = []sarifLogicalLocation{{
			Name:               safeLogicalLocation,
			FullyQualifiedName: safeLogicalLocation,
			Kind:               "resource",
		}}
	}
	return location
}

func sanitizedSARIFProperties(properties map[string]string, cwd string) map[string]string {
	if len(properties) == 0 {
		return nil
	}
	sanitized := make(map[string]string, len(properties))
	for key, value := range properties {
		sanitized[sarifText(key)] = sarifSanitizeText(value, cwd)
	}
	return sanitized
}

func validateSARIFResult(result sarifResult, index int) error {
	path := fmt.Sprintf("runs[0].results[%d]", index)
	if result.RuleID == "" {
		return fmt.Errorf("%s.ruleId: must not be empty", path)
	}
	switch result.Level {
	case "none", "note", "warning", "error":
	default:
		return fmt.Errorf("%s.level: unsupported level %q", path, result.Level)
	}
	if strings.TrimSpace(result.Message.Text) == "" {
		return fmt.Errorf("%s.message.text: must not be empty", path)
	}
	if len(result.Locations) == 0 {
		return fmt.Errorf("%s.locations: must contain at least one location", path)
	}
	for i, location := range result.Locations {
		if err := sarifValidateURI(location.PhysicalLocation.ArtifactLocation.URI); err != nil {
			return fmt.Errorf("%s.locations[%d].physicalLocation.artifactLocation.uri: %w", path, i, err)
		}
		region := location.PhysicalLocation.Region
		if region.StartLine < 1 {
			return fmt.Errorf("%s.locations[%d].physicalLocation.region.startLine: must be at least 1", path, i)
		}
		if region.StartColumn < 1 {
			return fmt.Errorf("%s.locations[%d].physicalLocation.region.startColumn: must be at least 1", path, i)
		}
		if region.EndLine < region.StartLine {
			return fmt.Errorf("%s.locations[%d].physicalLocation.region.endLine: must be greater than or equal to startLine", path, i)
		}
		if region.EndColumn < region.StartColumn {
			return fmt.Errorf("%s.locations[%d].physicalLocation.region.endColumn: must be greater than or equal to startColumn", path, i)
		}
	}
	switch result.BaselineState {
	case "new", "unchanged", "updated", "absent":
	default:
		return fmt.Errorf("%s.baselineState: unsupported value %q", path, result.BaselineState)
	}
	return nil
}

func validateSARIFJSON(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("SARIF self-check could not open output: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	for {
		if _, err := decoder.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("SARIF self-check failed near byte %d: %w", decoder.InputOffset(), err)
		}
	}
	return nil
}

func sarifRuleDescriptors() []sarifReportingDescriptor {
	descriptors := make([]sarifReportingDescriptor, len(SARIFRules))
	for i, rule := range SARIFRules {
		descriptors[i] = sarifReportingDescriptor{
			ID:               rule.ID,
			Name:             rule.Name,
			ShortDescription: sarifMessage{Text: rule.Description},
			FullDescription:  sarifMessage{Text: rule.Description},
			DefaultConfiguration: sarifReportingConfiguration{
				Level: SARIFSeverityLevels[rule.Severity],
			},
			Properties: sarifPropertyBag{Tags: rule.Tags},
		}
	}
	return descriptors
}

func loadSARIFBaseline(filename, automationID string) map[string]struct{} {
	baseline := map[string]struct{}{}
	file, err := os.Open(filename)
	if err != nil {
		return baseline
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	token, err := decoder.Token()
	if err != nil {
		return baseline
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return baseline
	}

	for decoder.More() {
		key, keyErr := decoder.Token()
		if keyErr != nil {
			return baseline
		}
		if key != "runs" {
			if err := skipJSONValue(decoder); err != nil {
				return baseline
			}
			continue
		}
		runsToken, runsErr := decoder.Token()
		if runsErr != nil {
			return baseline
		}
		if delimiter, ok := runsToken.(json.Delim); !ok || delimiter != '[' {
			return baseline
		}
		for decoder.More() {
			runBaseline, runID, runErr := readSARIFBaselineRun(decoder)
			if runErr != nil {
				return baseline
			}
			if runID == automationID {
				return runBaseline
			}
		}
		if _, err := decoder.Token(); err != nil {
			return baseline
		}
	}
	return baseline
}

func readSARIFBaselineRun(decoder *json.Decoder) (map[string]struct{}, string, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, "", err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, "", errors.New("SARIF run is not an object")
	}

	fingerprints := map[string]struct{}{}
	automationID := ""
	for decoder.More() {
		key, keyErr := decoder.Token()
		if keyErr != nil {
			return nil, "", keyErr
		}
		switch key {
		case "automationDetails":
			var details struct {
				ID string `json:"id"`
			}
			if err := decoder.Decode(&details); err != nil {
				return nil, "", err
			}
			automationID = details.ID
		case "results":
			resultsToken, resultsErr := decoder.Token()
			if resultsErr != nil {
				return nil, "", resultsErr
			}
			if delimiter, ok := resultsToken.(json.Delim); !ok || delimiter != '[' {
				return nil, "", errors.New("SARIF results is not an array")
			}
			for decoder.More() {
				var result struct {
					PartialFingerprints map[string]string `json:"partialFingerprints"`
				}
				if err := decoder.Decode(&result); err != nil {
					return nil, "", err
				}
				if fingerprint := result.PartialFingerprints["gobuster/v1"]; fingerprint != "" {
					fingerprints[fingerprint] = struct{}{}
				}
			}
			if _, err := decoder.Token(); err != nil {
				return nil, "", err
			}
		default:
			if err := skipJSONValue(decoder); err != nil {
				return nil, "", err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, "", err
	}
	return fingerprints, automationID, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return nil
	}
}

type sarifDriver struct {
	Name            string                     `json:"name"`
	Version         string                     `json:"version"`
	SemanticVersion string                     `json:"semanticVersion"`
	InformationURI  string                     `json:"informationUri"`
	Rules           []sarifReportingDescriptor `json:"rules"`
}

type sarifReportingDescriptor struct {
	ID                   string                      `json:"id"`
	Name                 string                      `json:"name"`
	ShortDescription     sarifMessage                `json:"shortDescription"`
	FullDescription      sarifMessage                `json:"fullDescription"`
	DefaultConfiguration sarifReportingConfiguration `json:"defaultConfiguration"`
	Properties           sarifPropertyBag            `json:"properties"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level"`
}

type sarifPropertyBag struct {
	Tags []string `json:"tags"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	BaselineState       string            `json:"baselineState"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int                   `json:"startLine"`
	StartColumn int                   `json:"startColumn"`
	EndLine     int                   `json:"endLine"`
	EndColumn   int                   `json:"endColumn"`
	Snippet     *sarifArtifactContent `json:"snippet,omitempty"`
}

type sarifArtifactContent struct {
	Text string `json:"text"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	StartTimeUTC               string              `json:"startTimeUtc"`
	EndTimeUTC                 string              `json:"endTimeUtc"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}
