package gobusterdns

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/fatih/color"
)

var green = color.New(color.FgGreen).FprintfFunc()

// Result represents a single result
type Result struct {
	Subdomain string
	IPs       []netip.Addr
	CNAME     string
}

// ResultToString converts the Result to its textual representation
func (r Result) ResultToString() (string, error) {
	buf := &bytes.Buffer{}

	if _, err := fmt.Fprintf(buf, "%s", r.Subdomain); err != nil {
		return "", err
	}

	if len(r.IPs) > 0 {
		ips := make([]string, len(r.IPs))
		for i := range r.IPs {
			ips[i] = r.IPs[i].String()
		}
		green(buf, " %s", strings.Join(ips, ","))
	}

	if r.CNAME != "" {
		green(buf, " CNAME: %s", r.CNAME)
	}

	if _, err := fmt.Fprintf(buf, "\n"); err != nil {
		return "", err
	}

	s := buf.String()
	return s, nil
}

// ToSARIF converts the result into stable SARIF data.
func (r Result) ToSARIF() libgobuster.SARIFFinding {
	properties := map[string]string{}
	if len(r.IPs) > 0 {
		ips := make([]string, len(r.IPs))
		for i := range r.IPs {
			ips[i] = r.IPs[i].String()
		}
		properties["ips"] = strings.Join(ips, ",")
	}
	if r.CNAME != "" {
		properties["cname"] = r.CNAME
	}

	message := fmt.Sprintf("DNS subdomain discovered: %s", r.Subdomain)
	if len(r.IPs) > 0 {
		message = fmt.Sprintf("%s (%s)", message, properties["ips"])
	}
	if r.CNAME != "" {
		message = fmt.Sprintf("%s (CNAME %s)", message, r.CNAME)
	}

	return libgobuster.SARIFFinding{
		RuleID:          libgobuster.SARIFDNSSubdomainRuleID,
		Message:         message,
		LogicalLocation: r.Subdomain,
		Properties:      properties,
	}
}
