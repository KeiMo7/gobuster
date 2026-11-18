package gobusterdns

import (
	"net/netip"
	"testing"

	"github.com/OJ/gobuster/v3/libgobuster"
)

func TestResultToSARIF(t *testing.T) {
	t.Parallel()

	result := Result{
		Subdomain: "dev.example.com",
		IPs:       []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		CNAME:     "dev.example.net",
	}
	finding := result.ToSARIF()

	if finding.RuleID != libgobuster.SARIFDNSSubdomainRuleID {
		t.Fatalf("ruleId = %q, want %q", finding.RuleID, libgobuster.SARIFDNSSubdomainRuleID)
	}
	if finding.LogicalLocation != "dev.example.com" {
		t.Fatalf("logical location = %q, want dev.example.com", finding.LogicalLocation)
	}
	if finding.Properties["ips"] != "192.0.2.10" {
		t.Fatalf("ips = %q, want 192.0.2.10", finding.Properties["ips"])
	}
	if finding.Properties["cname"] != "dev.example.net" {
		t.Fatalf("cname = %q, want dev.example.net", finding.Properties["cname"])
	}
	if level := libgobuster.SARIFLevelForRule(finding.RuleID); level != "note" {
		t.Fatalf("level = %q, want note", level)
	}
}
