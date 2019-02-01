package checker

import (
	"reflect"
	"testing"
)

func TestGetKeyValuePairs(t *testing.T) {
	tests := []struct {
		txt  string
		ld   string
		pd   string
		want map[string]string
	}{
		{"", ";", "=", map[string]string{}},
		{"v=STSv1; foo;", ";", "=", map[string]string{
			"v": "STSv1",
		}},
		{"v=STSv1; id=20171114T070707;", ";", "=", map[string]string{
			"v":  "STSv1",
			"id": "20171114T070707",
		}},
		{"version: STSv1\nmode: enforce\nmx: foo.example.com\nmx: bar.example.com\n\n", "\n", ":", map[string]string{
			"version": "STSv1",
			"mode":    "enforce",
			"mx":      "foo.example.com bar.example.com",
		}},
	}
	for _, test := range tests {
		got := getKeyValuePairs(test.txt, test.ld, test.pd)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("getKeyValuePairs(%s, %s, %s) = %v, want %v",
				test.txt, test.ld, test.pd, got, test.want)
		}
	}
}

func TestValidateMTASTSRecord(t *testing.T) {
	tests := []struct {
		txt    []string
		status Status
	}{
		{[]string{"v=STSv1; id=1234", "v=STSv1; id=5678"}, Failure},
		{[]string{"v=STSv1; id=20171114T070707;"}, Success},
		{[]string{"v=STSv1; id=;"}, Failure},
		{[]string{"v=STSv1; id=###;"}, Failure},
		{[]string{"v=spf1 a -all"}, Failure},
	}
	for _, test := range tests {
		result := validateMTASTSRecord(test.txt, &Result{})
		if result.Status != test.status {
			t.Errorf("validateMTASTSRecord(%v) = %v", test.txt, result)
		}
	}
}

func TestValidateMTASTSPolicyFile(t *testing.T) {
	tests := []struct {
		txt    string
		status Status
	}{
		{"version: STSv1\nmode: enforce\nmax_age:100000\nmx: foo.example.com\nmx: bar.example.com\n", Success},
		// Support UTF-8
		{"version: STSv1\nmode: enforce\nmax_age:100000\nmx: 🌟.🐢.com\n", Success},
		{"\nmx: foo.example.com\nmx: bar.example.com\n", Failure},
		{"version: STSv1\nmode: enforce\nmax_age:0\nmx: foo.example.com\nmx: bar.example.com\n", Failure},
		{"version: STSv1\nmode: start_turtles\nmax_age:100000\nmx: foo.example.com\nmx: bar.example.com\n", Failure},
	}
	for _, test := range tests {
		result, _ := validateMTASTSPolicyFile(test.txt, &Result{})
		if result.Status != test.status {
			t.Errorf("validateMTASTSPolicyFile(%v) = %v", test.txt, result)
		}
	}
}

func TestValidateMTASTSMXs(t *testing.T) {
	goodHostnameResult := HostnameResult{
		Result: &Result{
			Status: 3,
			Checks: map[string]*Result{
				"connectivity": {Connectivity, 0, nil, nil},
				"starttls":     {STARTTLS, 0, nil, nil},
			},
		},
	}
	noSTARTTLSHostnameResult := HostnameResult{
		Result: &Result{
			Status: 3,
			Checks: map[string]*Result{
				"connectivity": {Connectivity, 0, nil, nil},
				"starttls":     {STARTTLS, 3, nil, nil},
			},
		},
	}
	tests := []struct {
		policyFileMXs []string
		dnsMXs        map[string]HostnameResult
		status        Status
	}{
		{
			[]string{"mail.example.com"},
			map[string]HostnameResult{"mail.example.com": goodHostnameResult},
			Success,
		},
		{
			[]string{"mail.example.com", "extra-entries.are-okay.com"},
			map[string]HostnameResult{"mail.example.com": goodHostnameResult},
			Success,
		},
		{
			[]string{"*.example.com"},
			map[string]HostnameResult{"mail.example.com": goodHostnameResult},
			Success,
		},
		{
			[]string{},
			map[string]HostnameResult{"mail.example.com": goodHostnameResult},
			Warning,
		},
		{
			[]string{"nostarttls.example.com"},
			map[string]HostnameResult{"nostarttls.example.com": noSTARTTLSHostnameResult},
			Warning,
		},
	}
	for _, test := range tests {
		result := validateMTASTSMXs(test.policyFileMXs, test.dnsMXs, &Result{})
		if result.Status != test.status {
			t.Errorf("validateMTASTSMXs(%v, %v, %v) = %v", test.policyFileMXs, test.dnsMXs, Result{}, result)
		}
	}
}
