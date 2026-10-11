package tssh

import (
	"reflect"
	"testing"
)

func TestSplitConfigValuePreservesWindowsPaths(t *testing.T) {
	value := `C:\Users\LENVO/.ssh/known_hosts C:\Users\LENVO/.ssh/known_hosts2`
	got, err := splitConfigValue(value, "UserKnownHostsFile")
	if err != nil {
		t.Fatalf("split Windows config value: %v", err)
	}
	want := []string{`C:\Users\LENVO/.ssh/known_hosts`, `C:\Users\LENVO/.ssh/known_hosts2`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Windows config paths = %#v, want %#v", got, want)
	}
}

func TestSplitConfigValueWindowsQuotedPath(t *testing.T) {
	value := `"C:\Users\LEN VO\.ssh\known_hosts"`
	got, err := splitConfigValue(value, "UserKnownHostsFile")
	if err != nil {
		t.Fatalf("split quoted Windows config value: %v", err)
	}
	want := []string{`C:\Users\LEN VO\.ssh\known_hosts`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quoted Windows config path = %#v, want %#v", got, want)
	}
}
