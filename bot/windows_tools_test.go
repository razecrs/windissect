package main

import "testing"

func TestParseFlexibleUint(t *testing.T) {
	tests := map[string]uint64{"42": 42, "0x2A": 42, "2Ah": 42, "0b101010": 42, "0o52": 42, "DEAD_BEEF": 0xDEADBEEF}
	for input, want := range tests {
		got, _, err := parseFlexibleUint(input)
		if err != nil || got != want {
			t.Fatalf("parseFlexibleUint(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
}

func TestParseStatusSigned(t *testing.T) {
	got, err := parseStatusValue("-2147024891")
	if err != nil || got != 0x80070005 {
		t.Fatalf("got 0x%08X, %v", got, err)
	}
}

func TestGUIDMemoryLayout(t *testing.T) {
	match := guidPattern.FindStringSubmatch("00112233-4455-6677-8899-AABBCCDDEEFF")
	if match == nil {
		t.Fatal("valid GUID did not match")
	}
}
