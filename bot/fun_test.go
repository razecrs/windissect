package main

import "testing"

func TestParseAddress(t *testing.T) {
	for input, want := range map[string]uint64{"4096": 4096, "0x1000": 4096, "0X2A": 42} {
		got, err := parseAddress(input)
		if err != nil || got != want {
			t.Fatalf("parseAddress(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
}

func TestChooseRejectsOneOption(t *testing.T) {
	if _, err := choose(chooseArgs{Options: "only one"}); err == nil {
		t.Fatal("choose accepted one option")
	}
}

func TestRollBounds(t *testing.T) {
	if _, err := roll(rollArgs{Sides: 1, Count: 1}); err == nil {
		t.Fatal("roll accepted a one-sided die")
	}
	if _, err := roll(rollArgs{Sides: 6, Count: 2}); err != nil {
		t.Fatal(err)
	}
}
