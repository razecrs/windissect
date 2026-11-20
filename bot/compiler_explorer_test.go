package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCompilerPresetsNeverAcceptFlags(t *testing.T) {
	for key, preset := range compilerPresets {
		if key == "" || preset.id == "" || preset.name == "" || preset.extension == "" {
			t.Fatalf("incomplete compiler preset %q: %#v", key, preset)
		}
	}
}

func TestLimitOutput(t *testing.T) {
	if got, cut := limitOutput("abc", 3); got != "abc" || cut {
		t.Fatalf("unexpected exact-limit result: %q, %v", got, cut)
	}
	if got, cut := limitOutput("abcd", 3); !cut || got[:3] != "abc" {
		t.Fatalf("output was not truncated: %q, %v", got, cut)
	}
}

func TestCompilerExplorerLive(t *testing.T) {
	if os.Getenv("WINDISSECT_LIVE_TESTS") != "1" {
		t.Skip("set WINDISSECT_LIVE_TESTS=1 for the external API probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := requestCompilation(ctx, compilerPresets["c-gcc"], "-O2", "int add(int a, int b) { return a + b; }")
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != 0 || !strings.Contains(joinCompilerLines(result.Asm), "add") {
		t.Fatalf("unexpected compile result: code=%d asm=%d lines", result.Code, len(result.Asm))
	}
}
