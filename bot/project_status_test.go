package main

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"windissect 1.0.0": "1.0.0", "v1.2.3": "1.2.3", "Windissect-v10.0.12-setup": "10.0.12",
		"1.0.0": "1.0.0", " 1.0 ": "1.0.0", "1": "1.0.0", "V2.1": "2.1.0", "windissect v1.0.0 (x64)": "1.0.0",
	} {
		v, ok := parseVersion(in)
		if !ok || versionString(v) != want {
			t.Fatalf("parseVersion(%q) = %v, %v; want %s", in, v, ok, want)
		}
	}
	for _, in := range []string{"latest", "--version", "x64", "build22631"} {
		if v, ok := parseVersion(in); ok {
			t.Fatalf("parseVersion(%q) = %v; want no version", in, v)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	if compareVersions([3]int{0, 9, 9}, [3]int{1, 0, 0}) != -1 ||
		compareVersions([3]int{1, 10, 0}, [3]int{1, 9, 0}) != 1 ||
		compareVersions([3]int{1, 0, 0}, [3]int{1, 0, 0}) != 0 {
		t.Fatal("wrong ordering")
	}
}

func TestVersionEmbedStates(t *testing.T) {
	rel := githubRelease{TagName: "v1.0.0", HTMLURL: "https://example.test/r"}
	for yours, want := range map[string]string{
		"":                 "latest release",
		"windissect 0.9.0": "Update available",
		"1.0.0":            "up to date",
		"1.0":              "up to date",
		"1.1.0":            "development build",
		"--version":        "I got `--version`",
	} {
		if got := versionEmbed(rel, yours).Description; !strings.Contains(got, want) {
			t.Fatalf("yours=%q: %q does not mention %q", yours, got, want)
		}
	}
}

func TestMarkdownHeadingsAndSections(t *testing.T) {
	md := "# Known issues\r\n\r\n## First gap\r\ntext\n## Second gap\n"
	if got := markdownHeadings(md); len(got) != 2 || got[0] != "First gap" || got[1] != "Second gap" {
		t.Fatalf("headings = %q", got)
	}
	body := "## Download\n- not this\n## What's new\n- **GUI**: yes\n- Elytra\n## Checksums\n- no"
	if got := releaseSection(body, "What's new"); len(got) != 2 || got[1] != "• Elytra" {
		t.Fatalf("section = %q", got)
	}
}

func TestClip(t *testing.T) {
	if got := clip("a\nb\nc", 3); got != "a\n…" {
		t.Fatalf("clip = %q", got)
	}
}
