package main

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{"windissect 1.0.0": "1.0.0", "v1.2.3": "1.2.3", "Windissect-v10.0.12-setup": "10.0.12"} {
		v, ok := parseVersion(in)
		if !ok || versionString(v) != want {
			t.Fatalf("parseVersion(%q) = %v, %v; want %s", in, v, ok, want)
		}
	}
	if _, ok := parseVersion("latest"); ok {
		t.Fatal("parsed a version out of plain text")
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
		"1.1.0":            "development build",
		"newest":           "couldn't find a version",
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
