package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSymbolKeyUsesHexAge(t *testing.T) {
	got := symbolKey("00112233445566778899AABBCCDDEEFF", 0xA)
	if got != "00112233445566778899AABBCCDDEEFFA" {
		t.Fatalf("unexpected symbol key: %s", got)
	}
}

func TestSafePDBNameStripsBuildPath(t *testing.T) {
	got, err := safePDBName(`D:\build\obj\dwmcore.pdb`)
	if err != nil || got != "dwmcore.pdb" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSafePDBNameRejectsNonPDB(t *testing.T) {
	if _, err := safePDBName("payload.exe"); err == nil {
		t.Fatal("expected non-PDB name to be rejected")
	}
}

func TestFixGuidLegacyEncodingUsesHexAge(t *testing.T) {
	got := fixGuid("00112233445566778899AABBCCDDEEFF10")
	if got != "33221100554477668899AABBCCDDEEFFA" {
		t.Fatalf("unexpected legacy key: %s", got)
	}
}

func TestReplaceFileOverwritesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new.json")
	destination := filepath.Join(dir, "canonical.json")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(source, destination); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("unexpected replacement contents: %q", contents)
	}
	if _, err := os.Stat(destination + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("backup was not removed: %v", err)
	}
}

func TestInstalledNotepadPackageCanBeResolved(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	root := filepath.Join(programFiles, "WindowsApps")
	installed := resolveTargetPath(targetSpec{File: "Notepad.exe", Source: "notepad-app-x64"}, os.Getenv("SystemRoot"), t.TempDir())
	if installed == "" {
		t.Skip("modern Notepad x64 package is not installed")
	}
	got := resolveTargetPath(targetSpec{File: "Notepad.exe", Source: "notepad-app-x64"}, os.Getenv("SystemRoot"), t.TempDir())
	if got == "" {
		t.Fatalf("installed Notepad did not resolve from %q", root)
	}
}
