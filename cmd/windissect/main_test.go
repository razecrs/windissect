package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Windows tree on a case-sensitive filesystem: the manifest says
// "windows.ui.xaml.dll" under "system32", the disk says otherwise.
func TestBareTargetResolvesAcrossCase(t *testing.T) {
	windowsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(windowsDir, "System32"), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(windowsDir, "System32", "Windows.UI.Xaml.dll")
	if err := os.WriteFile(real, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := resolveTargetPath(targetSpec{File: "windows.ui.xaml.dll"}, windowsDir, t.TempDir())
	if got == "" {
		t.Fatal("a differently-cased System32 entry did not resolve")
	}
	if info, err := os.Stat(got); err != nil || info.IsDir() {
		t.Fatalf("resolved to %q, which is not the file: %v", got, err)
	}
	if got := resolveTargetPath(targetSpec{File: "absent.dll"}, windowsDir, t.TempDir()); got != "" {
		t.Fatalf("a missing file resolved to %q", got)
	}
}

// With no Windows directory a bare name must not be looked up relative to the
// working directory, and the error has to say why it was not found.
func TestBareTargetWithoutWindowsDir(t *testing.T) {
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "System32"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "System32", "dwmapi.dll"), []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	target := targetSpec{File: "dwmapi.dll"}
	if got := resolveTargetPath(target, "", t.TempDir()); got != "" {
		t.Fatalf("bare name resolved against the working directory: %q", got)
	}
	if msg := missingTargetError(target, ""); !strings.Contains(msg, "./dwmapi.dll") {
		t.Fatalf("error does not tell the user to pass a path: %q", msg)
	}
	if msg := missingTargetError(target, `C:\Windows`); msg != "binary not installed" {
		t.Fatalf("unexpected error with a Windows directory: %q", msg)
	}
}

func TestOutputStemReusesExistingSpelling(t *testing.T) {
	dir := t.TempDir()
	if got := existingStemFold(dir, "inputhost", ".json"); got != "inputhost" {
		t.Fatalf("empty directory changed the stem to %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "InputHost.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := existingStemFold(dir, "inputhost", ".json"); !strings.EqualFold(got, "inputhost") {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, existingStemFold(dir, "inputhost", ".json")+".json")); err != nil {
		t.Fatalf("folded stem does not name the existing IR: %v", err)
	}
}

func TestFindExtractorUsesHostExecutableName(t *testing.T) {
	base := t.TempDir()
	release := filepath.Join(base, "target", "release")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if got := findExtractor(base, ""); got != "" {
		t.Fatalf("found an extractor in an empty tree: %q", got)
	}
	want := filepath.Join(release, executableName("windissect"))
	if err := os.WriteFile(want, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := findExtractor(base, ""); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// `go build ./cmd/windissect` names the fleet windissect as well; it must not
// pick itself as the extractor and recurse.
func TestFindExtractorSkipsItself(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", "")
	self := filepath.Join(dir, executableName("windissect"))
	if err := os.WriteFile(self, []byte("fleet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := findExtractor(t.TempDir(), self); got != "" {
		t.Fatalf("the fleet chose itself as the extractor: %q", got)
	}
	fleet := filepath.Join(dir, executableName("windissect-fleet"))
	if err := os.WriteFile(fleet, []byte("fleet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := findExtractor(t.TempDir(), fleet); got != self {
		t.Fatalf("installed CLI beside the fleet was not found: got %q, want %q", got, self)
	}
}

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

// A shallow corpus entry is indistinguishable from a deep one by hash: the
// binary did not change, only how far it was taken. The whole taskbar group
// was reused this way once, finishing a deep run in zero seconds.
func TestShallowResultDoesNotSatisfyDeepRun(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "target.dll")
	if err := os.WriteFile(binary, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	ir := filepath.Join(dir, "target.ir.json")
	if err := os.WriteFile(ir, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	shallowEntry := corpusResult{
		Status: "verified-pdb",
		IR:     ir,
		SHA256: hash,
		Depth:  depthShallow,
	}

	if !reusableResult(shallowEntry, binary, true) {
		t.Fatal("a shallow entry should still satisfy a shallow run")
	}
	if reusableResult(shallowEntry, binary, false) {
		t.Fatal("a shallow entry must not satisfy a deep run")
	}

	// Entries written before depth was recorded read as shallow, which is
	// what the first taskbar pull actually was.
	legacy := shallowEntry
	legacy.Depth = ""
	if reusableResult(legacy, binary, false) {
		t.Fatal("a depth-less legacy entry must not satisfy a deep run")
	}

	deepEntry := shallowEntry
	deepEntry.Depth = depthFull
	deepEntry.Semantic = filepath.Join(dir, "semantic")
	if err := os.Mkdir(deepEntry.Semantic, 0o700); err != nil {
		t.Fatal(err)
	}
	if !reusableResult(deepEntry, binary, false) {
		t.Fatal("a deep entry should satisfy a deep run")
	}

	deepEntry.Semantic = ""
	if reusableResult(deepEntry, binary, false) {
		t.Fatal("a deep entry without semantic output must be retried")
	}
}

// The shape of the record that has been silently passing: a PDB resolved, the
// IR is well-formed JSON, and there is nothing in it. The published ReWindows
// taskbar build is exactly this - 3 symbols, 0 classes.
func TestGateRejectsEmptyExtraction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":true,"symbols":3,"functions":0,"vtables":0,"classes":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "taskbar.dll"); err == nil {
		t.Fatal("expected an empty extraction to be rejected")
	}
}

// Classes are 0 on a complete extraction too - they come from the later
// semantic stage - so the gate must not key on them.
func TestGateAcceptsRealExtractionWithZeroClasses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":true,"symbols":206365,"functions":48066,"vtables":16107,"classes":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "Microsoft.UI.Xaml.dll"); err != nil {
		t.Fatalf("rejected a complete extraction: %v", err)
	}
}

// A module with no PDB legitimately yields few symbols; that is unavailable,
// not a failed extraction, and must not be failed here.
func TestGateIgnoresTargetsWithoutPDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":false,"symbols":2,"functions":0,"vtables":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "vendor.dll"); err != nil {
		t.Fatalf("failed a target that never had symbols to begin with: %v", err)
	}
}

// A missing summary is not evidence of failure.
func TestGateIsSilentWithoutInventory(t *testing.T) {
	if err := gateCompleteness(filepath.Join(t.TempDir(), "absent.json"), "x.dll"); err != nil {
		t.Fatalf("absence of a summary failed the target: %v", err)
	}
}

func TestSeedCorpusCoverageMakesUnattemptedTargetsVisible(t *testing.T) {
	root := t.TempDir()
	extractor := filepath.Join(root, "windissect.exe")
	if err := os.WriteFile(extractor, []byte("extractor"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := []targetSpec{
		{ID: "done", File: "done.dll", Required: true},
		{ID: "required-later", File: "required.dll", Required: true},
		{ID: "optional-later", File: "optional.dll"},
	}
	if err := writeCorpusIndex(root, extractor, []corpusResult{{
		ID: "done", File: "done.dll", Required: true, Status: "verified-pdb",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := seedCorpusCoverage(root, extractor, targets); err != nil {
		t.Fatal(err)
	}

	statuses := make(map[string]string)
	for _, result := range readCorpusIndex(root).Targets {
		statuses[result.ID] = result.Status
	}
	if statuses["done"] != "verified-pdb" {
		t.Fatalf("completed result was replaced: %q", statuses["done"])
	}
	if statuses["required-later"] != "pending-required" {
		t.Fatalf("missing required target is invisible: %q", statuses["required-later"])
	}
	if statuses["optional-later"] != "pending-optional" {
		t.Fatalf("missing optional target is invisible: %q", statuses["optional-later"])
	}
}
