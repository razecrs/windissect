package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var symbolServer = "https://msdl.microsoft.com/download/symbols"
var pdbMagic = []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")

// builtinTargets is the built-in Windows UI corpus used when no --manifest is
// given. Required targets ship with every Windows 11 install; optional ones
// depend on the edition, build or installed app packages and are skipped when
// absent. manifests/windows-ui.json mirrors this list.
var builtinTargets = []targetSpec{
	// Desktop Window Manager and composition
	{ID: "uDWM", File: "uDWM.dll", Area: "dwm", Required: true},
	{ID: "dwmcore", File: "dwmcore.dll", Area: "dwm", Required: true},
	{ID: "dwmapi", File: "dwmapi.dll", Area: "dwm", Required: true},
	{ID: "dcomp", File: "dcomp.dll", Area: "dwm", Required: true},
	{ID: "duser", File: "duser.dll", Area: "dwm", Required: true},
	// DirectUI and classic shell controls
	{ID: "dui70", File: "dui70.dll", Area: "shell", Required: true},
	{ID: "ExplorerFrame", File: "ExplorerFrame.dll", Area: "shell", Required: true},
	{ID: "shell32", File: "shell32.dll", Area: "shell", Required: true},
	{ID: "shlwapi", File: "shlwapi.dll", Area: "shell", Required: true},
	{ID: "comctl32", File: "comctl32.dll", Area: "shell", Required: true},
	{ID: "uxtheme", File: "uxtheme.dll", Area: "shell", Required: true},
	{ID: "user32", File: "user32.dll", Area: "shell", Required: true},
	// Immersive shell, taskbar and Start
	{ID: "twinui", File: "twinui.dll", Area: "taskbar", Required: true},
	{ID: "twinui.pcshell", File: "twinui.pcshell.dll", Area: "taskbar", Required: true},
	{ID: "taskbar", File: "taskbar.dll", Area: "taskbar", Required: true},
	{ID: "twinapi", File: "twinapi.dll", Area: "taskbar", Required: true},
	{ID: "twinapi.appcore", File: "twinapi.appcore.dll", Area: "taskbar", Required: true},
	{ID: "Taskbar.View", File: "Taskbar.View.dll", Source: "client-core-system-app", Area: "taskbar"},
	{ID: "StartDocked", File: "StartDocked.dll", Source: "start-menu-system-app", Area: "start"},
	// XAML and Windows App SDK
	{ID: "windows.ui.xaml", File: "windows.ui.xaml.dll", Area: "xaml", Required: true},
	{ID: "Microsoft.ui.xaml", File: "Microsoft.ui.xaml.dll", Source: "windows-app-runtime-x64", Area: "xaml"},
	{ID: "Microsoft.UI.Windowing.Core", File: "Microsoft.UI.Windowing.Core.dll", Source: "windows-app-runtime-x64", Area: "xaml"},
	// Flyouts, notifications and tray
	{ID: "SndVolSSO", File: "SndVolSSO.dll", Area: "tray", Required: true},
	{ID: "ControlCenter", File: "ControlCenter.dll", Area: "tray"},
	{ID: "ActionCenter", File: "ActionCenter.dll", Area: "tray"},
	{ID: "pnidui", File: "pnidui.dll", Area: "tray"},
	// Input and message routing
	{ID: "InputHost", File: "inputhost.dll", Area: "input", Required: true},
	{ID: "CoreMessaging", File: "CoreMessaging.dll", Area: "input", Required: true},
	{ID: "TextInputFramework", File: "textinputframework.dll", Area: "input", Required: true},
	// Storage, settings and inbox apps
	{ID: "windows.storage", File: "windows.storage.dll", Area: "storage", Required: true},
	{ID: "shellcommon", File: "shellcommon.dll", Area: "storage"},
	{ID: "SystemSettings.View", File: "SystemSettings.View.dll", Area: "settings"},
	{ID: "Taskmgr", File: "Taskmgr.dll", Area: "apps"},
}

type targetSpec struct {
	ID       string `json:"id"`
	File     string `json:"file"`
	Source   string `json:"source"`
	Area     string `json:"area"`
	Required bool   `json:"required"`
}

type corpusManifest struct {
	Schema  int          `json:"schema"`
	Targets []targetSpec `json:"targets"`
}

type processOutcome struct {
	IRPath  string
	PDBUsed bool
}

type corpusResult struct {
	ID         string `json:"id"`
	File       string `json:"file"`
	Area       string `json:"area,omitempty"`
	Required   bool   `json:"required"`
	SourcePath string `json:"source_path,omitempty"`
	Status     string `json:"status"`
	SHA256     string `json:"sha256,omitempty"`
	PDBName    string `json:"pdb_name,omitempty"`
	PDBGuid    string `json:"pdb_guid,omitempty"`
	PDBAge     uint32 `json:"pdb_age,omitempty"`
	PDBUsed    bool   `json:"pdb_used"`
	IR         string `json:"ir,omitempty"`
	Headers    string `json:"headers,omitempty"`
	Rust       string `json:"rust,omitempty"`
	Error      string `json:"error,omitempty"`
}

type corpusIndex struct {
	Schema        int            `json:"schema"`
	GeneratedUTC  string         `json:"generated_utc"`
	WindowsBuild  string         `json:"windows_build"`
	Architecture  string         `json:"architecture"`
	ExtractorPath string         `json:"extractor_path"`
	ExtractorHash string         `json:"extractor_sha256"`
	Targets       []corpusResult `json:"targets"`
}

var buildOnce sync.Once
var detectedBuild uint32

func swapHex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		return s
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func fixGuid(rawGuid string) string {
	if len(rawGuid) <= 32 {
		return ""
	}
	d1 := swapHex(rawGuid[0:8])
	d2 := swapHex(rawGuid[8:12])
	d3 := swapHex(rawGuid[12:16])
	age, err := strconv.ParseUint(rawGuid[32:], 10, 32)
	if err != nil || age == 0 {
		return ""
	}
	return fmt.Sprintf("%s%s%s%s%X", d1, d2, d3, strings.ToUpper(rawGuid[16:32]), age)
}

func symbolKey(guid string, age uint32) string {
	guid = strings.ToUpper(strings.ReplaceAll(guid, "-", ""))
	if len(guid) == 32 && age > 0 {
		return fmt.Sprintf("%s%X", guid, age)
	}
	return fixGuid(guid)
}

func safePDBName(name string) (string, error) {
	if strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("unsafe PDB name")
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == "" || !strings.EqualFold(filepath.Ext(name), ".pdb") {
		return "", fmt.Errorf("invalid PDB name %q", name)
	}
	return name, nil
}

func validatePDB(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, len(pdbMagic))
	if _, err = io.ReadFull(f, b); err != nil {
		return err
	}
	if !bytes.Equal(b, pdbMagic) {
		return fmt.Errorf("not an MSF 7 PDB")
	}
	return nil
}

func downloadPDB(pdbName, correctedGuid string, outPath string) bool {
	if correctedGuid == "" {
		fmt.Println("[!] Invalid GUID+age")
		return false
	}
	u := fmt.Sprintf("%s/%s/%s/%s", strings.TrimRight(symbolServer, "/"), url.PathEscape(pdbName), url.PathEscape(correctedGuid), url.PathEscape(pdbName))
	fmt.Printf("[+] Fetching PDB from %s...\n", u)

	client := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		fmt.Printf("[!] Failed to create request: %v\n", err)
		return false
	}
	req.Header.Set("User-Agent", "Microsoft-Symbol-Server/10.0.0.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] Download error: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[!] HTTP %s for %s\n", resp.Status, u)
		return false
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return false
	}
	outFile, err := os.CreateTemp(filepath.Dir(outPath), ".pdb-*.tmp")
	if err != nil {
		fmt.Printf("[!] Failed to create output file: %v\n", err)
		return false
	}
	tmp := outFile.Name()
	defer os.Remove(tmp)

	n, err := io.Copy(outFile, resp.Body)
	if err != nil {
		fmt.Printf("[!] Failed saving PDB: %v\n", err)
		return false
	}
	if err := outFile.Close(); err != nil {
		return false
	}
	if err := validatePDB(tmp); err != nil {
		fmt.Printf("[!] Invalid PDB: %v\n", err)
		return false
	}
	if err := os.Rename(tmp, outPath); err != nil {
		fmt.Printf("[!] Cache commit failed: %v\n", err)
		return false
	}

	fmt.Printf("[+] Downloaded %s (%d bytes)\n", outPath, n)
	return true
}

func findExtractor(baseDir string) string {
	for _, n := range []string{"windissect-core.exe", "windissect-rs.exe"} {
		p := filepath.Join(baseDir, "target", "release", n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	candidate1 := filepath.Join(baseDir, "target", "release", "windissect.exe")
	if _, err := os.Stat(candidate1); err == nil {
		return candidate1
	}
	candidate2 := filepath.Join(baseDir, "target", "release", "dui70.exe")
	if _, err := os.Stat(candidate2); err == nil {
		return candidate2
	}
	return ""
}

func takeOption(args []string, name string) ([]string, string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] != name {
			continue
		}
		if i+1 >= len(args) {
			return nil, "", fmt.Errorf("%s requires a value", name)
		}
		value := args[i+1]
		return append(args[:i], args[i+2:]...), value, nil
	}
	return args, "", nil
}

func loadManifest(name string) ([]targetSpec, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var manifest corpusManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, err
	}
	if manifest.Schema != 1 {
		return nil, fmt.Errorf("unsupported corpus manifest schema %d", manifest.Schema)
	}
	seen := map[string]bool{}
	for i := range manifest.Targets {
		target := &manifest.Targets[i]
		if target.ID == "" || target.File == "" {
			return nil, fmt.Errorf("manifest target %d requires id and file", i)
		}
		if seen[target.ID] {
			return nil, fmt.Errorf("duplicate manifest target id %q", target.ID)
		}
		seen[target.ID] = true
	}
	return manifest.Targets, nil
}

func newestFile(patterns ...string) string {
	var matches []string
	for _, pattern := range patterns {
		found, _ := filepath.Glob(pattern)
		matches = append(matches, found...)
	}
	sort.Slice(matches, func(i, j int) bool {
		left, leftErr := os.Stat(matches[i])
		right, rightErr := os.Stat(matches[j])
		if leftErr == nil && rightErr == nil && !left.ModTime().Equal(right.ModTime()) {
			return left.ModTime().After(right.ModTime())
		}
		return matches[i] > matches[j]
	})
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && !info.IsDir() {
			return match
		}
	}
	return ""
}

func newestPackageFile(root, packagePattern string, relativeParts ...string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var candidates []string
	for _, entry := range entries {
		if !packageNameMatches(entry.Name(), packagePattern) {
			continue
		}
		parts := append([]string{root, entry.Name()}, relativeParts...)
		candidate := filepath.Join(parts...)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	patterns := make([]string, len(candidates))
	copy(patterns, candidates)
	return newestFile(patterns...)
}

func packageNameMatches(name, pattern string) bool {
	prefix, suffix, found := strings.Cut(pattern, "*")
	if found && !strings.Contains(suffix, "*") {
		return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}
	matched, err := filepath.Match(pattern, name)
	return err == nil && matched
}

func installedNotepadFile(relativeParts ...string) string {
	command := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-Command",
		"(Get-AppxPackage -Name Microsoft.WindowsNotepad | Sort-Object Version -Descending | Select-Object -First 1).InstallLocation",
	)
	output, err := command.Output()
	if err != nil {
		return ""
	}
	location := strings.TrimSpace(string(output))
	if location == "" {
		return ""
	}
	parts := append([]string{location}, relativeParts...)
	candidate := filepath.Join(parts...)
	if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

func resolveTargetPath(target targetSpec, windowsDir, probeDir string) string {
	if filepath.IsAbs(target.File) || strings.ContainsAny(target.File, `/\`) {
		if info, err := os.Stat(target.File); err == nil && !info.IsDir() {
			return target.File
		}
		return ""
	}
	system32 := filepath.Join(windowsDir, "System32", target.File)
	switch target.Source {
	case "", "system32":
		if info, err := os.Stat(system32); err == nil && !info.IsDir() {
			return system32
		}
	case "windows":
		candidate := filepath.Join(windowsDir, target.File)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	case "client-core-system-app":
		candidate := filepath.Join(windowsDir, "SystemApps", "MicrosoftWindows.Client.Core_cw5n1h2txyewy", target.File)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	case "start-menu-system-app":
		candidate := filepath.Join(windowsDir, "SystemApps", "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy", target.File)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	case "windows-app-runtime-x64":
		programFiles := os.Getenv("ProgramFiles")
		return newestFile(
			filepath.Join(programFiles, "WindowsApps", "Microsoft.WindowsAppRuntime.*_*_x64__8wekyb3d8bbwe", target.File),
			filepath.Join(windowsDir, "SystemApps", "Microsoft.WindowsAppRuntime.CBS*_8wekyb3d8bbwe", target.File),
		)
	case "notepad-app-x64":
		programFiles := os.Getenv("ProgramFiles")
		candidate := newestPackageFile(
			filepath.Join(programFiles, "WindowsApps"),
			"Microsoft.WindowsNotepad_*_x64__8wekyb3d8bbwe",
			"Notepad",
			target.File,
		)
		if candidate != "" {
			return candidate
		}
		return installedNotepadFile("Notepad", target.File)
	default:
		return ""
	}
	probe := filepath.Join(probeDir, target.File)
	if info, err := os.Stat(probe); err == nil && !info.IsDir() {
		return probe
	}
	return ""
}

func processDLL(dllPath, outputID, probeDir, irDir, exePath string) (processOutcome, error) {
	if _, err := os.Stat(dllPath); err != nil {
		return processOutcome{}, err
	}
	dllName := filepath.Base(dllPath)
	fmt.Println("\n==========================================")
	fmt.Printf("[*] Target: %s (%s)\n", dllName, dllPath)
	fmt.Println("==========================================")

	stem := outputID
	if stem == "" {
		stem = strings.TrimSuffix(dllName, filepath.Ext(dllName))
	}
	irOut := filepath.Join(irDir, stem+".json")

	work, err := os.MkdirTemp("", "windissect-")
	if err != nil {
		return processOutcome{}, err
	}
	defer os.RemoveAll(work)
	pass1 := filepath.Join(work, "pass1.json")
	cmd1 := exec.Command(exePath, "extract", dllPath, "--out", pass1)
	cmd1.Dir = work
	if out, err := cmd1.CombinedOutput(); err != nil {
		return processOutcome{}, fmt.Errorf("pass 1 failed: %w: %s", err, out)
	}

	irData, err := os.ReadFile(pass1)
	if err != nil {
		fmt.Printf("[!] Pass 1 failed to generate IR for %s\n", dllName)
		return processOutcome{}, err
	}

	var parsed struct {
		Binary struct {
			PdbName string `json:"pdb_name"`
			PdbGuid string `json:"pdb_guid"`
			PdbAge  uint32 `json:"pdb_age"`
		} `json:"binary"`
	}
	if err := json.Unmarshal(irData, &parsed); err != nil {
		fmt.Printf("[!] Failed to parse IR JSON: %v\n", err)
		return processOutcome{}, err
	}

	pdbName, err := safePDBName(parsed.Binary.PdbName)
	if err != nil && parsed.Binary.PdbName != "" {
		return processOutcome{}, err
	}
	rawGuid := parsed.Binary.PdbGuid
	fmt.Printf("[+] PE Metadata: PDB='%s', Raw GUID='%s'\n", pdbName, rawGuid)

	var pdbPath string
	if pdbName != "" && rawGuid != "" {
		key := symbolKey(rawGuid, parsed.Binary.PdbAge)
		if key == "" {
			return processOutcome{}, fmt.Errorf("invalid PDB GUID+age")
		}
		targetPdbPath := filepath.Join(probeDir, "symbols", pdbName, key, pdbName)
		if err := validatePDB(targetPdbPath); err == nil {
			fmt.Printf("[+] Using existing PDB at %s\n", targetPdbPath)
			pdbPath = targetPdbPath
		} else {
			if downloadPDB(pdbName, key, targetPdbPath) {
				pdbPath = targetPdbPath
			}
		}
	}

	// Pass 2: Extract with PDB
	final := filepath.Join(work, "final.json")
	args := []string{"extract", dllPath, "--out", final}
	if pdbPath != "" {
		args = append(args, "--pdb", pdbPath)
	}

	cmd2 := exec.Command(exePath, args...)
	cmd2.Dir = work
	output, err := runStreaming(cmd2)
	if err != nil {
		return processOutcome{}, fmt.Errorf("pass 2 failed: %w: %s", err, output)
	}
	if b, err := os.ReadFile(final); err != nil || !json.Valid(b) {
		return processOutcome{}, fmt.Errorf("pass 2 produced invalid IR")
	}
	verify := exec.Command(exePath, "verify", "--ir", final)
	verify.Dir = work
	if output, err := verify.CombinedOutput(); err != nil {
		return processOutcome{}, fmt.Errorf("verification failed: %w: %s", err, output)
	}
	if err := replaceFile(final, irOut); err != nil {
		return processOutcome{}, err
	}
	record := exec.Command(exePath, "record-build", irOut, "--history", filepath.Join(filepath.Dir(irDir), "history"))
	record.Dir = filepath.Dir(irDir)
	if output, err := record.CombinedOutput(); err != nil {
		return processOutcome{}, fmt.Errorf("record build failed: %w: %s", err, output)
	} else {
		fmt.Print(string(output))
	}
	return processOutcome{IRPath: irOut, PDBUsed: pdbPath != ""}, nil
}

func runStreaming(command *exec.Cmd) ([]byte, error) {
	var captured bytes.Buffer
	output := io.MultiWriter(os.Stdout, &captured)
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	return captured.Bytes(), err
}

// replaceFile installs a verified result while preserving the previous file
// until the replacement succeeds. This works on Windows, where os.Rename does
// not overwrite an existing destination.
func replaceFile(source, destination string) error {
	backup := destination + ".previous"
	_ = os.Remove(backup)
	if err := os.Rename(destination, backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("preserve previous IR: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		_ = os.Rename(backup, destination)
		return fmt.Errorf("install verified IR: %w", err)
	}
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous IR backup: %w", err)
	}
	return nil
}

func emitAllOutputs(baseDir, exePath string) error {
	irDir := filepath.Join(baseDir, "ir")
	headersDir := filepath.Join(baseDir, "headers")
	rustDir := filepath.Join(baseDir, "rust")
	if err := os.MkdirAll(headersDir, 0755); err != nil {
		return fmt.Errorf("create header output: %w", err)
	}
	if err := os.MkdirAll(rustDir, 0755); err != nil {
		return fmt.Errorf("create Rust output: %w", err)
	}

	entries, err := os.ReadDir(irDir)
	if err != nil {
		fmt.Printf("[!] Failed to read IR dir: %v\n", err)
		return err
	}

	fmt.Printf("[*] Emitting C/C++ and Rust outputs for %d IR databases\n", len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			stem := strings.TrimSuffix(entry.Name(), ".json")
			irFile := filepath.Join(irDir, entry.Name())
			outDir := filepath.Join(headersDir, stem)
			fmt.Printf("[*] Emitting headers for %s -> %s\n", entry.Name(), outDir)

			verify := exec.Command(exePath, "verify", "--ir", irFile)
			if out, err := verify.CombinedOutput(); err != nil {
				return fmt.Errorf("verify %s: %w: %s", entry.Name(), err, out)
			}
			cmd := exec.Command(exePath, "emit-headers", "--ir", irFile, "--out", outDir)
			out, err := cmd.CombinedOutput()
			fmt.Println(string(out))
			if err != nil {
				return fmt.Errorf("emit %s: %w", entry.Name(), err)
			}
			rustOut := filepath.Join(rustDir, stem)
			cmd = exec.Command(exePath, "emit-rust", "--ir", irFile, "--out", rustOut)
			out, err = cmd.CombinedOutput()
			fmt.Println(string(out))
			if err != nil {
				return fmt.Errorf("emit Rust %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func defaultTargets() []targetSpec {
	targets := make([]targetSpec, len(builtinTargets))
	copy(targets, builtinTargets)
	return targets
}

func resultMetadata(result *corpusResult) {
	b, err := os.ReadFile(result.IR)
	if err != nil {
		return
	}
	var ir struct {
		Binary struct {
			SHA256  string `json:"sha256"`
			PDBName string `json:"pdb_name"`
			PDBGuid string `json:"pdb_guid"`
			PDBAge  uint32 `json:"pdb_age"`
		} `json:"binary"`
	}
	if json.Unmarshal(b, &ir) == nil {
		result.SHA256 = ir.Binary.SHA256
		result.PDBName = ir.Binary.PDBName
		result.PDBGuid = ir.Binary.PDBGuid
		result.PDBAge = ir.Binary.PDBAge
	}
}

func writeCorpusIndex(root, extractorPath string, results []corpusResult) error {
	results = mergeCorpusResults(root, results)
	extractorHash, _ := fileSHA256(extractorPath)
	index := corpusIndex{
		Schema:        1,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		WindowsBuild:  strings.TrimSpace(os.Getenv("OS_BUILD_NUMBER")),
		Architecture:  os.Getenv("PROCESSOR_ARCHITECTURE"),
		ExtractorPath: extractorPath,
		ExtractorHash: extractorHash,
		Targets:       results,
	}
	if index.WindowsBuild == "" {
		index.WindowsBuild = fmt.Sprintf("%d.%d.%d", 10, 0, windowsBuild())
	}
	b, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(root, "compat-index.json.tmp")
	final := filepath.Join(root, "compat-index.json")
	if err := os.WriteFile(temporary, b, 0o644); err != nil {
		return err
	}
	if err := replaceFile(temporary, final); err != nil {
		return err
	}
	return writeCorpusReport(root, index)
}

func writeCorpusReport(root string, index corpusIndex) error {
	counts := make(map[string]int)
	for _, target := range index.Targets {
		counts[target.Status]++
	}
	var report strings.Builder
	fmt.Fprintf(&report, "# Windissect compatibility corpus\n\n")
	fmt.Fprintf(&report, "Generated: `%s`  \n", index.GeneratedUTC)
	fmt.Fprintf(&report, "Windows build: `%s`  \n", index.WindowsBuild)
	fmt.Fprintf(&report, "Architecture: `%s`  \n", index.Architecture)
	fmt.Fprintf(&report, "Extractor SHA-256: `%s`\n\n", index.ExtractorHash)
	fmt.Fprintf(&report, "- Exact-build PDB verified: %d\n", counts["verified-pdb"])
	fmt.Fprintf(&report, "- Static-only verified: %d\n", counts["verified-static"])
	fmt.Fprintf(&report, "- Required failures: %d\n", counts["failed-required"])
	fmt.Fprintf(&report, "- Optional failures/unavailable: %d\n\n", counts["failed-optional"]+counts["unavailable-optional"])
	report.WriteString("| Target | Binary | Status | PDB identity | Binary SHA-256 |\n")
	report.WriteString("|---|---|---|---|---|\n")
	for _, target := range index.Targets {
		pdbIdentity := "-"
		if target.PDBGuid != "" {
			pdbIdentity = fmt.Sprintf("`%s+%X`", target.PDBGuid, target.PDBAge)
		}
		sha := "-"
		if target.SHA256 != "" {
			sha = "`" + target.SHA256 + "`"
		}
		fmt.Fprintf(
			&report,
			"| `%s` | `%s` | `%s` | %s | %s |\n",
			target.ID,
			target.File,
			target.Status,
			pdbIdentity,
			sha,
		)
	}
	temporary := filepath.Join(root, "compat-report.md.tmp")
	final := filepath.Join(root, "compat-report.md")
	if err := os.WriteFile(temporary, []byte(report.String()), 0o644); err != nil {
		return err
	}
	return replaceFile(temporary, final)
}

func readCorpusIndex(root string) corpusIndex {
	b, err := os.ReadFile(filepath.Join(root, "compat-index.json"))
	if err != nil {
		return corpusIndex{}
	}
	var index corpusIndex
	if json.Unmarshal(b, &index) != nil || index.Schema != 1 {
		return corpusIndex{}
	}
	return index
}

func mergeCorpusResults(root string, updates []corpusResult) []corpusResult {
	existing := readCorpusIndex(root).Targets
	positions := make(map[string]int, len(existing))
	for i := range existing {
		positions[existing[i].ID] = i
	}
	for _, update := range updates {
		if position, ok := positions[update.ID]; ok {
			existing[position] = update
		} else {
			positions[update.ID] = len(existing)
			existing = append(existing, update)
		}
	}
	return existing
}

func fileSHA256(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil))), nil
}

func windowsBuild() uint32 {
	buildOnce.Do(func() {
		command := exec.Command("powershell.exe", "-NoProfile", "-Command", "[Environment]::OSVersion.Version.Build")
		out, err := command.Output()
		if err == nil {
			if build, parseErr := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32); parseErr == nil {
				detectedBuild = uint32(build)
			}
		}
	})
	return detectedBuild
}

func processTargets(targets []targetSpec, windowsDir, root, extractorPath string) ([]corpusResult, bool) {
	probeDir := filepath.Join(root, "probe")
	irDir := filepath.Join(root, "ir")
	_ = os.MkdirAll(probeDir, 0o755)
	_ = os.MkdirAll(irDir, 0o755)
	results := make([]corpusResult, 0, len(targets))
	prior := make(map[string]corpusResult)
	for _, result := range readCorpusIndex(root).Targets {
		prior[result.ID] = result
	}
	failed := false
	for _, target := range targets {
		result := corpusResult{ID: target.ID, File: target.File, Area: target.Area, Required: target.Required}
		result.SourcePath = resolveTargetPath(target, windowsDir, probeDir)
		if result.SourcePath == "" {
			result.Error = "binary not installed"
			if target.Required {
				result.Status = "failed-required"
				failed = true
			} else {
				result.Status = "unavailable-optional"
			}
			results = append(results, result)
			continue
		}
		if previous, ok := prior[target.ID]; ok && reusableResult(previous, result.SourcePath) {
			previous.SourcePath = result.SourcePath
			previous.Required = target.Required
			previous.Area = target.Area
			results = append(results, previous)
			fmt.Printf("[*] Reusing verified exact-build target %s\n", target.ID)
			continue
		}
		outcome, err := processDLL(result.SourcePath, target.ID, probeDir, irDir, extractorPath)
		if err != nil {
			result.Error = err.Error()
			if target.Required {
				result.Status = "failed-required"
				failed = true
			} else {
				result.Status = "failed-optional"
			}
			fmt.Printf("[!] %s: %v\n", target.ID, err)
		} else {
			result.IR = outcome.IRPath
			result.PDBUsed = outcome.PDBUsed
			result.Status = "verified-static"
			if outcome.PDBUsed {
				result.Status = "verified-pdb"
			}
			resultMetadata(&result)
		}
		results = append(results, result)
		_ = writeCorpusIndex(root, extractorPath, results)
	}
	return results, failed
}

func reusableResult(result corpusResult, sourcePath string) bool {
	if !strings.HasPrefix(result.Status, "verified-") || result.IR == "" || result.SHA256 == "" {
		return false
	}
	if info, err := os.Stat(result.IR); err != nil || info.IsDir() {
		return false
	}
	hash, err := fileSHA256(sourcePath)
	return err == nil && strings.EqualFold(hash, result.SHA256)
}

const usage = `windissect-fleet: batch extraction for a set of Windows binaries

Usage:
  windissect-fleet [options] [all|pull|emit] [binary ...]

Commands:
  all     pull, then emit (default)
  pull    for each target: extract, fetch the exact PDB from Microsoft's
          symbol server, extract again with it, verify, record build history
  emit    write C/C++ headers and a Rust crate for every IR in <root>\ir
  help    show this message

Targets:
  With no --manifest and no binary arguments, the built-in Windows UI list
  is used (see manifests/windows-ui.json). Binary arguments replace the list
  for that run: a bare file name is looked up in System32, a path is used as
  given.

Options:
  --extractor PATH  windissect.exe to run (default: target\release\windissect.exe)
  --root DIR        where ir, probe, history, headers and rust are written
                    (default: the repository root)
  --manifest FILE   JSON target list, see docs/fleet.md
  --only IDS        comma-separated target ids from the list to process

Exit status is 1 if a required target is missing or fails.
`

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "help" || arg == "-h" || arg == "--help" {
			fmt.Print(usage)
			return
		}
	}
	exePath, err := os.Executable()
	if err != nil {
		exePath = "."
	}
	baseDir := filepath.Dir(filepath.Dir(exePath))
	if _, err := os.Stat(filepath.Join(baseDir, "Cargo.toml")); os.IsNotExist(err) {
		baseDir, _ = os.Getwd()
	}
	args := os.Args[1:]
	args, extractorOption, err := takeOption(args, "--extractor")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	args, rootOption, err := takeOption(args, "--root")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	args, manifestOption, err := takeOption(args, "--manifest")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	args, onlyOption, err := takeOption(args, "--only")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	root := baseDir
	if rootOption != "" {
		root, err = filepath.Abs(rootOption)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	extractorPath := findExtractor(baseDir)
	if extractorOption != "" {
		extractorPath, err = filepath.Abs(extractorOption)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if extractorPath == "" {
		fmt.Fprintln(os.Stderr, "[!] extractor not found; use --extractor PATH")
		os.Exit(2)
	}
	fmt.Printf("[*] windissect standalone Go toolchain initialized.\n")
	fmt.Printf("[*] Base Dir: %s\n", baseDir)
	fmt.Printf("[*] Corpus Root: %s\n", root)
	fmt.Printf("[*] Extractor Binary: %s\n", extractorPath)

	cmd := "all"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd != "pull" && cmd != "emit" && cmd != "all" {
		fmt.Fprintf(os.Stderr, "[!] unknown command %q\n", cmd)
		os.Exit(2)
	}
	targets := defaultTargets()
	if manifestOption != "" {
		targets, err = loadManifest(manifestOption)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] manifest: %v\n", err)
			os.Exit(2)
		}
	}
	if onlyOption != "" {
		wanted := map[string]bool{}
		for _, id := range strings.Split(onlyOption, ",") {
			wanted[strings.TrimSpace(id)] = true
		}
		filtered := targets[:0]
		for _, target := range targets {
			if wanted[target.ID] {
				filtered = append(filtered, target)
				delete(wanted, target.ID)
			}
		}
		if len(wanted) > 0 {
			var unknown []string
			for id := range wanted {
				unknown = append(unknown, id)
			}
			sort.Strings(unknown)
			fmt.Fprintf(os.Stderr, "[!] unknown --only target(s): %s\n", strings.Join(unknown, ", "))
			os.Exit(2)
		}
		targets = filtered
	}
	if len(args) > 1 && cmd != "emit" {
		targets = nil
		for _, file := range args[1:] {
			targets = append(targets, targetSpec{
				ID:       strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)),
				File:     file,
				Required: true,
			})
		}
	}

	windowsDir := os.Getenv("SystemRoot")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}

	switch cmd {
	case "pull":
		results, failed := processTargets(targets, windowsDir, root, extractorPath)
		if err := writeCorpusIndex(root, extractorPath, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
		if failed {
			os.Exit(1)
		}
	case "emit":
		if err := emitAllOutputs(root, extractorPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "all":
		results, failed := processTargets(targets, windowsDir, root, extractorPath)
		if err := emitAllOutputs(root, extractorPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		} else {
			for i := range results {
				if results[i].IR != "" {
					results[i].Headers = filepath.Join(root, "headers", results[i].ID)
					results[i].Rust = filepath.Join(root, "rust", results[i].ID)
				}
			}
		}
		if err := writeCorpusIndex(root, extractorPath, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
		if failed {
			os.Exit(1)
		}
	}

	fmt.Println("\n[✓] windissect pipeline execution completed successfully!")
}
