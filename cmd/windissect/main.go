package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"
)

var symbolServer = "https://msdl.microsoft.com/download/symbols"
var pdbMagic = []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")

var targetDLLs = []string{
	// 1. Desktop Window Manager & Composition
	"uDWM.dll",
	"dwmcore.dll",
	"dwmapi.dll",
	"dcomp.dll",
	"duser.dll",
	// 2. DirectUI & Classic Shell Controls
	"dui70.dll",
	"ExplorerFrame.dll",
	"shell32.dll",
	"shlwapi.dll",
	"comctl32.dll",
	"uxtheme.dll",
	"user32.dll",
	// 3. Immersive Shell & Modern Taskbar/Start
	"twinui.dll",
	"twinui.pcshell.dll",
	"taskbar.dll",
	"StartDocked.dll",
	"twinapi.dll",
	"twinapi.appcore.dll",
	// 4. WinUI 2 / WinUI 3 / XAML & App SDK
	"windows.ui.xaml.dll",
	"Microsoft.ui.xaml.dll",
	"Microsoft.UI.Windowing.Core.dll",
	// 5. Control Center, Flyouts, Notifications & System Tray
	"SndVolSSO.dll",
	"ControlCenter.dll",
	"ActionCenter.dll",
	"pnidui.dll",
	// 6. Virtual Desktops, Input & Message Routing
	"inputhost.dll",
	"CoreMessaging.dll",
	"textinputframework.dll",
	// 7. Native Inbox Apps & File Dialogs
	"windows.storage.dll",
	"shellcommon.dll",
	"SystemSettings.View.dll",
	"Taskmgr.dll",
}

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

func processDLL(dllName string, system32Dir, probeDir, irDir, exePath string) error {
	dllPath := filepath.Join(system32Dir, dllName)
	if filepath.IsAbs(dllName) || strings.ContainsAny(dllName, `/\\`) {
		dllPath = dllName
	}
	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		dllPath = filepath.Join(probeDir, dllName)
		if _, err := os.Stat(dllPath); os.IsNotExist(err) {
			fmt.Printf("[?] Skipping %s: not found in System32 or probe/\n", dllName)
			return fmt.Errorf("DLL not found")
		}
	}

	fmt.Println("\n==========================================")
	fmt.Printf("[*] Target: %s (%s)\n", dllName, dllPath)
	fmt.Println("==========================================")

	stem := strings.TrimSuffix(filepath.Base(dllName), filepath.Ext(dllName))
	irOut := filepath.Join(irDir, stem+".json")

	work, err := os.MkdirTemp("", "windissect-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	pass1 := filepath.Join(work, "pass1.json")
	cmd1 := exec.Command(exePath, "extract", dllPath, "--out", pass1)
	cmd1.Dir = work
	if out, err := cmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("pass 1 failed: %w: %s", err, out)
	}

	irData, err := os.ReadFile(pass1)
	if err != nil {
		fmt.Printf("[!] Pass 1 failed to generate IR for %s\n", dllName)
		return err
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
		return err
	}

	pdbName, err := safePDBName(parsed.Binary.PdbName)
	if err != nil && parsed.Binary.PdbName != "" {
		return err
	}
	rawGuid := parsed.Binary.PdbGuid
	fmt.Printf("[+] PE Metadata: PDB='%s', Raw GUID='%s'\n", pdbName, rawGuid)

	var pdbPath string
	if pdbName != "" && rawGuid != "" {
		key := symbolKey(rawGuid, parsed.Binary.PdbAge)
		if key == "" {
			return fmt.Errorf("invalid PDB GUID+age")
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
	output, err := cmd2.CombinedOutput()
	fmt.Println(string(output))
	if err != nil {
		return fmt.Errorf("pass 2 failed: %w", err)
	}
	if b, err := os.ReadFile(final); err != nil || !json.Valid(b) {
		return fmt.Errorf("pass 2 produced invalid IR")
	}
	if err := replaceFile(final, irOut); err != nil {
		return err
	}
	record := exec.Command(exePath, "record-build", irOut, "--history", filepath.Join(filepath.Dir(irDir), "history"))
	record.Dir = filepath.Dir(irDir)
	if output, err := record.CombinedOutput(); err != nil {
		return fmt.Errorf("record build failed: %w: %s", err, output)
	} else {
		fmt.Print(string(output))
	}
	return nil
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

func emitAllHeaders(baseDir, exePath string) error {
	irDir := filepath.Join(baseDir, "ir")
	headersDir := filepath.Join(baseDir, "headers")
	_ = os.MkdirAll(headersDir, 0755)

	entries, err := os.ReadDir(irDir)
	if err != nil {
		fmt.Printf("[!] Failed to read IR dir: %v\n", err)
		return err
	}

	fmt.Printf("[*] Emitting C headers for %d IR databases into headers/\n", len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			stem := strings.TrimSuffix(entry.Name(), ".json")
			irFile := filepath.Join(irDir, entry.Name())
			outDir := filepath.Join(headersDir, stem)
			fmt.Printf("[*] Emitting headers for %s -> %s\n", entry.Name(), outDir)

			cmd := exec.Command(exePath, "emit-headers", "--ir", irFile, "--out", outDir)
			out, err := cmd.CombinedOutput()
			fmt.Println(string(out))
			if err != nil {
				return fmt.Errorf("emit %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		exePath = "."
	}
	baseDir := filepath.Dir(filepath.Dir(exePath))
	if _, err := os.Stat(filepath.Join(baseDir, "Cargo.toml")); os.IsNotExist(err) {
		baseDir, _ = os.Getwd()
	}

	probeDir := filepath.Join(baseDir, "probe")
	irDir := filepath.Join(baseDir, "ir")
	_ = os.MkdirAll(probeDir, 0755)
	_ = os.MkdirAll(irDir, 0755)

	extractorPath := findExtractor(baseDir)
	if len(os.Args) > 2 && os.Args[1] == "--extractor" {
		extractorPath = os.Args[2]
		os.Args = append([]string{os.Args[0]}, os.Args[3:]...)
	}
	if extractorPath == "" {
		fmt.Fprintln(os.Stderr, "[!] extractor not found; use --extractor PATH")
		os.Exit(2)
	}
	fmt.Printf("[*] windissect standalone Go toolchain initialized.\n")
	fmt.Printf("[*] Base Dir: %s\n", baseDir)
	fmt.Printf("[*] Extractor Binary: %s\n", extractorPath)

	args := os.Args[1:]
	cmd := "all"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd != "pull" && cmd != "emit" && cmd != "all" {
		fmt.Fprintf(os.Stderr, "[!] unknown command %q\n", cmd)
		os.Exit(2)
	}
	targets := targetDLLs
	if len(args) > 1 && cmd != "emit" {
		targets = args[1:]
	}

	system32Dir := filepath.Join(os.Getenv("SystemRoot"), "System32")
	if system32Dir == "System32" {
		system32Dir = "C:\\Windows\\System32"
	}

	switch cmd {
	case "pull":
		var failed bool
		for _, dll := range targets {
			if err := processDLL(dll, system32Dir, probeDir, irDir, extractorPath); err != nil {
				fmt.Printf("[!] %s: %v\n", dll, err)
				failed = true
			}
		}
		if failed {
			os.Exit(1)
		}
	case "emit":
		if err := emitAllHeaders(baseDir, extractorPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "all":
		var failed bool
		for _, dll := range targets {
			if err := processDLL(dll, system32Dir, probeDir, irDir, extractorPath); err != nil {
				fmt.Printf("[!] %s: %v\n", dll, err)
				failed = true
			}
		}
		if failed {
			os.Exit(1)
		}
		if err := emitAllHeaders(baseDir, extractorPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	fmt.Println("\n[✓] windissect pipeline execution completed successfully!")
}
