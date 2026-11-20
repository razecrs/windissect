package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/razecrs/starlings"
)

const triageFileLimit = 16 << 20

var triageSlots = make(chan struct{}, 2)

type triageArgs struct {
	File *starlings.Attachment `desc:"Windows EXE, DLL, SYS, OCX, or other PE/COFF image (max 16 MiB)"`
}

type peTriageReport struct {
	Schema               string                `json:"schema"`
	Filename             string                `json:"filename"`
	Size                 int                   `json:"size"`
	SHA256               string                `json:"sha256"`
	Format               string                `json:"format"`
	Architecture         string                `json:"architecture"`
	Kind                 string                `json:"kind"`
	Subsystem            string                `json:"subsystem"`
	ImageBase            string                `json:"image_base"`
	EntryPoint           string                `json:"entry_point_rva"`
	LinkerTimestamp      string                `json:"linker_timestamp,omitempty"`
	LinkerTimestampRaw   uint32                `json:"linker_timestamp_raw"`
	Characteristics      []string              `json:"characteristics,omitempty"`
	Mitigations          []string              `json:"mitigations,omitempty"`
	Sections             []peSectionReport     `json:"sections"`
	ImportedLibraryCount int                   `json:"imported_library_count"`
	ImportedSymbolCount  int                   `json:"imported_symbol_count"`
	NamedExportCount     int                   `json:"named_export_count"`
	ImportedLibraries    []string              `json:"imported_libraries,omitempty"`
	ImportedSymbols      []string              `json:"imported_symbols,omitempty"`
	Exports              []string              `json:"exports,omitempty"`
	DataDirectories      []string              `json:"data_directories,omitempty"`
	Debug                *peDebugReport        `json:"debug,omitempty"`
	Signature            peSignatureReport     `json:"authenticode"`
	OverlayBytes         int64                 `json:"overlay_bytes"`
	CapabilityIndicators []capabilityIndicator `json:"capability_indicators,omitempty"`
	Heuristics           []string              `json:"heuristics,omitempty"`
	Notes                []string              `json:"notes"`
}

type peSectionReport struct {
	Name            string  `json:"name"`
	RVA             string  `json:"rva"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawSize         uint32  `json:"raw_size"`
	Entropy         float64 `json:"entropy"`
	Characteristics string  `json:"characteristics"`
}

type peDebugReport struct {
	CodeView string `json:"codeview"`
	PDBPath  string `json:"pdb_path,omitempty"`
	PDBGUID  string `json:"pdb_guid,omitempty"`
	PDBAge   uint32 `json:"pdb_age,omitempty"`
}

type peSignatureReport struct {
	Present  bool   `json:"present"`
	Offset   string `json:"file_offset,omitempty"`
	Size     uint32 `json:"size,omitempty"`
	Verified bool   `json:"verified"`
	Note     string `json:"note"`
}

type capabilityIndicator struct {
	Category string   `json:"category"`
	Imports  []string `json:"imports"`
}

func registerTriage(bot *starlings.Client) {
	bot.Slash("triage", "Statically inspect a PE file without executing it", func(i *starlings.InteractionCreate, args triageArgs) error {
		return triagePE(bot, i, args)
	})
}

func triagePE(bot *starlings.Client, i *starlings.InteractionCreate, args triageArgs) error {
	if args.File == nil {
		return starlings.UserErrorf("Attach a Windows PE file to inspect.")
	}
	if args.File.Size <= 0 || args.File.Size > triageFileLimit {
		return starlings.UserErrorf("PE triage accepts files up to 16 MiB.")
	}
	select {
	case triageSlots <- struct{}{}:
		defer func() { <-triageSlots }()
	default:
		return starlings.UserErrorf("Both triage slots are busy. Try again shortly.")
	}
	if err := i.Defer(true); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	data, err := bot.DownloadAttachment(ctx, *args.File, triageFileLimit)
	if err != nil {
		return editTriageError(ctx, i, "I could not safely download that attachment. Check its size and try again.")
	}
	report, err := analyzePE(args.File.Filename, data)
	if err != nil {
		return editTriageError(ctx, i, "That attachment is not a valid, supported PE image: "+err.Error())
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	embed := triageEmbed(report)
	_, err = i.EditResponseFiles(ctx, starlings.InteractionResponseData{
		Embeds:          []starlings.Embed{*embed},
		AllowedMentions: starlings.NoMentions(),
	}, starlings.FileFromBytes("windissect-triage.json", append(raw, '\n')))
	return err
}

func editTriageError(ctx context.Context, i *starlings.InteractionCreate, message string) error {
	_, err := i.EditResponse(ctx, starlings.InteractionResponseData{Content: message, AllowedMentions: starlings.NoMentions()})
	return err
}

func analyzePE(filename string, data []byte) (report peTriageReport, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("malformed PE metadata")
		}
	}()
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return report, err
	}
	defer file.Close()

	sum := sha256.Sum256(data)
	report = peTriageReport{
		Schema: "windissect.pe-triage.v1", Filename: filepath.Base(filename), Size: len(data),
		SHA256: hex.EncodeToString(sum[:]), Architecture: peMachineName(file.Machine),
		LinkerTimestampRaw: file.TimeDateStamp,
		Notes: []string{
			"Static parse only: Windissect did not execute or load this file.",
			"Capability indicators describe imported APIs, not intent or a malware verdict.",
			"Linker timestamps and section names are untrusted metadata and may be forged.",
		},
	}
	if file.TimeDateStamp != 0 {
		report.LinkerTimestamp = time.Unix(int64(file.TimeDateStamp), 0).UTC().Format(time.RFC3339)
	}
	report.Characteristics = coffCharacteristics(file.Characteristics)
	report.Kind = "executable"
	if file.Characteristics&0x2000 != 0 {
		report.Kind = "DLL"
	} else if strings.EqualFold(filepath.Ext(filename), ".sys") {
		report.Kind = "driver image"
	}

	var directories []pe.DataDirectory
	var dllCharacteristics uint16
	switch optional := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		report.Format = "PE32"
		report.ImageBase = fmt.Sprintf("0x%X", optional.ImageBase)
		report.EntryPoint = fmt.Sprintf("0x%X", optional.AddressOfEntryPoint)
		report.Subsystem = peSubsystemName(optional.Subsystem)
		dllCharacteristics = optional.DllCharacteristics
		directories = optional.DataDirectory[:]
	case *pe.OptionalHeader64:
		report.Format = "PE32+"
		report.ImageBase = fmt.Sprintf("0x%X", optional.ImageBase)
		report.EntryPoint = fmt.Sprintf("0x%X", optional.AddressOfEntryPoint)
		report.Subsystem = peSubsystemName(optional.Subsystem)
		dllCharacteristics = optional.DllCharacteristics
		directories = optional.DataDirectory[:]
	default:
		return report, fmt.Errorf("missing PE optional header")
	}
	report.Mitigations = mitigationFlags(dllCharacteristics)
	report.DataDirectories = presentDirectories(directories)

	var imageEnd int64
	for _, section := range file.Sections {
		sectionData, readErr := section.Data()
		if readErr != nil {
			sectionData = nil
		}
		name := strings.TrimRight(section.Name, "\x00")
		flags := sectionFlags(section.Characteristics)
		report.Sections = append(report.Sections, peSectionReport{
			Name: name, RVA: fmt.Sprintf("0x%X", section.VirtualAddress), VirtualSize: section.VirtualSize,
			RawSize: section.Size, Entropy: math.Round(shannonEntropy(sectionData)*1000) / 1000,
			Characteristics: strings.Join(flags, " | "),
		})
		end := int64(section.Offset) + int64(section.Size)
		if end > imageEnd && end <= int64(len(data)) {
			imageEnd = end
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, "upx") || strings.Contains(lower, "mpress") || strings.Contains(lower, "aspack") || strings.Contains(lower, "themida") {
			report.Heuristics = append(report.Heuristics, "Section name resembles a common packer/protector: "+name)
		}
		if len(sectionData) >= 512 && shannonEntropy(sectionData) >= 7.2 {
			report.Heuristics = append(report.Heuristics, fmt.Sprintf("High-entropy section %s (%.3f bits/byte)", name, shannonEntropy(sectionData)))
		}
		if section.Characteristics&0x20000000 != 0 && section.Characteristics&0x80000000 != 0 {
			report.Heuristics = append(report.Heuristics, "Section is both writable and executable: "+name)
		}
	}
	if imageEnd < int64(len(data)) {
		report.OverlayBytes = int64(len(data)) - imageEnd
	}

	report.ImportedLibraries, _ = file.ImportedLibraries()
	report.ImportedSymbols, _ = file.ImportedSymbols()
	sort.Strings(report.ImportedLibraries)
	sort.Strings(report.ImportedSymbols)
	report.Exports = parseExportNames(data, file, directories)
	report.CapabilityIndicators = detectCapabilities(report.ImportedSymbols)
	report.ImportedLibraryCount = len(report.ImportedLibraries)
	report.ImportedSymbolCount = len(report.ImportedSymbols)
	report.NamedExportCount = len(report.Exports)
	if len(report.ImportedLibraries) > 512 {
		report.ImportedLibraries = report.ImportedLibraries[:512]
		report.Notes = append(report.Notes, "Imported-library evidence was capped at 512 entries in the JSON report.")
	}
	if len(report.ImportedSymbols) > 4096 {
		report.ImportedSymbols = report.ImportedSymbols[:4096]
		report.Notes = append(report.Notes, "Imported-symbol evidence was capped at 4,096 entries in the JSON report.")
	}
	report.Debug = findCodeView(data)
	report.Signature = inspectSecurityDirectory(data, directories)
	if len(report.ImportedSymbols) == 0 {
		report.Heuristics = append(report.Heuristics, "No named imports were recovered; this can be legitimate or consistent with packed/dynamic resolution")
	}
	if report.OverlayBytes > 0 {
		report.Heuristics = append(report.Heuristics, fmt.Sprintf("%d bytes follow the last section (may include a certificate table or benign overlay)", report.OverlayBytes))
	}
	return report, nil
}

func triageEmbed(report peTriageReport) *starlings.Embed {
	identity := fmt.Sprintf("`%s` · %s · %s · %s\nSHA-256 `%s`", report.Filename, report.Format, report.Architecture, report.Kind, report.SHA256)
	embed := starlings.NewEmbed("Windissect PE triage").SetColor(windissectBlue).SetDescription(identity).
		AddField("Image", fmt.Sprintf("Entry `%s` · base `%s`\nSubsystem: %s", report.EntryPoint, report.ImageBase, report.Subsystem), false).
		AddField("Surface", fmt.Sprintf("%d sections · %d libraries · %d imports · %d named exports", len(report.Sections), report.ImportedLibraryCount, report.ImportedSymbolCount, report.NamedExportCount), true).
		AddField("Authenticode", report.Signature.Note, true)
	if report.Debug != nil {
		debug := report.Debug.CodeView
		if report.Debug.PDBPath != "" {
			debug += "\n`" + report.Debug.PDBPath + "`\nGUID `" + report.Debug.PDBGUID + "` · age `" + fmt.Sprint(report.Debug.PDBAge) + "`"
		}
		embed.AddField("Debug identity", debug, false)
	}
	if len(report.CapabilityIndicators) > 0 {
		var lines []string
		for _, indicator := range report.CapabilityIndicators {
			lines = append(lines, "**"+indicator.Category+"**: `"+strings.Join(limitStrings(indicator.Imports, 6), "`, `")+"`")
		}
		embed.AddField("Imported capability indicators", strings.Join(lines, "\n"), false)
	}
	if len(report.Heuristics) > 0 {
		embed.AddField("Review cues—not verdicts", "• "+strings.Join(limitStrings(report.Heuristics, 6), "\n• "), false)
	}
	embed.SetFooter("Full evidence is attached as windissect-triage.json · static parsing only", "")
	return embed
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range data {
		counts[value]++
	}
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(data))
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func peMachineName(machine uint16) string {
	return map[uint16]string{0x014c: "x86", 0x0200: "IA-64", 0x01c0: "ARM", 0x01c4: "ARM Thumb-2", 0x8664: "x86-64", 0xaa64: "ARM64", 0xa641: "ARM64EC", 0x3a64: "CHPE x86"}[machine]
}

func peSubsystemName(subsystem uint16) string {
	if name := map[uint16]string{0: "unknown", 1: "native", 2: "Windows GUI", 3: "Windows console", 5: "OS/2 console", 7: "POSIX console", 9: "Windows CE GUI", 10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver", 13: "EFI ROM", 14: "Xbox", 16: "Windows boot application"}[subsystem]; name != "" {
		return name
	}
	return fmt.Sprintf("unknown (%d)", subsystem)
}

func coffCharacteristics(value uint16) []string {
	return namedBits16(value, map[uint16]string{0x0002: "executable-image", 0x0020: "large-address-aware", 0x0100: "32-bit-machine", 0x0200: "debug-stripped", 0x1000: "system", 0x2000: "dll", 0x4000: "uniprocessor-only"})
}

func mitigationFlags(value uint16) []string {
	return namedBits16(value, map[uint16]string{0x0040: "ASLR", 0x0080: "force-integrity", 0x0100: "DEP/NX", 0x0400: "no-SEH", 0x1000: "AppContainer", 0x2000: "WDM-driver", 0x4000: "Control Flow Guard", 0x8000: "terminal-server-aware"})
}

func namedBits16(value uint16, names map[uint16]string) []string {
	bits := make([]int, 0, len(names))
	for bit := range names {
		bits = append(bits, int(bit))
	}
	sort.Ints(bits)
	var result []string
	for _, bit := range bits {
		if value&uint16(bit) != 0 {
			result = append(result, names[uint16(bit)])
		}
	}
	return result
}

func sectionFlags(value uint32) []string {
	var result []string
	for bit, name := range map[uint32]string{0x00000020: "code", 0x00000040: "initialized-data", 0x00000080: "uninitialized-data", 0x02000000: "discardable", 0x20000000: "execute", 0x40000000: "read", 0x80000000: "write"} {
		if value&bit != 0 {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func presentDirectories(directories []pe.DataDirectory) []string {
	names := []string{"exports", "imports", "resources", "exceptions", "security", "base-relocations", "debug", "architecture", "global-ptr", "TLS", "load-config", "bound-import", "IAT", "delay-import", "CLR", "reserved"}
	var result []string
	for index, directory := range directories {
		if directory.VirtualAddress == 0 || directory.Size == 0 {
			continue
		}
		name := fmt.Sprintf("directory-%d", index)
		if index < len(names) {
			name = names[index]
		}
		result = append(result, fmt.Sprintf("%s: address 0x%X, size %d", name, directory.VirtualAddress, directory.Size))
	}
	return result
}

func inspectSecurityDirectory(data []byte, directories []pe.DataDirectory) peSignatureReport {
	report := peSignatureReport{Note: "No embedded Authenticode certificate table was declared."}
	if len(directories) <= 4 || directories[4].VirtualAddress == 0 || directories[4].Size == 0 {
		return report
	}
	directory := directories[4]
	report.Present, report.Offset, report.Size = true, fmt.Sprintf("0x%X", directory.VirtualAddress), directory.Size
	end := uint64(directory.VirtualAddress) + uint64(directory.Size)
	if end > uint64(len(data)) || end < uint64(directory.VirtualAddress) {
		report.Note = "A certificate table is declared, but its file range is invalid. Signature not verified."
		return report
	}
	report.Note = "Embedded certificate table present; cryptographic trust and chain are not verified by bot triage."
	return report
}

func findCodeView(data []byte) *peDebugReport {
	offset := bytes.Index(data, []byte("RSDS"))
	if offset < 0 {
		if bytes.Contains(data, []byte("NB10")) {
			return &peDebugReport{CodeView: "CodeView NB10 record present (legacy identity)"}
		}
		return nil
	}
	if offset+24 > len(data) {
		return &peDebugReport{CodeView: "Truncated CodeView RSDS record"}
	}
	guid := data[offset+4 : offset+20]
	formatted := fmt.Sprintf("%08X-%04X-%04X-%s-%s", binary.LittleEndian.Uint32(guid[0:4]), binary.LittleEndian.Uint16(guid[4:6]), binary.LittleEndian.Uint16(guid[6:8]), strings.ToUpper(hex.EncodeToString(guid[8:10])), strings.ToUpper(hex.EncodeToString(guid[10:16])))
	age := binary.LittleEndian.Uint32(data[offset+20 : offset+24])
	pathBytes := data[offset+24:]
	if zero := bytes.IndexByte(pathBytes, 0); zero >= 0 {
		pathBytes = pathBytes[:zero]
	}
	if len(pathBytes) > 1024 {
		pathBytes = pathBytes[:1024]
	}
	path := ""
	if utf8.Valid(pathBytes) {
		path = strings.Map(func(r rune) rune {
			if r < 0x20 {
				return -1
			}
			return r
		}, string(pathBytes))
	}
	return &peDebugReport{CodeView: "CodeView RSDS", PDBPath: path, PDBGUID: formatted, PDBAge: age}
}

func parseExportNames(data []byte, file *pe.File, directories []pe.DataDirectory) []string {
	if len(directories) == 0 || directories[0].VirtualAddress == 0 {
		return nil
	}
	offset, ok := rvaToOffset(file, directories[0].VirtualAddress)
	if !ok || offset+40 > uint32(len(data)) {
		return nil
	}
	header := data[offset : offset+40]
	count := binary.LittleEndian.Uint32(header[24:28])
	namesRVA := binary.LittleEndian.Uint32(header[32:36])
	if count > 4096 {
		count = 4096
	}
	namesOffset, ok := rvaToOffset(file, namesRVA)
	if !ok || uint64(namesOffset)+uint64(count)*4 > uint64(len(data)) {
		return nil
	}
	result := make([]string, 0, count)
	for index := uint32(0); index < count; index++ {
		nameRVA := binary.LittleEndian.Uint32(data[namesOffset+index*4 : namesOffset+index*4+4])
		nameOffset, valid := rvaToOffset(file, nameRVA)
		if !valid || nameOffset >= uint32(len(data)) {
			continue
		}
		if name := boundedCString(data[nameOffset:], 512); name != "" {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func rvaToOffset(file *pe.File, rva uint32) (uint32, bool) {
	for _, section := range file.Sections {
		size := section.VirtualSize
		if section.Size > size {
			size = section.Size
		}
		if rva >= section.VirtualAddress && uint64(rva) < uint64(section.VirtualAddress)+uint64(size) {
			delta := rva - section.VirtualAddress
			if delta >= section.Size {
				return 0, false
			}
			return section.Offset + delta, true
		}
	}
	return rva, rva < 0x1000
}

func boundedCString(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	if zero := bytes.IndexByte(data, 0); zero >= 0 {
		data = data[:zero]
	}
	if len(data) == 0 || !utf8.Valid(data) {
		return ""
	}
	for _, value := range data {
		if value < 0x20 || value > 0x7e {
			return ""
		}
	}
	return string(data)
}

func detectCapabilities(imports []string) []capabilityIndicator {
	groups := []struct {
		name  string
		terms []string
	}{
		{"Process and memory manipulation", []string{"openprocess", "writeprocessmemory", "readprocessmemory", "virtualallocex", "createremotethread", "ntwritevirtualmemory", "ntmapviewofsection"}},
		{"Dynamic code and library loading", []string{"virtualalloc", "virtualprotect", "loadlibrary", "getprocaddress", "ldrloaddll"}},
		{"Network access", []string{"winhttp", "internetopen", "internetconnect", "urldownloadtofile", "wsastartup", "wsaconnect", "connect:"}},
		{"Persistence-capable APIs", []string{"regsetvalue", "createservice", "startservice", "schtasks", "setwindowshookex"}},
		{"Debugging and analysis checks", []string{"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring"}},
		{"Cryptography", []string{"cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt", "cryptprotectdata"}},
	}
	var result []capabilityIndicator
	for _, group := range groups {
		var matches []string
		for _, imported := range imports {
			lower := strings.ToLower(imported)
			for _, term := range group.terms {
				if strings.Contains(lower, term) {
					matches = append(matches, imported)
					break
				}
			}
		}
		if len(matches) > 0 {
			result = append(result, capabilityIndicator{Category: group.name, Imports: matches})
		}
	}
	return result
}

func limitStrings(values []string, count int) []string {
	if len(values) <= count {
		return values
	}
	result := append([]string(nil), values[:count]...)
	return append(result, fmt.Sprintf("…and %d more", len(values)-count))
}
