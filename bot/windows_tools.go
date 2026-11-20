package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/razecrs/starlings"
)

var (
	learnClient = &http.Client{Timeout: 12 * time.Second}
	htmlTag     = regexp.MustCompile(`<[^>]+>`)
	guidPattern = regexp.MustCompile(`(?i)^\{?([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\}?$`)
)

type valueArgs struct {
	Value string `desc:"Numeric value; prefixes 0x, 0b and 0o are supported" max:"80"`
}

type detectAddressArgs struct {
	Value     string `desc:"Address or RVA to inspect" max:"32"`
	ImageBase string `name:"image-base" desc:"Module image base" max:"32"`
}

type statusArgs struct {
	Kind  string `desc:"Windows status family" choices:"HRESULT=hresult|NTSTATUS=ntstatus|Win32=win32"`
	Value string `desc:"Hex or signed/unsigned decimal value" max:"32"`
}

type docArgs struct {
	Query string `desc:"Windows API, structure, constant, or concept" min:"2" max:"200"`
}

type bytesArgs struct {
	Bytes string `desc:"Hex bytes such as 4D 5A 90 00" min:"2" max:"512"`
}

type guidArgs struct {
	GUID string `name:"guid" desc:"Windows GUID with or without braces" min:"32" max:"40"`
}

func registerWindowsTools(bot *starlings.Client) {
	bot.Slash("base", "Detect and convert a number between common bases", convertBase)
	bot.Slash("address", "Detect a VA or RVA relative to an image base", detectAddress)
	bot.Slash("winstatus", "Decode HRESULT, NTSTATUS, or Win32 error bits", decodeWindowsStatus)
	bot.Slash("pemachine", "Decode a PE COFF machine value", decodePEMachine)
	bot.Slash("magic", "Detect a file or executable signature from hex bytes", detectMagic)
	bot.Slash("guid", "Normalize a Windows GUID and show its in-memory bytes", inspectGUID)
	bot.Slash("windoc", "Pull matching official Microsoft Learn documentation", pullWindowsDocs)
}

func convertBase(args valueArgs) (starlings.Response, error) {
	value, detected, err := parseFlexibleUint(args.Value)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("I could not determine that number's base. Try `0x`, `0b`, `0o`, or decimal.")
	}
	bits := 1
	if value > 0 {
		bits = 64 - leadingZeros64(value)
	}
	embed := starlings.NewEmbed("Base detector").SetColor(windissectBlue).
		AddField("Detected", detected, true).
		AddField("Bit width", strconv.Itoa(bits), true).
		AddField("Hexadecimal", fmt.Sprintf("`0x%X`", value), false).
		AddField("Decimal", fmt.Sprintf("`%d`", value), false).
		AddField("Octal", fmt.Sprintf("`0o%o`", value), false).
		AddField("Binary", fmt.Sprintf("`0b%b`", value), false)
	return starlings.Ephemeral(embed), nil
}

func detectAddress(args detectAddressArgs) (starlings.Response, error) {
	value, _, err := parseFlexibleUint(args.Value)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("Address is not a recognized integer.")
	}
	base, _, err := parseFlexibleUint(args.ImageBase)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("Image base is not a recognized integer.")
	}
	embed := starlings.NewEmbed("Address detector").SetColor(windissectBlue)
	if value >= base {
		embed.SetDescription("The value is at or above the image base, so it is consistent with a **virtual address**.").
			AddField("VA", fmt.Sprintf("`0x%X`", value), true).
			AddField("Image base", fmt.Sprintf("`0x%X`", base), true).
			AddField("RVA", fmt.Sprintf("`0x%X`", value-base), false)
	} else {
		if ^uint64(0)-base < value {
			return starlings.Response{}, starlings.UserErrorf("Adding that RVA overflows 64 bits.")
		}
		embed.SetDescription("The value is below the image base, so it is consistent with an **RVA**.").
			AddField("RVA", fmt.Sprintf("`0x%X`", value), true).
			AddField("Image base", fmt.Sprintf("`0x%X`", base), true).
			AddField("VA", fmt.Sprintf("`0x%X`", base+value), false)
	}
	return starlings.Ephemeral(embed), nil
}

func decodeWindowsStatus(args statusArgs) (starlings.Response, error) {
	value, err := parseStatusValue(args.Value)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("Status must be a 32-bit hex or decimal value.")
	}
	embed := starlings.NewEmbed(strings.ToUpper(args.Kind)+" decoder").SetColor(windissectBlue).
		AddField("Value", fmt.Sprintf("`0x%08X` · unsigned `%d` · signed `%d`", value, value, int32(value)), false)
	switch args.Kind {
	case "hresult":
		severity := "success"
		if value&(1<<31) != 0 {
			severity = "failure"
		}
		facility := (value >> 16) & 0x7FF
		code := value & 0xFFFF
		embed.AddField("Severity", severity, true).
			AddField("Facility", fmt.Sprintf("%d (`0x%X`)", facility, facility), true).
			AddField("Code", fmt.Sprintf("%d (`0x%04X`)", code, code), true)
		if value&0xFFFF0000 == 0x80070000 {
			embed.AddField("Derived Win32 error", fmt.Sprintf("%d (`HRESULT_FROM_WIN32`)", code), false)
		}
	case "ntstatus":
		severity := []string{"success", "informational", "warning", "error"}[(value>>30)&3]
		customer := value&(1<<29) != 0
		facility := (value >> 16) & 0xFFF
		code := value & 0xFFFF
		embed.AddField("Severity", severity, true).
			AddField("Customer-defined", strconv.FormatBool(customer), true).
			AddField("Facility", fmt.Sprintf("%d (`0x%X`)", facility, facility), true).
			AddField("Code", fmt.Sprintf("%d (`0x%04X`)", code, code), true)
	case "win32":
		if value > 0xFFFF {
			embed.AddField("Notice", "Most Win32 error codes fit in 16 bits; this value may belong to another status family.", false)
		}
		embed.AddField("Code", strconv.FormatUint(uint64(value), 10), true).
			AddField("HRESULT_FROM_WIN32", fmt.Sprintf("`0x%08X`", uint32(0x80070000)|(value&0xFFFF)), false)
	default:
		return starlings.Response{}, starlings.UserErrorf("Choose HRESULT, NTSTATUS, or Win32.")
	}
	embed.AddField("Find the symbolic name", "Use `/windoc` with the hex value or suspected constant.", false)
	return starlings.Ephemeral(embed), nil
}

func decodePEMachine(args valueArgs) (starlings.Response, error) {
	value, _, err := parseFlexibleUint(args.Value)
	if err != nil || value > 0xFFFF {
		return starlings.Response{}, starlings.UserErrorf("PE machine values are 16-bit integers such as `0x8664`.")
	}
	machines := map[uint64]string{
		0x0000: "UNKNOWN", 0x014C: "I386 / x86", 0x01C0: "ARM", 0x01C4: "ARMNT / Thumb-2",
		0x0200: "IA64", 0x8664: "AMD64 / x86-64", 0xAA64: "ARM64", 0xA641: "ARM64EC", 0x3A64: "CHPE_X86",
	}
	name := machines[value]
	if name == "" {
		name = "Unknown or uncommon machine value"
	}
	embed := starlings.NewEmbed("PE machine detector").SetColor(windissectBlue).
		AddField("Value", fmt.Sprintf("`0x%04X`", value), true).
		AddField("Architecture", name, true).
		AddField("Official reference", "https://learn.microsoft.com/windows/win32/debug/pe-format#machine-types", false)
	return starlings.Ephemeral(embed), nil
}

func detectMagic(args bytesArgs) (starlings.Response, error) {
	clean := strings.NewReplacer(" ", "", "-", "", ":", "", "0x", "", "0X", "").Replace(args.Bytes)
	if len(clean)%2 != 0 {
		return starlings.Response{}, starlings.UserErrorf("Hex input needs complete byte pairs.")
	}
	data, err := hex.DecodeString(clean)
	if err != nil || len(data) == 0 {
		return starlings.Response{}, starlings.UserErrorf("Provide hexadecimal bytes such as `4D 5A 90 00`.")
	}
	type signature struct {
		bytes      []byte
		name, note string
	}
	signatures := []signature{
		{[]byte{'M', 'Z'}, "DOS MZ executable", "Usually the front of a PE image; confirm `PE\\0\\0` at `e_lfanew`."},
		{[]byte{'P', 'E', 0, 0}, "PE/COFF signature", "The NT headers signature, normally reached through the DOS header."},
		{[]byte{0x7F, 'E', 'L', 'F'}, "ELF executable", "Unix-like executable or shared-object format."},
		{[]byte{'P', 'K', 0x03, 0x04}, "ZIP container", "Also used by formats such as JAR, APK, DOCX, and other ZIP-based containers."},
		{[]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, "PNG image", "Portable Network Graphics signature."},
		{[]byte{'%', 'P', 'D', 'F'}, "PDF document", "Portable Document Format header."},
		{[]byte{0x1F, 0x8B}, "GZIP stream", "DEFLATE-compressed gzip data."},
	}
	name, note := "Unknown signature", "No built-in detector matched this prefix. It may still be a valid format or an interior byte sequence."
	for _, candidate := range signatures {
		if len(data) >= len(candidate.bytes) && string(data[:len(candidate.bytes)]) == string(candidate.bytes) {
			name, note = candidate.name, candidate.note
			break
		}
	}
	embed := starlings.NewEmbed("Magic-byte detector").SetColor(windissectBlue).
		AddField("Bytes", "`"+strings.ToUpper(hex.EncodeToString(data))+"`", false).
		AddField("Detected", name, false).
		AddField("Notes", note, false)
	return starlings.Ephemeral(embed), nil
}

func inspectGUID(args guidArgs) (starlings.Response, error) {
	match := guidPattern.FindStringSubmatch(strings.TrimSpace(args.GUID))
	if match == nil {
		return starlings.Response{}, starlings.UserErrorf("That is not a valid GUID.")
	}
	normalized := strings.ToUpper(strings.Join(match[1:], "-"))
	data1, _ := strconv.ParseUint(match[1], 16, 32)
	data2, _ := strconv.ParseUint(match[2], 16, 16)
	data3, _ := strconv.ParseUint(match[3], 16, 16)
	tail, _ := hex.DecodeString(match[4] + match[5])
	memory := make([]byte, 16)
	binary.LittleEndian.PutUint32(memory[0:4], uint32(data1))
	binary.LittleEndian.PutUint16(memory[4:6], uint16(data2))
	binary.LittleEndian.PutUint16(memory[6:8], uint16(data3))
	copy(memory[8:], tail)
	embed := starlings.NewEmbed("Windows GUID inspector").SetColor(windissectBlue).
		AddField("Canonical", "`{"+normalized+"}`", false).
		AddField("In-memory bytes", "`"+spacedHex(memory)+"`", false).
		AddField("Layout", "The first DWORD and two WORDs are little-endian in memory; the final 8 bytes keep display order.", false)
	return starlings.Ephemeral(embed), nil
}

func pullWindowsDocs(args docArgs) (starlings.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	query := strings.TrimSpace(args.Query)
	params := url.Values{"search": {query}, "locale": {"en-us"}, "$top": {"8"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://learn.microsoft.com/api/search?"+params.Encode(), nil)
	if err != nil {
		return starlings.Response{}, err
	}
	request.Header.Set("User-Agent", "WindissectBot/1.0 (+https://github.com/razecrs/windissect)")
	response, err := learnClient.Do(request)
	if err != nil {
		return starlings.Response{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return starlings.Response{}, fmt.Errorf("Microsoft Learn search returned %s", response.Status)
	}
	var body struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"results"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return starlings.Response{}, err
	}
	embed := starlings.NewEmbed("Microsoft Learn · " + query).SetColor(0x0078D4)
	added := 0
	for _, result := range body.Results {
		if !strings.HasPrefix(result.URL, "https://learn.microsoft.com/") || strings.Contains(result.URL, "/answers/") {
			continue
		}
		description := strings.TrimSpace(html.UnescapeString(htmlTag.ReplaceAllString(result.Description, "")))
		if len(description) > 240 {
			description = description[:239] + "…"
		}
		embed.AddField(result.Title, description+"\n[Open official documentation]("+result.URL+")", false)
		added++
		if added == 3 {
			break
		}
	}
	if added == 0 {
		return starlings.Response{}, starlings.UserErrorf("Microsoft Learn returned no official documentation for that query.")
	}
	embed.SetFooter("Results from Microsoft Learn", "")
	return starlings.Ephemeral(embed), nil
}

func parseFlexibleUint(input string) (uint64, string, error) {
	value := strings.ReplaceAll(strings.TrimSpace(input), "_", "")
	base, label := 10, "decimal"
	switch {
	case strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X"):
		base, label, value = 16, "hexadecimal", value[2:]
	case strings.HasPrefix(value, "0b") || strings.HasPrefix(value, "0B"):
		base, label, value = 2, "binary", value[2:]
	case strings.HasPrefix(value, "0o") || strings.HasPrefix(value, "0O"):
		base, label, value = 8, "octal", value[2:]
	case strings.HasSuffix(value, "h") || strings.HasSuffix(value, "H"):
		base, label, value = 16, "hexadecimal (`h` suffix)", value[:len(value)-1]
	case strings.ContainsAny(value, "abcdefABCDEF"):
		base, label = 16, "hexadecimal (A–F detected)"
	}
	parsed, err := strconv.ParseUint(value, base, 64)
	return parsed, label, err
}

func parseStatusValue(input string) (uint32, error) {
	value := strings.ReplaceAll(strings.TrimSpace(input), "_", "")
	if strings.HasPrefix(value, "-") {
		signed, err := strconv.ParseInt(value, 10, 32)
		return uint32(signed), err
	}
	parsed, _, err := parseFlexibleUint(value)
	if err != nil || parsed > 0xFFFFFFFF {
		return 0, fmt.Errorf("outside 32 bits")
	}
	return uint32(parsed), nil
}

func leadingZeros64(value uint64) int {
	zeros := 0
	for bit := uint64(1) << 63; bit != 0 && value&bit == 0; bit >>= 1 {
		zeros++
	}
	return zeros
}

func spacedHex(data []byte) string {
	parts := make([]string, len(data))
	for index, value := range data {
		parts[index] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, " ")
}
