package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/razecrs/starlings"
)

const compilerExplorerBase = "https://godbolt.org/api"

var (
	compilerExplorerClient = &http.Client{Timeout: 25 * time.Second}
	compileSlots           = make(chan struct{}, 2)
)

type compileArgs struct {
	Toolchain    string `desc:"Language and compiler" choices:"C · GCC 16.2=c-gcc|C · Clang 23.1=c-clang|C++ · GCC 16.2=cpp-gcc|C++ · Clang 23.1=cpp-clang|Rust · rustc 1.100=rust"`
	Optimization string `desc:"Optimization preset" choices:"Debug · O0=O0|Balanced · O1=O1|Release · O2=O2|Aggressive · O3=O3|Size · Os=Os"`
}

type compilerPreset struct {
	id        string
	name      string
	extension string
}

var compilerPresets = map[string]compilerPreset{
	"c-gcc":     {id: "cg162", name: "C · GCC 16.2", extension: "c"},
	"c-clang":   {id: "cclang2310", name: "C · Clang 23.1", extension: "c"},
	"cpp-gcc":   {id: "g162", name: "C++ · GCC 16.2", extension: "cpp"},
	"cpp-clang": {id: "clang2310", name: "C++ · Clang 23.1", extension: "cpp"},
	"rust":      {id: "r11000", name: "Rust · rustc 1.100", extension: "rs"},
}

type compilerExplorerRequest struct {
	Source  string                  `json:"source"`
	Options compilerExplorerOptions `json:"options"`
}

type compilerExplorerOptions struct {
	UserArguments   string                   `json:"userArguments"`
	CompilerOptions compilerExecutionOptions `json:"compilerOptions"`
	Filters         compilerFilters          `json:"filters"`
	Tools           []any                    `json:"tools"`
	Libraries       []any                    `json:"libraries"`
}

type compilerExecutionOptions struct {
	SkipAsm         bool  `json:"skipAsm"`
	ExecutorRequest bool  `json:"executorRequest"`
	Overrides       []any `json:"overrides"`
}

type compilerFilters struct {
	Binary       bool `json:"binary"`
	BinaryObject bool `json:"binaryObject"`
	CommentOnly  bool `json:"commentOnly"`
	Demangle     bool `json:"demangle"`
	Directives   bool `json:"directives"`
	Execute      bool `json:"execute"`
	Intel        bool `json:"intel"`
	Labels       bool `json:"labels"`
	LibraryCode  bool `json:"libraryCode"`
	Trim         bool `json:"trim"`
}

type compilerExplorerResponse struct {
	Code           int                  `json:"code"`
	TimedOut       bool                 `json:"timedOut"`
	Truncated      bool                 `json:"truncated"`
	ExecTime       int                  `json:"execTime"`
	Asm            []compilerOutputLine `json:"asm"`
	Stdout         []compilerOutputLine `json:"stdout"`
	Stderr         []compilerOutputLine `json:"stderr"`
	InputFile      string               `json:"inputFilename"`
	InstructionSet string               `json:"instructionSet"`
}

type compilerOutputLine struct {
	Text string `json:"text"`
}

func registerCompilerExplorer(bot *starlings.Client) {
	bot.Slash("compilers", "Show the safe Compiler Explorer presets", func() starlings.Response {
		embed := starlings.NewEmbed("Windissect compile lab").SetColor(windissectBlue).
			SetDescription("`/compile` sends a small source probe to Compiler Explorer and returns diagnostics plus assembly. It never requests execution.").
			AddField("Toolchains", "C: GCC 16.2 / Clang 23.1\nC++: GCC 16.2 / Clang 23.1\nRust: rustc 1.100", false).
			AddField("Safety", "No arbitrary flags, no executor request, two concurrent jobs, 3,500 source characters, bounded output and a 20-second deadline.", false).
			AddField("Privacy", "Source leaves this Discord/VPS and is processed by the public Compiler Explorer service. Never submit proprietary or secret code.", false).
			SetFooter("Powered by Compiler Explorer · godbolt.org", "")
		return starlings.Ephemeral(embed)
	})
	bot.Slash("compile", "Open the compile lab and paste a source probe", openCompileModal)
	bot.Modal("compile:{toolchain}:{optimization}", submitCompileModal)
}

func openCompileModal(i *starlings.InteractionCreate, args compileArgs) error {
	if _, ok := compilerPresets[args.Toolchain]; !ok {
		return starlings.UserErrorf("That compiler preset is unavailable.")
	}
	if compilerOptimization(args.Optimization) == "" {
		return starlings.UserErrorf("Choose one of the optimization presets.")
	}
	minimum, maximum := 1, 3500
	source := starlings.TextInput(starlings.TextInputParagraph, "source", "Paste C, C++, or Rust source here…", true)
	source.MinLength = &minimum
	source.MaxLength = maximum
	return i.Modal(
		starlings.CustomID("compile", args.Toolchain, args.Optimization),
		"Windissect compile lab",
		starlings.Label("Source code", "Sent to public Compiler Explorer; never paste private code.", source),
	)
}

func submitCompileModal(i *starlings.InteractionCreate) error {
	return compileProbe(i, i.Param("toolchain"), i.Param("optimization"), i.TextValue("source"))
}

func compilerOptimization(preset string) string {
	return map[string]string{"O0": "-O0", "O1": "-O1", "O2": "-O2", "O3": "-O3", "Os": "-Os"}[preset]
}

func compileProbe(i *starlings.InteractionCreate, toolchain, optimizationPreset, source string) error {
	preset, ok := compilerPresets[toolchain]
	if !ok {
		return starlings.UserErrorf("That compiler preset is unavailable.")
	}
	optimization := compilerOptimization(optimizationPreset)
	if optimization == "" {
		return starlings.UserErrorf("Choose one of the optimization presets.")
	}
	if source == "" {
		return starlings.UserErrorf("Paste some source code first.")
	}
	if len(source) > 3500 {
		return starlings.UserErrorf("Keep compile probes under 3,500 characters.")
	}
	select {
	case compileSlots <- struct{}{}:
		defer func() { <-compileSlots }()
	default:
		return starlings.UserErrorf("Both compiler slots are busy. Try again shortly.")
	}
	if err := i.Defer(true); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := requestCompilation(ctx, preset, optimization, source)
	if err != nil {
		_, editErr := i.EditResponse(ctx, starlings.InteractionResponseData{
			Content: "Compiler Explorer did not finish successfully. Try again shortly.", AllowedMentions: starlings.NoMentions(),
		})
		if editErr != nil {
			return editErr
		}
		return nil
	}

	assembly := joinCompilerLines(result.Asm)
	diagnostics := joinCompilerLines(append(result.Stderr, result.Stdout...))
	if assembly == "" {
		assembly = "; no assembly was produced\n"
	}
	assembly, asmCut := limitOutput(assembly, 512*1024)
	diagnostics, diagnosticsCut := limitOutput(diagnostics, 128*1024)
	status := "successful"
	if result.Code != 0 {
		status = fmt.Sprintf("failed with exit code %d", result.Code)
	}
	if result.TimedOut {
		status = "timed out on Compiler Explorer"
	}
	content := fmt.Sprintf("**%s** · `%s` · compilation %s · %d ms", preset.name, optimization, status, result.ExecTime)
	if result.Truncated || asmCut || diagnosticsCut {
		content += "\nOutput was truncated to keep the Discord response bounded."
	}
	files := []starlings.File{starlings.FileFromBytes("output."+preset.extension+".asm", []byte(assembly))}
	if diagnostics != "" {
		files = append(files, starlings.FileFromBytes("diagnostics.txt", []byte(diagnostics)))
	}
	_, err = i.EditResponseFiles(ctx, starlings.InteractionResponseData{
		Content: content, AllowedMentions: starlings.NoMentions(),
	}, files...)
	return err
}

func requestCompilation(ctx context.Context, preset compilerPreset, optimization, source string) (compilerExplorerResponse, error) {
	payload := compilerExplorerRequest{
		Source: source,
		Options: compilerExplorerOptions{
			UserArguments:   optimization,
			CompilerOptions: compilerExecutionOptions{Overrides: []any{}},
			Filters:         compilerFilters{CommentOnly: true, Demangle: true, Intel: true, Labels: true, Trim: true},
			Tools:           []any{}, Libraries: []any{},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return compilerExplorerResponse{}, err
	}
	endpoint := compilerExplorerBase + "/compiler/" + preset.id + "/compile"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return compilerExplorerResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "WindissectBot/1.0 (+https://github.com/razecrs/windissect)")
	response, err := compilerExplorerClient.Do(request)
	if err != nil {
		return compilerExplorerResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return compilerExplorerResponse{}, fmt.Errorf("compiler explorer returned %s", response.Status)
	}
	var result compilerExplorerResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return compilerExplorerResponse{}, err
	}
	return result, nil
}

func joinCompilerLines(lines []compilerOutputLine) string {
	var output strings.Builder
	for _, line := range lines {
		output.WriteString(line.Text)
		output.WriteByte('\n')
	}
	return output.String()
}

func limitOutput(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	return value[:limit] + "\n; output truncated by Windissect\n", true
}
