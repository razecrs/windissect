package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/razecrs/starlings"
)

const (
	windissectBlue = 0x86A9E8
	repositoryURL  = "https://github.com/razecrs/windissect"
	quickstartURL  = repositoryURL + "/blob/main/docs/quickstart.md"
	releasesURL    = repositoryURL + "/releases"
	privacyURL     = "https://razecrs.com/privacy"
	termsURL       = "https://razecrs.com/terms"
	logoURL        = "https://razecrs.com/img/windissect.png"
)

func main() {
	bot := newBot()
	if err := bot.Run(); err != nil {
		log.Fatal(err)
	}
}

func newBot() *starlings.Client {
	opts := []starlings.Option{
		starlings.WithStatus(starlings.StatusOnline, starlings.Watching("Windows internals become evidence")),
	}
	if token := firstEnv("WINDISSECT_BOT_TOKEN", "WINDISSECT_DISCORD_TOKEN", "DISCORD_TOKEN"); token != "" {
		opts = append(opts, starlings.WithToken(token))
	}

	bot := starlings.New(opts...)
	bot.Slash("ping", "Check whether Windissect is online", func() starlings.Response {
		return starlings.Ephemeral("Windissect is online. Evidence first, guesses never.")
	})
	bot.Slash("about", "What Windissect does and why it is different", about)
	bot.Slash("start", "Get the quickest safe path from a binary to verified output", start)
	bot.Slash("links", "Windissect downloads, source, docs, privacy and terms", links)
	bot.Slash("support", "Get the details needed for a useful support report", support)
	registerModeration(bot)
	registerFun(bot)
	registerRoles(bot)
	registerWindowsTools(bot)
	registerCompilerExplorer(bot)
	registerTriage(bot)
	bot.On(func(r *starlings.Ready) {
		log.Printf("Windissect bot online as %s", r.User.Tag())
		if appID := bot.ApplicationID(); appID != 0 {
			log.Printf("server invite: %s", inviteURL(appID))
		}
	})
	return bot
}

func about() *starlings.Embed {
	return card("Windissect", "Turns Windows PE binaries and matching PDBs into build-anchored interfaces it can prove.").
		SetURL(repositoryURL).
		AddField("Evidence-backed", "Every callable fact is tied to the exact image, PDB and supporting evidence. Candidates stay visibly separate.", false).
		AddField("Outputs", "Machine-readable IR, C/C++ headers, Rust FFI, symbols, recovered functions, history and semantic diffs.", false).
		AddField("Built for updates", "Record each Windows build, compare it with the last one, and find exactly what changed.", false)
}

func start() *starlings.Embed {
	return card("Start with one binary", "On Windows with Rust installed, clone Windissect and run the demo:").
		AddField("Command", "```powershell\npwsh -File scripts/demo.ps1\n```", false).
		AddField("Full guide", fmt.Sprintf("[Quick start](%s)", quickstartURL), true).
		AddField("Releases", fmt.Sprintf("[Downloads](%s)", releasesURL), true).
		SetFooter("Windissect will mark uncertainty; it will not silently turn it into an ABI.", "")
}

func links() *starlings.Embed {
	return card("Windissect links", "The official project surfaces.").
		AddField("Source", repositoryURL, false).
		AddField("Downloads", releasesURL, false).
		AddField("Documentation", quickstartURL, false).
		AddField("Privacy", privacyURL, true).
		AddField("Terms", termsURL, true)
}

func support() starlings.Response {
	embed := card("A useful Windissect report", "Share enough evidence to reproduce the problem without sharing private binaries publicly.").
		AddField("Include", "Windissect version/commit, command used, Windows build, target architecture, and the complete error text.", false).
		AddField("Attach when safe", "The generated verification report and provenance JSON. Redact private paths and do not upload proprietary binaries or PDBs without permission.", false).
		AddField("Before reporting", "Run `windissect verify --ir <your-ir.json>` and say which checks failed.", false)
	return starlings.Ephemeral(embed)
}

func card(title, description string) *starlings.Embed {
	return starlings.NewEmbed(title).
		SetDescription(description).
		SetColor(windissectBlue).
		SetThumbnail(logoURL)
}

func inviteURL(appID starlings.Snowflake) string {
	return fmt.Sprintf("https://discord.com/oauth2/authorize?client_id=%s&scope=bot%%20applications.commands&permissions=0", appID.String())
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
