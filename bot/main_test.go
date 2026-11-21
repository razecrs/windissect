package main

import (
	"strings"
	"testing"

	"github.com/razecrs/starlings"
)

func TestInviteUsesOnlyRequiredScopes(t *testing.T) {
	got := inviteURL(starlings.Snowflake(12345))
	if !strings.Contains(got, "client_id=12345") || !strings.Contains(got, "bot%20applications.commands") {
		t.Fatalf("unexpected invite URL: %s", got)
	}
	if !strings.Contains(got, "permissions=0") {
		t.Fatalf("bot should request no broad guild permissions: %s", got)
	}
}

func TestFirstEnvPrefersProductToken(t *testing.T) {
	t.Setenv("WINDISSECT_BOT_TOKEN", " product ")
	t.Setenv("WINDISSECT_DISCORD_TOKEN", "legacy-product")
	t.Setenv("DISCORD_TOKEN", "shared")
	if got := firstEnv("WINDISSECT_BOT_TOKEN", "WINDISSECT_DISCORD_TOKEN", "DISCORD_TOKEN"); got != "product" {
		t.Fatalf("got %q", got)
	}
}

func TestCardsStayInsideDiscordLimits(t *testing.T) {
	for name, embed := range map[string]*starlings.Embed{
		"about": about(),
		"start": start(),
		"links": links(),
	} {
		if len(embed.Title) > 256 || len(embed.Description) > 4096 || len(embed.Fields) > 25 {
			t.Fatalf("%s exceeds Discord embed limits", name)
		}
	}
}

func TestBotDefinesExpectedCommands(t *testing.T) {
	t.Setenv("WINDISSECT_BOT_TOKEN", "")
	t.Setenv("WINDISSECT_DISCORD_TOKEN", "")
	t.Setenv("DISCORD_TOKEN", "")
	t.Setenv("WINDISSECT_DATA_DIR", t.TempDir())
	commands := newBot().SlashDefinitions()
	if len(commands) != 38 {
		t.Fatalf("got %d commands, want 38", len(commands))
	}
}
