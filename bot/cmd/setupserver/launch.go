package main

// Launch readiness: everything a public Discord server needs on top of the
// channel layout. Community mode, the welcome screen, onboarding, AutoMod,
// the Elytra emojis and the 1.0 release posts. Every step converges, so
// rerunning the tool never duplicates anything.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/razecrs/starlings"
)

// text returns a text or announcement channel by name. Announcement channels
// start life as text channels, so callers shouldn't care which one it is now.
func (s *server) text(name string) starlings.Channel {
	if channel, ok := s.channels[channelKey(starlings.ChannelGuildAnnouncement, name)]; ok {
		return channel
	}
	return s.channels[channelKey(starlings.ChannelGuildText, name)]
}

func (s *server) mention(name string) string { return "<#" + s.text(name).ID.String() + ">" }

// ensureCommunity turns on Community mode, which unlocks the welcome screen,
// onboarding, announcement channels and Server Discovery eligibility.
func (s *server) ensureCommunity(ctx context.Context) error {
	guild, err := s.client.Guild(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("read guild features: %w", err)
	}
	if slices.Contains(guild.Features, "COMMUNITY") {
		return nil
	}
	features := append(slices.Clone(guild.Features), "COMMUNITY")
	if _, err := s.client.ModifyGuild(ctx, s.guildID, starlings.GuildParams{Features: &features}, auditReason); err != nil {
		return fmt.Errorf("enable community: %w", err)
	}
	return nil
}

// ensureAnnouncementChannels makes #announcements and #releases followable,
// so other servers can mirror Windissect releases into their own channels.
func (s *server) ensureAnnouncementChannels(ctx context.Context) error {
	for _, name := range []string{"announcements", "releases"} {
		channel, ok := s.channels[channelKey(starlings.ChannelGuildText, name)]
		if !ok {
			continue // already converted
		}
		kind := starlings.ChannelGuildAnnouncement
		updated, err := s.client.ModifyChannel(ctx, channel.ID, starlings.ChannelParams{Type: &kind}, auditReason)
		if err != nil {
			return fmt.Errorf("make %s an announcement channel: %w", name, err)
		}
		delete(s.channels, channelKey(starlings.ChannelGuildText, name))
		s.channels[channelKey(starlings.ChannelGuildAnnouncement, name)] = *updated
	}
	return nil
}

func (s *server) ensureWelcomeScreen(ctx context.Context) error {
	screen := starlings.WelcomeScreen{
		Description: "Proven maps of Windows internals. Grab the 1.0 installer, ask questions, and share what you find.",
		WelcomeChannels: []starlings.WelcomeScreenChannel{
			{ChannelID: s.text("getting-started").ID, Description: "Install Windissect and open your first DLL", EmojiName: "🚀"},
			{ChannelID: s.text("rules").ID, Description: "Five short rules", EmojiName: "📜"},
			{ChannelID: s.text("help").ID, Description: "Stuck? Ask here", EmojiName: "🛟"},
			{ChannelID: s.text("showcase").ID, Description: "Show what you found or built", EmojiName: "✨"},
		},
	}
	if _, err := s.client.ModifyWelcomeScreen(ctx, s.guildID, screen, auditReason); err != nil {
		return fmt.Errorf("welcome screen: %w", err)
	}
	return nil
}

// onboardingID makes a stable, valid-looking snowflake for an onboarding
// prompt or option. Discord only needs them unique within the flow.
func onboardingID(n int) starlings.Snowflake {
	const discordEpochMS = 1420070400000
	return starlings.Snowflake(uint64(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC).UnixMilli()-discordEpochMS)<<22 | uint64(n))
}

func (s *server) ensureOnboarding(ctx context.Context) error {
	ids := func(names ...string) []starlings.Snowflake {
		out := make([]starlings.Snowflake, 0, len(names))
		for _, name := range names {
			out = append(out, s.text(name).ID)
		}
		return out
	}
	onboarding := starlings.GuildOnboarding{
		Enabled: true,
		// Everyone sees the essentials and the main conversation channels.
		DefaultChannelIDs: ids("welcome", "rules", "announcements", "releases", "getting-started",
			"windissect", "help", "bot-commands", "showcase", "off-topic"),
		Prompts: []starlings.OnboardingPrompt{{
			ID: onboardingID(1), Type: 0, Title: "What brings you to Windissect?",
			InOnboarding: true, Required: false, SingleSelect: false,
			Options: []starlings.OnboardingOption{
				{ID: onboardingID(2), Title: "Using Windissect", Description: "Help, bug reports and feature ideas",
					Emoji: &starlings.Emoji{Name: "🧰"}, ChannelIDs: ids("help", "bugs-and-crashes", "feature-requests")},
				{ID: onboardingID(3), Title: "Windows internals and reverse engineering", Description: "Research channels and the Researcher role",
					Emoji: &starlings.Emoji{Name: "🔬"}, RoleIDs: []starlings.Snowflake{s.roles["researcher"].ID},
					ChannelIDs: ids("windows-internals", "reverse-engineering", "generated-output", "rewindows")},
				{ID: onboardingID(4), Title: "Contributing", Description: "Follow development, builds and CI",
					Emoji: &starlings.Emoji{Name: "🛠️"}, ChannelIDs: ids("contributors", "ci-and-builds")},
				{ID: onboardingID(5), Title: "Testing early builds", Description: "Get pinged for pre-release testing",
					Emoji: &starlings.Emoji{Name: "🧪"}, RoleIDs: []starlings.Snowflake{s.roles["early access"].ID}},
			},
		}},
	}
	if _, err := s.client.SetOnboarding(ctx, s.guildID, onboarding, auditReason); err != nil {
		return fmt.Errorf("onboarding: %w", err)
	}
	return nil
}

type autoModAction struct {
	Type     int            `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type autoModRule struct {
	ID              string          `json:"id,omitempty"`
	Name            string          `json:"name"`
	EventType       int             `json:"event_type"`
	TriggerType     int             `json:"trigger_type"`
	TriggerMetadata map[string]any  `json:"trigger_metadata,omitempty"`
	Actions         []autoModAction `json:"actions"`
	Enabled         bool            `json:"enabled"`
	ExemptRoles     []string        `json:"exempt_roles"`
}

// ensureAutoMod installs Discord-native filters, so spam is stopped even when
// the bot is offline. Matching is by rule name; existing rules are updated.
func (s *server) ensureAutoMod(ctx context.Context, inviteCode string) error {
	modLogs := s.text("mod-logs").ID.String()
	block := func(message string) autoModAction {
		return autoModAction{Type: 1, Metadata: map[string]any{"custom_message": message}}
	}
	alert := autoModAction{Type: 2, Metadata: map[string]any{"channel_id": modLogs}}
	staff := []string{s.roles["maintainer"].ID.String(), s.roles["moderator"].ID.String(), s.roles["contributor"].ID.String()}
	allow := []string{}
	if inviteCode != "" {
		allow = append(allow, "*discord.gg/"+inviteCode+"*")
	}
	rules := []autoModRule{
		{Name: "Spam", TriggerType: 3, Actions: []autoModAction{block("That looked like spam, so it wasn't posted."), alert}},
		{Name: "Mention spam", TriggerType: 5,
			TriggerMetadata: map[string]any{"mention_total_limit": 5, "mention_raid_protection_enabled": true},
			Actions: []autoModAction{block("Too many mentions in one message."), alert,
				{Type: 3, Metadata: map[string]any{"duration_seconds": 600}}}},
		{Name: "Slurs and sexual content", TriggerType: 4,
			TriggerMetadata: map[string]any{"presets": []int{2, 3}},
			Actions:         []autoModAction{block("That language isn't allowed here."), alert}},
		{Name: "Invites and scam links", TriggerType: 1, ExemptRoles: staff,
			TriggerMetadata: map[string]any{
				"keyword_filter": []string{"*discord.gg/*", "*discord.com/invite/*", "*discordapp.com/invite/*",
					"free nitro*", "*nitro for free*", "*nitro giveaway*", "*steam gift*", "*airdrop*claim*"},
				"allow_list": allow,
			},
			Actions: []autoModAction{block("Server invites and known scam phrases are blocked. Ask a Maintainer if you need to share one."), alert}},
	}

	raw, err := s.client.RequestRaw(ctx, starlings.RESTRequest{
		Method: http.MethodGet, Path: "/guilds/" + s.guildID.String() + "/auto-moderation/rules",
		Route: "GET /guilds/" + s.guildID.String() + "/auto-moderation/rules",
	})
	if err != nil {
		return fmt.Errorf("list automod rules: %w", err)
	}
	var existing []autoModRule
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("parse automod rules: %w", err)
	}
	byName := map[string]string{}
	for _, rule := range existing {
		byName[rule.Name] = rule.ID
	}
	for _, rule := range rules {
		rule.EventType, rule.Enabled = 1, true
		if rule.ExemptRoles == nil {
			rule.ExemptRoles = []string{}
		}
		req := starlings.RESTRequest{
			Method: http.MethodPost, Path: "/guilds/" + s.guildID.String() + "/auto-moderation/rules",
			Route: "POST /guilds/" + s.guildID.String() + "/auto-moderation/rules", Reason: auditReason,
		}
		if id := byName[rule.Name]; id != "" {
			// trigger_type can't be changed on an existing rule.
			body := map[string]any{"name": rule.Name, "event_type": rule.EventType, "trigger_metadata": rule.TriggerMetadata,
				"actions": rule.Actions, "enabled": true, "exempt_roles": rule.ExemptRoles}
			req.Method, req.Body = http.MethodPatch, body
			req.Path += "/" + id
			req.Route = "PATCH /guilds/" + s.guildID.String() + "/auto-moderation/rules/{id}"
		} else {
			req.Body = rule
		}
		if _, err := s.client.RequestRaw(ctx, req); err != nil {
			return fmt.Errorf("automod rule %q: %w", rule.Name, err)
		}
	}
	return nil
}

// ensureEmojis uploads the Elytra expressions as server emojis.
// WINDISSECT_MASCOT_DIR overrides where the PNGs are read from.
func (s *server) ensureEmojis(ctx context.Context) error {
	dir := envOr("WINDISSECT_MASCOT_DIR", filepath.Join("..", "gui", "assets", "brand", "mascot"))
	if _, err := os.Stat(dir); err != nil {
		log.Printf("skipping emojis: no mascot folder at %s", dir)
		return nil
	}
	existing, err := s.client.GuildEmojis(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("list emojis: %w", err)
	}
	have := map[string]bool{}
	for _, emoji := range existing {
		have[emoji.Name] = true
	}
	for _, pose := range []string{"idle", "wave", "happy", "wow", "sleep", "pixel"} {
		name := "elytra_" + pose
		if pose == "idle" {
			name = "elytra"
		}
		if have[name] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "elytra-"+pose+".png"))
		if err != nil {
			return fmt.Errorf("read emoji %s: %w", name, err)
		}
		image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
		if _, err := s.client.CreateGuildEmoji(ctx, s.guildID, name, image, nil, auditReason); err != nil {
			return fmt.Errorf("upload emoji %s: %w", name, err)
		}
	}
	return nil
}

func (s *server) emoji(ctx context.Context, name string) string {
	emojis, err := s.client.GuildEmojis(ctx, s.guildID)
	if err != nil {
		return ""
	}
	for _, e := range emojis {
		if e.Name == name {
			return fmt.Sprintf("<:%s:%s>", e.Name, e.ID)
		}
	}
	return ""
}

// post is one pinned bot message, identified by its embed footer.
type post struct {
	channel, footer string
	embed           *starlings.Embed
}

// ensurePosts publishes the 1.0 launch posts once. Each post is found again
// by its footer, so a rerun edits it in place instead of posting twice.
func (s *server) ensurePosts(ctx context.Context) error {
	wave := s.emoji(ctx, "elytra_wave")
	installer := "https://github.com/razecrs/windissect/releases/download/v1.0.0/Windissect-v1.0.0-setup-x64.exe"
	portable := "https://github.com/razecrs/windissect/releases/download/v1.0.0/Windissect-v1.0.0-windows-x64.zip"
	posts := []post{
		{"releases", "Windissect release · v1.0.0", starlings.NewEmbed("Windissect 1.0.0").
			SetURL("https://github.com/razecrs/windissect/releases/tag/v1.0.0").
			SetColor(0x5B84F7).
			SetDescription("The first release with a desktop app. Open a Windows DLL, EXE or SYS and browse what Windissect can prove about it. No command line needed.").
			AddField("Download", fmt.Sprintf("[Installer](%s) (11.5 MB, no admin needed)\n[Portable zip](%s) (15.1 MB)", installer, portable), false).
			AddField("Highlights", "• Desktop workbench with Types, Classes, VTables, Functions, Enums, Symbols, Strings and Evidence views\n"+
				"• Function recovery without a PDB\n• WinRT and WinMD output via `emit-winrt`\n• Electron app analysis\n• Optional Discord Rich Presence", false).
			AddField("Windows warning?", "The builds aren't code-signed yet. If SmartScreen appears, choose **More info → Run anyway**. Checksums are on the release page.", false),
		},
		{"announcements", "Windissect announcement · launch-1.0", starlings.NewEmbed("Windissect 1.0 is out "+wave).
			SetURL("https://github.com/razecrs/windissect/releases/tag/v1.0.0").
			SetColor(0x5B84F7).
			SetDescription("Windissect turns a Windows binary and its PDB into a map of its internals: classes, vtables, functions and the evidence behind each fact. It only emits what it can prove.\n\n"+
				"1.0 adds a desktop app and an installer, so you can go from download to browsing a DLL in a couple of minutes.").
			AddField("Get it", fmt.Sprintf("[Download 1.0](%s) · details in %s", "https://github.com/razecrs/windissect/releases/tag/v1.0.0", s.mention("releases")), false).
			AddField("New here?", fmt.Sprintf("Start in %s, ask in %s, and show what you find in %s.", s.mention("getting-started"), s.mention("help"), s.mention("showcase")), false).
			AddField("Meet Elytra", "Our mascot, a small beetle named after the wing cases that close over its back. Find it in the emoji picker.", false),
		},
	}
	posts = append(posts, s.thanksPosts()...)
	for _, post := range posts {
		post.embed.SetFooter(post.footer, "")
		channel := s.text(post.channel)
		pins, err := s.client.Pins(ctx, channel.ID)
		if err != nil {
			return fmt.Errorf("list pins in %s: %w", post.channel, err)
		}
		var existingID starlings.Snowflake
		for _, message := range pins {
			if message.Author != nil && message.Author.ID == botUserID && len(message.Embeds) > 0 &&
				message.Embeds[0].Footer != nil && message.Embeds[0].Footer.Text == post.footer {
				existingID = message.ID
				break
			}
		}
		data := starlings.SendData{Embeds: []starlings.Embed{*post.embed}, AllowedMentions: starlings.NoMentions()}
		if existingID != 0 {
			if _, err := s.client.EditMessage(ctx, channel.ID, existingID, data); err != nil {
				return fmt.Errorf("update post in %s: %w", post.channel, err)
			}
			continue
		}
		message, err := s.client.SendComplex(ctx, channel.ID, data)
		if err != nil {
			return fmt.Errorf("post in %s: %w", post.channel, err)
		}
		if err := s.client.PinMessage(ctx, channel.ID, message.ID, auditReason); err != nil {
			return fmt.Errorf("pin post in %s: %w", post.channel, err)
		}
	}
	return nil
}
