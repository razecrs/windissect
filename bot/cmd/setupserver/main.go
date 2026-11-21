// Command setupserver idempotently builds the official Windissect Discord
// community. It uses Starlings' REST surface and never deletes channels,
// roles, or messages; rerunning it converges names, topics and permissions.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/razecrs/starlings"
)

const (
	defaultGuildID = "1573065901165772840"
	botUserID      = starlings.Snowflake(1573065030927130815)
	auditReason    = "Windissect community bootstrap"
)

type roleSpec struct {
	name        string
	color       int
	permissions starlings.Permissions
	hoist       bool
}

type channelSpec struct {
	category string
	name     string
	topic    string
	typeID   starlings.ChannelType
	readOnly bool
	teamOnly bool
	slowmode int
	position int
}

type server struct {
	client     *starlings.Client
	guildID    starlings.Snowflake
	everyoneID starlings.Snowflake
	roles      map[string]starlings.Role
	channels   map[string]starlings.Channel
}

func main() {
	token := firstEnv("WINDISSECT_BOT_TOKEN", "WINDISSECT_DISCORD_TOKEN", "DISCORD_TOKEN")
	if token == "" {
		log.Fatal("set WINDISSECT_BOT_TOKEN")
	}
	guildID, err := starlings.ParseSnowflake(envOr("WINDISSECT_GUILD_ID", defaultGuildID))
	if err != nil {
		log.Fatalf("invalid WINDISSECT_GUILD_ID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := &server{
		client:     starlings.New(starlings.WithToken(token), starlings.WithAutoSync(false)),
		guildID:    guildID,
		everyoneID: guildID,
		roles:      make(map[string]starlings.Role),
		channels:   make(map[string]starlings.Channel),
	}
	if err := s.apply(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("Windissect server ready: %d roles, %d channels", len(s.roles), len(s.channels))
}

func (s *server) apply(ctx context.Context) error {
	if err := s.load(ctx); err != nil {
		return err
	}
	if err := s.ensureRoles(ctx); err != nil {
		return err
	}
	if err := s.ensureOwnerRole(ctx); err != nil {
		return err
	}
	if err := s.ensureLayout(ctx); err != nil {
		return err
	}
	if err := s.ensurePermissions(ctx); err != nil {
		return err
	}
	if err := s.configureGuild(ctx); err != nil {
		return err
	}
	if err := s.ensureCommunity(ctx); err != nil {
		return err
	}
	if err := s.ensureAnnouncementChannels(ctx); err != nil {
		return err
	}
	if err := s.ensureGuides(ctx); err != nil {
		return err
	}
	if err := s.ensureEmojis(ctx); err != nil {
		return err
	}
	if err := s.ensureWelcomeScreen(ctx); err != nil {
		return err
	}
	if err := s.ensureOnboarding(ctx); err != nil {
		return err
	}
	code, err := s.ensureInvite(ctx)
	if err != nil {
		return err
	}
	if err := s.ensureAutoMod(ctx, code); err != nil {
		return err
	}
	return s.ensurePosts(ctx)
}

func (s *server) ensureOwnerRole(ctx context.Context) error {
	guild, err := s.client.Guild(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("read guild owner: %w", err)
	}
	maintainer := s.roles["maintainer"]
	if err := s.client.AddMemberRole(ctx, s.guildID, guild.OwnerID, maintainer.ID, auditReason); err != nil {
		return fmt.Errorf("assign Maintainer to guild owner: %w", err)
	}
	return nil
}

func (s *server) load(ctx context.Context) error {
	roles, err := s.client.Roles(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("list roles: %w", err)
	}
	for _, role := range roles {
		s.roles[strings.ToLower(role.Name)] = role
	}
	channels, err := s.client.GuildChannels(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("list channels: %w", err)
	}
	for _, channel := range channels {
		s.channels[channelKey(channel.Type, channel.Name)] = channel
	}
	return nil
}

func (s *server) ensureRoles(ctx context.Context) error {
	specs := []roleSpec{
		{name: "Maintainer", color: 0xE05A6F, permissions: starlings.PermissionViewAuditLog |
			starlings.PermissionKickMembers | starlings.PermissionBanMembers |
			starlings.PermissionModerateMembers | starlings.PermissionManageChannels |
			starlings.PermissionManageMessages | starlings.PermissionManageThreads, hoist: true},
		{name: "Contributor", color: 0x86A9E8, hoist: true},
		{name: "Researcher", color: 0xA78BFA},
		{name: "Early Access", color: 0xF2C94C},
	}
	for _, spec := range specs {
		key := strings.ToLower(spec.name)
		role, found := s.roles[key]
		params := starlings.RoleParams{
			Name: &spec.name, Permissions: &spec.permissions, Color: &spec.color,
			Hoist: &spec.hoist, Mentionable: ptr(false),
		}
		var err error
		if found {
			_, err = s.client.ModifyRole(ctx, s.guildID, role.ID, params, auditReason)
		} else {
			created, createErr := s.client.CreateRole(ctx, s.guildID, params, auditReason)
			err = createErr
			if created != nil {
				s.roles[key] = *created
			}
		}
		if err != nil {
			return fmt.Errorf("ensure role %s: %w", spec.name, err)
		}
	}
	return nil
}

func (s *server) ensureLayout(ctx context.Context) error {
	// Preserve Discord's starter objects by turning them into useful channels.
	if err := s.renameStarter(ctx, starlings.ChannelGuildCategory, "Text Channels", "00 · START HERE", ""); err != nil {
		return err
	}
	if err := s.renameStarter(ctx, starlings.ChannelGuildText, "general", "welcome", "Read this first: what Windissect is, where to begin, and where each discussion belongs."); err != nil {
		return err
	}
	if err := s.renameStarter(ctx, starlings.ChannelGuildCategory, "Voice Channels", "05 · VOICE", ""); err != nil {
		return err
	}
	if err := s.renameStarter(ctx, starlings.ChannelGuildVoice, "General", "workshop", ""); err != nil {
		return err
	}

	categories := []string{"00 · START HERE", "01 · PRODUCT", "02 · RESEARCH", "03 · BUILD", "04 · COMMUNITY", "05 · VOICE", "06 · MODERATION"}
	for position, name := range categories {
		if _, err := s.ensureChannel(ctx, channelSpec{name: name, typeID: starlings.ChannelGuildCategory, position: position}); err != nil {
			return err
		}
	}

	specs := []channelSpec{
		{category: categories[0], name: "welcome", topic: "What Windissect is, how this server works, and where to start.", readOnly: true},
		{category: categories[0], name: "rules", topic: "The short rules that keep evidence, people, and shared binaries safe.", readOnly: true},
		{category: categories[0], name: "announcements", topic: "Project announcements from the Windissect maintainers.", readOnly: true},
		{category: categories[0], name: "releases", topic: "New Windissect builds, compatibility notes, and upgrade guidance.", readOnly: true},

		{category: categories[1], name: "windissect", topic: "General discussion about using and improving Windissect."},
		{category: categories[1], name: "getting-started", topic: "Install, run the demo, understand evidence, and produce your first verified output.", readOnly: true},
		{category: categories[1], name: "help", topic: "Usage questions and reproducible troubleshooting. Use /support before posting.", slowmode: 5},
		{category: categories[1], name: "bugs-and-crashes", topic: "Reproducible defects: version, Windows build, command, logs, and safe artifacts.", slowmode: 10},
		{category: categories[1], name: "feature-requests", topic: "Concrete workflows Windissect should make faster, safer, or more provable.", slowmode: 10},

		{category: categories[2], name: "windows-internals", topic: "Windows architecture, private interfaces, symbols, PDBs, PE/COFF, and ABI research."},
		{category: categories[2], name: "reverse-engineering", topic: "Methods, tooling, and evidence-backed reverse engineering discussion."},
		{category: categories[2], name: "generated-output", topic: "Review generated IR, headers, bindings, claims, conflicts, and semantic refinement."},
		{category: categories[2], name: "rewindows", topic: "Build-indexed Windows interface repositories generated from Windissect evidence."},

		{category: categories[3], name: "contributors", topic: "Implementation coordination and review. Everyone may read; contributors may write.", teamOnly: true},
		{category: categories[3], name: "ci-and-builds", topic: "Automated build, test, security, and release status.", readOnly: true},
		{category: categories[3], name: "bot-commands", topic: "Use Windissect and community slash commands here."},

		{category: categories[4], name: "showcase", topic: "Show what Windissect helped you understand or build."},
		{category: categories[4], name: "your-projects", topic: "Share relevant systems, modding, tooling, and reverse-engineering projects."},
		{category: categories[4], name: "off-topic", topic: "A relaxed space; the same respect and safety rules still apply.", slowmode: 5},

		{category: categories[5], name: "workshop", typeID: starlings.ChannelGuildVoice},
		{category: categories[5], name: "pair-reversing", typeID: starlings.ChannelGuildVoice},

		{category: categories[6], name: "mod-logs", topic: "Private moderation cases and automated audit records.", readOnly: true},
	}
	for position, spec := range specs {
		if spec.typeID == 0 {
			spec.typeID = starlings.ChannelGuildText
		}
		spec.position = position
		if _, err := s.ensureChannel(ctx, spec); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) renameStarter(ctx context.Context, kind starlings.ChannelType, oldName, newName, topic string) error {
	oldKey := channelKey(kind, oldName)
	if _, already := s.channels[channelKey(kind, newName)]; already {
		return nil
	}
	channel, found := s.channels[oldKey]
	if !found {
		return nil
	}
	params := starlings.ChannelParams{Name: &newName}
	if topic != "" {
		params.Topic = &topic
	}
	updated, err := s.client.ModifyChannel(ctx, channel.ID, params, auditReason)
	if err != nil {
		return fmt.Errorf("rename %s: %w", oldName, err)
	}
	delete(s.channels, oldKey)
	s.channels[channelKey(kind, newName)] = *updated
	return nil
}

func (s *server) ensureChannel(ctx context.Context, spec channelSpec) (*starlings.Channel, error) {
	if spec.typeID == starlings.ChannelGuildText {
		if _, converted := s.channels[channelKey(starlings.ChannelGuildAnnouncement, spec.name)]; converted {
			spec.typeID = starlings.ChannelGuildAnnouncement
		}
	}
	key := channelKey(spec.typeID, spec.name)
	channel, found := s.channels[key]
	var parentID starlings.Snowflake
	if spec.category != "" {
		parent, ok := s.channels[channelKey(starlings.ChannelGuildCategory, spec.category)]
		if !ok {
			return nil, fmt.Errorf("missing category %s", spec.category)
		}
		parentID = parent.ID
	}
	params := starlings.ChannelParams{
		Name: &spec.name, Type: &spec.typeID, Position: &spec.position,
	}
	if spec.topic != "" && spec.typeID == starlings.ChannelGuildText {
		params.Topic = &spec.topic
	}
	if spec.slowmode > 0 {
		params.RateLimitPerUser = &spec.slowmode
	}
	if parentID != 0 {
		params.ParentID = &parentID
	}
	var result *starlings.Channel
	var err error
	if found {
		result, err = s.client.ModifyChannel(ctx, channel.ID, params, auditReason)
	} else {
		result, err = s.client.CreateChannel(ctx, s.guildID, params, auditReason)
	}
	if err != nil {
		return nil, fmt.Errorf("ensure channel %s: %w", spec.name, err)
	}
	s.channels[key] = *result
	return result, nil
}

func (s *server) ensurePermissions(ctx context.Context) error {
	maintainer := s.roles["maintainer"]
	contributor := s.roles["contributor"]
	readOnly := map[string]bool{
		"welcome": true, "rules": true, "announcements": true, "releases": true,
		"getting-started": true, "ci-and-builds": true,
	}
	for name := range readOnly {
		channel := s.text(name)
		deny := starlings.PermissionSendMessages | starlings.PermissionCreatePublicThreads |
			starlings.PermissionCreatePrivateThreads | starlings.PermissionSendMessagesInThreads
		if err := s.client.SetPermissionOverwrite(ctx, channel.ID, s.everyoneID, 0, deny, starlings.OverwriteRole, auditReason); err != nil {
			return fmt.Errorf("lock %s: %w", name, err)
		}
		allow := starlings.PermissionViewChannel | starlings.PermissionSendMessages |
			starlings.PermissionEmbedLinks | starlings.PermissionAttachFiles | starlings.PermissionReadMessageHistory
		if err := s.client.SetPermissionOverwrite(ctx, channel.ID, maintainer.ID, allow, 0, starlings.OverwriteRole, auditReason); err != nil {
			return fmt.Errorf("allow maintainers in %s: %w", name, err)
		}
	}
	contributors := s.text("contributors")
	denySend := starlings.PermissionSendMessages | starlings.PermissionSendMessagesInThreads
	if err := s.client.SetPermissionOverwrite(ctx, contributors.ID, s.everyoneID, 0, denySend, starlings.OverwriteRole, auditReason); err != nil {
		return fmt.Errorf("lock contributors: %w", err)
	}
	allowTeam := starlings.PermissionViewChannel | starlings.PermissionSendMessages |
		starlings.PermissionEmbedLinks | starlings.PermissionAttachFiles | starlings.PermissionReadMessageHistory |
		starlings.PermissionSendMessagesInThreads
	for _, role := range []starlings.Role{contributor, maintainer} {
		if err := s.client.SetPermissionOverwrite(ctx, contributors.ID, role.ID, allowTeam, 0, starlings.OverwriteRole, auditReason); err != nil {
			return fmt.Errorf("allow %s in contributors: %w", role.Name, err)
		}
	}
	privateCategory := s.channels[channelKey(starlings.ChannelGuildCategory, "06 · MODERATION")]
	modLogs := s.text("mod-logs")
	privateDeny := starlings.PermissionViewChannel
	privateAllow := starlings.PermissionViewChannel | starlings.PermissionSendMessages |
		starlings.PermissionEmbedLinks | starlings.PermissionAttachFiles | starlings.PermissionReadMessageHistory
	for _, channel := range []starlings.Channel{privateCategory, modLogs} {
		if err := s.client.SetPermissionOverwrite(ctx, channel.ID, s.everyoneID, 0, privateDeny, starlings.OverwriteRole, auditReason); err != nil {
			return fmt.Errorf("hide %s: %w", channel.Name, err)
		}
		if err := s.client.SetPermissionOverwrite(ctx, channel.ID, maintainer.ID, privateAllow, 0, starlings.OverwriteRole, auditReason); err != nil {
			return fmt.Errorf("allow maintainers in %s: %w", channel.Name, err)
		}
		if err := s.client.SetPermissionOverwrite(ctx, channel.ID, botUserID, privateAllow, 0, starlings.OverwriteMember, auditReason); err != nil {
			return fmt.Errorf("allow bot in %s: %w", channel.Name, err)
		}
	}
	return nil
}

func (s *server) configureGuild(ctx context.Context) error {
	description := "Evidence-backed Windows internals, ABI recovery, generated interfaces, and the people building Windissect."
	verification, notifications, contentFilter := 2, 1, 2 // medium: account older than 5 minutes
	welcome := s.text("welcome")
	rules := s.text("rules")
	// Discord posts admin-only notices to the "community updates" channel, so
	// it belongs with the moderators, not in the public #announcements.
	modLogs := s.text("mod-logs")
	params := starlings.GuildParams{
		Description: &description, VerificationLevel: &verification,
		DefaultMessageNotifications: &notifications, ExplicitContentFilter: &contentFilter,
		SystemChannelID: &welcome.ID, RulesChannelID: &rules.ID, PublicUpdatesChannelID: &modLogs.ID,
	}
	if iconPath := strings.TrimSpace(os.Getenv("WINDISSECT_ICON_FILE")); iconPath != "" {
		data, err := os.ReadFile(iconPath)
		if err != nil {
			return fmt.Errorf("read server icon: %w", err)
		}
		icon := "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
		params.Icon = &icon
	}
	_, err := s.client.ModifyGuild(ctx, s.guildID, params, auditReason)
	if err != nil {
		return fmt.Errorf("configure guild: %w", err)
	}
	return nil
}

func (s *server) ensureInvite(ctx context.Context) (string, error) {
	welcome := s.text("welcome")
	zero := 0
	no := false
	invite, err := s.client.CreateInvite(ctx, welcome.ID, starlings.InviteParams{
		MaxAge: &zero, MaxUses: &zero, Temporary: &no, Unique: &no,
	}, auditReason)
	if err != nil {
		return "", fmt.Errorf("create welcome invite: %w", err)
	}
	log.Printf("community invite: https://discord.gg/%s", invite.Code)
	return invite.Code, nil
}

func (s *server) ensureGuides(ctx context.Context) error {
	guides := map[string]*starlings.Embed{
		"welcome": starlings.NewEmbed("Welcome to Windissect").
			SetColor(0x86A9E8).
			SetDescription("Windissect turns Windows binaries and matching PDBs into interfaces it can prove. This server is where users, reverse engineers, Windows modders, and contributors compare evidence—not guesses.").
			AddField("Start", "Read <#"+s.text("rules").ID.String()+">, then follow <#"+s.text("getting-started").ID.String()+">.", false).
			AddField("Need help?", "Run `/support`, then post the resulting checklist in <#"+s.text("help").ID.String()+">.", false).
			AddField("Here to research?", "Use the RESEARCH category for Windows internals, methods, generated output, and ReWindows data.", false).
			SetFooter("Windissect setup · welcome", ""),
		"rules": starlings.NewEmbed("Community rules").
			SetColor(0xE05A6F).
			SetDescription("Be rigorous with evidence and decent with people.").
			AddField("1 · Legal and authorized work", "Only analyze or share material you have the right to use. No malware deployment, credential theft, piracy, or evasion requests.", false).
			AddField("2 · Label certainty", "Separate verified facts, candidates, hypotheses, and copied claims. Include build identity when discussing private Windows interfaces.", false).
			AddField("3 · Protect private data", "Redact tokens, usernames, personal paths, dumps, proprietary binaries, and private PDBs before posting.", false).
			AddField("4 · Make reports reproducible", "Include versions, exact commands, Windows build, logs, and the smallest safe artifact that reproduces the issue.", false).
			AddField("5 · Respect the room", "No harassment, spam, slurs, impersonation, or unsolicited promotion. Critique technical claims, not people.", false).
			SetFooter("Windissect setup · rules", ""),
		"getting-started": starlings.NewEmbed("Get started in two minutes").
			SetColor(0x57F287).
			SetDescription("Windissect runs on Windows 10 and 11 (x64). Nothing else to install.").
			AddField("1 · Download", "Grab the installer from the [latest release](https://github.com/razecrs/windissect/releases/latest). It installs for your user only, so no admin prompt. Prefer no install? Take the portable zip.", false).
			AddField("2 · If Windows warns", "The builds aren't code-signed yet. On the SmartScreen screen choose **More info → Run anyway**.", false).
			AddField("3 · Open a binary", "Start **Windissect** from the Start menu and open any DLL, for example `C:\\Windows\\System32\\uxtheme.dll`. It downloads the matching PDB from Microsoft for you.", false).
			AddField("4 · Explore", "Browse Types, Classes, VTables, Functions and the Evidence behind each one. Output is saved under `%LOCALAPPDATA%\\Windissect\\workspace`.", false).
			AddField("Prefer the command line?", "`windissect --help`, or see the [quick start](https://github.com/razecrs/windissect/blob/main/docs/quickstart.md). Building from source needs Rust.", false).
			AddField("Good to know", "Anything marked *candidate* is research material, not a proven callable ABI. Windissect keeps the two apart on purpose.", false).
			SetFooter("Windissect setup · getting-started", ""),
		"help": starlings.NewEmbed("Before asking for help").
			SetColor(0xFEE75C).
			SetDescription("Run `/support` for the short checklist. A good report lets another person reproduce the failure without guessing.").
			AddField("Include", "Windissect version/commit, Windows build, target architecture, exact command, complete error text, and verification result.", false).
			AddField("Do not upload", "Private binaries, proprietary PDBs, tokens, or unredacted personal paths unless you own them and intentionally choose to share them.", false).
			SetFooter("Windissect setup · help", ""),
		"releases": starlings.NewEmbed("Release feed").
			SetColor(0x5865F2).
			SetDescription("Official releases and compatibility notes will be posted here. Download only from the project repository or links posted by maintainers.").
			AddField("Releases", "https://github.com/razecrs/windissect/releases", false).
			SetFooter("Windissect setup · releases", ""),
		"bot-commands": starlings.NewEmbed("Windissect bot commands").
			SetColor(0x86A9E8).
			SetDescription("Slash commands are available server-wide; this channel keeps experiments and dice rolls out of technical threads.").
			AddField("Project", "`/about` · `/start` · `/links` · `/support` · `/ping`", false).
			AddField("Releases", "`/version` · `/changelog` · `/todo`: latest release and downloads, what changed, and what's being worked on.", false).
			AddField("Community", "`/coinflip` · `/roll` · `/choose` · `/eightball` · `/avatar`", false).
			AddField("Technical tools", "`/hex` · `/snowflake` · `/rva` · `/base` · `/address` · `/winstatus` · `/pemachine` · `/magic` · `/guid` · `/windoc`", false).
			AddField("Compile lab", "`/compilers` · `/compile` — C, C++, and Rust to assembly through Compiler Explorer; execution disabled.", false).
			AddField("Binary lab", "`/triage` — bounded static PE inspection with a private evidence report; files are never executed.", false).
			AddField("Roles", "`/roles` · `/role`", false).
			AddField("Moderation · staff only", "`/warn` · `/warnings` · `/unwarn` · `/case` · `/timeout` · `/untimeout` · `/kick` · `/ban` · `/clear` · `/slowmode`", false).
			SetFooter("Windissect setup · bot-commands", ""),
	}
	names := make([]string, 0, len(guides))
	for name := range guides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		channel := s.text(name)
		pins, err := s.client.Pins(ctx, channel.ID)
		if err != nil {
			return fmt.Errorf("list pins in %s: %w", name, err)
		}
		var existingID starlings.Snowflake
		for _, message := range pins {
			if message.Author != nil && message.Author.ID == botUserID && len(message.Embeds) > 0 && message.Embeds[0].Footer != nil && strings.HasPrefix(message.Embeds[0].Footer.Text, "Windissect setup") {
				existingID = message.ID
				break
			}
		}
		if existingID != 0 {
			_, err := s.client.EditMessage(ctx, channel.ID, existingID, starlings.SendData{
				Embeds: []starlings.Embed{*guides[name]}, AllowedMentions: starlings.NoMentions(),
			})
			if err != nil {
				return fmt.Errorf("update guide in %s: %w", name, err)
			}
			continue
		}
		message, err := s.client.SendComplex(ctx, channel.ID, starlings.SendData{
			Embeds: []starlings.Embed{*guides[name]}, AllowedMentions: starlings.NoMentions(),
		})
		if err != nil {
			return fmt.Errorf("post guide in %s: %w", name, err)
		}
		if err := s.client.PinMessage(ctx, channel.ID, message.ID, auditReason); err != nil {
			return fmt.Errorf("pin guide in %s: %w", name, err)
		}
	}
	return nil
}

func channelKey(kind starlings.ChannelType, name string) string {
	return fmt.Sprintf("%d:%s", kind, strings.ToLower(name))
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func ptr[T any](value T) *T { return &value }
