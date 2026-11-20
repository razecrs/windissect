package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razecrs/starlings"
)

type moderationService struct {
	bot        *starlings.Client
	store      *caseStore
	logChannel atomic.Uint64
}

type memberReasonArgs struct {
	Member *starlings.Member `desc:"Member to moderate"`
	Reason string            `desc:"Why this action is necessary" min:"3" max:"500"`
}

type timeoutArgs struct {
	Member   *starlings.Member `desc:"Member to time out"`
	Duration time.Duration     `desc:"Length such as 10m, 2h, or 3d"`
	Reason   string            `desc:"Why this action is necessary" min:"3" max:"500"`
}

type memberArgs struct {
	Member *starlings.Member `desc:"Member to inspect"`
}

type warningIDArgs struct {
	CaseID uint64 `name:"case" desc:"Warning case number" min:"1"`
	Reason string `desc:"Why the warning is being removed" min:"3" max:"500"`
}

type caseIDArgs struct {
	CaseID uint64 `name:"case" desc:"Moderation case number" min:"1"`
}

type clearArgs struct {
	Count int `desc:"Number of recent messages to delete" min:"1" max:"100"`
}

type slowmodeArgs struct {
	Seconds int `desc:"Delay between messages; zero disables it" min:"0" max:"21600"`
}

func registerModeration(bot *starlings.Client) {
	store, err := openCaseStore(moderationDataDir())
	if err != nil {
		panic(err)
	}
	m := &moderationService{bot: bot, store: store}
	go store.pruneEvery(time.Hour)

	bot.Slash("warn", "Record a formal warning for a member", m.warn).
		GuildOnly().Require(starlings.PermissionModerateMembers)
	bot.Slash("warnings", "Show a member's active warnings", m.warnings).
		GuildOnly().Require(starlings.PermissionModerateMembers)
	bot.Slash("unwarn", "Resolve an active warning", m.unwarn).
		GuildOnly().Require(starlings.PermissionModerateMembers)
	bot.Slash("case", "Inspect a moderation case", m.showCase).
		GuildOnly().Require(starlings.PermissionModerateMembers)
	bot.Slash("timeout", "Temporarily stop a member from participating", m.timeout).
		GuildOnly().Require(starlings.PermissionModerateMembers).
		BotNeeds(starlings.PermissionModerateMembers)
	bot.Slash("untimeout", "Remove a member's timeout", m.untimeout).
		GuildOnly().Require(starlings.PermissionModerateMembers).
		BotNeeds(starlings.PermissionModerateMembers)
	bot.Slash("kick", "Remove a member from the server", m.kick).
		GuildOnly().Require(starlings.PermissionKickMembers).
		BotNeeds(starlings.PermissionKickMembers)
	bot.Slash("ban", "Ban a member from the server", m.ban).
		GuildOnly().Require(starlings.PermissionBanMembers).
		BotNeeds(starlings.PermissionBanMembers)
	bot.Slash("clear", "Delete recent messages from this channel", m.clear).
		GuildOnly().Require(starlings.PermissionManageMessages).
		BotNeeds(starlings.PermissionManageMessages | starlings.PermissionReadMessageHistory)
	bot.Slash("slowmode", "Set this channel's message delay", m.slowmode).
		GuildOnly().Require(starlings.PermissionManageChannels).
		BotNeeds(starlings.PermissionManageChannels)
}

func (m *moderationService) warn(i *starlings.InteractionCreate, args memberReasonArgs) (starlings.Response, error) {
	if err := validateTarget(i, args.Member); err != nil {
		return starlings.Response{}, err
	}
	entry, err := m.record(i, "warn", args.Member, args.Reason, "")
	if err != nil {
		return starlings.Response{}, err
	}
	m.audit(i, entry, 0xFEE75C)
	return starlings.Ephemeral(fmt.Sprintf("Warning **#%d** recorded for %s.", entry.ID, args.Member.DisplayName())), nil
}

func (m *moderationService) warnings(_ *starlings.InteractionCreate, args memberArgs) (starlings.Response, error) {
	if args.Member == nil || args.Member.User == nil {
		return starlings.Response{}, starlings.UserErrorf("That member could not be resolved.")
	}
	warnings := m.store.activeWarnings(args.Member.User.ID.String())
	embed := starlings.NewEmbed("Active warnings · " + args.Member.DisplayName()).SetColor(0xFEE75C)
	if len(warnings) == 0 {
		embed.SetDescription("No active warnings.")
		return starlings.Ephemeral(embed), nil
	}
	if len(warnings) > 10 {
		warnings = warnings[:10]
	}
	for _, warning := range warnings {
		embed.AddField(fmt.Sprintf("#%d · %s", warning.ID, warning.CreatedAt.Format("2006-01-02")), warning.Reason+"\nModerator: "+warning.ModeratorName, false)
	}
	return starlings.Ephemeral(embed), nil
}

func (m *moderationService) unwarn(i *starlings.InteractionCreate, args warningIDArgs) (starlings.Response, error) {
	moderator := i.Invoker()
	if moderator == nil {
		return starlings.Response{}, starlings.UserErrorf("The moderator identity was unavailable.")
	}
	entry, err := m.store.resolveWarning(args.CaseID, moderator.ID.String(), moderator.Tag(), args.Reason)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("%s", err)
	}
	m.audit(i, entry, 0x57F287)
	return starlings.Ephemeral(fmt.Sprintf("Warning **#%d** resolved.", entry.ID)), nil
}

func (m *moderationService) showCase(_ *starlings.InteractionCreate, args caseIDArgs) (starlings.Response, error) {
	entry, found := m.store.get(args.CaseID)
	if !found {
		return starlings.Response{}, starlings.UserErrorf("Case #%d does not exist.", args.CaseID)
	}
	embed := caseEmbed(entry, 0x86A9E8)
	return starlings.Ephemeral(embed), nil
}

func (m *moderationService) timeout(i *starlings.InteractionCreate, args timeoutArgs) (starlings.Response, error) {
	if err := validateTarget(i, args.Member); err != nil {
		return starlings.Response{}, err
	}
	if args.Duration <= 0 || args.Duration > starlings.MaxTimeout {
		return starlings.Response{}, starlings.UserErrorf("Duration must be greater than zero and no longer than 28 days.")
	}
	if err := args.Member.Timeout(args.Duration, args.Reason); err != nil {
		return starlings.Response{}, err
	}
	entry, err := m.record(i, "timeout", args.Member, args.Reason, args.Duration.String())
	if err != nil {
		return starlings.Response{}, err
	}
	m.audit(i, entry, 0xFEE75C)
	return starlings.Ephemeral(fmt.Sprintf("%s timed out for **%s**. Case **#%d**.", args.Member.DisplayName(), args.Duration, entry.ID)), nil
}

func (m *moderationService) untimeout(i *starlings.InteractionCreate, args memberReasonArgs) (starlings.Response, error) {
	if err := validateTarget(i, args.Member); err != nil {
		return starlings.Response{}, err
	}
	if err := args.Member.ClearTimeout(args.Reason); err != nil {
		return starlings.Response{}, err
	}
	entry, err := m.record(i, "untimeout", args.Member, args.Reason, "")
	if err != nil {
		return starlings.Response{}, err
	}
	m.audit(i, entry, 0x57F287)
	return starlings.Ephemeral(fmt.Sprintf("Timeout removed from %s. Case **#%d**.", args.Member.DisplayName(), entry.ID)), nil
}

func (m *moderationService) kick(i *starlings.InteractionCreate, args memberReasonArgs) (starlings.Response, error) {
	if err := validateTarget(i, args.Member); err != nil {
		return starlings.Response{}, err
	}
	if err := args.Member.Kick(args.Reason); err != nil {
		return starlings.Response{}, err
	}
	entry, err := m.record(i, "kick", args.Member, args.Reason, "")
	if err != nil {
		return starlings.Response{}, err
	}
	m.audit(i, entry, 0xED4245)
	return starlings.Ephemeral(fmt.Sprintf("%s was kicked. Case **#%d**.", args.Member.DisplayName(), entry.ID)), nil
}

func (m *moderationService) ban(i *starlings.InteractionCreate, args memberReasonArgs) (starlings.Response, error) {
	if err := validateTarget(i, args.Member); err != nil {
		return starlings.Response{}, err
	}
	if err := args.Member.Ban(args.Reason, 0); err != nil {
		return starlings.Response{}, err
	}
	entry, err := m.record(i, "ban", args.Member, args.Reason, "")
	if err != nil {
		return starlings.Response{}, err
	}
	m.audit(i, entry, 0xED4245)
	return starlings.Ephemeral(fmt.Sprintf("%s was banned. Case **#%d**.", args.Member.DisplayName(), entry.ID)), nil
}

func (m *moderationService) clear(i *starlings.InteractionCreate, args clearArgs) (starlings.Response, error) {
	moderator := i.Invoker()
	result, err := m.bot.Purge(context.Background(), i.ChannelID, starlings.PurgeOptions{
		Count: args.Count, MaxOld: -1, Reason: auditReasonText(moderator, "clear messages"),
	})
	if err != nil {
		return starlings.Response{}, err
	}
	return starlings.Ephemeral(fmt.Sprintf("Deleted **%d** message(s); scanned %d.", result.Deleted, result.Scanned)), nil
}

func (m *moderationService) slowmode(i *starlings.InteractionCreate, args slowmodeArgs) (starlings.Response, error) {
	moderator := i.Invoker()
	_, err := m.bot.ModifyChannel(context.Background(), i.ChannelID, starlings.ChannelParams{
		RateLimitPerUser: &args.Seconds,
	}, auditReasonText(moderator, "change slowmode"))
	if err != nil {
		return starlings.Response{}, err
	}
	if args.Seconds == 0 {
		return starlings.Ephemeral("Slowmode disabled for this channel."), nil
	}
	return starlings.Ephemeral(fmt.Sprintf("Slowmode set to **%d seconds**.", args.Seconds)), nil
}

func (m *moderationService) record(i *starlings.InteractionCreate, action string, target *starlings.Member, reason, duration string) (moderationCase, error) {
	moderator := i.Invoker()
	if moderator == nil || target == nil || target.User == nil {
		return moderationCase{}, starlings.UserErrorf("Discord did not provide enough member information.")
	}
	return m.store.add(moderationCase{
		Action: action, TargetID: target.User.ID.String(), TargetName: target.DisplayName(),
		ModeratorID: moderator.ID.String(), ModeratorName: moderator.Tag(), Reason: reason, Duration: duration,
	})
}

func (m *moderationService) audit(i *starlings.InteractionCreate, entry moderationCase, color int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	channelID := starlings.Snowflake(m.logChannel.Load())
	if channelID == 0 {
		channels, err := m.bot.GuildChannels(ctx, i.GuildID)
		if err != nil {
			log.Printf("resolve mod-logs: %v", err)
			return
		}
		for _, channel := range channels {
			if channel.Name == "mod-logs" {
				channelID = channel.ID
				m.logChannel.Store(uint64(channel.ID))
				break
			}
		}
	}
	if channelID == 0 {
		log.Printf("mod-logs channel was not found")
		return
	}
	_, err := m.bot.SendComplex(ctx, channelID, starlings.SendData{
		Embeds: []starlings.Embed{*caseEmbed(entry, color)}, AllowedMentions: starlings.NoMentions(),
	})
	if err != nil {
		log.Printf("write moderation audit: %v", err)
	}
}

func caseEmbed(entry moderationCase, color int) *starlings.Embed {
	status := "complete"
	if entry.Active {
		status = "active"
	}
	embed := starlings.NewEmbed(fmt.Sprintf("Case #%d · %s", entry.ID, strings.ToUpper(entry.Action))).
		SetColor(color).
		AddField("Target", entry.TargetName+" (`"+entry.TargetID+"`)", false).
		AddField("Moderator", entry.ModeratorName+" (`"+entry.ModeratorID+"`)", false).
		AddField("Reason", entry.Reason, false).
		AddField("Status", status, true).
		SetTimestamp(entry.CreatedAt).
		SetFooter("Windissect moderation", "")
	if entry.Duration != "" {
		embed.AddField("Duration", entry.Duration, true)
	}
	if entry.Resolution != "" {
		embed.AddField("Resolution", entry.Resolution+"\nBy "+entry.ResolvedByName, false)
	}
	return embed
}

func validateTarget(i *starlings.InteractionCreate, target *starlings.Member) error {
	if target == nil || target.User == nil {
		return starlings.UserErrorf("That member could not be resolved.")
	}
	invoker := i.Invoker()
	if invoker != nil && invoker.ID == target.User.ID {
		return starlings.UserErrorf("You cannot use that moderation action on yourself.")
	}
	if target.User.Bot {
		return starlings.UserErrorf("Bot accounts must be managed through integrations and roles.")
	}
	return nil
}

func auditReasonText(user *starlings.User, action string) string {
	if user == nil {
		return "Windissect bot: " + action
	}
	return fmt.Sprintf("Windissect bot: %s by %s (%s)", action, user.Tag(), user.ID)
}
