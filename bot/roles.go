package main

import (
	"context"
	"strings"

	"github.com/razecrs/starlings"
)

type roleArgs struct {
	Role   string `desc:"Community role" choices:"Researcher=researcher|Early Access=early-access"`
	Action string `desc:"Add or remove the role" choices:"Add=add|Remove=remove"`
}

func registerRoles(bot *starlings.Client) {
	bot.Slash("roles", "Show available community roles", func() starlings.Response {
		embed := starlings.NewEmbed("Community roles").SetColor(windissectBlue).
			AddField("Researcher", "Windows internals, ABI, symbols, PDB, PE/COFF, and reverse-engineering discussion.", false).
			AddField("Early Access", "People who want compatibility notes and preview-build testing opportunities.", false).
			AddField("Contributor", "Granted by maintainers after a contribution or active implementation work.", false).
			AddField("Maintainer", "Project staff with moderation and publishing responsibility.", false).
			SetFooter("Use /role for Researcher or Early Access", "")
		return starlings.Ephemeral(embed)
	})
	bot.Slash("role", "Add or remove a self-service community role", func(i *starlings.InteractionCreate, args roleArgs) (starlings.Response, error) {
		if i.Member == nil {
			return starlings.Response{}, starlings.UserErrorf("This command only works inside the server.")
		}
		wanted := map[string]string{"researcher": "Researcher", "early-access": "Early Access"}[args.Role]
		if wanted == "" {
			return starlings.Response{}, starlings.UserErrorf("That role is not self-service.")
		}
		roles, err := bot.Roles(context.Background(), i.GuildID)
		if err != nil {
			return starlings.Response{}, err
		}
		var roleID starlings.Snowflake
		for _, role := range roles {
			if strings.EqualFold(role.Name, wanted) {
				roleID = role.ID
				break
			}
		}
		if roleID == 0 {
			return starlings.Response{}, starlings.UserErrorf("The %s role is not configured.", wanted)
		}
		reason := "Windissect self-service role"
		switch args.Action {
		case "add":
			if err := i.Member.AddRole(roleID, reason); err != nil {
				return starlings.Response{}, err
			}
			return starlings.Ephemeral("Added **" + wanted + "**."), nil
		case "remove":
			if err := i.Member.RemoveRole(roleID, reason); err != nil {
				return starlings.Response{}, err
			}
			return starlings.Ephemeral("Removed **" + wanted + "**."), nil
		default:
			return starlings.Response{}, starlings.UserErrorf("Choose Add or Remove.")
		}
	}).GuildOnly().BotNeeds(starlings.PermissionManageRoles)
}
