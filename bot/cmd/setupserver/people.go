package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/razecrs/starlings"
)

// moderators get the Moderator role. Keep this list short and to people the
// maintainer knows: the role can kick, ban and time out members.
var moderators = []struct {
	id   starlings.Snowflake
	name string // for the log only
}{
	{id: 1280695437946388572, name: "w.y.d"},
}

// thanks are the people credited in #thanks, one pinned post each. A post is
// found again by its footer, so editing an entry here (for example swapping a
// Reddit name for a Discord mention once someone joins) edits the post in
// place. Keep each key stable once published.
var thanks = []struct {
	key, who, what string
}{
	{
		key:  "wyd-tui",
		who:  "<@1280695437946388572>",
		what: "Tested an installed 1.0.0 and found that running `windissect` with no arguments failed with \"TUI is not built\", because the terminal UI only existed in a source checkout. Fixed in 1.0.1: the TUI now ships as a standalone executable that needs no Node.js.",
	},
	{
		key:  "pfak-local-pdb",
		who:  "u/pfak on r/ReverseEngineering",
		what: "Spotted that a PDB sitting next to the binary was downloaded again instead of being used. Fixed in 1.0.1: the pull now uses a matching local PDB and only downloads when there isn't one.",
	},
}

func (s *server) ensureModerators(ctx context.Context) error {
	role := s.roles["moderator"]
	for _, m := range moderators {
		if err := s.client.AddMemberRole(ctx, s.guildID, m.id, role.ID, auditReason); err != nil {
			return fmt.Errorf("assign Moderator to %s: %w", m.name, err)
		}
	}
	return nil
}

// ensureRoleOrder keeps Moderator directly under Maintainer. A new role is
// created at the bottom, where it could not act on Contributors or
// Researchers, since Discord only lets a role moderate the roles below it.
//
// The slots the managed roles hold now are handed out again in the intended
// order, so roles outside the list (the bot's own) never move.
func (s *server) ensureRoleOrder(ctx context.Context) error {
	order := []string{"early access", "researcher", "contributor", "moderator", "maintainer"} // bottom to top
	roles, err := s.client.Roles(ctx, s.guildID)
	if err != nil {
		return fmt.Errorf("list roles: %w", err)
	}
	byName := map[string]starlings.Role{}
	for _, role := range roles {
		byName[strings.ToLower(role.Name)] = role
	}
	slots := make([]int, 0, len(order))
	for _, name := range order {
		role, ok := byName[name]
		if !ok {
			return fmt.Errorf("role %q is missing", name)
		}
		slots = append(slots, role.Position)
	}
	sort.Ints(slots)
	positions := make([]starlings.RolePosition, 0, len(order))
	inOrder := true
	for i, name := range order {
		role := byName[name]
		if role.Position != slots[i] {
			inOrder = false
		}
		positions = append(positions, starlings.RolePosition{ID: role.ID, Position: ptr(slots[i])})
	}
	if inOrder {
		return nil
	}
	if _, err := s.client.ReorderRoles(ctx, s.guildID, positions, auditReason); err != nil {
		return fmt.Errorf("order roles: %w", err)
	}
	return nil
}

func (s *server) thanksPosts() []post {
	posts := make([]post, 0, len(thanks))
	for _, t := range thanks {
		posts = append(posts, post{
			channel: "thanks",
			footer:  "Windissect thanks · " + t.key,
			embed: starlings.NewEmbed("Thank you").
				SetColor(0xF2C94C).
				SetDescription(t.who + "\n\n" + t.what),
		})
	}
	return posts
}
