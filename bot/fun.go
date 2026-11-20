package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/razecrs/starlings"
)

type rollArgs struct {
	Sides int `desc:"Sides on each die" min:"2" max:"1000"`
	Count int `desc:"Number of dice" min:"1" max:"20"`
}

type chooseArgs struct {
	Options string `desc:"Choices separated with |" min:"3" max:"1000"`
}

type questionArgs struct {
	Question string `desc:"Question for the evidence orb" min:"3" max:"500"`
}

type textArgs struct {
	Text string `desc:"Text to encode" min:"1" max:"200"`
}

type snowflakeArgs struct {
	ID string `desc:"Discord snowflake ID" min:"17" max:"20"`
}

type addressArgs struct {
	Base string `desc:"Image base, decimal or 0x-prefixed" max:"18"`
	RVA  string `desc:"Relative virtual address, decimal or 0x-prefixed" max:"18"`
}

type avatarArgs struct {
	Member *starlings.Member `desc:"Whose avatar to show"`
}

func registerFun(bot *starlings.Client) {
	bot.Slash("coinflip", "Flip a cryptographically fair coin", func() string {
		if randomInt(2) == 0 {
			return "🪙 **Heads.**"
		}
		return "🪙 **Tails.**"
	})
	bot.Slash("roll", "Roll one or more dice", roll)
	bot.Slash("choose", "Choose fairly from pipe-separated options", choose)
	bot.Slash("eightball", "Ask the evidence orb a question", eightBall)
	bot.Slash("hex", "Encode UTF-8 text as hexadecimal bytes", encodeHex)
	bot.Slash("snowflake", "Decode the timestamp inside a Discord ID", decodeSnowflake)
	bot.Slash("rva", "Add an RVA to an image base", calculateRVA)
	bot.Slash("avatar", "Show a member's full-size avatar", avatar).GuildOnly()
}

func roll(args rollArgs) (string, error) {
	if args.Sides < 2 || args.Sides > 1000 || args.Count < 1 || args.Count > 20 {
		return "", starlings.UserErrorf("Use 1–20 dice with 2–1000 sides each.")
	}
	values := make([]string, args.Count)
	total := 0
	for index := range values {
		value := randomInt(args.Sides) + 1
		total += value
		values[index] = strconv.Itoa(value)
	}
	if args.Count == 1 {
		return fmt.Sprintf("🎲 Rolled **%d** on a d%d.", total, args.Sides), nil
	}
	return fmt.Sprintf("🎲 d%d × %d: `%s` → **%d**", args.Sides, args.Count, strings.Join(values, ", "), total), nil
}

func choose(args chooseArgs) (string, error) {
	raw := strings.Split(args.Options, "|")
	options := make([]string, 0, len(raw))
	for _, option := range raw {
		if trimmed := strings.TrimSpace(option); trimmed != "" {
			options = append(options, trimmed)
		}
	}
	if len(options) < 2 {
		return "", starlings.UserErrorf("Give me at least two choices separated with `|`.")
	}
	if len(options) > 25 {
		return "", starlings.UserErrorf("Keep it to 25 choices or fewer.")
	}
	return "🔬 The evidence selects: **" + options[randomInt(len(options))] + "**", nil
}

func eightBall(args questionArgs) string {
	answers := []string{
		"The evidence strongly supports it.",
		"Probable—but verify the exact build.",
		"The symbols say yes.",
		"Candidate only. More evidence required.",
		"The ABI is unstable; ask again after refinement.",
		"Conflict detected. Do not ship that assumption.",
		"No. The call graph rejects it.",
		"Outlook unclear; run Windissect.",
	}
	return fmt.Sprintf("🎱 **%s**\n%s", args.Question, answers[randomInt(len(answers))])
}

func encodeHex(args textArgs) starlings.Response {
	encoded := strings.ToUpper(hex.EncodeToString([]byte(args.Text)))
	var grouped strings.Builder
	for index := 0; index < len(encoded); index += 2 {
		if grouped.Len() > 0 {
			grouped.WriteByte(' ')
		}
		grouped.WriteString(encoded[index : index+2])
	}
	return starlings.Ephemeral("```text\n" + grouped.String() + "\n```")
}

func decodeSnowflake(args snowflakeArgs) (starlings.Response, error) {
	id, err := starlings.ParseSnowflake(strings.TrimSpace(args.ID))
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("That is not a valid Discord snowflake.")
	}
	timestamp := id.Time()
	embed := starlings.NewEmbed("Snowflake decoded").
		SetColor(windissectBlue).
		AddField("ID", "`"+id.String()+"`", false).
		AddField("Created", fmt.Sprintf("<t:%d:F> · <t:%d:R>", timestamp.Unix(), timestamp.Unix()), false)
	return starlings.Ephemeral(embed), nil
}

func calculateRVA(args addressArgs) (starlings.Response, error) {
	base, err := parseAddress(args.Base)
	if err != nil {
		return starlings.Response{}, starlings.UserErrorf("Image base must be decimal or `0x`-prefixed hexadecimal.")
	}
	rva, err := parseAddress(args.RVA)
	if err != nil || ^uint64(0)-base < rva {
		return starlings.Response{}, starlings.UserErrorf("RVA is invalid or the addition overflows 64 bits.")
	}
	return starlings.Ephemeral(fmt.Sprintf("`0x%X + 0x%X = 0x%X`", base, rva, base+rva)), nil
}

func avatar(args avatarArgs) (starlings.Response, error) {
	if args.Member == nil || args.Member.User == nil {
		return starlings.Response{}, starlings.UserErrorf("That member could not be resolved.")
	}
	url := args.Member.AvatarURL(args.Member.GuildID(), 1024)
	if url == "" {
		url = args.Member.User.AvatarURL(1024)
	}
	embed := starlings.NewEmbed(args.Member.DisplayName()).SetColor(windissectBlue).SetImage(url)
	return starlings.Reply(embed), nil
}

func parseAddress(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return strconv.ParseUint(value[2:], 16, 64)
	}
	return strconv.ParseUint(value, 10, 64)
}

func randomInt(maximum int) int {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)))
	if err != nil {
		panic(fmt.Sprintf("secure randomness unavailable: %v", err))
	}
	return int(value.Int64())
}
