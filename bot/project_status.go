package main

// /version, /todo and /changelog: live project status pulled from GitHub, so
// the answers stay current without redeploying the bot. Responses are cached
// for a few minutes to stay well inside GitHub's unauthenticated rate limit.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razecrs/starlings"
)

const (
	githubAPI       = "https://api.github.com/repos/razecrs/windissect"
	knownIssuesRaw  = "https://raw.githubusercontent.com/razecrs/windissect/main/docs/known-issues.md"
	knownIssuesURL  = repositoryURL + "/blob/main/docs/known-issues.md"
	issuesURL       = repositoryURL + "/issues"
	statusCacheTTL  = 5 * time.Minute
	statusBodyLimit = 1 << 20
)

var statusClient = &http.Client{Timeout: 10 * time.Second}

type versionArgs struct {
	Yours string `desc:"Your version, from windissect --version or the app's About box" max:"64" optional:""`
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

type githubRepo struct {
	OpenIssues int `json:"open_issues_count"`
}

// cached holds one fetched value for statusCacheTTL.
type cached[T any] struct {
	mu    sync.Mutex
	value T
	at    time.Time
}

func (c *cached[T]) get(ctx context.Context, fetch func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < statusCacheTTL {
		return c.value, nil
	}
	v, err := fetch(ctx)
	if err != nil {
		if !c.at.IsZero() {
			return c.value, nil // serve stale data rather than nothing
		}
		return v, err
	}
	c.value, c.at = v, time.Now()
	return v, nil
}

var (
	latestRelease cached[githubRelease]
	knownIssues   cached[[]string]
	repoInfo      cached[githubRepo]
)

func registerProjectStatus(bot *starlings.Client) {
	bot.Slash("version", "Latest Windissect release, and whether yours is up to date", func(i *starlings.InteractionCreate, args versionArgs) error {
		return deferred(i, func(ctx context.Context) (*starlings.Embed, error) {
			rel, err := latestRelease.get(ctx, fetchLatestRelease)
			if err != nil {
				return nil, err
			}
			return versionEmbed(rel, args.Yours), nil
		})
	})
	bot.Slash("todo", "What's being worked on: known issues and open reports", func(i *starlings.InteractionCreate, _ struct{}) error {
		return deferred(i, func(ctx context.Context) (*starlings.Embed, error) {
			issues, err := knownIssues.get(ctx, fetchKnownIssues)
			if err != nil {
				return nil, err
			}
			repo, _ := repoInfo.get(ctx, fetchRepo) // optional extra
			return todoEmbed(issues, repo.OpenIssues), nil
		})
	})
	bot.Slash("changelog", "What changed in the latest Windissect release", func(i *starlings.InteractionCreate, _ struct{}) error {
		return deferred(i, func(ctx context.Context) (*starlings.Embed, error) {
			rel, err := latestRelease.get(ctx, fetchLatestRelease)
			if err != nil {
				return nil, err
			}
			return changelogEmbed(rel), nil
		})
	})
}

// deferred acknowledges the command at once (GitHub can be slower than
// Discord's 3-second window), then edits in the result.
func deferred(i *starlings.InteractionCreate, build func(context.Context) (*starlings.Embed, error)) error {
	if err := i.Defer(false); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	embed, err := build(ctx)
	data := starlings.InteractionResponseData{AllowedMentions: starlings.NoMentions()}
	if err != nil {
		data.Content = fmt.Sprintf("Couldn't reach GitHub just now. Check %s directly.", releasesURL)
	} else {
		data.Embeds = []starlings.Embed{*embed}
	}
	_, err = i.EditResponse(ctx, data)
	return err
}

func getJSON(ctx context.Context, url string, out any) error {
	body, err := getBody(ctx, url, "application/vnd.github+json")
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func getBody(ctx context.Context, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "windissect-discord-bot")
	resp, err := statusClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, statusBodyLimit))
}

func fetchLatestRelease(ctx context.Context) (githubRelease, error) {
	var rel githubRelease
	err := getJSON(ctx, githubAPI+"/releases/latest", &rel)
	if err == nil && rel.TagName == "" {
		err = errors.New("latest release has no tag")
	}
	return rel, err
}

func fetchRepo(ctx context.Context) (githubRepo, error) {
	var repo githubRepo
	return repo, getJSON(ctx, githubAPI, &repo)
}

func fetchKnownIssues(ctx context.Context) ([]string, error) {
	body, err := getBody(ctx, knownIssuesRaw, "text/plain")
	if err != nil {
		return nil, err
	}
	return markdownHeadings(string(body)), nil
}

// markdownHeadings returns the text of every "## " heading.
func markdownHeadings(md string) []string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "## ") {
			out = append(out, strings.TrimSpace(line[3:]))
		}
	}
	return out
}

var semverPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// parseVersion finds x.y.z anywhere in text such as "windissect 1.0.0" or "v1.0.0".
func parseVersion(text string) ([3]int, bool) {
	m := semverPattern.FindStringSubmatch(text)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for k := range v {
		v[k], _ = strconv.Atoi(m[k+1])
	}
	return v, true
}

func compareVersions(a, b [3]int) int {
	for k := range a {
		if a[k] != b[k] {
			if a[k] < b[k] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionString(v [3]int) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

func versionEmbed(rel githubRelease, yours string) *starlings.Embed {
	latest, _ := parseVersion(rel.TagName)
	embed := card("Windissect "+versionString(latest), "").SetURL(rel.HTMLURL)

	switch mine, ok := parseVersion(yours); {
	case strings.TrimSpace(yours) == "":
		embed.SetDescription("This is the latest release. Run `windissect --version` and pass it as `yours` to check your copy.")
	case !ok:
		embed.SetDescription(fmt.Sprintf("I couldn't find a version like `1.0.0` in `%s`. Try the output of `windissect --version`.", strings.TrimSpace(yours)))
	case compareVersions(mine, latest) < 0:
		embed.SetDescription(fmt.Sprintf("**Update available:** you have %s, the latest is %s. Grab it below.", versionString(mine), versionString(latest)))
	case compareVersions(mine, latest) == 0:
		embed.SetDescription(fmt.Sprintf("**You're up to date** on %s.", versionString(mine)))
	default:
		embed.SetDescription(fmt.Sprintf("You're on %s, ahead of the latest release (%s). That's a development build.", versionString(mine), versionString(latest)))
	}

	if !rel.PublishedAt.IsZero() {
		embed.AddField("Released", fmt.Sprintf("<t:%d:D>", rel.PublishedAt.Unix()), true)
	}
	var downloads []string
	for _, a := range rel.Assets {
		switch {
		case strings.HasSuffix(a.Name, "-setup-x64.exe"):
			downloads = append(downloads, fmt.Sprintf("[Installer](%s) · %s", a.URL, megabytes(a.Size)))
		case strings.HasSuffix(a.Name, ".zip"):
			downloads = append(downloads, fmt.Sprintf("[Portable zip](%s) · %s", a.URL, megabytes(a.Size)))
		}
	}
	if len(downloads) > 0 {
		embed.AddField("Download", strings.Join(downloads, "\n"), true)
	}
	return embed.SetFooter("Unsigned build: if SmartScreen warns, choose More info → Run anyway.", "")
}

func megabytes(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/1e6) }

func todoEmbed(issues []string, openReports int) *starlings.Embed {
	embed := card("What's being worked on", "Known gaps from the docs. Each one has the details and the evidence route that would close it.")
	if len(issues) == 0 {
		embed.AddField("Known issues", "None listed right now.", false)
	} else {
		lines := make([]string, 0, len(issues))
		for _, h := range issues {
			lines = append(lines, "• "+h)
		}
		embed.AddField("Known issues", clip(strings.Join(lines, "\n"), 1000)+fmt.Sprintf("\n[Read the details](%s)", knownIssuesURL), false)
	}
	embed.AddField("Open reports", fmt.Sprintf("[%d on GitHub](%s)", openReports, issuesURL), true)
	embed.AddField("Found something?", "Run `/support` for what to include in a report.", true)
	return embed
}

func changelogEmbed(rel githubRelease) *starlings.Embed {
	latest, _ := parseVersion(rel.TagName)
	embed := card("What's new in "+versionString(latest), "").SetURL(rel.HTMLURL)
	bullets := releaseSection(rel.Body, "What's new")
	if len(bullets) == 0 {
		embed.SetDescription(fmt.Sprintf("[Read the release notes](%s)", rel.HTMLURL))
		return embed
	}
	embed.SetDescription(clip(strings.Join(bullets, "\n"), 3800) + fmt.Sprintf("\n\n[Full release notes](%s)", rel.HTMLURL))
	return embed
}

// releaseSection returns the bullet lines under the "## <title>" heading.
func releaseSection(body, title string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "## ") {
			in = strings.EqualFold(strings.TrimSpace(line[3:]), title)
			continue
		}
		if in && strings.HasPrefix(line, "- ") {
			out = append(out, "•"+line[1:])
		}
	}
	return out
}

func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := strings.LastIndex(s[:limit], "\n")
	if cut <= 0 {
		cut = limit
	}
	return s[:cut] + "\n…"
}
