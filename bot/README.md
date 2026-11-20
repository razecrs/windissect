# Windissect Discord bot

The official Windissect server bot is intentionally small: product help,
official links, a support checklist, and a health check. It is built with
[Starlings](https://github.com/razecrs/starlings) and uses slash commands, so
it does not need Discord's privileged message-content intent.

## Run locally

1. Create a bot application in the Discord developer portal and copy
   `.env.example` to `.env`.
2. Put the bot token in `DISCORD_TOKEN` and the development server ID in
   `DISCORD_GUILD_ID`. A shared production environment may instead export
   `WINDISSECT_BOT_TOKEN`.
3. Run `go run .` from this directory.
4. Copy the `server invite` URL printed after READY and authorize it in the
   server you administer.

Official bot install link: [add Windissect to a server](https://discord.com/oauth2/authorize?client_id=1573065030927130815&scope=bot%20applications.commands&permissions=0).

The invite requests only `bot` and `applications.commands`, with zero broad
guild permissions. Tokens belong in the environment or deployment secret
store, never source control.

## Commands

- `/about` explains the evidence model and output.
- `/start` gives the shortest supported quick start.
- `/links` returns official project, release and legal links.
- `/support` privately shows the reproducibility checklist.
- `/ping` is a private health check.

Moderation commands provide persistent case numbers and private `mod-logs`:
`/warn`, `/warnings`, `/unwarn`, `/case`, `/timeout`, `/untimeout`, `/kick`,
`/ban`, `/clear`, and `/slowmode`. Discord permissions are checked both for
the moderator and the bot before an action runs.

Community commands include `/coinflip`, `/roll`, `/choose`, `/eightball`,
`/avatar`, `/hex`, `/snowflake`, and the Windissect-flavoured `/rva`
calculator.

Windows research utilities include `/base`, `/address`, `/winstatus`,
`/pemachine`, `/magic`, `/guid`, and `/windoc`. `/role` lets members manage
the safe self-service Researcher and Early Access roles; Contributor and
Maintainer remain staff-controlled.

`/compile` opens a private multiline modal for a bounded C, C++, or Rust probe,
then returns Compiler Explorer assembly and diagnostics as attachments. `/compilers` documents the
fixed toolchain and optimization presets. Execution and arbitrary compiler
flags are intentionally unavailable.

`/triage` accepts a PE image up to 16 MiB and performs static-only inspection:
hashes, headers, mitigations, section entropy, imports, exports, CodeView/PDB
identity, certificate-table presence, capability indicators, and review cues.
It never executes or loads the submitted binary, and returns the full evidence
as a private JSON attachment.

For production, leave `DISCORD_GUILD_ID` unset so Starlings publishes global
commands. Set it during development for immediate guild-scoped updates.
