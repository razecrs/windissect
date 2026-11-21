# Discord Rich Presence

Windissect can show what you are inspecting on your Discord profile, the way
editor extensions do:

```
Windissect
Inspecting bootux.dll
Types › BUXButtonCollection
00:12 elapsed
```

It talks to the Discord desktop app over its local IPC endpoint (a named pipe
on Windows, a Unix socket on Linux). Windissect does not
sign users into Discord and never receives their Discord token. If Discord is
not running, nothing happens, and the card appears after Discord starts.

## Zero-config installed builds

Release builds ship Windissect's public Discord application ID. A user installs
Windissect, opens it while the Discord desktop client is running, and the card
appears—there is no bot installation, OAuth prompt, or per-user developer app.

The public application uses:

- Application ID `1573065030927130815`;
- `https://razecrs.com/img/windissect.png` for its large card image;
- `https://razecrs.com/privacy` and `https://razecrs.com/terms` for the
  registered privacy policy and terms.

The VPS only serves those public HTTPS resources. Presence state itself travels
directly from Windissect to the user's local Discord desktop app.

## Development override

Developers testing another Discord application can override the built-in ID:

- environment: `WINDISSECT_DISCORD_CLIENT_ID=<id>`; or
- `%APPDATA%\Windissect\settings.json`:

  ```json
  {
    "discord_client_id": "<id>",
    "discord_presence": true,
    "discord_show_names": true
  }
  ```

The ID is public application metadata, not a client secret. Never put a Discord
bot token or OAuth client secret in Windissect settings.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `discord_presence` | `true` | Show the card at all (Tools → Discord presence). |
| `discord_show_names` | `true` | Show module, class and doc names. Off shows only the section and counts, for when what you are reversing is private (Tools → Show module names). |

Both toggles in the Tools sidebar save to `settings.json`.

If the card is hidden, check Discord **User Settings → Activity Privacy → Share
your detected activities with others**. Spotify can be displayed alongside or
ahead of application activity; it does not carry Windissect's presence state.

## How it works

`gui/src/discord.rs` speaks Discord's IPC directly, with no extra crates: it
opens `\\.\pipe\discord-ipc-0..9` on Windows, or on Linux the socket
`discord-ipc-0..9` in `$XDG_RUNTIME_DIR` (else `$TMPDIR`, `$TMP`, `$TEMP`,
then `/tmp`) and in its Flatpak (`app/com.discordapp.Discord/`) and Snap
(`snap.discord/`) subdirectories, validates Discord's `READY` handshake, then
sends `SET_ACTIVITY` frames. A worker thread sends only the latest state, at
most every 5 seconds, reconnects every 15 seconds while Discord is closed, and
never blocks the window. Discord fetches and proxies the public image URL; it
does not fetch module names or analysis data from the VPS.
