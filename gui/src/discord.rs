//! Discord Rich Presence over Discord's local IPC, with no extra crates.
//!
//! The Discord client listens on `\\.\pipe\discord-ipc-N` (N = 0..9). Each
//! frame is `[u32 LE opcode][u32 LE length][JSON]`: opcode 0 is the handshake
//! `{"v":1,"client_id":..}`, opcode 1 carries commands such as SET_ACTIVITY.
//! Everything runs on one worker thread fed by a channel: the window only
//! ever sends the latest activity, the worker connects (and reconnects when
//! Discord restarts), rate-limits, and never blocks the UI. A second thread
//! validates Discord's acknowledgement before an activity becomes the cached
//! state.
//!
//! Windissect ships its public Discord application ID, so installed builds
//! work without user setup. Environment/settings overrides remain available
//! for development builds; see DISCORD.md.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const OP_HANDSHAKE: u32 = 0;
const OP_FRAME: u32 = 1;
/// Discord accepts about one activity update per 15 s per client before it
/// starts dropping them; coalescing to one per 5 s keeps the card current.
const MIN_INTERVAL: Duration = Duration::from_secs(5);
const RECONNECT_EVERY: Duration = Duration::from_secs(15);
const MAX_TEXT: usize = 128;

/// Windissect's own Discord application. Its ID is public (it is in every
/// invite link), so it ships built in and presence works with no setup; the
/// settings file or WINDISSECT_DISCORD_CLIENT_ID can point at another app.
const DEFAULT_CLIENT_ID: &str = "1573065030927130815";

/// The card's picture, loaded by Discord from a public URL, so the app needs
/// no uploaded art assets.
const LARGE_IMAGE: &str = "https://razecrs.com/img/windissect.png";
const PROJECT_URL: &str = "https://github.com/razecrs/windissect";
const WEBSITE_URL: &str = "https://razecrs.com";
const MAX_FRAME: usize = 1 << 20;

// ---- settings ------------------------------------------------------------------

/// `%APPDATA%\Windissect\settings.json`. Unknown keys are kept on save.
pub struct Settings {
    pub client_id: Option<String>,
    pub presence: bool,
    pub show_names: bool,
    /// True when the ID came from the environment (it is then not saved).
    from_env: bool,
}

fn settings_path() -> Option<PathBuf> {
    crate::engine::settings_path()
}

fn read_settings_json() -> Value {
    settings_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

impl Settings {
    pub fn load() -> Self {
        let file = read_settings_json();
        let env_id = std::env::var("WINDISSECT_DISCORD_CLIENT_ID")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let file_id = file
            .get("discord_client_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        Self {
            from_env: env_id.is_some(),
            client_id: env_id
                .or(file_id)
                .or_else(|| Some(DEFAULT_CLIENT_ID.to_string())),
            presence: file
                .get("discord_presence")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            show_names: file
                .get("discord_show_names")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }
    }

    pub fn save(&self) {
        let Some(path) = settings_path() else {
            return;
        };
        let mut file = read_settings_json();
        if let Some(map) = file.as_object_mut() {
            map.insert("discord_presence".into(), json!(self.presence));
            map.insert("discord_show_names".into(), json!(self.show_names));
            // The built-in ID is the default, not a choice: never written out.
            if let Some(id) = self
                .client_id
                .as_ref()
                .filter(|id| !self.from_env && id.as_str() != DEFAULT_CLIENT_ID)
            {
                map.insert("discord_client_id".into(), json!(id));
            }
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(&file) {
            let _ = std::fs::write(path, text);
        }
    }

    pub fn path_display() -> String {
        settings_path().map_or_else(
            || {
                if cfg!(windows) {
                    r"%APPDATA%\Windissect\settings.json".into()
                } else {
                    "~/.config/Windissect/settings.json".into()
                }
            },
            |p| p.display().to_string(),
        )
    }
}

// ---- activity ------------------------------------------------------------------

#[derive(Clone, PartialEq, Debug)]
pub struct Activity {
    pub details: String,
    pub state: String,
    /// Unix seconds: Discord shows "elapsed" from here.
    pub start: Option<u64>,
    /// An asset key in the Discord application, e.g. "types"; harmless when missing.
    pub small_image: Option<String>,
    pub small_text: Option<String>,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Discord rejects fields over 128 characters, and those under 2.
fn fit(text: &str) -> String {
    let mut out: String = text.chars().take(MAX_TEXT).collect();
    if text.chars().count() > MAX_TEXT {
        out.pop();
        out.push('\u{2026}');
    }
    while out.chars().count() < 2 {
        out.push(' ');
    }
    out
}

fn activity_json(activity: &Activity) -> Value {
    let mut assets = json!({ "large_image": LARGE_IMAGE, "large_text": "Windissect" });
    if let Some(key) = &activity.small_image {
        assets["small_image"] = json!(key);
        if let Some(text) = &activity.small_text {
            assets["small_text"] = json!(fit(text));
        }
    }
    let mut value = json!({
        "details": fit(&activity.details),
        "state": fit(&activity.state),
        "assets": assets,
        "buttons": [
            { "label": "Get Windissect", "url": PROJECT_URL },
            { "label": "Website", "url": WEBSITE_URL }
        ],
    });
    if let Some(start) = activity.start {
        value["timestamps"] = json!({ "start": start });
    }
    value
}

// ---- the connection ------------------------------------------------------------

fn write_frame(mut pipe: impl Write, opcode: u32, payload: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(payload)?;
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&opcode.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    pipe.write_all(&frame)?;
    pipe.flush()
}

fn read_frame(mut pipe: impl Read) -> std::io::Result<(u32, Value)> {
    let mut header = [0u8; 8];
    pipe.read_exact(&mut header)?;
    let opcode = u32::from_le_bytes(header[..4].try_into().expect("four-byte opcode"));
    let len = u32::from_le_bytes(header[4..].try_into().expect("four-byte length")) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Discord IPC frame is {len} bytes (limit {MAX_FRAME})"),
        ));
    }
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)?;
    let payload = serde_json::from_slice(&body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok((opcode, payload))
}

fn connect(client_id: &str) -> Option<File> {
    for n in 0..10 {
        let path = format!(r"\\.\pipe\discord-ipc-{n}");
        let Ok(mut pipe) = OpenOptions::new().read(true).write(true).open(&path) else {
            continue;
        };
        if write_frame(
            &mut pipe,
            OP_HANDSHAKE,
            &json!({ "v": 1, "client_id": client_id }),
        )
        .is_err()
        {
            continue;
        }
        let Ok((opcode, ready)) = read_frame(&mut pipe) else {
            continue;
        };
        if opcode != OP_FRAME || ready.get("evt").and_then(Value::as_str) != Some("READY") {
            continue;
        }
        return Some(pipe);
    }
    None
}

fn activity_acknowledged(reply: &Value, nonce: &str) -> bool {
    reply.get("cmd").and_then(Value::as_str) == Some("SET_ACTIVITY")
        && reply.get("nonce").and_then(Value::as_str) == Some(nonce)
        && reply.get("evt").is_none_or(Value::is_null)
}

enum Message {
    Set(Option<Activity>),
    Stop,
}

/// Owns the worker thread; dropping it clears the card and disconnects.
pub struct Presence {
    tx: Sender<Message>,
}

impl Presence {
    pub fn start(client_id: String) -> Self {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("discord-presence".into())
            .spawn(move || worker(client_id, rx))
            .ok();
        Self { tx }
    }

    /// The latest activity wins; `None` clears the card.
    pub fn set(&self, activity: Option<Activity>) {
        let _ = self.tx.send(Message::Set(activity));
    }
}

impl Drop for Presence {
    fn drop(&mut self) {
        let _ = self.tx.send(Message::Stop);
    }
}

fn worker(client_id: String, rx: Receiver<Message>) {
    let pid = std::process::id();
    let mut pipe: Option<File> = None;
    let mut last_attempt: Option<Instant> = None;
    let mut last_sent: Option<Instant> = None;
    let mut sent: Option<Option<Activity>> = None;
    let mut wanted: Option<Activity> = None;
    let mut nonce: u64 = 0;
    let mut stopping = false;
    loop {
        // Wake for the next message, or when a held-back update may go out.
        let wait = match (last_sent, sent.as_ref() != Some(&wanted)) {
            (Some(at), true) => MIN_INTERVAL
                .saturating_sub(at.elapsed())
                .max(Duration::from_millis(50)),
            (None, true) => Duration::from_millis(50),
            _ => Duration::from_secs(30),
        };
        match rx.recv_timeout(wait) {
            Ok(Message::Set(activity)) => wanted = activity,
            Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => {
                wanted = None;
                stopping = true;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        // Coalesce: keep only the newest of whatever is queued.
        while let Ok(message) = rx.try_recv() {
            match message {
                Message::Set(activity) => wanted = activity,
                Message::Stop => {
                    wanted = None;
                    stopping = true;
                }
            }
        }

        if sent.as_ref() != Some(&wanted) {
            let due = stopping || last_sent.is_none_or(|at| at.elapsed() >= MIN_INTERVAL);
            if pipe.is_none() && last_attempt.is_none_or(|at| at.elapsed() >= RECONNECT_EVERY) {
                last_attempt = Some(Instant::now());
                pipe = connect(&client_id);
                if pipe.is_some() {
                    sent = None; // a new connection starts with an empty card
                }
            }
            if let (true, Some(conn)) = (due, pipe.as_mut()) {
                {
                    nonce += 1;
                    let activity = wanted.as_ref().map_or(Value::Null, activity_json);
                    let request_nonce = format!("windissect-{pid}-{nonce}");
                    let command = json!({
                        "cmd": "SET_ACTIVITY",
                        "args": { "pid": pid, "activity": activity },
                        "nonce": request_nonce,
                    });
                    let acknowledged = write_frame(&mut *conn, OP_FRAME, &command)
                        .and_then(|()| read_frame(&mut *conn))
                        .is_ok_and(|(opcode, reply)| {
                            opcode == OP_FRAME && activity_acknowledged(&reply, &request_nonce)
                        });
                    if acknowledged {
                        sent = Some(wanted.clone());
                        last_sent = Some(Instant::now());
                    } else {
                        pipe = None; // rejected or disconnected; handshake again
                        last_attempt = None;
                    }
                }
            }
        }
        if stopping {
            return; // dropping the pipe ends the session; Discord clears the card
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_fit_discord_limits() {
        assert_eq!(fit("a").chars().count(), 2);
        let long = "x".repeat(300);
        let out = fit(&long);
        assert_eq!(out.chars().count(), MAX_TEXT);
        assert!(out.ends_with('\u{2026}'));
    }

    #[test]
    fn activity_carries_assets_and_timestamp() {
        let value = activity_json(&Activity {
            details: "Inspecting bootux.dll".into(),
            state: "Types \u{203a} BUXButtonCollection".into(),
            start: Some(1_700_000_000),
            small_image: Some("types".into()),
            small_text: Some("Types".into()),
        });
        assert_eq!(value["assets"]["large_image"], LARGE_IMAGE);
        assert_eq!(value["assets"]["small_image"], "types");
        assert_eq!(value["timestamps"]["start"], 1_700_000_000);
        assert_eq!(value["state"], "Types \u{203a} BUXButtonCollection");
        assert_eq!(value["buttons"][0]["url"], PROJECT_URL);
        assert_eq!(value["buttons"][1]["url"], WEBSITE_URL);
    }

    #[test]
    fn ipc_frame_round_trips_without_losing_alignment() {
        let payload = json!({ "evt": "READY", "data": { "v": 1 } });
        let mut bytes = Vec::new();
        write_frame(&mut bytes, OP_FRAME, &payload).unwrap();
        let (opcode, decoded) = read_frame(bytes.as_slice()).unwrap();
        assert_eq!(opcode, OP_FRAME);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn activity_cache_requires_the_matching_discord_ack() {
        let reply = json!({
            "cmd": "SET_ACTIVITY",
            "data": { "details": "Inspecting dxgi.dll" },
            "evt": null,
            "nonce": "windissect-42-2"
        });
        assert!(activity_acknowledged(&reply, "windissect-42-2"));
        assert!(!activity_acknowledged(&reply, "windissect-42-1"));

        let rejected = json!({
            "cmd": "SET_ACTIVITY",
            "evt": "ERROR",
            "nonce": "windissect-42-2"
        });
        assert!(!activity_acknowledged(&rejected, "windissect-42-2"));
    }
}
