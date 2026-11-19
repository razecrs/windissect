//! Zero-copy JavaScript lexer and Electron loader / API / IPC analyzer.
//!
//! Designed to stay fast and dependency-free across both small hand-written
//! loader scripts (`index.js`, preload scripts) and multi-megabyte minified
//! Webpack / esbuild / Vite / Rspack Electron bundles.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Line ending style observed verbatim in a loader or entry script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LineEnding {
    Lf,
    Crlf,
    Mixed,
    None,
}

/// High-level structural classification of an Electron loader or entry script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoaderKind {
    AsarPassthrough,
    AsarWrapper,
    ElectronEntrypoint,
    NativeModuleWrapper,
    BundledEntrypoint,
    Script,
}

/// Structural features extracted from a loader or entry script without losing
/// its exact byte shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderShape {
    pub kind: Option<LoaderKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports_form: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asar_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_addons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leading_comments: Vec<String>,
    #[serde(default)]
    pub module_load_hook: bool,
    #[serde(default)]
    pub electron_proxy: bool,
    #[serde(default)]
    pub browser_window_intercept: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_events: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web_contents_hooks: Vec<String>,
}

/// Exact byte-formatting metadata of a loader or entry script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderFormatting {
    pub valid_utf8: bool,
    pub has_utf8_bom: bool,
    pub line_ending: LineEnding,
    pub trailing_newline: bool,
}

/// Complete exact-shape record for a loader (`index.js`) or entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectronLoaderRecord {
    pub path: String,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_main: Option<String>,
    pub sha256: String,
    pub byte_len: u64,
    pub line_count: usize,
    pub formatting: LoaderFormatting,
    pub is_minified_bundle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_preview: Option<String>,
    pub shape: LoaderShape,
}

/// Process context hint inferred from script path and Electron API usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptRole {
    Loader,
    Main,
    Preload,
    Renderer,
    Module,
    Unknown,
}

/// Provenance of an observed Electron API call or reference inside a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiProvenance {
    Binding,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiHit {
    pub namespace: String,
    pub member: Option<String>,
    pub provenance: ApiProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcHit {
    pub channel: String,
    pub direction: String,
    pub resolution: String,
    pub symbol_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicIpcHit {
    pub operation: String,
    pub expression: String,
}

/// Per-script static extraction output before whole-app aggregation.
#[derive(Debug, Clone, Default)]
pub struct ScriptFindings {
    pub role: Option<ScriptRole>,
    pub api_hits: Vec<ApiHit>,
    pub ipc_hits: Vec<IpcHit>,
    pub dynamic_ipc: Vec<DynamicIpcHit>,
    pub context_bridges: Vec<String>,
    pub requires: Vec<String>,
}

// ---------------------------------------------------------------------------
// Electron API vocabulary
// ---------------------------------------------------------------------------

const ELECTRON_APIS_UNAMBIGUOUS: &[&str] = &[
    "ipcMain",
    "ipcRenderer",
    "contextBridge",
    "BrowserWindow",
    "BrowserView",
    "WebContentsView",
    "BaseWindow",
    "webContents",
    "desktopCapturer",
    "powerMonitor",
    "powerSaveBlocker",
    "safeStorage",
    "systemPreferences",
    "globalShortcut",
    "nativeTheme",
    "nativeImage",
    "autoUpdater",
    "crashReporter",
    "webFrame",
    "webFrameMain",
    "contentTracing",
    "inAppPurchase",
    "utilityProcess",
    "MessageChannelMain",
    "TouchBar",
    "webUtils",
];

const ELECTRON_EXPORTS_ALL: &[&str] = &[
    "app",
    "autoUpdater",
    "BaseWindow",
    "BrowserView",
    "BrowserWindow",
    "clipboard",
    "contentTracing",
    "contextBridge",
    "crashReporter",
    "desktopCapturer",
    "dialog",
    "globalShortcut",
    "inAppPurchase",
    "ipcMain",
    "ipcRenderer",
    "Menu",
    "MenuItem",
    "MessageChannelMain",
    "nativeImage",
    "nativeTheme",
    "net",
    "netLog",
    "Notification",
    "powerMonitor",
    "powerSaveBlocker",
    "protocol",
    "pushNotifications",
    "safeStorage",
    "screen",
    "session",
    "shareMenu",
    "shell",
    "systemPreferences",
    "TouchBar",
    "Tray",
    "utilityProcess",
    "webContents",
    "webFrame",
    "webFrameMain",
    "webUtils",
];

fn is_known_electron_export(name: &str) -> bool {
    ELECTRON_EXPORTS_ALL.contains(&name)
}

fn is_unambiguous_electron_api(name: &str) -> bool {
    ELECTRON_APIS_UNAMBIGUOUS.contains(&name)
}

/// Unambiguous Electron-specific `api.member` combinations when `api` itself is a
/// generic word like `app`, `session`, `shell`, or `dialog`.
fn is_unambiguous_qualified_call(ns: &str, member: Option<&str>) -> bool {
    match (ns, member) {
        (
            "app",
            Some(
                "whenReady"
                | "getPath"
                | "setPath"
                | "getAppPath"
                | "isPackaged"
                | "requestSingleInstanceLock"
                | "setAppUserModelId"
                | "getReleaseChannel"
                | "quit"
                | "relaunch"
                | "accessibilitySupportEnabled",
            ),
        )
        | ("session", Some("defaultSession" | "fromPartition" | "fromPath"))
        | ("shell", Some("openExternal" | "openPath" | "showItemInFolder" | "trashItem"))
        | (
            "dialog",
            Some(
                "showOpenDialog" | "showOpenDialogSync" | "showSaveDialog" | "showSaveDialogSync"
                | "showMessageBox" | "showMessageBoxSync" | "showErrorBox",
            ),
        )
        | (
            "protocol",
            Some(
                "handle"
                | "registerSchemesAsPrivileged"
                | "registerFileProtocol"
                | "registerHttpProtocol",
            ),
        )
        | ("Menu", Some("buildFromTemplate" | "setApplicationMenu" | "getApplicationMenu"))
        | (
            "clipboard",
            Some("readText" | "writeText" | "readImage" | "writeImage" | "availableFormats"),
        ) => true,
        _ => is_unambiguous_electron_api(ns),
    }
}

fn ipc_direction(receiver_kind: &str, method: &str) -> Option<(&'static str, usize)> {
    match (receiver_kind, method) {
        ("ipcMain", "on" | "addListener") => Some(("main-on", 0)),
        ("ipcMain", "once") => Some(("main-once", 0)),
        ("ipcMain", "handle") => Some(("main-handle", 0)),
        ("ipcMain", "handleOnce") => Some(("main-handle-once", 0)),
        ("ipcMain", "removeHandler" | "removeListener" | "removeAllListeners" | "off") => {
            Some(("main-remove", 0))
        }
        ("ipcRenderer", "on" | "addListener") => Some(("renderer-on", 0)),
        ("ipcRenderer", "once") => Some(("renderer-once", 0)),
        ("ipcRenderer", "removeListener" | "removeAllListeners" | "off") => {
            Some(("renderer-remove", 0))
        }
        ("ipcRenderer", "send") => Some(("renderer-send", 0)),
        ("ipcRenderer", "sendSync") => Some(("renderer-send-sync", 0)),
        ("ipcRenderer", "invoke") => Some(("renderer-invoke", 0)),
        ("ipcRenderer", "postMessage") => Some(("renderer-post-message", 0)),
        ("ipcRenderer", "sendToHost") => Some(("renderer-send-to-host", 0)),
        ("ipcRenderer", "sendTo") => Some(("renderer-send-to", 1)),
        ("webContents", "send") => Some(("main-to-renderer", 0)),
        ("webContents", "postMessage") => Some(("main-post-message", 0)),
        ("webContents", "sendToFrame") => Some(("main-to-frame", 1)),
        ("facade", "on" | "addListener") => Some(("wrapper-on", 0)),
        ("facade", "once") => Some(("wrapper-once", 0)),
        ("facade", "handle") => Some(("wrapper-handle", 0)),
        ("facade", "handleOnce") => Some(("wrapper-handle-once", 0)),
        ("facade", "invoke") => Some(("wrapper-invoke", 0)),
        ("facade", "send") => Some(("wrapper-send", 0)),
        ("facade", "sendSync") => Some(("wrapper-send-sync", 0)),
        ("facade", "removeHandler" | "removeListener" | "off") => Some(("wrapper-remove", 0)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Zero-copy JS tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Ident,
    Number,
    Str,
    SimpleTemplate,
    TemplateChunk,
    Regex,
    Dot,
    OptDot,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Colon,
    Eq,
    Arrow,
    Other,
}

#[derive(Debug, Clone, Copy)]
struct Tok {
    kind: TokKind,
    start: usize,
    end: usize,
}

impl Tok {
    fn text(self, src: &str) -> &str {
        &src[self.start..self.end]
    }
}

fn tokenize(src: &str) -> Vec<Tok> {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut out = Vec::with_capacity((len / 6).max(16));
    // Track brace depths inside `${ ... }` template expressions so nested
    // braces distinguish an ordinary `}` from resuming the enclosing template.
    let mut template_braces: Vec<u32> = Vec::new();

    if bytes.starts_with(b"#!") {
        while i < len && bytes[i] != b'\n' {
            i += 1;
        }
    }

    while i < len {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'/'
            && i + 1 < len
            && let Some((tok, next)) = scan_slash(bytes, i, src, &out)
        {
            if let Some(t) = tok {
                out.push(t);
            }
            i = next;
            continue;
        }
        if b == b'\'' || b == b'"' {
            let start = i;
            i = scan_quoted(bytes, i + 1, b);
            out.push(Tok {
                kind: TokKind::Str,
                start,
                end: i,
            });
            continue;
        }
        if b == b'`' || (b == b'}' && template_braces.last() == Some(&0)) {
            if b == b'}' {
                template_braces.pop();
            }
            let start = i;
            let (end, interpolated) = scan_template_segment(bytes, i + 1);
            i = end;
            let kind = if interpolated {
                template_braces.push(0);
                TokKind::TemplateChunk
            } else if b == b'`' {
                TokKind::SimpleTemplate
            } else {
                TokKind::TemplateChunk
            };
            out.push(Tok { kind, start, end });
            continue;
        }
        if b == b'}'
            && let Some(depth) = template_braces.last_mut()
        {
            *depth -= 1;
        }
        if b == b'{'
            && let Some(depth) = template_braces.last_mut()
        {
            *depth += 1;
        }
        if b.is_ascii_digit() || (b == b'.' && i + 1 < len && bytes[i + 1].is_ascii_digit()) {
            let start = i;
            i = scan_number(bytes, i);
            out.push(Tok {
                kind: TokKind::Number,
                start,
                end: i,
            });
            continue;
        }
        if is_ident_start(bytes, i) {
            let start = i;
            i = scan_ident(bytes, i);
            out.push(Tok {
                kind: TokKind::Ident,
                start,
                end: i,
            });
            continue;
        }
        let (kind, next) = scan_punct(bytes, i, b);
        out.push(Tok {
            kind,
            start: i,
            end: next,
        });
        i = next;
    }
    out
}

fn scan_slash(bytes: &[u8], i: usize, src: &str, out: &[Tok]) -> Option<(Option<Tok>, usize)> {
    let len = bytes.len();
    if bytes[i + 1] == b'/' {
        let mut cursor = i + 2;
        while cursor < len && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        return Some((None, cursor));
    }
    if bytes[i + 1] == b'*' {
        let mut cursor = i + 2;
        while cursor + 1 < len && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/') {
            cursor += 1;
        }
        return Some((None, (cursor + 2).min(len)));
    }
    if !prev_allows_regex(out.last().copied(), src) {
        return None;
    }
    let mut cursor = i + 1;
    let mut in_class = false;
    while cursor < len {
        let c = bytes[cursor];
        if c == b'\\' && cursor + 1 < len {
            cursor += 2;
            continue;
        }
        if c == b'\n' || c == b'\r' {
            break;
        }
        if c == b'[' {
            in_class = true;
        } else if c == b']' {
            in_class = false;
        } else if c == b'/' && !in_class {
            cursor += 1;
            while cursor < len && bytes[cursor].is_ascii_alphabetic() {
                cursor += 1;
            }
            break;
        }
        cursor += 1;
    }
    Some((
        Some(Tok {
            kind: TokKind::Regex,
            start: i,
            end: cursor,
        }),
        cursor,
    ))
}

const fn scan_punct(bytes: &[u8], mut i: usize, b: u8) -> (TokKind, usize) {
    let len = bytes.len();
    let kind = match b {
        b'.' => {
            i += 1;
            if i + 1 < len && bytes[i] == b'.' && bytes[i + 1] == b'.' {
                i += 2;
                TokKind::Other
            } else {
                TokKind::Dot
            }
        }
        b'?' => {
            if i + 1 < len
                && bytes[i + 1] == b'.'
                && !(i + 2 < len && bytes[i + 2].is_ascii_digit())
            {
                i += 2;
                TokKind::OptDot
            } else {
                i += 1;
                TokKind::Other
            }
        }
        b'(' => {
            i += 1;
            TokKind::LParen
        }
        b')' => {
            i += 1;
            TokKind::RParen
        }
        b'{' => {
            i += 1;
            TokKind::LBrace
        }
        b'}' => {
            i += 1;
            TokKind::RBrace
        }
        b'[' => {
            i += 1;
            TokKind::LBracket
        }
        b']' => {
            i += 1;
            TokKind::RBracket
        }
        b',' => {
            i += 1;
            TokKind::Comma
        }
        b';' => {
            i += 1;
            TokKind::Semi
        }
        b':' => {
            i += 1;
            TokKind::Colon
        }
        b'=' => {
            i += 1;
            if i < len && bytes[i] == b'>' {
                i += 1;
                TokKind::Arrow
            } else if i < len && bytes[i] == b'=' {
                i += 1;
                if i < len && bytes[i] == b'=' {
                    i += 1;
                }
                TokKind::Other
            } else {
                TokKind::Eq
            }
        }
        b'!' => {
            i += 1;
            if i < len && bytes[i] == b'=' {
                i += 1;
                if i < len && bytes[i] == b'=' {
                    i += 1;
                }
            }
            TokKind::Other
        }
        b'+' | b'-' => {
            i += 1;
            if i < len && (bytes[i] == b || bytes[i] == b'=') {
                i += 1;
            }
            TokKind::Other
        }
        _ => {
            // Step full UTF-8 char on unexpected non-ASCII symbol so `start..end` stays valid UTF-8.
            i += utf8_char_len(bytes, i);
            TokKind::Other
        }
    };
    (kind, i)
}

fn prev_allows_regex(prev: Option<Tok>, src: &str) -> bool {
    let Some(tok) = prev else {
        return true;
    };
    match tok.kind {
        TokKind::Ident => matches!(
            tok.text(src),
            "return"
                | "throw"
                | "case"
                | "typeof"
                | "void"
                | "delete"
                | "await"
                | "yield"
                | "in"
                | "instanceof"
                | "new"
                | "else"
                | "do"
                | "of"
        ),
        TokKind::Number
        | TokKind::Str
        | TokKind::SimpleTemplate
        | TokKind::TemplateChunk
        | TokKind::Regex
        | TokKind::RParen
        | TokKind::RBracket => false,
        TokKind::Other => !matches!(tok.text(src), "++" | "--"),
        _ => true,
    }
}

const fn scan_quoted(bytes: &[u8], mut i: usize, quote: u8) -> usize {
    let len = bytes.len();
    while i < len {
        let b = bytes[i];
        if b == b'\\' && i + 1 < len {
            i += 1 + utf8_char_len(bytes, i + 1);
            continue;
        }
        if b == quote {
            return i + 1;
        }
        i += 1;
    }
    len
}

const fn scan_template_segment(bytes: &[u8], mut i: usize) -> (usize, bool) {
    let len = bytes.len();
    while i < len {
        let b = bytes[i];
        if b == b'\\' && i + 1 < len {
            i += 1 + utf8_char_len(bytes, i + 1);
            continue;
        }
        if b == b'`' {
            return (i + 1, false);
        }
        if b == b'$' && i + 1 < len && bytes[i + 1] == b'{' {
            return (i + 2, true);
        }
        i += 1;
    }
    (len, false)
}

const fn scan_number(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len {
        let b = bytes[i];
        if b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b'.'
            || ((b == b'+' || b == b'-') && i > 0 && matches!(bytes[i - 1], b'e' | b'E'))
        {
            i += 1;
        } else {
            break;
        }
    }
    i
}

const fn is_ident_start(bytes: &[u8], i: usize) -> bool {
    let b = bytes[i];
    b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80
}

const fn is_ident_continue(bytes: &[u8], i: usize) -> bool {
    let b = bytes[i];
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

const fn scan_ident(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len && is_ident_continue(bytes, i) {
        i += utf8_char_len(bytes, i);
    }
    i
}

const fn utf8_char_len(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    if b < 0x80 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

/// Decode a JS string literal (`"..."`, `'...'`, or interpolation-free `` `...` ``).
fn unescape_js_str(raw: &str) -> String {
    if raw.len() < 2 {
        return String::new();
    }
    let inner = &raw[1..raw.len() - 1];
    if !inner.contains('\\') {
        return inner.to_string();
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            None => break,
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('x') => {
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(a), Some(b)) = (h1, h2)
                    && let Ok(code) = u8::from_str_radix(&format!("{a}{b}"), 16)
                {
                    out.push(char::from(code));
                }
            }
            Some('u') => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut hex = String::new();
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            break;
                        }
                        hex.push(ch);
                    }
                    if let Ok(cp) = u32::from_str_radix(&hex, 16)
                        && let Some(decoded) = char::from_u32(cp)
                    {
                        out.push(decoded);
                    }
                } else {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        if let Some(ch) = chars.next() {
                            hex.push(ch);
                        }
                    }
                    if let Ok(cp) = u32::from_str_radix(&hex, 16)
                        && let Some(decoded) = char::from_u32(cp)
                    {
                        out.push(decoded);
                    }
                }
            }
            Some('\n') => {}
            Some('\r') => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            Some(other) => out.push(other),
        }
    }
    out
}

fn tok_str(tok: Tok, src: &str) -> Option<String> {
    matches!(tok.kind, TokKind::Str | TokKind::SimpleTemplate)
        .then(|| unescape_js_str(tok.text(src)))
}

// ---------------------------------------------------------------------------
// Loader exact original shape extraction
// ---------------------------------------------------------------------------

/// Metadata bundle identifying a loader or script file on disk or inside ASAR.
pub struct LoaderInput<'a> {
    pub path: &'a str,
    pub location: &'a str,
    pub archive: Option<&'a str>,
    pub role: &'a str,
    pub package_name: Option<&'a str>,
    pub package_main: Option<&'a str>,
}

/// Inspect exact byte formatting and structural JS shape of a loader / entry script.
#[must_use]
pub fn inspect_loader(input: &LoaderInput<'_>, bytes: &[u8]) -> ElectronLoaderRecord {
    let sha256 = crate::hex::lower(&Sha256::digest(bytes));
    let has_utf8_bom = bytes.starts_with(b"\xEF\xBB\xBF");
    let line_ending = detect_line_ending(bytes);
    let trailing_newline = bytes.ends_with(b"\n") || bytes.ends_with(b"\r");
    let line_count = count_lines(bytes);
    let utf8 = std::str::from_utf8(bytes).ok();

    let avg_line_len = bytes.len().checked_div(line_count).unwrap_or(bytes.len());
    let is_minified_bundle = bytes.len() > 64 * 1024 && avg_line_len > 400;

    let shape = utf8.map_or_else(LoaderShape::default, analyze_loader_shape);

    let keep_full_text =
        !is_minified_bundle && (input.location == "filesystem" || bytes.len() <= 131_072);
    let (exact_text, exact_hex, head_preview) = match (utf8, keep_full_text) {
        (Some(text), true) => (Some(text.to_string()), None, None),
        (Some(text), false) => {
            let preview: String = text.chars().take(240).collect();
            (None, None, Some(preview))
        }
        (None, true) => (None, Some(crate::hex::lower(bytes)), None),
        (None, false) => (
            None,
            None,
            Some(crate::hex::lower(&bytes[..bytes.len().min(120)])),
        ),
    };

    ElectronLoaderRecord {
        path: input.path.to_string(),
        location: input.location.to_string(),
        archive: input.archive.map(str::to_string),
        role: input.role.to_string(),
        package_name: input.package_name.map(str::to_string),
        package_main: input.package_main.map(str::to_string),
        sha256,
        byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        line_count,
        formatting: LoaderFormatting {
            valid_utf8: utf8.is_some(),
            has_utf8_bom,
            line_ending,
            trailing_newline,
        },
        is_minified_bundle,
        exact_text,
        exact_hex,
        head_preview,
        shape,
    }
}

fn detect_line_ending(bytes: &[u8]) -> LineEnding {
    let mut has_crlf = false;
    let mut has_lf = false;
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if idx > 0 && bytes[idx - 1] == b'\r' {
                has_crlf = true;
            } else {
                has_lf = true;
            }
        }
    }
    match (has_crlf, has_lf) {
        (false, false) => LineEnding::None,
        (true, false) => LineEnding::Crlf,
        (false, true) => LineEnding::Lf,
        (true, true) => LineEnding::Mixed,
    }
}

fn count_lines(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let mut newlines = 0usize;
    for &byte in bytes {
        if byte == b'\n' {
            newlines += 1;
        }
    }
    if bytes.ends_with(b"\n") {
        newlines
    } else {
        newlines + 1
    }
}

fn analyze_loader_shape(src: &str) -> LoaderShape {
    let leading_comments = extract_leading_comments(src);
    let tokens = tokenize(src);
    let requires = collect_requires(&tokens, src);
    let asar_targets: Vec<String> = requires
        .iter()
        .filter(|spec| spec.to_ascii_lowercase().ends_with(".asar"))
        .cloned()
        .collect();
    let native_addons: Vec<String> = requires
        .iter()
        .filter(|spec| spec.to_ascii_lowercase().ends_with(".node"))
        .cloned()
        .collect();

    let exports_form = extract_exports_form(&tokens, src);
    let module_load_hook = has_module_load_hook(&tokens, src);
    let electron_proxy = has_proxy_hook(&tokens, src, false);
    let browser_window_intercept = has_proxy_hook(&tokens, src, true);
    let app_events = collect_method_string_args(&tokens, src, "app", &["on", "once"]);
    let web_contents_hooks = collect_web_contents_hooks(&tokens, src);

    let pure_passthrough = !asar_targets.is_empty()
        && is_pure_asar_passthrough(&tokens, src)
        && !module_load_hook
        && !electron_proxy
        && !browser_window_intercept;

    let line_count = count_lines(src.as_bytes());
    let avg_line_len = src.len().checked_div(line_count).unwrap_or(src.len());
    let is_bundled = src.len() > 64 * 1024 && avg_line_len > 400;

    let kind = if is_bundled {
        Some(LoaderKind::BundledEntrypoint)
    } else if pure_passthrough {
        Some(LoaderKind::AsarPassthrough)
    } else if !asar_targets.is_empty() {
        Some(LoaderKind::AsarWrapper)
    } else if !native_addons.is_empty()
        && !requires
            .iter()
            .any(|r| r == "electron" || r.starts_with("electron/"))
    {
        Some(LoaderKind::NativeModuleWrapper)
    } else if requires
        .iter()
        .any(|r| r == "electron" || r.starts_with("electron/"))
    {
        Some(LoaderKind::ElectronEntrypoint)
    } else {
        Some(LoaderKind::Script)
    };

    LoaderShape {
        kind,
        exports_form,
        asar_targets,
        native_addons,
        requires,
        leading_comments,
        module_load_hook,
        electron_proxy,
        browser_window_intercept,
        app_events,
        web_contents_hooks,
    }
}

fn extract_leading_comments(src: &str) -> Vec<String> {
    let trimmed = src.trim_start_matches('\u{FEFF}');
    let mut out = Vec::new();
    let mut rest = trimmed;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            let end = after.find('\n').unwrap_or(after.len());
            out.push(format!("//{}", after[..end].trim_end_matches('\r')));
            rest = &after[end..];
        } else if let Some(after) = rest.strip_prefix("/*") {
            let end = after.find("*/").unwrap_or(after.len());
            let snippet = after[..end].trim();
            if !snippet.is_empty() {
                out.push(format!("/* {snippet} */"));
            }
            rest = if end + 2 <= after.len() {
                &after[end + 2..]
            } else {
                ""
            };
        } else {
            break;
        }
        if out.len() >= 12 {
            break;
        }
    }
    out
}

fn extract_exports_form(tokens: &[Tok], src: &str) -> Option<String> {
    let mut last: Option<String> = None;
    for i in 0..tokens.len() {
        // `module.exports = ...`
        if i + 4 < tokens.len()
            && tokens[i].text(src) == "module"
            && tokens[i + 1].kind == TokKind::Dot
            && tokens[i + 2].text(src) == "exports"
            && tokens[i + 3].kind == TokKind::Eq
        {
            if let Some(snippet) = slice_statement_expr(tokens, i, i + 4, src) {
                last = Some(snippet);
            }
        } else if i + 2 < tokens.len()
            && tokens[i].text(src) == "export"
            && tokens[i + 1].text(src) == "default"
            && let Some(snippet) = slice_statement_expr(tokens, i, i + 2, src)
        {
            last = Some(snippet);
        }
    }
    last
}

fn slice_statement_expr(
    tokens: &[Tok],
    stmt_start: usize,
    rhs_start: usize,
    src: &str,
) -> Option<String> {
    let mut depth = 0usize;
    let mut end_tok = tokens.len() - 1;
    for (idx, tok) in tokens.iter().enumerate().skip(rhs_start) {
        match tok.kind {
            TokKind::LParen | TokKind::LBrace | TokKind::LBracket => depth += 1,
            TokKind::RParen | TokKind::RBrace | TokKind::RBracket => {
                depth = depth.saturating_sub(1);
            }
            TokKind::Semi if depth == 0 => {
                end_tok = idx.saturating_sub(1);
                break;
            }
            _ => {}
        }
        if idx - stmt_start > 48 {
            return None;
        }
    }
    if end_tok < rhs_start {
        return None;
    }
    let slice = src[tokens[stmt_start].start..tokens[end_tok].end].trim();
    (slice.len() <= 240 && !slice.contains('\n')).then(|| slice.to_string())
}

fn is_pure_asar_passthrough(tokens: &[Tok], src: &str) -> bool {
    let mut i = 0usize;
    if tokens.first().and_then(|t| tok_str(*t, src)).as_deref() == Some("use strict") {
        i = 1;
        if tokens.get(i).is_some_and(|t| t.kind == TokKind::Semi) {
            i += 1;
        }
    }
    // Expect `module.exports = require("...asar")[;]`
    let remaining = &tokens[i..];
    let core_len = if remaining.last().is_some_and(|t| t.kind == TokKind::Semi) {
        remaining.len() - 1
    } else {
        remaining.len()
    };
    if core_len != 8 {
        return false;
    }
    remaining[0].text(src) == "module"
        && remaining[1].kind == TokKind::Dot
        && remaining[2].text(src) == "exports"
        && remaining[3].kind == TokKind::Eq
        && remaining[4].text(src) == "require"
        && remaining[5].kind == TokKind::LParen
        && tok_str(remaining[6], src).is_some_and(|s| s.to_ascii_lowercase().ends_with(".asar"))
        && remaining[7].kind == TokKind::RParen
}

fn has_module_load_hook(tokens: &[Tok], src: &str) -> bool {
    tokens.windows(4).any(|w| {
        (w[1].kind == TokKind::Dot || w[1].kind == TokKind::OptDot)
            && w[2].text(src) == "_load"
            && w[3].kind == TokKind::Eq
    }) || tokens.windows(6).any(|w| {
        w[0].text(src) == "Module"
            && w[1].kind == TokKind::Dot
            && w[2].text(src) == "prototype"
            && w[3].kind == TokKind::Dot
            && w[4].text(src) == "require"
            && w[5].kind == TokKind::Eq
    })
}

fn has_proxy_hook(tokens: &[Tok], src: &str, bw_only: bool) -> bool {
    for i in 0..tokens.len() {
        if tokens[i].kind == TokKind::Ident
            && tokens[i].text(src) == "Proxy"
            && tokens.get(i + 1).is_some_and(|t| t.kind == TokKind::LParen)
        {
            let target_window = &tokens[i + 2..(i + 8).min(tokens.len())];
            let has_bw = target_window.iter().any(|t| t.text(src) == "BrowserWindow");
            let has_electron = target_window.iter().any(|t| t.text(src) == "electron");
            if bw_only && has_bw {
                return true;
            }
            if !bw_only && (has_electron || has_bw) {
                return true;
            }
        }
    }
    false
}

fn collect_method_string_args(
    tokens: &[Tok],
    src: &str,
    receiver: &str,
    methods: &[&str],
) -> Vec<String> {
    let mut found = BTreeSet::new();
    for i in 0..tokens.len() {
        if tokens[i].text(src) == receiver
            && tokens
                .get(i + 1)
                .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot))
            && let Some(method_tok) = tokens.get(i + 2)
            && methods.contains(&method_tok.text(src))
            && tokens.get(i + 3).is_some_and(|t| t.kind == TokKind::LParen)
            && let Some(arg_tok) = tokens.get(i + 4)
            && let Some(s) = tok_str(*arg_tok, src)
        {
            found.insert(s);
        }
    }
    found.into_iter().collect()
}

fn collect_web_contents_hooks(tokens: &[Tok], src: &str) -> Vec<String> {
    let mut found: BTreeSet<String> =
        collect_method_string_args(tokens, src, "webContents", &["on", "once"])
            .into_iter()
            .collect();
    for i in 0..tokens.len() {
        if tokens[i].text(src) == "webContents"
            && tokens
                .get(i + 1)
                .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot))
            && let Some(method_tok) = tokens.get(i + 2)
            && matches!(
                method_tok.text(src),
                "insertCSS" | "executeJavaScript" | "setWindowOpenHandler"
            )
        {
            found.insert(method_tok.text(src).to_string());
        }
    }
    found.into_iter().collect()
}

fn collect_requires(tokens: &[Tok], src: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let mut seen = BTreeSet::new();
    for i in 0..tokens.len() {
        if tokens[i].text(src) == "require"
            && tokens.get(i + 1).is_some_and(|t| t.kind == TokKind::LParen)
            && let Some(arg) = tokens.get(i + 2)
            && tokens.get(i + 3).is_some_and(|t| t.kind == TokKind::RParen)
            && let Some(spec) = tok_str(*arg, src)
            && seen.insert(spec.clone())
        {
            specs.push(spec);
        } else if tokens[i].text(src) == "from"
            && let Some(next) = tokens.get(i + 1)
            && let Some(spec) = tok_str(*next, src)
            && is_import_statement(tokens, i, src)
            && seen.insert(spec.clone())
        {
            specs.push(spec);
        } else if tokens[i].text(src) == "import"
            && let Some(next) = tokens.get(i + 1)
            && let Some(spec) = tok_str(*next, src)
            && seen.insert(spec.clone())
        {
            specs.push(spec);
        }
    }
    specs
}

fn is_import_statement(tokens: &[Tok], from_idx: usize, src: &str) -> bool {
    let start = from_idx.saturating_sub(24);
    for idx in (start..from_idx).rev() {
        match tokens[idx].kind {
            TokKind::Semi => return false,
            TokKind::Ident if tokens[idx].text(src) == "import" => return true,
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Whole-script Electron API & IPC extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum ConstVal {
    Unique(String),
    Ambiguous,
}

#[derive(Default)]
struct ConstTable {
    by_name: BTreeMap<String, ConstVal>,
    by_prop: BTreeMap<String, ConstVal>,
}

impl ConstTable {
    fn insert_name(&mut self, key: &str, value: String) {
        if key.len() < 2 && !key.chars().all(|c| c.is_ascii_uppercase()) {
            return;
        }
        Self::insert_slot(&mut self.by_name, key, value);
    }

    fn insert_prop(&mut self, prop: &str, value: String) {
        if prop.len() < 2 {
            return;
        }
        Self::insert_slot(&mut self.by_prop, prop, value);
    }

    fn insert_slot(map: &mut BTreeMap<String, ConstVal>, key: &str, value: String) {
        match map.get_mut(key) {
            None => {
                map.insert(key.to_string(), ConstVal::Unique(value));
            }
            Some(ConstVal::Unique(prev)) if *prev != value => {
                *map.get_mut(key).unwrap() = ConstVal::Ambiguous;
            }
            Some(_) => {}
        }
    }

    fn lookup_ident(&self, ident: &str) -> Option<&str> {
        match self.by_name.get(ident) {
            Some(ConstVal::Unique(v)) => Some(v.as_str()),
            _ => match self.by_prop.get(ident) {
                Some(ConstVal::Unique(v)) => Some(v.as_str()),
                _ => None,
            },
        }
    }

    fn lookup_prop(&self, prop: &str) -> Option<&str> {
        match self.by_prop.get(prop) {
            Some(ConstVal::Unique(v)) => Some(v.as_str()),
            _ => match self.by_name.get(prop) {
                Some(ConstVal::Unique(v)) => Some(v.as_str()),
                _ => None,
            },
        }
    }
}

#[derive(Default)]
struct ScopeFrame {
    electron_aliases: BTreeSet<String>,
    default_wrapped_aliases: BTreeSet<String>,
    destructured_apis: BTreeMap<String, String>,
    wrapper_ipc_fns: BTreeMap<String, String>,
    shadowed: BTreeSet<String>,
}

struct ScopeStack {
    frames: Vec<ScopeFrame>,
}

impl ScopeStack {
    fn new() -> Self {
        Self {
            frames: vec![ScopeFrame::default()],
        }
    }

    fn current_mut(&mut self) -> &mut ScopeFrame {
        self.frames.last_mut().expect("root scope frame")
    }

    fn push(&mut self, shadowed: BTreeSet<String>) {
        self.frames.push(ScopeFrame {
            shadowed,
            ..Default::default()
        });
    }

    fn pop(&mut self) {
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }

    fn shadow(&mut self, ident: &str) {
        let frame = self.current_mut();
        frame.electron_aliases.remove(ident);
        frame.default_wrapped_aliases.remove(ident);
        frame.destructured_apis.remove(ident);
        frame.wrapper_ipc_fns.remove(ident);
        frame.shadowed.insert(ident.to_string());
    }

    fn bind_alias(&mut self, ident: &str, default_wrapped: bool) {
        let frame = self.current_mut();
        frame.shadowed.remove(ident);
        frame.destructured_apis.remove(ident);
        if default_wrapped {
            frame.default_wrapped_aliases.insert(ident.to_string());
        } else {
            frame.default_wrapped_aliases.remove(ident);
        }
        frame.electron_aliases.insert(ident.to_string());
    }

    fn bind_destructured(&mut self, ident: &str, api: &str) {
        let frame = self.current_mut();
        frame.shadowed.remove(ident);
        frame.electron_aliases.remove(ident);
        frame
            .destructured_apis
            .insert(ident.to_string(), api.to_string());
    }

    fn bind_ipc_wrapper(&mut self, fn_name: &str, dir: &str) {
        let frame = self.current_mut();
        frame.shadowed.remove(fn_name);
        frame
            .wrapper_ipc_fns
            .insert(fn_name.to_string(), dir.to_string());
    }

    fn is_electron_alias(&self, ident: &str) -> Option<bool> {
        for frame in self.frames.iter().rev() {
            if frame.electron_aliases.contains(ident) {
                return Some(frame.default_wrapped_aliases.contains(ident));
            }
            if frame.shadowed.contains(ident) || frame.destructured_apis.contains_key(ident) {
                return None;
            }
        }
        None
    }

    fn lookup_destructured(&self, ident: &str) -> Option<&str> {
        for frame in self.frames.iter().rev() {
            if let Some(api) = frame.destructured_apis.get(ident) {
                return Some(api.as_str());
            }
            if frame.shadowed.contains(ident) || frame.electron_aliases.contains(ident) {
                return None;
            }
        }
        None
    }

    fn lookup_ipc_wrapper(&self, ident: &str) -> Option<&str> {
        for frame in self.frames.iter().rev() {
            if let Some(dir) = frame.wrapper_ipc_fns.get(ident) {
                return Some(dir.as_str());
            }
            if frame.shadowed.contains(ident) {
                return None;
            }
        }
        None
    }
}

/// Inspect any JS file (loader, bundle, preload, main script) for Electron APIs,
/// IPC channels, `contextBridge` globals, requires, and inferred script role.
#[must_use]
pub fn analyze_script(path: &str, src: &str) -> ScriptFindings {
    let tokens = tokenize(src);
    let requires = collect_requires(&tokens, src);
    let mut electron_mod_ids = BTreeSet::new();
    collect_electron_module_ids(&tokens, src, &mut electron_mod_ids);
    let mut constants = ConstTable::default();
    collect_constants(&tokens, src, &mut constants);

    let mut findings = ScriptFindings {
        requires,
        ..Default::default()
    };

    collect_ipc_enums_and_whitelists(&tokens, src, &constants, &mut findings.ipc_hits);
    scan_script_scoped(&tokens, src, &electron_mod_ids, &constants, &mut findings);
    findings.role = Some(infer_script_role(path, &findings));
    findings
}

fn infer_script_role(path: &str, findings: &ScriptFindings) -> ScriptRole {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/index.js") || lower == "index.js" {
        if findings
            .requires
            .iter()
            .any(|r| r.to_ascii_lowercase().ends_with(".asar"))
        {
            return ScriptRole::Loader;
        }
        if findings
            .requires
            .iter()
            .any(|r| r.to_ascii_lowercase().ends_with(".node"))
        {
            return ScriptRole::Module;
        }
    }
    if lower.contains("preload")
        || !findings.context_bridges.is_empty()
        || findings
            .api_hits
            .iter()
            .any(|h| matches!(h.namespace.as_str(), "ipcRenderer" | "contextBridge"))
    {
        return ScriptRole::Preload;
    }
    if findings.api_hits.iter().any(|h| {
        matches!(
            h.namespace.as_str(),
            "ipcMain" | "BrowserWindow" | "app" | "webContents"
        )
    }) || lower.ends_with("main.js")
        || lower.ends_with("bundle.js")
    {
        return ScriptRole::Main;
    }
    if std::path::Path::new(&lower)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("node"))
        || lower.contains("modules/")
    {
        return ScriptRole::Module;
    }
    if !findings.api_hits.is_empty() || !findings.ipc_hits.is_empty() {
        return ScriptRole::Renderer;
    }
    ScriptRole::Unknown
}

fn is_electron_specifier(spec: &str) -> bool {
    matches!(
        spec,
        "electron" | "electron/main" | "electron/renderer" | "electron/common"
    )
}

fn collect_electron_module_ids(tokens: &[Tok], src: &str, out: &mut BTreeSet<String>) {
    for i in 0..tokens.len() {
        if tokens[i].text(src) != "require"
            || tokens.get(i + 1).is_none_or(|t| t.kind != TokKind::LParen)
            || tokens.get(i + 3).is_none_or(|t| t.kind != TokKind::RParen)
        {
            continue;
        }
        let Some(spec) = tokens.get(i + 2).and_then(|t| tok_str(*t, src)) else {
            continue;
        };
        if !is_electron_specifier(&spec) {
            continue;
        }
        // Check enclosing module body for `<param>.exports = require("electron")`
        let exports_eq = i >= 3
            && tokens[i - 1].kind == TokKind::Eq
            && tokens[i - 2].text(src) == "exports"
            && tokens[i - 3].kind == TokKind::Dot;
        if !exports_eq {
            continue;
        }
        let back_limit = i.saturating_sub(24);
        for j in (back_limit..i).rev() {
            if tokens[j].kind == TokKind::LBrace {
                // `<id>(mod){...}` or `<id>:(mod)=>{...}` or `electron(e){...}`
                let mut k = j;
                if k > 0 && tokens[k - 1].kind == TokKind::Arrow {
                    k -= 1;
                }
                if k > 0 && tokens[k - 1].kind == TokKind::RParen {
                    let mut p = k - 1;
                    while p > back_limit && tokens[p].kind != TokKind::LParen {
                        p -= 1;
                    }
                    if tokens.get(p).is_some_and(|t| t.kind == TokKind::LParen) && p > 0 {
                        let mut id_idx = p - 1;
                        if tokens[id_idx].kind == TokKind::Colon && id_idx > 0 {
                            id_idx -= 1;
                        }
                        if matches!(tokens[id_idx].kind, TokKind::Number | TokKind::Ident) {
                            out.insert(tokens[id_idx].text(src).to_string());
                        }
                    }
                }
                break;
            }
        }
    }
}

fn collect_constants(tokens: &[Tok], src: &str, table: &mut ConstTable) {
    for i in 0..tokens.len() {
        // `IDENT = STR` (skip parameter defaults or comparisons; `TokKind::Eq` excludes == / ===)
        if i + 2 < tokens.len()
            && tokens[i].kind == TokKind::Ident
            && tokens[i + 1].kind == TokKind::Eq
            && let Some(val) = tok_str(tokens[i + 2], src)
            && is_candidate_constant_string(&val)
        {
            if i >= 2 && tokens[i - 1].kind == TokKind::Dot && tokens[i - 2].kind == TokKind::Ident
            {
                table.insert_prop(tokens[i].text(src), val);
            } else if i == 0 || tokens[i - 1].kind != TokKind::Dot {
                table.insert_name(tokens[i].text(src), val);
            }
        } else if i + 2 < tokens.len()
            && tokens[i].kind == TokKind::Ident
            && tokens[i + 1].kind == TokKind::Colon
            && let Some(val) = tok_str(tokens[i + 2], src)
            && is_candidate_constant_string(&val)
        {
            table.insert_prop(tokens[i].text(src), val);
        }
    }
}

fn is_candidate_constant_string(val: &str) -> bool {
    !val.is_empty() && val.len() <= 160 && !val.contains('\n') && !val.contains('\r')
}

fn collect_esm_import_at(tokens: &[Tok], i: usize, src: &str, scope: &mut ScopeStack) {
    let limit = (i + 32).min(tokens.len());
    for j in (i + 1)..limit {
        if tokens[j].kind == TokKind::Semi {
            break;
        }
        if tokens[j].text(src) == "from"
            && let Some(spec) = tokens.get(j + 1).and_then(|t| tok_str(*t, src))
            && is_electron_specifier(&spec)
        {
            parse_esm_import_bindings(&tokens[i + 1..j], src, scope);
            break;
        }
    }
}

fn update_scope_at_assignment(
    tokens: &[Tok],
    eq_idx: usize,
    src: &str,
    mod_ids: &BTreeSet<String>,
    scope: &mut ScopeStack,
) {
    let rhs = &tokens[eq_idx + 1..];
    if let Some((is_default_wrap, sub_api, consumed)) = match_electron_expr(rhs, src, mod_ids) {
        let is_chain_after = rhs
            .get(consumed)
            .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot));
        if let Some(sub) = sub_api {
            if !is_chain_after
                && is_plain_lhs_ident(tokens, eq_idx)
                && is_known_electron_export(&sub)
            {
                scope.bind_destructured(tokens[eq_idx - 1].text(src), &sub);
            }
        } else if !is_chain_after {
            bind_lhs(tokens, eq_idx, src, is_default_wrap, scope);
        } else if rhs
            .get(consumed + 1)
            .is_some_and(|t| t.kind == TokKind::Ident)
            && rhs
                .get(consumed + 2)
                .is_none_or(|t| !matches!(t.kind, TokKind::Dot | TokKind::OptDot | TokKind::LParen))
        {
            let member = rhs[consumed + 1].text(src);
            if is_plain_lhs_ident(tokens, eq_idx) && is_known_electron_export(member) {
                scope.bind_destructured(tokens[eq_idx - 1].text(src), member);
            }
        }
        return;
    }

    if !rhs.is_empty()
        && rhs[0].kind == TokKind::Ident
        && let Some(default_wrapped) = scope.is_electron_alias(rhs[0].text(src))
    {
        let alias_end = if default_wrapped
            && rhs.get(1).is_some_and(|t| t.kind == TokKind::Dot)
            && rhs.get(2).is_some_and(|t| t.text(src) == "default")
        {
            3
        } else {
            1
        };
        let has_subprop = rhs
            .get(alias_end)
            .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot));
        if !has_subprop {
            bind_lhs(tokens, eq_idx, src, default_wrapped, scope);
            return;
        }
        if is_plain_lhs_ident(tokens, eq_idx)
            && rhs
                .get(alias_end + 1)
                .is_some_and(|t| t.kind == TokKind::Ident)
            && rhs
                .get(alias_end + 2)
                .is_none_or(|t| !matches!(t.kind, TokKind::Dot | TokKind::OptDot | TokKind::LParen))
        {
            let api = rhs[alias_end + 1].text(src);
            if is_known_electron_export(api) {
                scope.bind_destructured(tokens[eq_idx - 1].text(src), api);
                return;
            }
        }
    }

    if let Some((fn_name, dir)) = try_extract_ipc_wrapper_at(tokens, eq_idx, src) {
        scope.bind_ipc_wrapper(&fn_name, &dir);
        return;
    }

    if is_plain_lhs_ident(tokens, eq_idx) {
        scope.shadow(tokens[eq_idx - 1].text(src));
    }
}

const fn is_plain_lhs_ident(tokens: &[Tok], eq_idx: usize) -> bool {
    eq_idx >= 1
        && matches!(tokens[eq_idx - 1].kind, TokKind::Ident)
        && (eq_idx < 2 || !matches!(tokens[eq_idx - 2].kind, TokKind::Dot | TokKind::OptDot))
}

fn parse_esm_import_bindings(binding: &[Tok], src: &str, scope: &mut ScopeStack) {
    if binding.is_empty() {
        return;
    }
    if binding.len() >= 3
        && binding[0].text(src) == "*"
        && binding[1].text(src) == "as"
        && binding[2].kind == TokKind::Ident
    {
        scope.bind_alias(binding[2].text(src), false);
        return;
    }
    if binding[0].kind == TokKind::LBrace {
        bind_destructured_object(&binding[1..], src, scope);
        return;
    }
    if binding[0].kind == TokKind::Ident {
        scope.bind_alias(binding[0].text(src), false);
    }
}

fn bind_lhs(
    tokens: &[Tok],
    eq_idx: usize,
    src: &str,
    is_default_wrap: bool,
    scope: &mut ScopeStack,
) {
    if is_plain_lhs_ident(tokens, eq_idx) {
        scope.bind_alias(tokens[eq_idx - 1].text(src), is_default_wrap);
        return;
    }
    if eq_idx > 0 && tokens[eq_idx - 1].kind == TokKind::RBrace {
        let start = eq_idx.saturating_sub(80);
        for j in (start..eq_idx - 1).rev() {
            if tokens[j].kind == TokKind::LBrace {
                bind_destructured_object(&tokens[j + 1..eq_idx - 1], src, scope);
                break;
            }
        }
    }
}

fn bind_destructured_object(inside: &[Tok], src: &str, scope: &mut ScopeStack) {
    for item in inside.split(|t| t.kind == TokKind::Comma) {
        let trimmed: Vec<&Tok> = item.iter().filter(|t| t.kind != TokKind::RBrace).collect();
        match trimmed.as_slice() {
            [orig] if orig.kind == TokKind::Ident => {
                let name = orig.text(src);
                if is_known_electron_export(name) {
                    scope.bind_destructured(name, name);
                }
            }
            [orig, mid, alias]
                if orig.kind == TokKind::Ident
                    && (mid.kind == TokKind::Colon || mid.text(src) == "as")
                    && alias.kind == TokKind::Ident =>
            {
                let orig_name = orig.text(src);
                if is_known_electron_export(orig_name) {
                    scope.bind_destructured(alias.text(src), orig_name);
                }
            }
            _ => {}
        }
    }
}

/// Match `require("electron")`, `r("electron")`, `__webpack_require__(id)`, or
/// `__importStar(...)` / `__importDefault(...)` wrappers around one of them.
/// Returns `(is_default_wrapped, optional_trailing_subprop, tokens_consumed)`.
fn match_electron_expr(
    slice: &[Tok],
    src: &str,
    mod_ids: &BTreeSet<String>,
) -> Option<(bool, Option<String>, usize)> {
    // Unwrap TypeScript helpers: `__importStar(<expr>)` / `__importDefault(<expr>)`
    if slice.len() >= 4
        && slice[0].kind == TokKind::Ident
        && matches!(slice[0].text(src), "__importStar" | "__importDefault")
        && slice[1].kind == TokKind::LParen
    {
        let is_def = slice[0].text(src) == "__importDefault";
        if let Some((_, sub, inner_len)) = match_electron_expr(&slice[2..], src, mod_ids)
            && slice
                .get(2 + inner_len)
                .is_some_and(|t| t.kind == TokKind::RParen)
        {
            return Some((is_def, sub, 3 + inner_len));
        }
    }

    // `(0, r)("electron")` or direct `require("electron")` / `r("electron")` / `__webpack_require__(id)`
    let (fn_tok, arg_start) = if slice.len() >= 4
        && slice[0].kind == TokKind::Ident
        && slice[1].kind == TokKind::LParen
    {
        (slice[0].text(src), 2usize)
    } else {
        return None;
    };

    let arg = slice.get(arg_start)?;
    let close = slice.get(arg_start + 1)?;
    if close.kind != TokKind::RParen {
        return None;
    }

    let matched = match tok_str(*arg, src) {
        Some(ref spec) if is_electron_specifier(spec) => {
            matches!(
                fn_tok,
                "require" | "r" | "n" | "e" | "t" | "i" | "__webpack_require__"
            ) || fn_tok.len() <= 2
        }
        _ => {
            matches!(fn_tok, "__webpack_require__" | "r" | "n" | "t" | "e" | "i")
                && mod_ids.contains(arg.text(src))
        }
    };
    if !matched {
        return None;
    }

    let consumed = arg_start + 2;
    Some((false, None, consumed))
}

fn try_extract_ipc_wrapper_at(
    tokens: &[Tok],
    eq_idx: usize,
    src: &str,
) -> Option<(String, String)> {
    if !is_plain_lhs_ident(tokens, eq_idx)
        || tokens.get(eq_idx + 1)?.text(src) != "function"
        || tokens.get(eq_idx + 2)?.kind != TokKind::LParen
    {
        return None;
    }
    let fn_name = tokens[eq_idx - 1].text(src);
    if matches!(
        fn_name,
        "on" | "once" | "send" | "invoke" | "handle" | "require" | "log"
    ) {
        return None;
    }
    check_ipc_wrapper_body(tokens, eq_idx + 2, fn_name, src)
}

fn try_extract_ipc_wrapper_decl(
    tokens: &[Tok],
    fn_kw_idx: usize,
    src: &str,
) -> Option<(String, String)> {
    if tokens.get(fn_kw_idx + 1)?.kind != TokKind::Ident
        || tokens.get(fn_kw_idx + 2)?.kind != TokKind::LParen
    {
        return None;
    }
    let fn_name = tokens[fn_kw_idx + 1].text(src);
    if matches!(
        fn_name,
        "on" | "once" | "send" | "invoke" | "handle" | "require" | "log"
    ) {
        return None;
    }
    check_ipc_wrapper_body(tokens, fn_kw_idx + 2, fn_name, src)
}

fn check_ipc_wrapper_body(
    tokens: &[Tok],
    paren_idx: usize,
    fn_name: &str,
    src: &str,
) -> Option<(String, String)> {
    let param0 = tokens
        .get(paren_idx + 1)
        .filter(|t| t.kind == TokKind::Ident)?;
    let param0_name = param0.text(src);
    let bstart = tokens
        .iter()
        .enumerate()
        .take((paren_idx + 16).min(tokens.len()))
        .skip(paren_idx + 1)
        .find_map(|(idx, tok)| (tok.kind == TokKind::LBrace).then_some(idx + 1))?;
    let bend = (bstart + 40).min(tokens.len());
    for w in tokens[bstart..bend].windows(5) {
        if matches!(w[0].text(src), "ipcMain" | "ipcRenderer")
            && w[1].kind == TokKind::Dot
            && let Some((dir, 0)) = ipc_direction(w[0].text(src), w[2].text(src))
            && w[3].kind == TokKind::LParen
            && w[4].kind == TokKind::Ident
            && w[4].text(src) == param0_name
        {
            return Some((fn_name.to_string(), dir.to_string()));
        }
    }
    None
}

fn collect_ipc_enums_and_whitelists(
    tokens: &[Tok],
    src: &str,
    constants: &ConstTable,
    out: &mut Vec<IpcHit>,
) {
    for i in 0..tokens.len() {
        // Enum-style: `IPCEvents1.FOO_BAR = "DISCORD_FOO_BAR"`
        if i + 4 < tokens.len()
            && tokens[i].kind == TokKind::Ident
            && tokens[i + 1].kind == TokKind::Dot
            && tokens[i + 2].kind == TokKind::Ident
            && tokens[i + 3].kind == TokKind::Eq
            && tokens[i].text(src).to_ascii_lowercase().contains("ipc")
            && let Some(val) = tok_str(tokens[i + 4], src)
            && is_valid_channel_name(&val)
        {
            out.push(IpcHit {
                channel: val,
                direction: "enum-constant".to_string(),
                resolution: "enum".to_string(),
                symbol_name: Some(format!(
                    "{}.{}",
                    tokens[i].text(src),
                    tokens[i + 2].text(src)
                )),
            });
            continue;
        }

        // Whitelist set/array: `RENDERER_IPC_SEND_WHITELIST = new Set([ ... ])`
        if i + 5 < tokens.len()
            && tokens[i].kind == TokKind::Ident
            && tokens[i + 1].kind == TokKind::Eq
            && is_ipc_whitelist_ident(tokens[i].text(src))
        {
            let name = tokens[i].text(src);
            let upper = name.to_ascii_uppercase();
            let dir = if upper.contains("SEND") {
                "whitelist-send"
            } else if upper.contains("INVOKE") {
                "whitelist-invoke"
            } else if upper.contains("LISTEN") || upper.contains("ON") || upper.contains("RECV") {
                "whitelist-listen"
            } else {
                "whitelist"
            };

            let array_start = if tokens[i + 2].text(src) == "new"
                && tokens[i + 3].text(src) == "Set"
                && tokens[i + 4].kind == TokKind::LParen
                && tokens
                    .get(i + 5)
                    .is_some_and(|t| t.kind == TokKind::LBracket)
            {
                Some(i + 6)
            } else if tokens[i + 2].kind == TokKind::LBracket {
                Some(i + 3)
            } else {
                None
            };

            if let Some(start) = array_start
                && let Some(end) = find_matching_bracket(tokens, start)
            {
                for item in tokens[start..end].split(|t| t.kind == TokKind::Comma) {
                    if let Some((ch, sym, _res)) = resolve_channel_expr(item, src, constants) {
                        out.push(IpcHit {
                            channel: ch,
                            direction: dir.to_string(),
                            resolution: "whitelist".to_string(),
                            symbol_name: sym,
                        });
                    }
                }
            }
        }
    }
}

fn is_ipc_whitelist_ident(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("IPC")
        && (upper.contains("WHITELIST")
            || upper.contains("ALLOWLIST")
            || upper.contains("CHANNELS"))
}

fn find_matching_bracket(tokens: &[Tok], after_open: usize) -> Option<usize> {
    let mut depth = 1usize;
    for (idx, tok) in tokens.iter().enumerate().skip(after_open) {
        match tok.kind {
            TokKind::LBracket => depth += 1,
            TokKind::RBracket => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_matching_paren(tokens: &[Tok], after_open: usize) -> Option<usize> {
    let mut depth = 1usize;
    for (idx, tok) in tokens.iter().enumerate().skip(after_open) {
        match tok.kind {
            TokKind::LParen => depth += 1,
            TokKind::RParen => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_call_args(tokens: &[Tok]) -> Vec<&[Tok]> {
    let mut args = Vec::new();
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_bracket = 0usize;
    let mut start = 0usize;
    for (idx, tok) in tokens.iter().enumerate() {
        match tok.kind {
            TokKind::LParen => depth_paren += 1,
            TokKind::RParen => depth_paren = depth_paren.saturating_sub(1),
            TokKind::LBrace => depth_brace += 1,
            TokKind::RBrace => depth_brace = depth_brace.saturating_sub(1),
            TokKind::LBracket => depth_bracket += 1,
            TokKind::RBracket => depth_bracket = depth_bracket.saturating_sub(1),
            TokKind::Comma if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                args.push(&tokens[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() {
        args.push(&tokens[start..]);
    }
    args
}

fn scan_script_scoped(
    tokens: &[Tok],
    src: &str,
    mod_ids: &BTreeSet<String>,
    constants: &ConstTable,
    findings: &mut ScriptFindings,
) {
    let mut scope = ScopeStack::new();
    let mut i = 0usize;
    while i < tokens.len() {
        match tokens[i].kind {
            TokKind::LBrace => {
                scope.push(preceding_fn_params(tokens, i, src));
                i += 1;
                continue;
            }
            TokKind::RBrace => {
                scope.pop();
                i += 1;
                continue;
            }
            TokKind::Ident if tokens[i].text(src) == "import" => {
                collect_esm_import_at(tokens, i, src, &mut scope);
            }
            TokKind::Ident if tokens[i].text(src) == "function" => {
                if let Some((fn_name, dir)) = try_extract_ipc_wrapper_decl(tokens, i, src) {
                    scope.bind_ipc_wrapper(&fn_name, &dir);
                }
            }
            TokKind::Eq => {
                update_scope_at_assignment(tokens, i, src, mod_ids, &mut scope);
            }
            _ => {}
        }

        if let Some(next_i) = scan_single_site(tokens, i, src, mod_ids, constants, &scope, findings)
        {
            i = next_i;
            continue;
        }
        i += 1;
    }
}

fn preceding_fn_params(tokens: &[Tok], lbrace_idx: usize, src: &str) -> BTreeSet<String> {
    let mut params = BTreeSet::new();
    if lbrace_idx == 0 {
        return params;
    }
    let mut cursor = lbrace_idx;
    if tokens[cursor - 1].kind == TokKind::Arrow {
        cursor -= 1;
    }
    if cursor == 0 {
        return params;
    }
    if tokens[cursor - 1].kind == TokKind::RParen {
        let limit = cursor.saturating_sub(24);
        for j in (limit..cursor - 1).rev() {
            if tokens[j].kind == TokKind::LParen {
                for tok in &tokens[j + 1..cursor - 1] {
                    if tok.kind == TokKind::Ident {
                        params.insert(tok.text(src).to_string());
                    }
                }
                break;
            }
        }
    } else if tokens[cursor - 1].kind == TokKind::Ident
        && tokens[lbrace_idx - 1].kind == TokKind::Arrow
    {
        params.insert(tokens[cursor - 1].text(src).to_string());
    }
    params
}

fn scan_single_site(
    tokens: &[Tok],
    i: usize,
    src: &str,
    mod_ids: &BTreeSet<String>,
    constants: &ConstTable,
    scope: &ScopeStack,
    findings: &mut ScriptFindings,
) -> Option<usize> {
    if let Some(next_i) =
        match_bound_electron_site(tokens, i, src, mod_ids, constants, scope, findings)
    {
        return Some(next_i);
    }
    match_global_or_facade_site(tokens, i, src, constants, scope, findings)
}

fn match_bound_electron_site(
    tokens: &[Tok],
    i: usize,
    src: &str,
    mod_ids: &BTreeSet<String>,
    constants: &ConstTable,
    scope: &ScopeStack,
    findings: &mut ScriptFindings,
) -> Option<usize> {
    // 1. Direct `require("electron").Api(.Member)?` / `r("electron").Api(.Member)?`
    if let Some((is_def, None, consumed)) = match_electron_expr(&tokens[i..], src, mod_ids) {
        let after = i + consumed;
        let chain_start = if is_def
            && tokens.get(after).is_some_and(|t| t.kind == TokKind::Dot)
            && tokens
                .get(after + 1)
                .is_some_and(|t| t.text(src) == "default")
        {
            after + 2
        } else {
            after
        };
        if let Some(advance) = try_consume_electron_ns_access(
            tokens,
            chain_start,
            src,
            ApiProvenance::Binding,
            constants,
            findings,
        ) {
            return Some(chain_start + advance);
        }
        return Some(after);
    }

    // 2. Bound electron namespace alias: `electron.app.getPath(...)` / `electron_1.default.app`
    if tokens[i].kind == TokKind::Ident
        && !is_dot_member(tokens, i)
        && let Some(default_wrapped) = scope.is_electron_alias(tokens[i].text(src))
    {
        let mut chain_start = i + 1;
        if default_wrapped
            && tokens
                .get(chain_start)
                .is_some_and(|t| t.kind == TokKind::Dot)
            && tokens
                .get(chain_start + 1)
                .is_some_and(|t| t.text(src) == "default")
        {
            chain_start += 2;
        }
        if let Some(advance) = try_consume_electron_ns_access(
            tokens,
            chain_start,
            src,
            ApiProvenance::Binding,
            constants,
            findings,
        ) {
            return Some(chain_start + advance);
        }
    }

    // 3. Destructured Electron export: `ipcMain.handle(...)` or `new BrowserWindow(...)`
    if tokens[i].kind == TokKind::Ident
        && !is_dot_member(tokens, i)
        && let Some(api_name) = scope.lookup_destructured(tokens[i].text(src))
    {
        let advance = record_api_and_dispatch(
            tokens,
            i + 1,
            api_name,
            ApiProvenance::Binding,
            src,
            constants,
            findings,
        );
        return Some(i + 1 + advance);
    }
    None
}

fn match_global_or_facade_site(
    tokens: &[Tok],
    i: usize,
    src: &str,
    constants: &ConstTable,
    scope: &ScopeStack,
    findings: &mut ScriptFindings,
) -> Option<usize> {
    // 4. Direct known Electron symbols (when alias resolution crossed scopes/wrappers)
    if tokens[i].kind == TokKind::Ident && !is_dot_member(tokens, i) {
        let ident = tokens[i].text(src);
        if is_known_electron_export(ident) {
            let member = peek_member(tokens, i + 1, src);
            if is_unambiguous_qualified_call(ident, member.as_deref()) {
                let advance = record_api_and_dispatch(
                    tokens,
                    i + 1,
                    ident,
                    ApiProvenance::Direct,
                    src,
                    constants,
                    findings,
                );
                return Some(i + 1 + advance);
            }
        }
    }

    // 5. `win.webContents.send(...)` / `win.webContents.on(...)`
    if tokens[i].kind == TokKind::Ident
        && tokens[i].text(src) == "webContents"
        && is_dot_member(tokens, i)
    {
        let advance = record_api_and_dispatch(
            tokens,
            i + 1,
            "webContents",
            ApiProvenance::Direct,
            src,
            constants,
            findings,
        );
        return Some(i + 1 + advance);
    }

    // 6. Discord/custom IPC facade calls: e.g. `DiscordIPC.main.handle(...)`
    if tokens[i].kind == TokKind::Ident
        && tokens[i].text(src).contains("DiscordIPC")
        && let Some(advance) = try_consume_ipc_facade(tokens, i, src, constants, findings)
    {
        return Some(i + advance);
    }

    // 7. Scoped local IPC wrapper function call `k("REMOTE_BROWSER_...", ...)`
    if tokens[i].kind == TokKind::Ident
        && !is_dot_member(tokens, i)
        && let Some(dir) = scope.lookup_ipc_wrapper(tokens[i].text(src))
        && tokens.get(i + 1).is_some_and(|t| t.kind == TokKind::LParen)
        && let Some(close) = find_matching_paren(tokens, i + 2)
    {
        let args = split_call_args(&tokens[i + 2..close]);
        if let Some(arg0) = args.first()
            && let Some((ch, sym, _)) = resolve_channel_expr(arg0, src, constants)
        {
            findings.ipc_hits.push(IpcHit {
                channel: ch,
                direction: dir.to_string(),
                resolution: "wrapper".to_string(),
                symbol_name: sym,
            });
        }
    }
    None
}

const fn is_dot_member(tokens: &[Tok], idx: usize) -> bool {
    idx > 0 && matches!(tokens[idx - 1].kind, TokKind::Dot | TokKind::OptDot)
}

fn peek_member(tokens: &[Tok], after_ns: usize, src: &str) -> Option<String> {
    let dot = tokens.get(after_ns)?;
    if !matches!(dot.kind, TokKind::Dot | TokKind::OptDot) {
        return None;
    }
    let mem = tokens.get(after_ns + 1)?;
    (mem.kind == TokKind::Ident).then(|| mem.text(src).to_string())
}

fn try_consume_electron_ns_access(
    tokens: &[Tok],
    dot_idx: usize,
    src: &str,
    provenance: ApiProvenance,
    constants: &ConstTable,
    findings: &mut ScriptFindings,
) -> Option<usize> {
    if !tokens
        .get(dot_idx)
        .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot))
    {
        return None;
    }
    let ns_tok = tokens.get(dot_idx + 1)?;
    if ns_tok.kind != TokKind::Ident {
        return None;
    }
    let ns = ns_tok.text(src);
    if !is_known_electron_export(ns) {
        return None;
    }
    let after = record_api_and_dispatch(
        tokens,
        dot_idx + 2,
        ns,
        provenance,
        src,
        constants,
        findings,
    );
    Some(2 + after)
}

fn is_js_runtime_prop(member: &str) -> bool {
    member.len() < 2
        || matches!(
            member,
            "apply"
                | "call"
                | "bind"
                | "toString"
                | "valueOf"
                | "hasOwnProperty"
                | "length"
                | "prototype"
                | "exports"
                | "default"
                | "__esModule"
                | "constructor"
                | "push"
                | "pop"
                | "slice"
                | "splice"
                | "concat"
                | "join"
                | "map"
                | "filter"
                | "reduce"
                | "forEach"
                | "keys"
                | "values"
                | "entries"
        )
}

fn record_api_and_dispatch(
    tokens: &[Tok],
    after_ns: usize,
    ns: &str,
    provenance: ApiProvenance,
    src: &str,
    constants: &ConstTable,
    findings: &mut ScriptFindings,
) -> usize {
    if tokens
        .get(after_ns)
        .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot))
        && let Some(mem_tok) = tokens.get(after_ns + 1)
        && mem_tok.kind == TokKind::Ident
    {
        let member = mem_tok.text(src);
        if is_js_runtime_prop(member) {
            return 0;
        }
        findings.api_hits.push(ApiHit {
            namespace: ns.to_string(),
            member: Some(member.to_string()),
            provenance,
        });

        let paren_idx = after_ns + 2;
        if tokens
            .get(paren_idx)
            .is_some_and(|t| t.kind == TokKind::LParen)
            && let Some(close) = find_matching_paren(tokens, paren_idx + 1)
        {
            let args = split_call_args(&tokens[paren_idx + 1..close]);
            if ns == "contextBridge" && member == "exposeInMainWorld" {
                if let Some(arg0) = args.first()
                    && let Some((key, _, _)) = resolve_channel_expr(arg0, src, constants)
                {
                    findings.context_bridges.push(key);
                }
            } else if matches!(ns, "ipcMain" | "ipcRenderer" | "webContents")
                && let Some((dir, arg_idx)) = ipc_direction(ns, member)
                && let Some(chan_arg) = args.get(arg_idx)
            {
                record_ipc_arg(chan_arg, dir, src, constants, findings);
            }
        }
        return 2;
    }

    findings.api_hits.push(ApiHit {
        namespace: ns.to_string(),
        member: None,
        provenance,
    });
    0
}

fn try_consume_ipc_facade(
    tokens: &[Tok],
    start: usize,
    src: &str,
    constants: &ConstTable,
    findings: &mut ScriptFindings,
) -> Option<usize> {
    // Match `DiscordIPC_1.DiscordIPC.main.handle(arg, ...)`
    let mut cursor = start + 1;
    let mut segments: Vec<&str> = vec![tokens[start].text(src)];
    while tokens
        .get(cursor)
        .is_some_and(|t| matches!(t.kind, TokKind::Dot | TokKind::OptDot))
        && tokens
            .get(cursor + 1)
            .is_some_and(|t| t.kind == TokKind::Ident)
    {
        segments.push(tokens[cursor + 1].text(src));
        cursor += 2;
        if tokens
            .get(cursor)
            .is_some_and(|t| t.kind == TokKind::LParen)
        {
            break;
        }
        if segments.len() >= 6 {
            return None;
        }
    }
    let method = *segments.last()?;
    let side = if segments.contains(&"main") {
        "main"
    } else if segments.contains(&"renderer") {
        "renderer"
    } else {
        "facade"
    };
    let (dir, arg_idx) = ipc_direction(side, method)?;
    if !tokens
        .get(cursor)
        .is_some_and(|t| t.kind == TokKind::LParen)
    {
        return None;
    }
    let close = find_matching_paren(tokens, cursor + 1)?;
    let args = split_call_args(&tokens[cursor + 1..close]);
    if let Some(arg) = args.get(arg_idx) {
        record_ipc_arg(arg, dir, src, constants, findings);
    }
    Some(cursor - start)
}

fn record_ipc_arg(
    arg: &[Tok],
    dir: &str,
    src: &str,
    constants: &ConstTable,
    findings: &mut ScriptFindings,
) {
    if let Some((channel, symbol_name, resolution)) = resolve_channel_expr(arg, src, constants) {
        findings.ipc_hits.push(IpcHit {
            channel,
            direction: dir.to_string(),
            resolution,
            symbol_name,
        });
    } else if !arg.is_empty() {
        let first = arg.first().unwrap().start;
        let last = arg.last().unwrap().end;
        let expr = src[first..last].trim();
        if !expr.is_empty() && expr.len() <= 120 {
            findings.dynamic_ipc.push(DynamicIpcHit {
                operation: dir.to_string(),
                expression: expr.to_string(),
            });
        }
    }
}

fn resolve_channel_expr(
    tokens: &[Tok],
    src: &str,
    constants: &ConstTable,
) -> Option<(String, Option<String>, String)> {
    let trimmed: &[Tok] = trim_parens(tokens);
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == 1 {
        if let Some(lit) = tok_str(trimmed[0], src)
            && is_valid_channel_name(&lit)
        {
            return Some((lit, None, "literal".to_string()));
        }
        if trimmed[0].kind == TokKind::Ident {
            let ident = trimmed[0].text(src);
            if let Some(resolved) = constants.lookup_ident(ident)
                && is_valid_channel_name(resolved)
            {
                return Some((
                    resolved.to_string(),
                    Some(ident.to_string()),
                    "constant".to_string(),
                ));
            }
        }
        return None;
    }

    // Dotted chain like `DiscordIPC_1.IPCEvents.ACCESSIBILITY_GET_ENABLED`
    if trimmed.iter().enumerate().all(|(idx, tok)| {
        if idx % 2 == 0 {
            tok.kind == TokKind::Ident
        } else {
            matches!(tok.kind, TokKind::Dot | TokKind::OptDot)
        }
    }) && trimmed.len() >= 3
        && let Some(last_ident) = trimmed.last().map(|t| t.text(src))
        && let Some(resolved) = constants.lookup_prop(last_ident)
        && is_valid_channel_name(resolved)
    {
        let chain = &src[trimmed[0].start..trimmed[trimmed.len() - 1].end];
        return Some((
            resolved.to_string(),
            Some(chain.to_string()),
            "constant".to_string(),
        ));
    }

    // Simple helper wrapper like `ipcUtil.createKey("start")` or `getDiscordIPCEvent("FOO")`
    if let Some(lit) = extract_single_literal_helper_arg(trimmed, src)
        && is_valid_channel_name(&lit)
    {
        return Some((lit, None, "wrapper".to_string()));
    }

    None
}

fn extract_single_literal_helper_arg(tokens: &[Tok], src: &str) -> Option<String> {
    let lparen = tokens.iter().position(|t| t.kind == TokKind::LParen)?;
    if tokens.last()?.kind != TokKind::RParen || lparen + 2 >= tokens.len() {
        return None;
    }
    let helper_name = &src[tokens[0].start..tokens[lparen - 1].end];
    let inner = &tokens[lparen + 1..tokens.len() - 1];
    if inner.len() == 1
        && let Some(lit) = tok_str(inner[0], src)
    {
        if helper_name.contains("getDiscordIPCEvent") {
            return Some(if lit.starts_with("DISCORD_") {
                lit
            } else {
                format!("DISCORD_{lit}")
            });
        }
        if helper_name.contains("createKey") {
            return Some(format!("sentry:{lit}"));
        }
    }
    None
}

fn trim_parens(mut tokens: &[Tok]) -> &[Tok] {
    while tokens.len() >= 2
        && tokens.first().is_some_and(|t| t.kind == TokKind::LParen)
        && tokens.last().is_some_and(|t| t.kind == TokKind::RParen)
    {
        tokens = &tokens[1..tokens.len() - 1];
    }
    tokens
}

fn is_valid_channel_name(val: &str) -> bool {
    !val.is_empty()
        && val.len() <= 160
        && !val.contains('\n')
        && !val.contains('\r')
        && val.chars().any(char::is_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_exact_loader_shape_and_wrapper_hooks() {
        let stock = b"module.exports = require('./core.asar');";
        let rec = inspect_loader(
            &LoaderInput {
                path: "modules/discord_desktop_core/index.js",
                location: "filesystem",
                archive: None,
                role: "asar-loader",
                package_name: Some("discord_desktop_core"),
                package_main: Some("index.js"),
            },
            stock,
        );
        assert_eq!(rec.byte_len, 40);
        assert_eq!(rec.formatting.line_ending, LineEnding::None);
        assert!(!rec.formatting.trailing_newline);
        assert_eq!(
            rec.exact_text.as_deref(),
            Some("module.exports = require('./core.asar');")
        );
        assert_eq!(rec.shape.kind, Some(LoaderKind::AsarPassthrough));
        assert_eq!(rec.shape.asar_targets, vec!["./core.asar"]);
        assert!(!rec.shape.module_load_hook);

        let wrapped = concat!(
            "\u{FEFF}// Custom Loader\r\n",
            "const Module = require('module');\r\n",
            "const electron = require('electron');\r\n",
            "const WrappedBW = new Proxy(electron.BrowserWindow, {});\r\n",
            "Module._load = function() { return WrappedBW; };\r\n",
            "electron.app.on('browser-window-created', () => {});\r\n",
            "module.exports = require('./core.asar');\r\n",
        );
        let wrec = inspect_loader(
            &LoaderInput {
                path: "modules/discord_desktop_core/index.js",
                location: "filesystem",
                archive: None,
                role: "asar-loader",
                package_name: Some("discord_desktop_core"),
                package_main: Some("index.js"),
            },
            wrapped.as_bytes(),
        );
        assert!(wrec.formatting.has_utf8_bom);
        assert_eq!(wrec.formatting.line_ending, LineEnding::Crlf);
        assert!(wrec.formatting.trailing_newline);
        assert_eq!(wrec.exact_text.as_deref(), Some(wrapped));
        assert_eq!(wrec.shape.kind, Some(LoaderKind::AsarWrapper));
        assert_eq!(wrec.shape.leading_comments, vec!["// Custom Loader"]);
        assert!(wrec.shape.module_load_hook);
        assert!(wrec.shape.electron_proxy);
        assert!(wrec.shape.browser_window_intercept);
        assert_eq!(wrec.shape.app_events, vec!["browser-window-created"]);
    }

    #[test]
    fn extracts_webpack_esbuild_esm_apis_and_resolved_ipc_channels() {
        let bundle = r#"
            const modules = {
                1288(module1) {
                    "use strict";
                    module1.exports = require("electron");
                }
            };
            IPCEvents1.CLIPBOARD_COPY = "DISCORD_CLIPBOARD_COPY";
            IPCEvents1.APP_GET_PATH = "DISCORD_APP_GET_PATH";
            const CLIPBOARD_CUT = "DISCORD_CLIPBOARD_CUT";
            let electron = __importStar(__webpack_require__(1288));
            const RENDERER_IPC_SEND_WHITELIST = new Set([IPCEvents1.APP_GET_PATH]);
            electron.ipcMain.handle(IPCEvents1.CLIPBOARD_COPY, async _ => {
                return electron.webContents.getFocusedWebContents()?.copy();
            });
            electron.ipcMain.handle(CLIPBOARD_CUT, async _ => {});
            electron.app.on("browser-window-created", () => {});
            // Ensure WebContents lifecycle events are NOT misreported as IPC channels:
            win.webContents.on("did-finish-load", () => {});
            win.webContents.send(IPCEvents1.APP_GET_PATH, "userData");
            win.webContents.sendToFrame(frame.frameId, "frame:sync-state", {});
            DiscordIPC_1.DiscordIPC.main.handle(IPCEvents1.CLIPBOARD_COPY, () => {});
        "#;
        let f = analyze_script("core.asar/bundle.js", bundle);
        assert_eq!(f.role, Some(ScriptRole::Main));
        assert!(f.api_hits.iter().any(|a| a.namespace == "ipcMain"
            && a.member.as_deref() == Some("handle")
            && a.provenance == ApiProvenance::Binding));
        assert!(f.api_hits.iter().any(|a| a.namespace == "app"
            && a.member.as_deref() == Some("on")
            && a.provenance == ApiProvenance::Binding));

        let channels: BTreeSet<(&str, &str)> = f
            .ipc_hits
            .iter()
            .map(|h| (h.channel.as_str(), h.direction.as_str()))
            .collect();
        assert!(channels.contains(&("DISCORD_CLIPBOARD_COPY", "main-handle")));
        assert!(channels.contains(&("DISCORD_CLIPBOARD_CUT", "main-handle")));
        assert!(channels.contains(&("DISCORD_APP_GET_PATH", "main-to-renderer")));
        assert!(channels.contains(&("DISCORD_APP_GET_PATH", "whitelist-send")));
        assert!(channels.contains(&("frame:sync-state", "main-to-frame")));
        assert!(!channels.iter().any(|(ch, _)| *ch == "did-finish-load"));
    }

    #[test]
    fn extracts_esbuild_and_preload_context_bridge() {
        let js = r#"
            const { contextBridge, ipcRenderer, desktopCapturer } = require("electron/renderer");
            contextBridge.exposeInMainWorld("MyBridge", {
                ping: () => ipcRenderer.invoke("app:ping"),
                status: () => ipcRenderer.sendSync("app:status"),
            });
            ipcRenderer.on("app:notify", (_e, msg) => console.log(msg));
            // esbuild-style wrapper for generic Electron apps
            let n = r("electron");
            n.ipcMain.on("get-runtime-config-overrides", () => {});
            let k = function(e, cb) { n.ipcMain.on(e, cb); };
            k("REMOTE_BROWSER_GET_GLOBAL", () => {});
            desktopCapturer.getSources({ types: ['window'] });
        "#;
        let f = analyze_script("preload.js", js);
        assert_eq!(f.context_bridges, vec!["MyBridge"]);
        assert!(
            f.ipc_hits
                .iter()
                .any(|h| h.channel == "app:ping" && h.direction == "renderer-invoke")
        );
        assert!(
            f.ipc_hits
                .iter()
                .any(|h| h.channel == "app:status" && h.direction == "renderer-send-sync")
        );
        assert!(
            f.ipc_hits
                .iter()
                .any(|h| h.channel == "app:notify" && h.direction == "renderer-on")
        );
        assert!(
            f.ipc_hits
                .iter()
                .any(|h| h.channel == "get-runtime-config-overrides" && h.direction == "main-on")
        );
        assert!(
            f.ipc_hits
                .iter()
                .any(|h| h.channel == "REMOTE_BROWSER_GET_GLOBAL" && h.direction == "main-on")
        );
        assert!(
            f.api_hits
                .iter()
                .any(|a| a.namespace == "desktopCapturer"
                    && a.member.as_deref() == Some("getSources"))
        );
    }

    #[test]
    fn minified_aliases_and_ipc_wrappers_stay_block_scoped() {
        let js = r#"
            function modA(e, t, r) {
                let n = r("electron");
                let { app: a, protocol: p } = n;
                a.whenReady();
                p.registerSchemesAsPrivileged([]);
                let k = function(ch, fn) { n.ipcMain.on(ch, fn); };
                k("real:channel", () => {});
            }
            function modB(a, p, k) {
                a.customProp();
                p.PCT_ENCODED();
                k("not-an-ipc-channel");
                let n = { length: 3, customFoo: 1 };
                return n.customFoo + n.length;
            }
            function modC() {
                let n = require("electron");
                n = otherObj;
                n.app.whatever();
            }
        "#;
        let f = analyze_script("bundle.js", js);
        assert!(
            f.api_hits
                .iter()
                .any(|a| a.namespace == "app" && a.member.as_deref() == Some("whenReady"))
        );
        assert!(
            !f.api_hits
                .iter()
                .any(|a| a.member.as_deref() == Some("customProp")
                    || a.member.as_deref() == Some("PCT_ENCODED")
                    || a.member.as_deref() == Some("whatever"))
        );
        let ipcs: BTreeSet<&str> = f.ipc_hits.iter().map(|h| h.channel.as_str()).collect();
        assert!(ipcs.contains("real:channel"));
        assert!(!ipcs.contains("not-an-ipc-channel"));
    }
}
