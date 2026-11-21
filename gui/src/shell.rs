//! The window, laid out like an editor:
//!
//!   activity bar | sidebar (module, docs, tools) | editor tabs | inspector
//!   output panel
//!   status bar
//!
//! Flow: drop a file, open one, or pick from a System32 (this machine's, or
//! off Windows a mounted install's);
//! Windissect reads where its PDB lives, asks before downloading it, extracts
//! and verifies. Each section of the IR then opens as an editor tab, and the
//! inspector shows whatever row is selected.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui_kit::component::Disableable as _;
use gpui_kit::component::Sizable as _;
use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::text::TextView;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::assets;
use crate::discord::{self, Presence};
use crate::engine::{Cancel, DllEntry, Doc, Engine, PdbInfo, human_size};
use crate::ir::{self, Detail, Summary, Tone};

// ---- palette -----------------------------------------------------------------
const EDITOR: u32 = 0x0e1013;
const CHROME: u32 = 0x15181d;
const RAISED: u32 = 0x1c2027;
const HOVER: u32 = 0x22272f;
const SELECT: u32 = 0x1d2a42;
const LINE: u32 = 0x262b33;
const TEXT: u32 = 0xd7dae0;
const MUTED: u32 = 0x8a919c;
const FAINT: u32 = 0x5d6470;
const ACCENT: u32 = 0x6d9cff;
const GOOD: u32 = 0x5fd4a0;
const WARN: u32 = 0xe6b450;
const BAD: u32 = 0xff7a85;
const MONO: &str = "Cascadia Mono";
/// The mark's colour (matte periwinkle, as in assets/brand).
const MARK: u32 = 0xc9d6f2;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Pe,
    Winmd,
    Electron,
    /// An IR written earlier: opened as is, nothing re-run.
    Ir,
}

#[derive(Clone)]
struct Module {
    path: PathBuf,
    name: String,
    stem: String,
    kind: Kind,
    size: u64,
}

impl Module {
    fn from_path(path: PathBuf) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy().into_owned();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let kind = if path.is_dir() || ext == "asar" || name.eq_ignore_ascii_case("index.js") {
            Kind::Electron
        } else if ext == "winmd" {
            Kind::Winmd
        } else if ext == "json" {
            Kind::Ir
        } else {
            Kind::Pe
        };
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Some(Self {
            path,
            name,
            stem,
            kind,
            size,
        })
    }
}

enum Stage {
    Choose,
    Inspecting,
    AskPdb(PdbInfo),
    Running(String),
    Ready(Arc<Summary>, PathBuf),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq)]
enum Activity {
    Module,
    Docs,
    Tools,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    /// The start page: choosing a module, then its overview.
    Start,
    /// One section of the IR (index into Summary::tables).
    Section(usize),
    /// A document; usize::MAX is the built-in guide.
    Doc(usize),
}

const GUIDE_DOC: usize = usize::MAX;

gpui_kit::actions!(
    windissect,
    [
        /// Open the "Go to" palette: jump to any row of the loaded IR by name.
        GoTo
    ]
);

/// Rows the palette shows at most.
const GOTO_LIMIT: usize = 50;
/// Rows PageUp/PageDown move by in a section list.
const PAGE_ROWS: usize = 20;

/// The guide, with where the DLL list comes from filled in: only Windows has
/// a System32 of its own to list.
macro_rules! guide {
    ($dlls_from:literal) => {
        concat!(
            "# Start here\n\nDrop a **DLL**, **EXE** or **.winmd** onto the start page, open one, \
or switch on **List Windows DLLs** and pick one ",
            $dlls_from,
            "\n\nFor a Windows binary, Windissect \
reads where its PDB lives and asks before downloading it from Microsoft's symbol server. With the PDB it \
recovers internal names, types and vtables; without it, exports only.\n\nEach part of the result opens as \
a tab. Select a row to inspect it. Everything is written to the workspace (Tools \u{2192} Open workspace). \
Nothing here is guessed: the IR keeps verified facts apart from candidates, and `verify` checks it."
        )
    };
}
#[cfg(windows)]
const GUIDE: &str = guide!("from this machine.");
#[cfg(not(windows))]
const GUIDE: &str = guide!(
    "from a mounted Windows install (WSL's /mnt/c, or a drive under /media), \
or from a folder you choose."
);

const TOOLS: [(&str, &str, &str); 7] = [
    ("Verify", "shield-check", "re-check the IR's invariants"),
    (
        "C++ headers",
        "file-code",
        "verified ABI + opt-in candidates",
    ),
    (
        "C symbol table",
        "hash",
        "mangled name \u{2192} RVA, build-pinned",
    ),
    (
        "Evidence",
        "layers",
        "verified claims apart from candidates",
    ),
    ("Rust bindings", "boxes", "a buildable FFI crate"),
    ("Docs", "book-open", "markdown reference for this module"),
    ("Strings", "binary", "printable ASCII and UTF-16"),
];

fn section_icon(title: &str) -> &'static str {
    match title {
        "Symbols" => "hash",
        "Functions" => "braces",
        "Types" => "layers",
        "VTables" => "list-tree",
        "Classes" => "boxes",
        "Enums" => "binary",
        "Claims" => "shield-check",
        "Conflicts" => "triangle-alert",
        _ => "file-text",
    }
}

pub struct Shell {
    engine: Engine,
    module: Option<Module>,
    stage: Stage,
    list_system: bool,
    system_dlls: Arc<Vec<DllEntry>>,
    /// The folder `system_dlls` came from; `None` once a search found no
    /// Windows install to list (only possible off Windows). Only shown off
    /// Windows, where it is not obvious whose System32 this is.
    #[cfg_attr(windows, allow(dead_code))]
    dll_dir: Option<PathBuf>,
    #[cfg_attr(windows, allow(dead_code))]
    dll_scanned: bool,
    dll_query: Entity<InputState>,
    dll_filtered: Vec<usize>,
    query: Entity<InputState>,
    filtered: Vec<usize>,
    selected: Option<usize>,
    docs: Vec<Doc>,
    doc_cache: HashMap<usize, SharedString>,
    activity: Activity,
    tabs: Vec<Tab>,
    active: usize,
    inspector_open: bool,
    panel_open: bool,
    log: Vec<String>,
    log_scroll: ScrollHandle,
    busy: bool,
    /// The running job: what it is doing now, since when, and how to stop it.
    step: Option<SharedString>,
    started: Option<Instant>,
    cancel: Option<Cancel>,
    /// Inspector sub-table rows shown in full: (block, row).
    expanded: HashSet<(usize, usize)>,
    /// A short confirmation in the status bar ("Copied").
    flash: Option<SharedString>,
    flash_generation: u64,
    /// The window's own focus, so key bindings reach the shell.
    focus: FocusHandle,
    /// The section list, focused by clicking a row; arrow keys move through it.
    list_focus: FocusHandle,
    section_scroll: UniformListScrollHandle,
    goto_open: bool,
    goto_query: Entity<InputState>,
    /// (section, row) matches, best first.
    goto_results: Vec<(usize, usize)>,
    goto_index: usize,
    discord: discord::Settings,
    presence: Option<Presence>,
    presence_last: Option<Option<discord::Activity>>,
    /// Unix seconds when the current module was opened (Discord's "elapsed").
    opened_at: Option<u64>,
    _subscriptions: Vec<Subscription>,
}

impl Shell {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let engine = Engine::locate();
        let dll_query = cx.new(|cx| InputState::new(window, cx).placeholder("Filter Windows DLLs"));
        let query = cx.new(|cx| InputState::new(window, cx).placeholder("Search this section"));
        let goto_query = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Go to a symbol, function, type, vtable\u{2026}")
        });
        let subscriptions = vec![
            cx.subscribe_in(&goto_query, window, |this, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.refilter_goto(cx);
                }
            }),
            cx.subscribe_in(&dll_query, window, |this, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.refilter_dlls(cx);
                }
            }),
            cx.subscribe_in(&query, window, |this, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.refilter(cx);
                }
            }),
        ];
        let docs = engine.docs();
        let mut shell = Self {
            engine,
            module: None,
            stage: Stage::Choose,
            list_system: false,
            system_dlls: Arc::new(Vec::new()),
            dll_dir: None,
            dll_scanned: false,
            dll_query,
            dll_filtered: Vec::new(),
            query,
            filtered: Vec::new(),
            selected: None,
            docs,
            doc_cache: HashMap::new(),
            activity: Activity::Module,
            tabs: vec![Tab::Start],
            active: 0,
            inspector_open: true,
            panel_open: true,
            log: Vec::new(),
            log_scroll: ScrollHandle::new(),
            busy: false,
            step: None,
            started: None,
            cancel: None,
            expanded: HashSet::new(),
            flash: None,
            flash_generation: 0,
            focus: cx.focus_handle(),
            list_focus: cx.focus_handle(),
            section_scroll: UniformListScrollHandle::new(),
            goto_open: false,
            goto_query,
            goto_results: Vec::new(),
            goto_index: 0,
            discord: discord::Settings::load(),
            presence: None,
            presence_last: None,
            opened_at: None,
            _subscriptions: subscriptions,
        };
        shell.focus.focus(window, cx);
        let cli = shell.engine.cli.display().to_string();
        shell.note(format!("engine: {cli}"));
        shell.note(format!("workspace: {}", shell.engine.workspace.display()));
        if shell.engine.fleet.is_none() {
            shell.note("PDB download needs the fleet driver from a Windissect checkout; exports-only analysis still works".into());
        }
        shell.start_presence();
        // `windissect-gui <file>`: open it straight away (also how "Open with" arrives).
        if let Some(path) = std::env::args_os()
            .nth(1)
            .map(PathBuf::from)
            .filter(|p| p.exists())
        {
            shell.open(path, cx);
        }
        shell
    }

    fn note(&mut self, line: String) {
        for l in line.lines() {
            self.log.push(l.to_string());
        }
        let excess = self.log.len().saturating_sub(2000);
        self.log.drain(..excess);
        self.log_scroll.scroll_to_bottom();
    }

    // ---- tabs ----------------------------------------------------------------

    fn current_section(&self) -> Option<usize> {
        match self.tabs.get(self.active) {
            Some(Tab::Section(i)) => Some(*i),
            _ => None,
        }
    }

    fn open_tab(&mut self, tab: Tab, cx: &mut Context<Self>) {
        let index = match self.tabs.iter().position(|t| *t == tab) {
            Some(i) => i,
            None => {
                self.tabs.push(tab);
                self.tabs.len() - 1
            }
        };
        self.activate(index, cx);
    }

    fn activate(&mut self, index: usize, cx: &mut Context<Self>) {
        if self.active != index {
            self.active = index;
            self.selected = None;
        }
        if let Some(Tab::Doc(d)) = self.tabs.get(index).copied() {
            let docs = &self.docs;
            self.doc_cache
                .entry(d)
                .or_insert_with(|| match docs.get(d) {
                    Some(doc) => std::fs::read_to_string(&doc.path)
                        .unwrap_or_default()
                        .into(),
                    None => GUIDE.into(),
                });
        }
        self.refilter(cx);
        cx.notify();
    }

    fn close_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        if index == 0 || index >= self.tabs.len() {
            return;
        }
        self.tabs.remove(index);
        let next = if self.active >= index {
            self.active.saturating_sub(1)
        } else {
            self.active
        };
        self.active = usize::MAX;
        self.activate(next.min(self.tabs.len() - 1), cx);
    }

    // ---- choosing a module ------------------------------------------------

    fn set_list_system(&mut self, on: bool, cx: &mut Context<Self>) {
        self.list_system = on;
        if on && self.system_dlls.is_empty() {
            cx.spawn(async move |this, cx| {
                let dlls = cx
                    .background_executor()
                    .spawn(async { Engine::system_dlls() })
                    .await;
                let _ = this.update(cx, |this, cx| {
                    (this.dll_dir, this.system_dlls) = (dlls.0, Arc::new(dlls.1));
                    this.dll_scanned = true;
                    this.refilter_dlls(cx);
                });
            })
            .detach();
        }
        cx.notify();
    }

    /// Lists the DLLs in a folder the user picks. Off Windows this is the way
    /// in when no mounted Windows install turned up, or the wrong one did.
    #[cfg(not(windows))]
    fn pick_dll_dir(&mut self, cx: &mut Context<Self>) {
        self.pick_path(true, "List DLLs", cx, |_, dir, cx| {
            cx.spawn(async move |this, cx| {
                let scan = dir.clone();
                let dlls = cx
                    .background_executor()
                    .spawn(async move { Engine::dlls_in(&scan) })
                    .await;
                let _ = this.update(cx, |this, cx| {
                    (this.dll_dir, this.system_dlls) = (Some(dir), Arc::new(dlls));
                    this.dll_scanned = true;
                    this.refilter_dlls(cx);
                });
            })
            .detach();
        });
    }

    fn refilter_dlls(&mut self, cx: &mut Context<Self>) {
        let query = self.dll_query.read(cx).value().to_ascii_lowercase();
        self.dll_filtered = self
            .system_dlls
            .iter()
            .enumerate()
            .filter(|(_, d)| query.is_empty() || d.name.to_ascii_lowercase().contains(&query))
            .map(|(i, _)| i)
            .collect();
        cx.notify();
    }

    fn pick_file(&mut self, cx: &mut Context<Self>) {
        self.pick_path(false, "Open", cx, Self::open);
    }

    /// Asks for one file (or folder) and hands it to `then`. On Linux the
    /// system dialog comes from the XDG file-chooser portal, which some
    /// desktops (WSLg, bare window managers) lack; zenity or kdialog stand in
    /// there, and if neither exists the output panel says why nothing opened.
    fn pick_path(
        &mut self,
        directories: bool,
        prompt: &'static str,
        cx: &mut Context<Self>,
        then: impl FnOnce(&mut Self, PathBuf, &mut Context<Self>) + 'static,
    ) {
        let answer = cx.prompt_for_paths(PathPromptOptions {
            files: !directories,
            directories,
            multiple: false,
            prompt: Some(prompt.into()),
        });
        cx.spawn(async move |this, cx| {
            let picked = match answer.await {
                Ok(Ok(paths)) => paths.and_then(|p| p.into_iter().next()),
                Ok(Err(portal_error)) => {
                    let fallback = cx
                        .background_executor()
                        .spawn(async move { dialog_program_pick(directories, prompt) })
                        .await;
                    match fallback {
                        Some(path) => path,
                        None => {
                            let _ = this.update(cx, |this, cx| {
                                this.note(format!(
                                    "\u{2717} no file dialog available: {portal_error}. \
                                     Install xdg-desktop-portal, zenity or kdialog."
                                ));
                                cx.notify();
                            });
                            None
                        }
                    }
                }
                Err(_) => None,
            };
            if let Some(path) = picked {
                let _ = this.update(cx, |this, cx| then(this, path, cx));
            }
        })
        .detach();
    }

    fn open(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(module) = Module::from_path(path) else {
            return;
        };
        self.note(format!("\u{25b8} {}", module.path.display()));
        self.opened_at = Some(discord::unix_now());
        self.module = Some(module.clone());
        self.tabs.retain(|t| !matches!(t, Tab::Section(_)));
        self.active = usize::MAX;
        self.activate(0, cx);
        match module.kind {
            Kind::Pe => {
                self.stage = Stage::Inspecting;
                let engine = self.engine.clone();
                let path = module.path.clone();
                cx.spawn(async move |this, cx| {
                    let info = cx
                        .background_executor()
                        .spawn(async move { engine.pdb_info(&path) })
                        .await;
                    let _ = this.update(cx, |this, cx| {
                        match info {
                            Some(info) if info.key.is_some() => this.stage = Stage::AskPdb(info),
                            Some(info) => {
                                this.note(info.note.unwrap_or_else(|| "no CodeView record".into()));
                                this.analyze(false, cx);
                            }
                            None => this.analyze(false, cx),
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
            Kind::Winmd | Kind::Electron | Kind::Ir => self.analyze(false, cx),
        }
        cx.notify();
    }

    fn close_module(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.module = None;
        self.stage = Stage::Choose;
        self.tabs.retain(|t| !matches!(t, Tab::Section(_)));
        self.active = usize::MAX;
        self.activate(0, cx);
    }

    // ---- analysis ----------------------------------------------------------

    fn analyze(&mut self, with_pdb: bool, cx: &mut Context<Self>) {
        let Some(module) = self.module.clone() else {
            return;
        };
        let engine = self.engine.clone();
        self.stage = Stage::Running(match (module.kind, with_pdb) {
            (Kind::Pe, true) => "Downloading the PDB, extracting and verifying".into(),
            (Kind::Pe, false) => "Extracting exports and verifying".into(),
            (Kind::Winmd, _) => "Reading WinRT metadata".into(),
            (Kind::Electron, _) => "Reading the Electron app".into(),
            (Kind::Ir, _) => "Loading the IR".into(),
        });
        let (tx, rx) = async_channel::unbounded::<Event>();
        let cancel = self.begin_job(cx);
        let job_cancel = cancel.clone();
        cx.spawn(async move |this, cx| {
            let job = cx
                .background_executor()
                .spawn(async move { run_pipeline(&engine, &module, with_pdb, &tx, &job_cancel) });
            Self::pump(&this, rx, cx).await;
            let result = job.await;
            let _ = this.update(cx, |this, cx| {
                let cancelled = cancel.is_cancelled();
                this.end_job();
                match result {
                    Ok((summary, ir_path)) => {
                        this.note(format!("IR \u{2192} {}", ir_path.display()));
                        this.stage = Stage::Ready(Arc::new(summary), ir_path);
                        this.open_tab(Tab::Section(0), cx);
                    }
                    Err(_) if cancelled => {
                        this.note("\u{2717} cancelled".into());
                        this.stage = Stage::Failed("cancelled".into());
                    }
                    Err(err) => this.stage = Stage::Failed(err),
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Marks the window busy and starts the elapsed-time tick.
    fn begin_job(&mut self, cx: &mut Context<Self>) -> Cancel {
        let cancel = Cancel::default();
        self.busy = true;
        self.panel_open = true;
        self.started = Some(Instant::now());
        self.step = None;
        self.cancel = Some(cancel.clone());
        cx.notify();
        // Redraw once a second while busy so the elapsed time moves.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                let still = this
                    .update(cx, |this, cx| {
                        cx.notify();
                        this.busy
                    })
                    .unwrap_or(false);
                if !still {
                    break;
                }
            }
        })
        .detach();
        cancel
    }

    fn end_job(&mut self) {
        self.busy = false;
        self.step = None;
        self.started = None;
        self.cancel = None;
    }

    fn cancel_job(&mut self, cx: &mut Context<Self>) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
            self.step = Some("Cancelling\u{2026}".into());
            cx.notify();
        }
    }

    /// Applies streamed events to the window until the job closes the channel.
    async fn pump(this: &WeakEntity<Self>, rx: async_channel::Receiver<Event>, cx: &mut AsyncApp) {
        while let Ok(first) = rx.recv().await {
            // Drain whatever else is already queued: one redraw per batch.
            let mut batch = vec![first];
            while let Ok(more) = rx.try_recv() {
                batch.push(more);
                if batch.len() >= 512 {
                    break;
                }
            }
            let alive = this.update(cx, |this, cx| {
                for event in batch {
                    match event {
                        Event::Line(line) => {
                            if let Some(step) = step_from_line(&line) {
                                this.step = Some(step.into());
                            }
                            this.note(line);
                        }
                        Event::Step(step) => this.step = Some(step.into()),
                    }
                }
                cx.notify();
            });
            if alive.is_err() {
                break;
            }
        }
    }

    /// Rows of the active section whose name or columns contain the query.
    fn refilter(&mut self, cx: &mut Context<Self>) {
        let (Stage::Ready(summary, _), Some(section)) = (&self.stage, self.current_section())
        else {
            return;
        };
        let Some(table) = summary.tables.get(section) else {
            return;
        };
        let query = self.query.read(cx).value().to_ascii_lowercase();
        self.filtered = table
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                query.is_empty()
                    || row.name.to_ascii_lowercase().contains(&query)
                    || row.search.to_ascii_lowercase().contains(&query)
                    || row
                        .cols
                        .iter()
                        .any(|c| c.to_ascii_lowercase().contains(&query))
            })
            .map(|(i, _)| i)
            .collect();
        if self
            .selected
            .is_some_and(|sel| !self.filtered.contains(&sel))
        {
            self.selected = None;
        }
        cx.notify();
    }

    // ---- tools ---------------------------------------------------------------

    fn ready_ir(&self) -> Option<PathBuf> {
        match &self.stage {
            Stage::Ready(_, path) => Some(path.clone()),
            _ => None,
        }
    }

    fn tool(&mut self, label: &'static str, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let (Some(ir_path), Some(module)) = (self.ready_ir(), self.module.clone()) else {
            return;
        };
        let engine = self.engine.clone();
        self.note(format!("\u{25b8} {label}"));
        let (tx, rx) = async_channel::unbounded::<Event>();
        let cancel = self.begin_job(cx);
        let job_cancel = cancel.clone();
        cx.spawn(async move |this, cx| {
            let job = cx.background_executor().spawn(async move {
                run_tool(&engine, label, &ir_path, &module, &tx, &job_cancel)
            });
            Self::pump(&this, rx, cx).await;
            let (ok, out) = job.await;
            let _ = this.update(cx, |this, cx| {
                let cancelled = cancel.is_cancelled();
                this.end_job();
                if cancelled {
                    this.note(format!("\u{2717} {label} cancelled"));
                } else if let Some(out) = out {
                    this.note(format!(
                        "{} {}",
                        if ok {
                            "\u{2713} wrote"
                        } else {
                            "\u{2717} failed:"
                        },
                        out.display()
                    ));
                } else if !ok {
                    this.note(format!("\u{2717} {label} failed"));
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn copy(&mut self, text: String, cx: &mut Context<Self>) {
        let preview: String = text.chars().take(48).collect();
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.flash = Some(
            format!(
                "Copied {preview}{}",
                if preview.len() >= 48 { "\u{2026}" } else { "" }
            )
            .into(),
        );
        self.flash_generation += 1;
        let generation = self.flash_generation;
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(1800))
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.flash_generation == generation {
                    this.flash = None;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    // ---- keyboard ------------------------------------------------------------

    /// Ctrl+P: the palette over a loaded IR; before that, the DLL filter.
    fn open_goto(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(self.stage, Stage::Ready(..)) {
            if self.module.is_none() {
                self.set_list_system(true, cx);
                self.activate(0, cx);
                self.dll_query
                    .update(cx, |state, cx| state.focus(window, cx));
            }
            return;
        }
        self.goto_open = true;
        self.goto_index = 0;
        self.goto_query.update(cx, |state, cx| {
            state.set_value("", window, cx);
            state.focus(window, cx);
        });
        self.refilter_goto(cx);
        cx.notify();
    }

    fn close_goto(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.goto_open = false;
        self.focus.focus(window, cx);
        cx.notify();
    }

    /// Best matches across every section: exact, then prefix, then substring
    /// of the name, then substring of the full text, then the query's letters
    /// in order. Shorter names win ties.
    fn refilter_goto(&mut self, cx: &mut Context<Self>) {
        self.goto_index = 0;
        self.goto_results.clear();
        let Stage::Ready(summary, _) = &self.stage else {
            return;
        };
        let query = self.goto_query.read(cx).value().to_lowercase();
        if query.is_empty() {
            cx.notify();
            return;
        }
        let mut scored: Vec<(u32, usize, usize, usize)> = Vec::new();
        for (s, table) in summary.tables.iter().enumerate() {
            for (r, row) in table.rows.iter().enumerate() {
                let name = row.name.to_lowercase();
                let score = if name == query {
                    0
                } else if name.starts_with(&query) {
                    1
                } else if let Some(at) = name.find(&query) {
                    // A match at a word boundary (`Class::Method`) reads better.
                    let boundary = at == 0 || !name.as_bytes()[at - 1].is_ascii_alphanumeric();
                    if boundary { 2 } else { 3 }
                } else if row.search.to_lowercase().contains(&query) {
                    4
                } else if is_subsequence(&query, &name) {
                    5
                } else {
                    continue;
                };
                scored.push((score, row.name.len(), s, r));
            }
        }
        scored.sort_unstable();
        self.goto_results = scored
            .into_iter()
            .take(GOTO_LIMIT)
            .map(|(_, _, s, r)| (s, r))
            .collect();
        cx.notify();
    }

    fn goto_move(&mut self, delta: isize, cx: &mut Context<Self>) {
        let len = self.goto_results.len();
        if len > 0 {
            self.goto_index = (self.goto_index as isize + delta).rem_euclid(len as isize) as usize;
            cx.notify();
        }
    }

    /// Opens the chosen row: its section's tab, the row selected and scrolled
    /// into view, the list focused so the arrow keys carry on from there.
    fn goto_accept(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(&(section, row)) = self.goto_results.get(self.goto_index) else {
            return;
        };
        self.goto_open = false;
        self.open_tab(Tab::Section(section), cx);
        if !self.filtered.contains(&row) {
            self.query
                .update(cx, |state, cx| state.set_value("", window, cx));
            self.refilter(cx);
        }
        self.select_row(row, cx);
        self.list_focus.focus(window, cx);
        cx.notify();
    }

    fn select_row(&mut self, row: usize, cx: &mut Context<Self>) {
        if self.selected != Some(row) {
            self.expanded.clear();
        }
        self.selected = Some(row);
        self.inspector_open = true;
        if let Some(position) = self.filtered.iter().position(|&r| r == row) {
            self.section_scroll
                .scroll_to_item(position, ScrollStrategy::Nearest);
        }
        cx.notify();
    }

    /// Arrow keys, PageUp/PageDown, Home/End in a focused section list.
    fn list_key(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let len = self.filtered.len();
        if len == 0 {
            return;
        }
        let at = self
            .selected
            .and_then(|sel| self.filtered.iter().position(|&r| r == sel));
        let last = len - 1;
        let next = match (event.keystroke.key.as_str(), at) {
            ("down", None) | ("home", _) => 0,
            ("up", None) | ("end", _) => last,
            ("down", Some(i)) => (i + 1).min(last),
            ("up", Some(i)) => i.saturating_sub(1),
            ("pagedown", i) => (i.unwrap_or(0) + PAGE_ROWS).min(last),
            ("pageup", i) => i.unwrap_or(0).saturating_sub(PAGE_ROWS),
            _ => return,
        };
        cx.stop_propagation();
        self.select_row(self.filtered[next], cx);
    }

    // ---- Discord presence --------------------------------------------------

    fn start_presence(&mut self) {
        self.presence = None;
        self.presence_last = None;
        if !self.discord.presence {
            return;
        }
        match self.discord.client_id.clone() {
            Some(id) => self.presence = Some(Presence::start(id)),
            None => self.note(format!(
                "Discord presence is off: no client ID. Set WINDISSECT_DISCORD_CLIENT_ID or \"discord_client_id\" in {} (see gui/DISCORD.md); \"discord_show_names\": false hides module and class names.",
                discord::Settings::path_display()
            )),
        }
    }

    fn toggle_presence(&mut self, cx: &mut Context<Self>) {
        self.discord.presence = !self.discord.presence;
        self.discord.save();
        self.start_presence();
        cx.notify();
    }

    fn toggle_presence_names(&mut self, cx: &mut Context<Self>) {
        self.discord.show_names = !self.discord.show_names;
        self.discord.save();
        self.presence_last = None;
        cx.notify();
    }

    /// What Discord should show right now.
    fn current_activity(&self) -> discord::Activity {
        let names = self.discord.show_names;
        let tab = self.tabs.get(self.active).copied().unwrap_or(Tab::Start);
        if let Tab::Doc(d) = tab {
            let title = self
                .docs
                .get(d)
                .map_or("Start here".to_string(), |doc| doc.title.clone());
            return discord::Activity {
                details: "Reading docs".into(),
                state: if names {
                    title
                } else {
                    "Windissect documentation".into()
                },
                start: self.opened_at,
                small_image: Some("docs".into()),
                small_text: Some("Docs".into()),
            };
        }
        let Some(module) = &self.module else {
            return discord::Activity {
                details: "Choosing a module".into(),
                state: "Windissect".into(),
                start: None,
                small_image: None,
                small_text: None,
            };
        };
        let details = if names {
            format!("Inspecting {}", module.name)
        } else {
            "Inspecting a module".into()
        };
        let (state, small) = match &self.stage {
            Stage::Ready(summary, _) => {
                let section = self.current_section().and_then(|i| summary.tables.get(i));
                match section {
                    Some(table) => {
                        let row = self.selected.and_then(|i| table.rows.get(i));
                        let state = match (row, names) {
                            (Some(row), true) => format!(
                                "{} \u{203a} {}",
                                table.title,
                                row.title.clone().unwrap_or_else(|| row.name.clone())
                            ),
                            _ => format!("{} \u{b7} {} rows", table.title, table.rows.len()),
                        };
                        (state, Some(table.title))
                    }
                    None => {
                        let symbols = summary.tables.first().map_or(0, |t| t.rows.len());
                        let pdb = if summary.binary.pdb_name.is_some() {
                            "PDB"
                        } else {
                            "exports only"
                        };
                        (format!("{symbols} symbols \u{b7} {pdb}"), None)
                    }
                }
            }
            Stage::Running(_) | Stage::Inspecting => ("Analyzing\u{2026}".to_string(), None),
            Stage::AskPdb(_) => ("Fetching symbols".to_string(), None),
            Stage::Failed(_) => ("Analysis failed".to_string(), None),
            Stage::Choose => ("Windissect".to_string(), None),
        };
        discord::Activity {
            details,
            state,
            start: self.opened_at,
            small_image: small.map(str::to_ascii_lowercase),
            small_text: small.map(str::to_string),
        }
    }

    /// Sends the activity when it changed; the worker rate-limits.
    fn sync_presence(&mut self) {
        let Some(presence) = &self.presence else {
            return;
        };
        let now = Some(self.current_activity());
        if self.presence_last.as_ref() != Some(&now) {
            presence.set(now.clone());
            self.presence_last = Some(now);
        }
    }

    /// Picks where IR and outputs go; saved to settings.json, used from now on.
    fn pick_workspace(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.pick_path(true, "Use as workspace", cx, |this, dir, cx| {
            let _ = std::fs::create_dir_all(dir.join("ir"));
            match crate::engine::save_workspace(&dir) {
                Ok(()) => {
                    this.engine.workspace = dir.clone();
                    this.note(format!("workspace: {} (saved)", dir.display()));
                }
                Err(err) => this.note(format!(
                    "\u{2717} could not save the workspace setting: {err}"
                )),
            }
            cx.notify();
        });
    }

    fn open_workspace(&mut self) {
        let opener = if cfg!(windows) {
            "explorer.exe"
        } else {
            "xdg-open"
        };
        if let Err(err) = std::process::Command::new(opener)
            .arg(&self.engine.workspace)
            .spawn()
        {
            self.note(format!(
                "\u{2717} could not open {}: {err}",
                self.engine.workspace.display()
            ));
        }
    }
}

/// A dialog program for Linux desktops without the file-chooser portal:
/// zenity, then kdialog. `None` when neither is installed; `Some(None)` when
/// the user cancelled.
fn dialog_program_pick(directories: bool, title: &str) -> Option<Option<PathBuf>> {
    if cfg!(windows) {
        return None;
    }
    let title_arg = format!("--title={title}");
    let zenity: Vec<&str> = if directories {
        vec!["--file-selection", "--directory", &title_arg]
    } else {
        vec!["--file-selection", &title_arg]
    };
    let kdialog: Vec<&str> = if directories {
        vec!["--getexistingdirectory", "."]
    } else {
        vec!["--getopenfilename", "."]
    };
    for (program, args) in [("zenity", zenity), ("kdialog", kdialog)] {
        let Ok(out) = std::process::Command::new(program).args(&args).output() else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return Some((out.status.success() && !text.is_empty()).then(|| PathBuf::from(text)));
    }
    None
}

/// What a running job reports to the window.
enum Event {
    Line(String),
    Step(&'static str),
}

/// The step a line of fleet output announces, if any. The fleet runs
/// download, extraction and verification as one command.
fn step_from_line(line: &str) -> Option<&'static str> {
    let l = line.to_ascii_lowercase();
    if l.contains("pdb")
        && (l.contains("download") || l.contains("fetch") || l.contains("symbol server"))
    {
        Some("Downloading PDB\u{2026}")
    } else if l.contains("verif") {
        Some("Verifying\u{2026}")
    } else if l.contains("extract") && !l.contains("extractor binary") {
        Some("Extracting\u{2026}")
    } else {
        None
    }
}

/// Runs one command, forwarding its output as lines. Blocking; runs on a
/// background thread. Ends the forwarding before returning.
fn stream_step(
    engine: &Engine,
    program: &Path,
    args: &[String],
    events: &async_channel::Sender<Event>,
    cancel: &Cancel,
    cap: Option<usize>,
) -> bool {
    let name = program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let _ = events.send_blocking(Event::Line(format!("$ {name} {}", args.join(" "))));
    let (lines_tx, lines_rx) = async_channel::unbounded::<String>();
    let forward_events = events.clone();
    // Re-labels raw lines as events; with a cap, the rest are only counted.
    let relay = std::thread::spawn(move || {
        let mut seen = 0usize;
        while let Ok(line) = lines_rx.recv_blocking() {
            seen += 1;
            if cap.is_none_or(|c| seen <= c) {
                let _ = forward_events.send_blocking(Event::Line(line));
            }
        }
        if let Some(c) = cap.filter(|c| seen > *c) {
            let _ = forward_events.send_blocking(Event::Line(format!(
                "\u{2026} {} more lines not shown",
                seen - c
            )));
        }
    });
    let ok = engine.stream(program, args, &lines_tx, cancel);
    drop(lines_tx);
    let _ = relay.join();
    ok
}

/// Runs the analysis for one module on a background thread, streaming its
/// output. Returns the loaded IR summary or why it failed.
fn run_pipeline(
    engine: &Engine,
    module: &Module,
    with_pdb: bool,
    events: &async_channel::Sender<Event>,
    cancel: &Cancel,
) -> Result<(Summary, PathBuf), String> {
    let ir_path = match module.kind {
        Kind::Ir => module.path.clone(),
        Kind::Electron => engine.ir_path(&format!("{}-electron", module.stem)),
        _ => engine.ir_path(&module.stem),
    };
    let steps: Vec<(&'static str, PathBuf, Vec<String>)> = match (module.kind, with_pdb) {
        (Kind::Pe, true) => {
            let Some(fleet) = engine.fleet.clone() else {
                return Err(
                    "PDB download needs the fleet driver from a Windissect checkout".into(),
                );
            };
            vec![(
                "Downloading PDB\u{2026}",
                fleet,
                vec![
                    "--root".into(),
                    engine.workspace.display().to_string(),
                    "--extractor".into(),
                    engine.cli.display().to_string(),
                    "pull".into(),
                    module.path.display().to_string(),
                ],
            )]
        }
        (Kind::Pe, false) => vec![
            (
                "Extracting\u{2026}",
                engine.cli.clone(),
                vec![
                    "extract".into(),
                    module.path.display().to_string(),
                    "--out".into(),
                    ir_path.display().to_string(),
                ],
            ),
            (
                "Verifying\u{2026}",
                engine.cli.clone(),
                vec![
                    "verify".into(),
                    "--ir".into(),
                    ir_path.display().to_string(),
                ],
            ),
        ],
        (Kind::Winmd, _) => vec![(
            "Reading WinRT metadata\u{2026}",
            engine.cli.clone(),
            vec![
                "winmd".into(),
                module.path.display().to_string(),
                "--out".into(),
                ir_path.display().to_string(),
            ],
        )],
        (Kind::Ir, _) => Vec::new(),
        (Kind::Electron, _) => vec![(
            "Reading the Electron app\u{2026}",
            engine.cli.clone(),
            vec![
                "electron".into(),
                module.path.display().to_string(),
                "--out".into(),
                ir_path.display().to_string(),
            ],
        )],
    };
    for (step, program, args) in steps {
        if cancel.is_cancelled() {
            return Err("cancelled".into());
        }
        let _ = events.send_blocking(Event::Step(step));
        if !stream_step(engine, &program, &args, events, cancel, None) {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            let name = program
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            return Err(format!(
                "{name} {} failed; see Output",
                args.first().cloned().unwrap_or_default()
            ));
        }
    }
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    let _ = events.send_blocking(Event::Step("Loading the IR\u{2026}"));
    ir::load(&ir_path)
        .map(|summary| (summary, ir_path.clone()))
        .map_err(|err| format!("could not read {}: {err}", ir_path.display()))
}

/// Runs one tool on the loaded IR, streaming its output. Returns whether it
/// succeeded and the folder it wrote, if it writes one.
fn run_tool(
    engine: &Engine,
    label: &str,
    ir_path: &Path,
    module: &Module,
    events: &async_channel::Sender<Event>,
    cancel: &Cancel,
) -> (bool, Option<PathBuf>) {
    let ir = ir_path.display().to_string();
    let (command, out): (&str, Option<PathBuf>) = match label {
        "C++ headers" => (
            "emit-headers",
            Some(engine.out_dir("headers", &module.stem)),
        ),
        "C symbol table" => ("emit-syms", Some(engine.out_dir("syms", &module.stem))),
        "Evidence" => (
            "emit-evidence",
            Some(engine.out_dir("evidence", &module.stem)),
        ),
        "Rust bindings" => ("emit-rust", Some(engine.out_dir("rust", &module.stem))),
        "Docs" => ("doc", Some(engine.out_dir("docs", &module.stem))),
        "Verify" => ("verify", None),
        "Strings" => ("strings", None),
        _ => {
            let _ = events.send_blocking(Event::Line(format!("unknown tool {label}")));
            return (false, None);
        }
    };
    let _ = events.send_blocking(Event::Step(match command {
        "verify" => "Verifying\u{2026}",
        "strings" => "Scanning strings\u{2026}",
        _ => "Writing\u{2026}",
    }));
    let (args, cap): (Vec<String>, Option<usize>) = match (&out, command) {
        (_, "strings") => (
            vec!["strings".into(), module.path.display().to_string()],
            Some(400),
        ),
        (None, _) => (vec![command.into(), "--ir".into(), ir], None),
        (Some(dir), _) => {
            let _ = std::fs::create_dir_all(dir);
            (
                vec![
                    command.into(),
                    "--ir".into(),
                    ir,
                    "--out".into(),
                    dir.display().to_string(),
                ],
                None,
            )
        }
    };
    let ok = stream_step(engine, &engine.cli, &args, events, cancel, cap);
    (ok, out)
}

// ---- rendering ---------------------------------------------------------------

fn icon(name: &str, color: u32) -> Svg {
    svg()
        .path(assets::icon(name))
        .size(px(15.))
        .flex_shrink_0()
        .text_color(rgb(color))
}

fn caption(text: impl Into<SharedString>) -> Div {
    div().text_xs().text_color(rgb(FAINT)).child(text.into())
}

fn tone_color(tone: Tone) -> u32 {
    match tone {
        Tone::Good => GOOD,
        Tone::Neutral => MUTED,
        Tone::Weak => WARN,
        Tone::Bad => BAD,
    }
}

/// A sidebar row: icon, label, optional right-hand text.
fn side_row(
    id: impl Into<ElementId>,
    glyph: &str,
    text: impl Into<SharedString>,
    right: String,
    active: bool,
    enabled: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(26.))
        .mx_1()
        .px_2()
        .flex()
        .items_center()
        .gap_2()
        .rounded(px(4.))
        .text_sm()
        .text_color(rgb(if !enabled {
            FAINT
        } else if active {
            TEXT
        } else {
            MUTED
        }))
        .when(active, |d| d.bg(rgb(SELECT)))
        .when(enabled && !active, |d| {
            d.hover(|s| s.bg(rgb(HOVER)).text_color(rgb(TEXT)))
        })
        .when(enabled, |d| d.cursor_pointer())
        .child(icon(
            glyph,
            if active {
                ACCENT
            } else if enabled {
                MUTED
            } else {
                FAINT
            },
        ))
        .child(div().flex_1().min_w_0().truncate().child(text.into()))
        .when(!right.is_empty(), |d| {
            d.child(
                div()
                    .font_family(MONO)
                    .text_xs()
                    .text_color(rgb(FAINT))
                    .child(right),
            )
        })
}

fn panel_header(title: &'static str) -> Div {
    div()
        .h(px(32.))
        .flex_shrink_0()
        .px_3()
        .flex()
        .items_center()
        .gap_2()
        .text_xs()
        .text_color(rgb(FAINT))
        .child(title)
}

impl Shell {
    fn render_activity_bar(&mut self, cx: &mut Context<Self>) -> Div {
        let item = |cx: &mut Context<Self>,
                    id: &'static str,
                    glyph: &'static str,
                    activity: Activity,
                    active: bool| {
            div()
                .id(id)
                .size(px(44.))
                .flex()
                .items_center()
                .justify_center()
                .border_l_2()
                .border_color(rgb(if active { ACCENT } else { CHROME }))
                .cursor_pointer()
                .child(
                    svg()
                        .path(assets::icon(glyph))
                        .size(px(20.))
                        .text_color(rgb(if active { TEXT } else { FAINT })),
                )
                .hover(|s| s.bg(rgb(RAISED)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.activity = activity;
                    cx.notify();
                }))
        };
        let current = self.activity;
        div()
            .w(px(44.))
            .h_full()
            .flex()
            .flex_col()
            .bg(rgb(CHROME))
            .border_r_1()
            .border_color(rgb(LINE))
            .child(
                div()
                    .size(px(44.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(
                        svg()
                            .path(assets::icon("windissect-mark"))
                            .size(px(24.))
                            .text_color(rgb(MARK)),
                    ),
            )
            .child(item(
                cx,
                "act-module",
                "package",
                Activity::Module,
                current == Activity::Module,
            ))
            .child(item(
                cx,
                "act-docs",
                "book-open",
                Activity::Docs,
                current == Activity::Docs,
            ))
            .child(item(
                cx,
                "act-tools",
                "wrench",
                Activity::Tools,
                current == Activity::Tools,
            ))
    }

    fn render_sidebar(&mut self, cx: &mut Context<Self>) -> Div {
        let body = match self.activity {
            Activity::Module => self.render_module_tree(cx),
            Activity::Docs => self.render_doc_list(cx),
            Activity::Tools => self.render_tool_list(cx),
        };
        let title = match self.activity {
            Activity::Module => "MODULE",
            Activity::Docs => "DOCS",
            Activity::Tools => "TOOLS",
        };
        div()
            .w(px(250.))
            .h_full()
            .flex()
            .flex_col()
            .bg(rgb(CHROME))
            .border_r_1()
            .border_color(rgb(LINE))
            .child(panel_header(title))
            .child(body)
    }

    fn render_module_tree(&mut self, cx: &mut Context<Self>) -> Div {
        let mut list = div().flex().flex_col().gap_0p5();
        list = list
            .child(
                side_row(
                    "open-file",
                    "upload",
                    "Open file\u{2026}",
                    String::new(),
                    false,
                    !self.busy,
                )
                .on_click(cx.listener(|this, _, _, cx| this.pick_file(cx))),
            )
            .child(
                side_row(
                    "system-dlls",
                    "cpu",
                    "Windows DLLs",
                    String::new(),
                    false,
                    !self.busy,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.close_module(cx);
                    this.set_list_system(true, cx);
                })),
            );
        let Some(module) = self.module.clone() else {
            return list;
        };
        list = list.child(div().h(px(10.))).child(
            side_row(
                "module",
                "package",
                module.name.clone(),
                String::new(),
                self.tabs.get(self.active) == Some(&Tab::Start),
                true,
            )
            .on_click(cx.listener(|this, _, _, cx| this.activate(0, cx))),
        );
        match &self.stage {
            Stage::Ready(summary, _) => {
                let current = self.current_section();
                for (i, table) in summary.tables.iter().enumerate() {
                    let row = side_row(
                        ("section", i),
                        section_icon(table.title),
                        table.title,
                        table.rows.len().to_string(),
                        current == Some(i),
                        true,
                    )
                    .pl(px(26.))
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.open_tab(Tab::Section(i), cx)),
                    );
                    list = list.child(row);
                }
            }
            Stage::Running(_) | Stage::Inspecting => {
                list = list.child(div().pl(px(34.)).py_1().child(caption("working\u{2026}")));
            }
            Stage::AskPdb(_) => {
                list = list.child(
                    div()
                        .pl(px(34.))
                        .py_1()
                        .child(caption("waiting: download the PDB?")),
                );
            }
            Stage::Failed(_) => {
                list = list.child(
                    div()
                        .pl(px(34.))
                        .py_1()
                        .text_xs()
                        .text_color(rgb(BAD))
                        .child("analysis failed"),
                );
            }
            Stage::Choose => {}
        }
        list
    }

    fn render_doc_list(&mut self, cx: &mut Context<Self>) -> Div {
        let active = self.tabs.get(self.active).copied();
        let entries = std::iter::once((GUIDE_DOC, "Start here".to_string()))
            .chain(
                self.docs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| (i, d.title.clone())),
            )
            .map(|(i, title)| {
                side_row(
                    ("doc", i),
                    "file-text",
                    title,
                    String::new(),
                    active == Some(Tab::Doc(i)),
                    true,
                )
                .on_click(cx.listener(move |this, _, _, cx| this.open_tab(Tab::Doc(i), cx)))
            })
            .collect::<Vec<_>>();
        div().flex().flex_col().gap_0p5().children(entries)
    }

    fn render_tool_list(&mut self, cx: &mut Context<Self>) -> Div {
        let ready = self.ready_ir().is_some() && !self.busy;
        let rows = TOOLS
            .iter()
            .map(|(name, glyph, hint)| {
                let name: &'static str = name;
                div()
                    .flex()
                    .flex_col()
                    .child(
                        side_row(name, glyph, name, String::new(), false, ready).when(ready, |d| {
                            d.on_click(cx.listener(move |this, _, _, cx| this.tool(name, cx)))
                        }),
                    )
                    .child(div().pl(px(34.)).pb_1().child(caption(*hint)))
            })
            .collect::<Vec<_>>();
        div()
            .flex_1()
            .flex()
            .flex_col()
            .child(div().flex().flex_col().children(rows))
            .child(div().flex_1())
            .child(div().px_3().pb_1().child(caption("DISCORD")))
            .child(
                side_row(
                    "discord-presence",
                    "terminal",
                    "Discord presence",
                    if self.discord.client_id.is_none() {
                        "no ID".into()
                    } else if self.discord.presence {
                        "on".into()
                    } else {
                        "off".into()
                    },
                    false,
                    true,
                )
                .on_click(cx.listener(|this, _, _, cx| this.toggle_presence(cx))),
            )
            .child(
                side_row(
                    "discord-names",
                    "file-text",
                    "Show module names",
                    if self.discord.show_names {
                        "on".into()
                    } else {
                        "off".into()
                    },
                    false,
                    self.discord.presence,
                )
                .when(self.discord.presence, |d| {
                    d.on_click(cx.listener(|this, _, _, cx| this.toggle_presence_names(cx)))
                }),
            )
            .child(div().h(px(8.)))
            .child(
                div()
                    .pb_2()
                    .child(
                        side_row(
                            "open-ws",
                            "folder-open",
                            "Open workspace",
                            String::new(),
                            false,
                            true,
                        )
                        .on_click(cx.listener(|this, _, _, _| this.open_workspace())),
                    )
                    .child(
                        side_row(
                            "pick-ws",
                            "folder-open",
                            "Workspace folder\u{2026}",
                            String::new(),
                            false,
                            !self.busy,
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.pick_workspace(cx))),
                    )
                    .child(
                        div()
                            .px_3()
                            .pt_1()
                            .child(caption(self.engine.workspace.display().to_string()).truncate()),
                    ),
            )
            .when(!ready, |d| {
                d.child(
                    div()
                        .px_3()
                        .pb_3()
                        .child(caption("Tools run on an analysed module.")),
                )
            })
    }

    fn render_tab_strip(&mut self, cx: &mut Context<Self>) -> Div {
        let summary = match &self.stage {
            Stage::Ready(summary, _) => Some(summary.clone()),
            _ => None,
        };
        let tabs = self
            .tabs
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, tab)| {
                let active = i == self.active;
                let (glyph, title): (&str, String) = match tab {
                    Tab::Start => (
                        "package",
                        self.module
                            .as_ref()
                            .map_or("Start".into(), |m| m.name.clone()),
                    ),
                    Tab::Section(s) => {
                        let title = summary
                            .as_ref()
                            .and_then(|x| x.tables.get(s))
                            .map_or("", |t| t.title);
                        (section_icon(title), title.to_string())
                    }
                    Tab::Doc(d) => (
                        "file-text",
                        self.docs
                            .get(d)
                            .map_or("Start here".into(), |doc| doc.title.clone()),
                    ),
                };
                div()
                    .id(("tab", i))
                    .h_full()
                    .px_3()
                    .flex()
                    .items_center()
                    .gap_2()
                    .border_r_1()
                    .border_color(rgb(LINE))
                    .bg(rgb(if active { EDITOR } else { CHROME }))
                    .when(active, |d| d.border_t_1().border_color(rgb(ACCENT)))
                    .text_sm()
                    .text_color(rgb(if active { TEXT } else { MUTED }))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| this.activate(i, cx)))
                    .child(icon(glyph, if active { ACCENT } else { FAINT }))
                    .child(title)
                    .when(tab != Tab::Start, |d| {
                        d.child(
                            div()
                                .id(("close", i))
                                .rounded(px(3.))
                                .hover(|s| s.bg(rgb(HOVER)))
                                .child(
                                    svg()
                                        .path(assets::icon("x"))
                                        .size(px(12.))
                                        .text_color(rgb(FAINT)),
                                )
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    cx.stop_propagation();
                                    this.close_tab(i, cx);
                                })),
                        )
                    })
            })
            .collect::<Vec<_>>();
        div()
            .h(px(34.))
            .flex_shrink_0()
            .flex()
            .bg(rgb(CHROME))
            .border_b_1()
            .border_color(rgb(LINE))
            .children(tabs)
    }

    fn render_start(&mut self, cx: &mut Context<Self>) -> Div {
        let Some(module) = self.module.clone() else {
            return self.render_chooser(cx);
        };
        let kind = match module.kind {
            Kind::Pe => "PE image",
            Kind::Winmd => "WinRT metadata",
            Kind::Electron => "Electron app",
            Kind::Ir => "Windissect IR",
        };
        let head = div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .text_2xl()
                    .text_color(rgb(TEXT))
                    .child(module.name.clone()),
            )
            .child(caption(format!(
                "{kind} \u{b7} {} \u{b7} {}",
                human_size(module.size),
                module.path.display()
            )));
        let body: Div = match &self.stage {
            Stage::Choose => div(),
            Stage::Inspecting => div()
                .text_sm()
                .text_color(rgb(MUTED))
                .child("Reading the image\u{2026}"),
            Stage::Running(what) => {
                let step = self.step.clone();
                let elapsed = self.started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_sm()
                            .text_color(rgb(TEXT))
                            .child(div().size(px(7.)).rounded_full().bg(rgb(ACCENT)))
                            .child(format!("{what}\u{2026}"))
                            .child(caption(format!("{elapsed}s"))),
                    )
                    .when_some(step, |d, step| {
                        d.child(
                            div()
                                .pl(px(15.))
                                .text_xs()
                                .text_color(rgb(MUTED))
                                .child(step),
                        )
                    })
                    .child(
                        div().pl(px(15.)).flex().child(
                            Button::new("cancel-run")
                                .small()
                                .outline()
                                .label("Cancel")
                                .on_click(
                                    cx.listener(|this, _: &ClickEvent, _, cx| this.cancel_job(cx)),
                                ),
                        ),
                    )
            }
            Stage::Failed(err) => div()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_sm().text_color(rgb(BAD)).child(err.clone()))
                .child(
                    div().flex().child(
                        Button::new("retry")
                            .small()
                            .label("Try again, exports only")
                            .on_click(
                                cx.listener(|this, _: &ClickEvent, _, cx| this.analyze(false, cx)),
                            ),
                    ),
                ),
            Stage::AskPdb(info) => {
                let fleet = self.engine.fleet.is_some();
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(px(760.))
                    .p_4()
                    .rounded(px(8.))
                    .border_1()
                    .border_color(rgb(LINE))
                    .bg(rgb(CHROME))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(icon("download", ACCENT))
                            .child(div().text_color(rgb(TEXT)).child("Public symbols are available")),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child("With the PDB, Windissect recovers internal names, types and vtables. Without it, exports only."),
                    )
                    .child(
                        div()
                            .font_family(MONO)
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(format!("{}  {}", info.pdb_name.clone().unwrap_or_default(), info.key.clone().unwrap_or_default())),
                    )
                    .child(div().font_family(MONO).text_xs().text_color(rgb(FAINT)).child(info.url.clone().unwrap_or_default()))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("pdb-yes")
                                    .primary()
                                    .small()
                                    .label("Download PDB and analyze")
                                    .disabled(!fleet)
                                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.analyze(true, cx))),
                            )
                            .child(
                                Button::new("pdb-no")
                                    .ghost()
                                    .small()
                                    .label("Exports only")
                                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.analyze(false, cx))),
                            ),
                    )
                    .when(!fleet, |d| d.child(caption("PDB download needs the fleet driver from a Windissect checkout")))
            }
            Stage::Ready(summary, _) => {
                let b = &summary.binary;
                let facts = [
                    ("Machine", b.machine.clone().unwrap_or_default()),
                    (
                        "Image size",
                        b.image_size.map(human_size).unwrap_or_default(),
                    ),
                    ("PDB", b.pdb_name.clone().unwrap_or_else(|| "none".into())),
                    ("PDB GUID", b.pdb_guid.clone().unwrap_or_default()),
                    (
                        "Imports",
                        if b.dependencies.is_empty() {
                            "none".into()
                        } else {
                            b.dependencies.join(", ")
                        },
                    ),
                ];
                let cards = summary
                    .tables
                    .iter()
                    .enumerate()
                    .map(|(i, table)| {
                        div()
                            .id(("overview", i))
                            .w(px(168.))
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .rounded(px(6.))
                            .border_1()
                            .border_color(rgb(LINE))
                            .bg(rgb(CHROME))
                            .cursor_pointer()
                            .hover(|s| s.border_color(rgb(ACCENT)))
                            .on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.open_tab(Tab::Section(i), cx)
                                }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(icon(section_icon(table.title), MUTED))
                                    .child(
                                        div().text_sm().text_color(rgb(MUTED)).child(table.title),
                                    ),
                            )
                            .child(
                                div()
                                    .text_xl()
                                    .font_family(MONO)
                                    .text_color(rgb(TEXT))
                                    .child(table.rows.len().to_string()),
                            )
                    })
                    .collect::<Vec<_>>();
                div()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(
                        div().flex().flex_col().gap_1().children(
                            facts
                                .into_iter()
                                .filter(|(_, v)| !v.is_empty())
                                .map(|(k, v)| {
                                    div()
                                        .flex()
                                        .gap_3()
                                        .text_sm()
                                        .child(
                                            div()
                                                .w(px(90.))
                                                .flex_shrink_0()
                                                .text_color(rgb(FAINT))
                                                .child(k),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .font_family(MONO)
                                                .text_xs()
                                                .text_color(rgb(TEXT))
                                                .child(v),
                                        )
                                }),
                        ),
                    )
                    .child(div().flex().flex_wrap().gap_2().children(cards))
            }
        };
        div()
            .flex()
            .flex_col()
            .gap_6()
            .p_6()
            .child(head)
            .child(body)
    }

    fn render_chooser(&mut self, cx: &mut Context<Self>) -> Div {
        let drop_zone = div()
            .id("drop")
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_2()
            .h(px(if self.list_system { 110. } else { 220. }))
            .rounded(px(8.))
            .border_1()
            .border_dashed()
            .border_color(rgb(LINE))
            .bg(rgb(CHROME))
            .drag_over::<ExternalPaths>(|style, _, _, _| {
                style.border_color(rgb(ACCENT)).bg(rgb(RAISED))
            })
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                if let Some(path) = paths.paths().first() {
                    this.open(path.clone(), cx);
                }
            }))
            .child(icon("upload", FAINT))
            .child(
                div()
                    .text_color(rgb(TEXT))
                    .child("Drop a DLL, EXE, .winmd, Electron app or IR .json"),
            )
            .child(
                div().flex().gap_2().child(
                    Button::new("open")
                        .small()
                        .outline()
                        .label("Open file\u{2026}")
                        .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.pick_file(cx))),
                ),
            );
        let switch = Switch::new("list-system")
            .checked(self.list_system)
            .label("List Windows DLLs")
            .on_click(
                cx.listener(|this, checked: &bool, _, cx| this.set_list_system(*checked, cx)),
            );
        let brand = div()
            .flex()
            .items_center()
            .gap_3()
            .child(
                svg()
                    .path(assets::icon("windissect-mark"))
                    .size(px(40.))
                    .text_color(rgb(MARK)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(div().text_xl().text_color(rgb(TEXT)).child("Windissect"))
                    .child(caption(
                        "Take Windows apart: symbols, types, vtables, proofs.",
                    )),
            );
        let mut body = div()
            .flex()
            .flex_col()
            .gap_4()
            .p_6()
            .size_full()
            .child(brand)
            .child(drop_zone)
            .child(switch);
        if self.list_system {
            let total = self.system_dlls.len();
            let count = self.dll_filtered.len();
            let mut header = div()
                .flex()
                .items_center()
                .gap_3()
                .child(div().w(px(360.)).child(Input::new(&self.dll_query).small()));
            #[cfg(windows)]
            {
                header = header.child(caption(format!("{count} of {total}")));
            }
            // Off Windows the list is somebody else's System32, or none at
            // all, so say which, and let the user point at one instead.
            #[cfg(not(windows))]
            {
                let where_from = match (&self.dll_dir, self.dll_scanned) {
                    (Some(dir), _) => format!("{count} of {total} in {}", dir.display()),
                    (None, true) => "No Windows install found under /mnt, /media or \
                                     /run/media. Choose a folder of DLLs instead."
                        .to_string(),
                    (None, false) => format!("{count} of {total}"),
                };
                header = header.child(caption(where_from)).child(
                    Button::new("dll-dir")
                        .small()
                        .outline()
                        .label("Choose folder\u{2026}")
                        .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.pick_dll_dir(cx))),
                );
            }
            body = body.child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .gap_2()
                    .child(header)
                    .child(
                        uniform_list(
                            "dlls",
                            count,
                            cx.processor(move |this, range: Range<usize>, _, cx| {
                                range
                                    .filter_map(|row| {
                                        let entry = this
                                            .system_dlls
                                            .get(*this.dll_filtered.get(row)?)?
                                            .clone();
                                        let path = entry.path.clone();
                                        Some(
                                            div()
                                                .id(("dll", row))
                                                .w_full()
                                                .h(px(26.))
                                                .px_2()
                                                .flex()
                                                .items_center()
                                                .gap_3()
                                                .rounded(px(4.))
                                                .hover(|s| s.bg(rgb(HOVER)))
                                                .cursor_pointer()
                                                .child(icon("file-code", FAINT))
                                                .child(
                                                    div()
                                                        .flex_1()
                                                        .min_w_0()
                                                        .truncate()
                                                        .font_family(MONO)
                                                        .text_xs()
                                                        .text_color(rgb(TEXT))
                                                        .child(entry.name),
                                                )
                                                .child(
                                                    div()
                                                        .w(px(80.))
                                                        .flex_shrink_0()
                                                        .text_xs()
                                                        .text_color(rgb(FAINT))
                                                        .child(human_size(entry.size)),
                                                )
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.open(path.clone(), cx)
                                                })),
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        )
                        .w_full()
                        .flex_1(),
                    ),
            );
        }
        body
    }

    fn render_section(&mut self, section: usize, cx: &mut Context<Self>) -> Div {
        let Stage::Ready(summary, _) = &self.stage else {
            return div();
        };
        let Some(table) = summary.tables.get(section) else {
            return div();
        };
        let headers = table.headers;
        let widths = table.widths;
        let total = table.rows.len();
        let empty = table.empty;
        let count = self.filtered.len();
        let mut tally = [0usize; 4];
        for row in &table.rows {
            tally[match row.tone {
                Tone::Good => 0,
                Tone::Neutral => 1,
                Tone::Weak => 2,
                Tone::Bad => 3,
            }] += 1;
        }
        let chip = |tone: Tone, label: &'static str, n: usize| {
            div()
                .flex()
                .items_center()
                .gap_1p5()
                .px_2()
                .py_0p5()
                .rounded(px(4.))
                .bg(rgb(RAISED))
                .child(div().size(px(6.)).rounded_full().bg(rgb(tone_color(tone))))
                .child(
                    div()
                        .font_family(MONO)
                        .text_xs()
                        .text_color(rgb(TEXT))
                        .child(n.to_string()),
                )
                .child(caption(label))
        };
        let heading = div()
            .flex_shrink_0()
            .px_4()
            .pt_3()
            .pb_2()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(icon(section_icon(table.title), ACCENT))
                    .child(div().text_base().text_color(rgb(TEXT)).child(table.title))
                    .child(div().flex_1())
                    .when(tally[0] > 0, |d| {
                        d.child(chip(Tone::Good, "verified", tally[0]))
                    })
                    .when(tally[1] > 0, |d| {
                        d.child(chip(Tone::Neutral, "likely", tally[1]))
                    })
                    .when(tally[2] > 0, |d| {
                        d.child(chip(Tone::Weak, "weak", tally[2]))
                    })
                    .when(tally[3] > 0, |d| {
                        d.child(chip(Tone::Bad, "conflicting", tally[3]))
                    }),
            )
            .child(caption(table.description));
        let toolbar = div()
            .h(px(38.))
            .flex_shrink_0()
            .px_4()
            .flex()
            .items_center()
            .gap_3()
            .child(div().w(px(340.)).child(Input::new(&self.query).small()))
            .child(caption(if count == total {
                format!("{total} rows")
            } else {
                format!("{count} of {total}")
            }));
        let mut header = div()
            .h(px(26.))
            .flex_shrink_0()
            .px_4()
            .flex()
            .items_center()
            .gap_3()
            .bg(rgb(CHROME))
            .border_y_1()
            .border_color(rgb(LINE))
            .child(div().w(px(6.)).flex_shrink_0())
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_xs()
                    .text_color(rgb(FAINT))
                    .child("NAME"),
            );
        for (h, w) in headers.iter().zip(widths) {
            if w > 0. {
                header = header.child(
                    div()
                        .flex_shrink_0()
                        .w(px(w))
                        .text_xs()
                        .text_color(rgb(FAINT))
                        .child(h.to_uppercase()),
                );
            }
        }
        let rows: AnyElement = if total == 0 {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_sm()
                .text_color(rgb(FAINT))
                .child(empty)
                .into_any_element()
        } else {
            uniform_list(
                ("rows", section),
                count,
                cx.processor(move |this, range: Range<usize>, _, cx| {
                    let (Stage::Ready(summary, _), Some(section)) =
                        (&this.stage, this.current_section())
                    else {
                        return Vec::new();
                    };
                    let Some(table) = summary.tables.get(section) else {
                        return Vec::new();
                    };
                    let widths = table.widths;
                    range
                        .filter_map(|row| {
                            let index = *this.filtered.get(row)?;
                            let item = table.rows.get(index)?;
                            let selected = this.selected == Some(index);
                            let mut line = div()
                                .id(("row", index))
                                .w_full()
                                .h(px(24.))
                                .px_4()
                                .flex()
                                .items_center()
                                .gap_3()
                                .cursor_pointer()
                                .when(selected, |d| d.bg(rgb(SELECT)))
                                .when(!selected, |d| d.hover(|s| s.bg(rgb(HOVER))))
                                .child(
                                    div()
                                        .flex_shrink_0()
                                        .size(px(6.))
                                        .rounded_full()
                                        .bg(rgb(tone_color(item.tone))),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .truncate()
                                        .font_family(MONO)
                                        .text_xs()
                                        .text_color(rgb(if item.tone == Tone::Weak {
                                            MUTED
                                        } else {
                                            TEXT
                                        }))
                                        .child(item.name.clone()),
                                );
                            for (i, w) in widths.iter().enumerate() {
                                if *w > 0. {
                                    line = line.child(
                                        div()
                                            .flex_shrink_0()
                                            .w(px(*w))
                                            .truncate()
                                            .font_family(MONO)
                                            .text_xs()
                                            .text_color(rgb(if i == 2 { FAINT } else { MUTED }))
                                            .child(item.cols[i].clone()),
                                    );
                                }
                            }
                            Some(line.on_click(cx.listener(move |this, _, window, cx| {
                                if this.selected != Some(index) {
                                    this.expanded.clear();
                                }
                                this.selected = Some(index);
                                this.inspector_open = true;
                                this.list_focus.focus(window, cx);
                                cx.notify();
                            })))
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(&self.section_scroll)
            .w_full()
            .flex_1()
            .into_any_element()
        };
        let rows = div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .track_focus(&self.list_focus)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _, cx| this.list_key(event, cx)))
            .child(rows);
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(heading)
            .child(toolbar)
            .child(header)
            .child(rows)
    }

    fn render_doc(&mut self, doc: usize) -> Div {
        let text = self.doc_cache.get(&doc).cloned().unwrap_or_default();
        div().size_full().child(
            div()
                .id(("doc-scroll", doc))
                .size_full()
                .overflow_y_scroll()
                .px_8()
                .py_6()
                .child(
                    div()
                        .max_w(px(860.))
                        .text_sm()
                        .child(TextView::markdown(("doc-text", doc), text)),
                ),
        )
    }

    fn render_inspector(&mut self, cx: &mut Context<Self>) -> Option<Div> {
        let section = self.current_section()?;
        if !self.inspector_open {
            return None;
        }
        let Stage::Ready(summary, _) = &self.stage else {
            return None;
        };
        let table = summary.tables.get(section)?;
        let header = panel_header("INSPECTOR").child(div().flex_1()).child(
            div()
                .id("close-inspector")
                .rounded(px(3.))
                .hover(|s| s.bg(rgb(HOVER)))
                .cursor_pointer()
                .child(
                    svg()
                        .path(assets::icon("x"))
                        .size(px(13.))
                        .text_color(rgb(FAINT)),
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.inspector_open = false;
                    cx.notify();
                })),
        );
        let body = match self.selected.and_then(|i| table.rows.get(i)) {
            None => div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .px_4()
                .text_sm()
                .text_color(rgb(FAINT))
                .child("Select a row to inspect it")
                .into_any_element(),
            Some(item) => {
                // A small copy button; `id` must be unique in the inspector.
                let copy_button = |cx: &mut Context<Self>, id: ElementId, text: String| {
                    div()
                        .id(id)
                        .flex_shrink_0()
                        .p_0p5()
                        .rounded(px(3.))
                        .cursor_pointer()
                        .hover(|s| s.bg(rgb(HOVER)))
                        .child(
                            svg()
                                .path(assets::icon("copy"))
                                .size(px(12.))
                                .text_color(rgb(FAINT)),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.copy(text.clone(), cx);
                        }))
                };
                let mut props = div().flex().flex_col().gap_0p5();
                let mut blocks = div().flex().flex_col().gap_4();
                for (block, detail) in item.detail.iter().enumerate() {
                    match detail {
                        Detail::Prop(key, value) => {
                            let value_copy = value.clone();
                            props = props.child(
                                div()
                                    .id(("prop", block))
                                    .group("prop")
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .px_1()
                                    .py_0p5()
                                    .rounded(px(3.))
                                    .cursor_pointer()
                                    .hover(|s| s.bg(rgb(HOVER)))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.copy(value_copy.clone(), cx)
                                    }))
                                    .child(
                                        div()
                                            .w(px(92.))
                                            .flex_shrink_0()
                                            .text_xs()
                                            .text_color(rgb(FAINT))
                                            .child(key.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .font_family(MONO)
                                            .text_xs()
                                            .text_color(rgb(TEXT))
                                            .child(value.clone()),
                                    )
                                    .child(
                                        div()
                                            .invisible()
                                            .group_hover("prop", |s| s.visible())
                                            .child(
                                                svg()
                                                    .path(assets::icon("copy"))
                                                    .size(px(12.))
                                                    .text_color(rgb(FAINT)),
                                            ),
                                    ),
                            );
                        }
                        Detail::Fold(key, value) => {
                            let open = self.expanded.contains(&(block, usize::MAX));
                            let lines: Vec<&str> = value.lines().collect();
                            let more = lines.len() > 1 || value.len() > 90;
                            let shown: Vec<String> = if open {
                                lines.iter().map(|l| l.to_string()).collect()
                            } else {
                                vec![lines.first().map(|l| l.to_string()).unwrap_or_default()]
                            };
                            blocks = blocks.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(caption(key.clone()))
                                            .child(div().flex_1())
                                            .when(more, |d| {
                                                d.child(
                                                    div()
                                                        .id(ElementId::Name(
                                                            format!("fold-{block}").into(),
                                                        ))
                                                        .px_1()
                                                        .rounded(px(3.))
                                                        .cursor_pointer()
                                                        .hover(|s| s.bg(rgb(HOVER)))
                                                        .text_xs()
                                                        .text_color(rgb(ACCENT))
                                                        .child(if open {
                                                            "show less".to_string()
                                                        } else if lines.len() > 1 {
                                                            format!(
                                                                "show all ({} lines)",
                                                                lines.len()
                                                            )
                                                        } else {
                                                            "show all".to_string()
                                                        })
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                if !this
                                                                    .expanded
                                                                    .remove(&(block, usize::MAX))
                                                                {
                                                                    this.expanded.insert((
                                                                        block,
                                                                        usize::MAX,
                                                                    ));
                                                                }
                                                                cx.notify();
                                                            },
                                                        )),
                                                )
                                            })
                                            .child(copy_button(
                                                cx,
                                                ElementId::Name(
                                                    format!("copy-fold-{block}").into(),
                                                ),
                                                value.clone(),
                                            )),
                                    )
                                    .child(
                                        div()
                                            .p_2()
                                            .rounded(px(4.))
                                            .bg(rgb(EDITOR))
                                            .font_family(MONO)
                                            .text_xs()
                                            .text_color(rgb(TEXT))
                                            .children(shown.into_iter().map(|l| {
                                                if open {
                                                    div().child(l)
                                                } else {
                                                    div().truncate().child(l)
                                                }
                                            })),
                                    ),
                            );
                        }
                        Detail::Code(key, value) => {
                            blocks = blocks.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .child(div().flex_1().child(caption(key.clone())))
                                            .child(copy_button(
                                                cx,
                                                ElementId::Name(
                                                    format!("copy-code-{block}").into(),
                                                ),
                                                value.clone(),
                                            )),
                                    )
                                    .child(
                                        div()
                                            .p_2()
                                            .rounded(px(4.))
                                            .bg(rgb(EDITOR))
                                            .font_family(MONO)
                                            .text_xs()
                                            .text_color(rgb(TEXT))
                                            .children(
                                                value.lines().map(|l| div().child(l.to_string())),
                                            ),
                                    ),
                            );
                        }
                        Detail::Table {
                            title,
                            headers,
                            rows,
                            notes,
                            total,
                        } => {
                            let columns = headers.len().max(1);
                            let head = div()
                                .flex()
                                .gap_2()
                                .px_2()
                                .py_1()
                                .border_b_1()
                                .border_color(rgb(LINE))
                                .children(headers.iter().enumerate().map(|(i, h)| {
                                    div()
                                        .when(i + 1 == columns, |d| d.flex_1().min_w_0())
                                        .when(i + 1 != columns, |d| d.w(px(58.)).flex_shrink_0())
                                        .text_xs()
                                        .text_color(rgb(FAINT))
                                        .child(h.to_uppercase())
                                }));
                            let mut body_rows = Vec::new();
                            for (r, cells) in rows.iter().enumerate() {
                                let open = self.expanded.contains(&(block, r));
                                let note = notes.get(r).filter(|n| !n.is_empty()).cloned();
                                // What a copy of this row carries: the full name if there is one.
                                let full = note.clone().unwrap_or_else(|| cells.join("  "));
                                let mut row = div()
                                    .id(ElementId::Name(format!("sub-{block}-{r}").into()))
                                    .flex()
                                    .flex_col()
                                    .gap_0p5()
                                    .px_2()
                                    .py_1()
                                    .rounded(px(3.))
                                    .cursor_pointer()
                                    .when(open, |d| d.bg(rgb(SELECT)))
                                    .when(!open, |d| d.hover(|s| s.bg(rgb(HOVER))))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if !this.expanded.remove(&(block, r)) {
                                            this.expanded.insert((block, r));
                                        }
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .children(cells.iter().enumerate().map(|(i, cell)| {
                                                div()
                                                    .when(i + 1 == columns, |d| {
                                                        d.flex_1().min_w_0()
                                                    })
                                                    .when(i + 1 != columns, |d| {
                                                        d.w(px(58.)).flex_shrink_0()
                                                    })
                                                    .when(!open, |d| d.truncate())
                                                    .font_family(MONO)
                                                    .text_xs()
                                                    .text_color(rgb(if i == 0 {
                                                        ACCENT
                                                    } else {
                                                        TEXT
                                                    }))
                                                    .child(cell.clone())
                                            }))
                                            .when(open, |d| {
                                                d.child(copy_button(
                                                    cx,
                                                    ElementId::Name(
                                                        format!("copy-sub-{block}-{r}").into(),
                                                    ),
                                                    full.clone(),
                                                ))
                                            }),
                                    );
                                if let Some(note) = note.filter(|n| Some(n) != cells.last()) {
                                    row = if open {
                                        row.child(
                                            div()
                                                .pt_1()
                                                .font_family(MONO)
                                                .text_xs()
                                                .text_color(rgb(MUTED))
                                                .children(
                                                    note.lines()
                                                        .map(|l| div().child(l.to_string())),
                                                ),
                                        )
                                    } else {
                                        let first = note.lines().next().unwrap_or("").to_string();
                                        row.child(
                                            div()
                                                .truncate()
                                                .font_family(MONO)
                                                .text_xs()
                                                .text_color(rgb(FAINT))
                                                .child(first),
                                        )
                                    };
                                }
                                body_rows.push(row);
                            }
                            blocks = blocks.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(caption(if *total > rows.len() {
                                        format!("{title} \u{b7} first {} of {total} \u{b7} click a row to expand", rows.len())
                                    } else {
                                        format!("{title} \u{b7} {total} \u{b7} click a row to expand")
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .rounded(px(4.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .bg(rgb(EDITOR))
                                            .child(head)
                                            .children(body_rows),
                                    ),
                            );
                        }
                    }
                }
                let name = item.name.clone();
                let heading = item.title.clone().unwrap_or_else(|| name.clone());
                let subtitle = item.subtitle.clone();
                div()
                    .id(("inspect", section * 10_000_000 + self.selected.unwrap_or(0)))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .px_3()
                    .pb_4()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .size(px(7.))
                                            .rounded_full()
                                            .bg(rgb(tone_color(item.tone))),
                                    )
                                    .child(div().flex_1().child(caption(table.title)))
                                    .child(copy_button(cx, "copy-name".into(), name.clone())),
                            )
                            .child(
                                div()
                                    .font_family(MONO)
                                    .text_base()
                                    .text_color(rgb(TEXT))
                                    .child(heading),
                            )
                            .when_some(subtitle, |d, sub| {
                                d.child(
                                    div()
                                        .font_family(MONO)
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child(sub),
                                )
                            }),
                    )
                    .child(props)
                    .child(blocks)
                    .into_any_element()
            }
        };
        Some(
            div()
                .w(px(400.))
                .h_full()
                .flex()
                .flex_col()
                .bg(rgb(CHROME))
                .border_l_1()
                .border_color(rgb(LINE))
                .child(header)
                .child(body),
        )
    }

    fn render_output(&mut self, cx: &mut Context<Self>) -> Option<Div> {
        if !self.panel_open {
            return None;
        }
        let header = panel_header("OUTPUT").child(div().flex_1()).child(
            div()
                .id("close-output")
                .rounded(px(3.))
                .hover(|s| s.bg(rgb(HOVER)))
                .cursor_pointer()
                .child(
                    svg()
                        .path(assets::icon("x"))
                        .size(px(13.))
                        .text_color(rgb(FAINT)),
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.panel_open = false;
                    cx.notify();
                })),
        );
        let lines = self.log.iter().cloned().collect::<Vec<_>>();
        Some(
            div()
                .h(px(180.))
                .flex_shrink_0()
                .flex()
                .flex_col()
                .bg(rgb(EDITOR))
                .border_t_1()
                .border_color(rgb(LINE))
                .child(header)
                .child(
                    div()
                        .id("output")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .track_scroll(&self.log_scroll)
                        .px_3()
                        .pb_2()
                        .font_family(MONO)
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .children(lines.into_iter().map(|l| {
                            let color = if l.starts_with('$') || l.starts_with('\u{25b8}') {
                                ACCENT
                            } else if l.contains('\u{2713}') || l.contains("[\u{221a}]") {
                                GOOD
                            } else if l.contains('\u{2717}')
                                || l.to_ascii_lowercase().contains("error")
                            {
                                BAD
                            } else {
                                MUTED
                            };
                            div().text_color(rgb(color)).child(l)
                        })),
                ),
        )
    }

    fn render_status_bar(&mut self, cx: &mut Context<Self>) -> Div {
        let (text, color) = if self.busy {
            ("working", ACCENT)
        } else if matches!(self.stage, Stage::Ready(..)) {
            ("ready", GOOD)
        } else if matches!(self.stage, Stage::Failed(_)) {
            ("failed", BAD)
        } else {
            ("idle", FAINT)
        };
        let module = self
            .module
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let pdb = match &self.stage {
            Stage::Ready(summary, _) => summary
                .binary
                .pdb_name
                .clone()
                .unwrap_or_else(|| "no PDB".into()),
            _ => String::new(),
        };
        let toggle =
            |cx: &mut Context<Self>, id: &'static str, glyph: &'static str, on: bool, which: u8| {
                div()
                    .id(id)
                    .px_1()
                    .rounded(px(3.))
                    .hover(|s| s.bg(rgb(HOVER)))
                    .cursor_pointer()
                    .child(
                        svg()
                            .path(assets::icon(glyph))
                            .size(px(13.))
                            .text_color(rgb(if on { TEXT } else { FAINT })),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if which == 0 {
                            this.panel_open = !this.panel_open;
                        } else {
                            this.inspector_open = !this.inspector_open;
                        }
                        cx.notify();
                    }))
            };
        div()
            .h(px(24.))
            .flex_shrink_0()
            .px_3()
            .flex()
            .items_center()
            .gap_4()
            .bg(rgb(CHROME))
            .border_t_1()
            .border_color(rgb(LINE))
            .text_xs()
            .text_color(rgb(MUTED))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1p5()
                    .child(div().size(px(6.)).rounded_full().bg(rgb(color)))
                    .child(text),
            )
            .when_some(self.flash.clone(), |d, flash| {
                d.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .text_color(rgb(GOOD))
                        .child(
                            svg()
                                .path(assets::icon("check"))
                                .size(px(12.))
                                .text_color(rgb(GOOD)),
                        )
                        .child(flash),
                )
            })
            .when(self.busy, |d| {
                let step = self
                    .step
                    .clone()
                    .unwrap_or_else(|| "Working\u{2026}".into());
                let elapsed = self.started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                d.child(div().text_color(rgb(TEXT)).child(step))
                    .child(div().font_family(MONO).child(format!("{elapsed}s")))
                    .child(
                        div()
                            .id("status-cancel")
                            .px_1()
                            .rounded(px(3.))
                            .cursor_pointer()
                            .text_color(rgb(BAD))
                            .hover(|s| s.bg(rgb(HOVER)))
                            .child("Cancel")
                            .on_click(cx.listener(|this, _, _, cx| this.cancel_job(cx))),
                    )
            })
            .when(!module.is_empty(), |d| d.child(module))
            .when(!pdb.is_empty(), |d| d.child(pdb))
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(
                        div()
                            .px_1()
                            .rounded(px(3.))
                            .bg(rgb(RAISED))
                            .font_family(MONO)
                            .text_color(rgb(MUTED))
                            .child("Ctrl+P"),
                    )
                    .child(div().text_color(rgb(FAINT)).child(
                        if matches!(self.stage, Stage::Ready(..)) {
                            "go to"
                        } else {
                            "find a DLL"
                        },
                    )),
            )
            .child(toggle(
                cx,
                "toggle-output",
                "panel-bottom",
                self.panel_open,
                0,
            ))
            .child(toggle(
                cx,
                "toggle-inspector",
                "panel-right",
                self.inspector_open,
                1,
            ))
    }
}

/// `abc` matches `aXbYc`: every query character, in order.
fn is_subsequence(query: &str, text: &str) -> bool {
    let mut chars = text.chars();
    query.chars().all(|q| chars.any(|c| c == q))
}

impl Shell {
    /// The "Go to" palette, floating over the editor.
    fn render_goto(&mut self, cx: &mut Context<Self>) -> Stateful<Div> {
        let titles: Vec<&'static str> = match &self.stage {
            Stage::Ready(summary, _) => summary.tables.iter().map(|t| t.title).collect(),
            _ => Vec::new(),
        };
        let query_empty = self.goto_query.read(cx).value().is_empty();
        let rows = self
            .goto_results
            .iter()
            .enumerate()
            .filter_map(|(i, &(section, row))| {
                let Stage::Ready(summary, _) = &self.stage else {
                    return None;
                };
                let item = summary.tables.get(section)?.rows.get(row)?;
                let title = titles.get(section).copied().unwrap_or("");
                let active = i == self.goto_index;
                Some(
                    div()
                        .id(("goto", i))
                        .h(px(28.))
                        .px_3()
                        .flex()
                        .items_center()
                        .gap_2()
                        .rounded(px(4.))
                        .cursor_pointer()
                        .when(active, |d| d.bg(rgb(SELECT)))
                        .when(!active, |d| d.hover(|s| s.bg(rgb(HOVER))))
                        .child(icon(
                            section_icon(title),
                            if active { ACCENT } else { FAINT },
                        ))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .font_family(MONO)
                                .text_xs()
                                .text_color(rgb(TEXT))
                                .child(item.name.clone()),
                        )
                        .child(
                            div()
                                .flex_shrink_0()
                                .text_xs()
                                .text_color(rgb(FAINT))
                                .child(title),
                        )
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.goto_index = i;
                            this.goto_accept(window, cx);
                        })),
                )
            })
            .collect::<Vec<_>>();
        let footer = if query_empty {
            "Type a name. \u{2191}\u{2193} to move \u{b7} Enter to open \u{b7} Esc to close"
                .to_string()
        } else if rows.is_empty() {
            "No matches".to_string()
        } else {
            format!(
                "{}{} \u{b7} \u{2191}\u{2193} to move \u{b7} Enter to open \u{b7} Esc to close",
                rows.len(),
                if rows.len() == GOTO_LIMIT {
                    "+ matches, best first"
                } else {
                    " matches"
                }
            )
        };
        // A dim backdrop over the editor; clicking it closes the palette.
        div()
            .id("goto-backdrop")
            .absolute()
            .inset_0()
            .flex()
            .justify_center()
            .items_start()
            .pt(px(56.))
            .bg(rgba(0x0000_0066))
            .occlude()
            .on_click(cx.listener(|this, _, window, cx| this.close_goto(window, cx)))
            .child(
                div()
                    .id("goto")
                    .w(px(640.))
                    .max_h(px(460.))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_2()
                    .rounded(px(8.))
                    .border_1()
                    .border_color(rgb(LINE))
                    .bg(rgb(CHROME))
                    .shadow_lg()
                    .occlude()
                    // Keys reach the palette before the text box: Up/Down/Enter/Esc are ours.
                    .capture_key_down(cx.listener(|this, event: &KeyDownEvent, window, cx| {
                        match event.keystroke.key.as_str() {
                            "up" => this.goto_move(-1, cx),
                            "down" => this.goto_move(1, cx),
                            "enter" => this.goto_accept(window, cx),
                            "escape" => this.close_goto(window, cx),
                            _ => return,
                        }
                        cx.stop_propagation();
                    }))
                    .on_click(|_, _, cx| cx.stop_propagation())
                    .child(Input::new(&self.goto_query))
                    .child(
                        div()
                            .id("goto-results")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .children(rows),
                    )
                    .child(div().px_2().pb_1().child(caption(footer))),
            )
    }
}

impl Render for Shell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Every state change re-renders, so this is where presence follows it.
        self.sync_presence();
        let activity = self.render_activity_bar(cx);
        let sidebar = self.render_sidebar(cx);
        let tabs = self.render_tab_strip(cx);
        let content = match self.tabs.get(self.active).copied().unwrap_or(Tab::Start) {
            Tab::Start => self.render_start(cx),
            Tab::Section(s) => self.render_section(s, cx),
            Tab::Doc(d) => self.render_doc(d),
        };
        let inspector = self.render_inspector(cx);
        let output = self.render_output(cx);
        let status = self.render_status_bar(cx);
        let goto = self.goto_open.then(|| self.render_goto(cx));
        div()
            .key_context("Windissect")
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &GoTo, window, cx| this.open_goto(window, cx)))
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(EDITOR))
            .text_color(rgb(TEXT))
            .text_sm()
            // Linux windows are client decorated (see main.rs), so the title
            // and the minimize, maximize and close buttons are drawn here.
            .when(cfg!(target_os = "linux"), |d| {
                d.child(
                    gpui_kit::component::TitleBar::new()
                        .bg(rgb(CHROME))
                        .border_color(rgb(LINE))
                        .child(div().text_color(rgb(MUTED)).child("Windissect")),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(activity)
                    .child(sidebar)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .relative()
                            .child(tabs)
                            .child(div().flex_1().min_h_0().bg(rgb(EDITOR)).child(content))
                            .children(output)
                            .children(goto),
                    )
                    .children(inspector),
            )
            .child(status)
    }
}
