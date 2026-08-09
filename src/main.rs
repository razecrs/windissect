//! Windissect: target-independent Windows PE/PDB dissection pipeline.

mod demangle;
mod diff;
mod docs;
mod emit;
mod emit_asm;
mod emit_evidence;
mod emit_rust;
mod emit_syms;
mod enrich;
mod evidencepack;
mod extract;
mod history;
mod layoutinfer;
mod model;
mod oracle;
mod pdbsym;
mod pdbtype;
mod reflection;
mod rtti;
mod typeparse;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};
use model::{Database, Provenance, SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Dissect Windows PE binaries and matching PDBs into trustworthy IR and bindings")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract exports + PDB internals, demangle + structure, write the IR.
    Extract {
        dll: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        out: PathBuf,
        /// PDB for internal names; used if present.
        #[arg(long)]
        pdb: Option<PathBuf>,
    },
    /// Emit a reconstructed C++ header for a single class.
    EmitCpp {
        /// e.g. DirectUI::Element
        qualified: String,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit C++ header files for all classes into headers/.
    EmitHeaders {
        #[arg(short, long, default_value = "headers")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit buildable Rust FFI crate into rust/.
    EmitRust {
        #[arg(short, long, default_value = "rust")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit a plain C23 symbol table (mangled name -> RVA) for runtime resolution.
    EmitSyms {
        #[arg(short, long, default_value = "syms")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
        /// Symbol table stem name (defaults to the IR filename stem).
        #[arg(long)]
        name: Option<String>,
        /// PE image base for RVA math (verified against the binary).
        #[arg(long)]
        base: Option<u64>,
    },
    /// Emit strict verified claims separately from evidence-only candidates.
    EmitEvidence {
        #[arg(short, long, default_value = "evidence")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit annotated native-syntax assembly from canonical instruction IR.
    EmitAsm {
        #[arg(short, long, default_value = "disassembly.asm")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// List the classes in the IR by member count.
    Classes {
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Validate the IR against invariants + ground-truth spot checks.
    Verify {
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
        /// Optional target-specific golden checks (currently: dui70).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Generate codebase and API markdown documentation (like Doxygen).
    Doc {
        #[arg(short, long, default_value = "docs")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Compare two IR databases and report Windows build changes.
    Diff {
        old: PathBuf,
        new: PathBuf,
        /// JSON report path. Prints JSON to stdout when omitted.
        #[arg(long)]
        json_out: Option<PathBuf>,
        /// Optional human-readable Markdown report path.
        #[arg(long)]
        markdown_out: Option<PathBuf>,
    },
    /// Store an IR in the per-target build archive and diff it from the previous build.
    RecordBuild {
        ir: PathBuf,
        #[arg(long, default_value = "history")]
        history: PathBuf,
    },
    /// Validate a manual evidence corpus used to gate an automated rule.
    ValidateEvidencePack { pack: PathBuf },
    /// Import normalized IDA/r2 observations into an IR proof graph.
    ImportOracle {
        ir: PathBuf,
        oracle: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Extract { dll, out, pdb } => extract(dll, out, pdb),
        Cmd::EmitCpp { qualified, ir } => emit_cpp(qualified, ir),
        Cmd::EmitHeaders { out, ir } => {
            let db = load_ir(&ir)?;
            let count = emit::emit_all_headers(&db, &out)?;
            println!("wrote {count} C++ class headers to {}/", out.display());
            Ok(())
        }
        Cmd::EmitRust { out, ir } => {
            let db = load_ir(&ir)?;
            emit_rust::generate_crate(&db, &out)?;
            println!("wrote Rust FFI bindings crate to {}/", out.display());
            Ok(())
        }
        Cmd::EmitSyms {
            out,
            ir,
            name,
            base,
        } => {
            let db = load_ir(&ir)?;
            let stem = name.unwrap_or_else(|| {
                ir.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "syms".into())
            });
            let image_base = base.or(db.binary.image_base).unwrap_or(0);
            emit_syms::emit_syms(&db, &stem, &out, image_base)
        }
        Cmd::EmitEvidence { out, ir } => {
            let db = load_ir(&ir)?;
            emit_evidence::emit(&db, &out)?;
            println!("wrote strict evidence surfaces to {}/", out.display());
            Ok(())
        }
        Cmd::EmitAsm { out, ir } => {
            let db = load_ir(&ir)?;
            emit_asm::emit(&db, &out)?;
            println!("wrote annotated assembly to {}", out.display());
            Ok(())
        }
        Cmd::Classes { ir } => list_classes(ir),
        Cmd::Verify { ir, profile } => {
            let db = load_ir(&ir)?;
            if !verify::run_profile(&db, profile.as_deref()) {
                std::process::exit(1);
            }
            Ok(())
        }
        Cmd::Doc { out, ir } => {
            let db = load_ir(&ir)?;
            docs::generate_all(Some(&db), &out)?;
            println!("generated documentation in {}/", out.display());
            Ok(())
        }
        Cmd::Diff {
            old,
            new,
            json_out,
            markdown_out,
        } => {
            let old_db = load_ir(&old)?;
            let new_db = load_ir(&new)?;
            anyhow::ensure!(
                old_db.binary.file.eq_ignore_ascii_case(&new_db.binary.file),
                "cannot diff different targets: {} vs {}",
                old_db.binary.file,
                new_db.binary.file
            );
            let report = diff::compare(&old_db, &new_db);
            if let Some(path) = json_out {
                diff::write_json(&report, &path)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            if let Some(path) = markdown_out {
                diff::write_markdown(&report, &path)?;
            }
            Ok(())
        }
        Cmd::RecordBuild { ir, history: root } => {
            let result = history::record(&load_ir(&ir)?, &root)?;
            println!(
                "recorded {} build {}{} in {}",
                result.target,
                result.key,
                result
                    .previous
                    .as_ref()
                    .map(|p| format!(" (changes from {p})"))
                    .unwrap_or_default(),
                result.directory.display()
            );
            Ok(())
        }
        Cmd::ValidateEvidencePack { pack } => {
            let result = evidencepack::validate_path(&pack)?;
            println!(
                "{}: {} cases, {} binaries, maturity {:?}",
                result.id, result.cases, result.binaries, result.maturity
            );
            Ok(())
        }
        Cmd::ImportOracle {
            ir,
            oracle: input,
            out,
        } => {
            let mut db = load_ir(&ir)?;
            let count = oracle::import_path(&mut db, &input)?;
            diff::atomic_write(&out, &serde_json::to_vec_pretty(&db)?)?;
            println!(
                "imported {count} oracle observations into {}",
                out.display()
            );
            Ok(())
        }
    }
}

fn load_ir(path: &PathBuf) -> Result<Database> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice::<Database>(&bytes)?.migrate())
}

fn emit_cpp(qualified: String, ir: PathBuf) -> Result<()> {
    let db = load_ir(&ir)?;
    let (ns, class) = qualified
        .rsplit_once("::")
        .unwrap_or(("", qualified.as_str()));
    print!("{}", emit::cpp_class(&db, ns, class));
    Ok(())
}

fn list_classes(ir: PathBuf) -> Result<()> {
    let db = load_ir(&ir)?;
    for (ns, class, n) in emit::classes(&db).into_iter().take(30) {
        println!("{n:5}  {ns}::{class}");
    }
    Ok(())
}

fn extract(dll: PathBuf, out: PathBuf, pdb: Option<PathBuf>) -> Result<()> {
    if let Some(path) = &pdb {
        anyhow::ensure!(path.exists(), "PDB does not exist: {}", path.display());
    }
    let mut ex = extract::from_pe(&dll, pdb.as_deref())?;

    for s in &mut ex.symbols {
        if let Some(d) = demangle::demangle(&s.mangled) {
            s.sig = demangle::parse_decl(&d);
            s.demangled = Some(d);
        }
        s.library = is_library(&s.mangled, s.demangled.as_deref());
        s.kind = demangle::classify(s);
    }

    let mut db = Database {
        schema: SCHEMA_VERSION,
        generated: date_today(),
        tool: "rust: goblin + msvc-demangler + pdb".into(),
        binary: ex.info,
        symbols: ex.symbols,
        ..Default::default()
    };

    if pdb.is_none() {
        db.type_recovery = serde_json::json!({
            "status": "unavailable-no-pdb",
            "reason": "no PDB was supplied; PE-native analysis remains available"
        });
    }

    // Phase B.5: PDB Type/Layout/VTable Recovery (if PDB provided)
    if let Some(pdb_path) = &pdb {
        let extracted_types = pdbtype::extract_types(pdb_path)?;
        pdbtype::enrich_database_with_types(&mut db, extracted_types);
    }

    // Phase C: Static Enrichment (function sizes, reloc-normalized body hashes, call graph, Win32 imports)
    let pe_bytes = std::fs::read(&dll)?;
    enrich::enrich_database(&mut db, &pe_bytes)?;

    // Phase C.5: recover MSVC vftables directly from PE data. This remains
    // available when Microsoft's public PDB has an empty/stripped TPI stream.
    rtti::recover(&mut db, &pe_bytes)?;

    // Phase C.75: conservative exact-build member-offset recovery.  This only
    // records direct `this + displacement` observations; it does not pretend
    // that an observed store is enough to assign a semantic field name.
    layoutinfer::recover(&mut db, &pe_bytes)?;

    // Phase D: Reflection System Recovery
    reflection::recover_reflection(&mut db, &pe_bytes)?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, serde_json::to_vec_pretty(&db)?)?;
    report(&db, &out);
    Ok(())
}

/// CRT/STL/ETW boilerplate — real code, but not the target's own.
fn is_library(mangled: &str, demangled: Option<&str>) -> bool {
    const M: &[&str] = &[
        "_tlg",
        "@std@@",
        "@Concurrency@@",
        "@wil@@",
        "_CRT",
        "__scrt",
        "@_Cnd",
        "@_Mtx",
        "atexit",
        "free",
        "malloc",
        "realloc",
        "calloc",
        "wcscmp",
        "wcslen",
        "wcscpy",
        "memcpy",
        "memset",
        "memmove",
        "memcmp",
        "acosf",
        "ceilf",
        "cosf",
        "expf",
        "floor",
        "floorf",
        "powf",
        "sin",
        "sinf",
        "sqrt",
        "sqrtf",
        "abs",
        "labs",
    ];
    if M.iter().any(|p| mangled == *p || mangled.contains(p)) {
        return true;
    }
    if let Some(d) = demangled {
        const D: &[&str] = &["std::", "Concurrency::", "wil::"];
        return D.iter().any(|p| d.contains(p));
    }
    false
}

fn report(db: &Database, out: &Path) {
    let (mut exported, mut internal, mut library, mut parsed) = (0, 0, 0, 0);
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for s in &db.symbols {
        if s.exported {
            exported += 1;
        } else {
            internal += 1;
        }
        if s.library {
            library += 1;
        }
        if s.sig.parse_ok {
            parsed += 1;
        }
        if !s.library {
            *by_kind.entry(format!("{:?}", s.kind)).or_default() += 1;
        }
    }
    let n = db.symbols.len();
    println!("wrote {}", out.display());
    println!(
        "binary:     {} · pdb_guid {:?}",
        db.binary.file, db.binary.pdb_guid
    );
    println!("symbols:    {n}  ({exported} exported, {internal} internal-from-pdb)");
    println!("library:    {library} boilerplate (flagged, emitters skip)");
    println!(
        "signatures: {parsed} structured ({:.1}%)",
        100.0 * parsed as f64 / n as f64
    );
    println!("target-owned symbols, by shape:");
    let mut kinds: Vec<_> = by_kind.into_iter().collect();
    kinds.sort_by_key(|item| std::cmp::Reverse(item.1));
    for (k, c) in kinds {
        println!("  {k:10} {c}");
    }
    // Provenance is preserved as the identity source (export vs pdb).
    let pdb_named = db
        .symbols
        .iter()
        .filter(|s| s.provenance == Provenance::Pdb)
        .count();
    println!(
        "provenance: {pdb_named} named from PDB, {} from export table",
        n - pdb_named
    );
}

/// UTC yyyy-mm-dd from the system clock, without a chrono dependency.
fn date_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (mut y, mut d) = (1970i64, (secs / 86_400) as i64);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let dy = if leap { 366 } else { 365 };
        if d < dy {
            break;
        }
        d -= dy;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while d >= ml[m] {
        d -= ml[m];
        m += 1;
    }
    format!("{y:04}-{:02}-{:02}", m + 1, d + 1)
}
