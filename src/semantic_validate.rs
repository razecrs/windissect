//! Compiler round-trip validation for emitted semantic surfaces.

use anyhow::{Result, ensure};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct CompilerCheck {
    pub tool: String,
    pub surface: String,
    pub status: String,
    pub detail: String,
}

pub fn run(root: &Path, stem: &str) -> Result<Vec<CompilerCheck>> {
    let directory = root.join("layout-check");
    fs::create_dir_all(&directory)?;
    let verified_header = root
        .join("verified/include")
        .join(format!("{stem}_semantic.hpp"));
    let candidate_header = root
        .join("candidates/include")
        .join(format!("{stem}_semantic_candidates.hpp"));
    let facts_header = root
        .join("verified/include")
        .join(format!("{stem}_semantic_facts.hpp"));
    ensure!(
        verified_header.is_file(),
        "missing {}",
        verified_header.display()
    );
    ensure!(
        candidate_header.is_file(),
        "missing {}",
        candidate_header.display()
    );
    ensure!(facts_header.is_file(), "missing {}", facts_header.display());
    let verified_tu = directory.join("verified.cpp");
    let candidate_tu = directory.join("candidates.cpp");
    fs::write(
        &verified_tu,
        format!(
            "#include \"../verified/include/{stem}_semantic.hpp\"\n#include \"../verified/include/{stem}_semantic_facts.hpp\"\nint main() {{ return 0; }}\n"
        ),
    )?;
    fs::write(
        &candidate_tu,
        format!(
            "#define WINDISSECT_ENABLE_CANDIDATE_SEMANTICS 1\n#include \"../candidates/include/{stem}_semantic_candidates.hpp\"\nint main() {{ return 0; }}\n"
        ),
    )?;

    let cpp_compiler = select_cpp_compiler(&directory)?;
    let checks = vec![
        run_tool(
            &cpp_compiler,
            "verified-cpp",
            &["-std=c++20", "-fsyntax-only"],
            &verified_tu,
        ),
        run_tool(
            &cpp_compiler,
            "candidate-cpp",
            &["-std=c++20", "-fsyntax-only"],
            &candidate_tu,
        ),
        run_cargo(root),
    ];
    crate::diff::atomic_write(
        &directory.join("compiler-validation.json"),
        &serde_json::to_vec_pretty(&checks)?,
    )?;
    Ok(checks)
}

fn select_cpp_compiler(directory: &Path) -> Result<String> {
    let probe = directory.join("compiler-probe.cpp");
    fs::write(&probe, "#include <cstddef>\nint main() { return 0; }\n")?;

    let mut candidates = Vec::new();
    if let Ok(configured) = std::env::var("CXX")
        && !configured.trim().is_empty()
    {
        candidates.push(configured);
    }
    candidates.extend(["g++".to_owned(), "clang++".to_owned()]);
    candidates.dedup();

    let mut failures = Vec::new();
    for compiler in candidates {
        match Command::new(&compiler)
            .args(["-std=c++20", "-fsyntax-only"])
            .arg(&probe)
            .output()
        {
            Ok(output) if output.status.success() => {
                let _ = fs::remove_file(&probe);
                return Ok(compiler);
            }
            Ok(output) => failures.push(format!(
                "{compiler}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => failures.push(format!("{compiler}: {error}")),
        }
    }

    let _ = fs::remove_file(&probe);
    anyhow::bail!(
        "no usable C++20 compiler found; set CXX to a working compiler:\n{}",
        failures.join("\n")
    )
}

fn run_tool(tool: &str, surface: &str, args: &[&str], input: &Path) -> CompilerCheck {
    let result = Command::new(tool).args(args).arg(input).output();
    match result {
        Ok(output) if output.status.success() => CompilerCheck {
            tool: tool.into(),
            surface: surface.into(),
            status: "passed".into(),
            detail: String::new(),
        },
        Ok(output) => CompilerCheck {
            tool: tool.into(),
            surface: surface.into(),
            status: "failed".into(),
            detail: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CompilerCheck {
            tool: tool.into(),
            surface: surface.into(),
            status: "skipped".into(),
            detail: "tool not found".into(),
        },
        Err(error) => CompilerCheck {
            tool: tool.into(),
            surface: surface.into(),
            status: "failed".into(),
            detail: error.to_string(),
        },
    }
}

fn run_cargo(root: &Path) -> CompilerCheck {
    // Keep generated crates and rustc metadata on the corpus volume. Large
    // Windows UI surfaces can exhaust a small system TEMP drive even when the
    // selected output root has hundreds of gigabytes free.
    let scratch = root.join("layout-check/cargo-scratch");
    let _ = fs::remove_dir_all(&scratch);
    let manifest = scratch.join("Cargo.toml");
    let source_manifest = root.join("verified/rust/Cargo.toml");
    let source_lib = root.join("verified/rust/src/lib.rs");
    let prepare = fs::create_dir_all(scratch.join("src"))
        .and_then(|()| fs::copy(source_manifest, &manifest).map(|_| ()))
        .and_then(|()| fs::copy(source_lib, scratch.join("src/lib.rs")).map(|_| ()));
    if let Err(error) = prepare {
        return CompilerCheck {
            tool: "cargo".into(),
            surface: "verified-rust".into(),
            status: "failed".into(),
            detail: error.to_string(),
        };
    }
    let result = Command::new("cargo")
        .args(["check", "--offline", "--manifest-path"])
        .arg(&manifest)
        .env("RUSTFLAGS", "-D warnings")
        .output();
    let check = match result {
        Ok(output) if output.status.success() => CompilerCheck {
            tool: "cargo".into(),
            surface: "verified-rust".into(),
            status: "passed".into(),
            detail: String::new(),
        },
        Ok(output) => CompilerCheck {
            tool: "cargo".into(),
            surface: "verified-rust".into(),
            status: "failed".into(),
            detail: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(error) => CompilerCheck {
            tool: "cargo".into(),
            surface: "verified-rust".into(),
            status: if error.kind() == std::io::ErrorKind::NotFound {
                "skipped"
            } else {
                "failed"
            }
            .into(),
            detail: error.to_string(),
        },
    };
    let _ = fs::remove_dir_all(&scratch);
    check
}
