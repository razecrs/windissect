//! Embeds the Windissect icon into the exe. Uses llvm-rc (LLVM) or rc.exe
//! (Windows SDK), whichever is on PATH; without either the exe simply keeps
//! the default icon, so the build never fails for want of a resource compiler.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=windissect.rc");
    println!("cargo:rerun-if-changed=assets/brand/windissect.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("windissect.res");
    let compiled = ["llvm-rc", "rc"].iter().any(|tool| {
        Command::new(tool)
            .args(["/nologo", "/fo"])
            .arg(&out)
            .arg("windissect.rc")
            .status()
            .is_ok_and(|s| s.success())
    });
    if compiled {
        // MSVC's linker takes a compiled .res directly.
        println!("cargo:rustc-link-arg-bins={}", out.display());
    } else {
        println!("cargo:warning=no resource compiler (llvm-rc or rc) found; the exe keeps the default icon");
    }
}
