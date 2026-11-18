#[cfg(not(target_os = "windows"))]
compile_error!("windissect-flight-recorder only supports Windows");

mod config;
mod provenance;
mod storage;

fn main() {
    let config = match config::Config::parse() {
        Ok(Some(config)) => config,
        Ok(None) => {
            config::Config::print_help();
            return;
        }
        Err(error) => {
            eprintln!("error: {error}\n");
            config::Config::print_help();
            std::process::exit(2);
        }
    };
    provenance::print_manifest();
    let store = storage::SegmentStore::open(config.output_dir.clone(), config.budget_bytes)
        .unwrap_or_else(|error| {
            eprintln!("cannot open {}: {error}", config.output_dir.display());
            std::process::exit(1);
        });
    eprintln!(
        "configured: {} MiB, {} kbps, {} fps, {}s segments, queue {}",
        store.budget() / 1024 / 1024,
        config.bitrate / 1000,
        config.max_fps,
        config.segment_duration.as_secs(),
        config.queue_depth
    );
    eprintln!("capture backend is being initialized");
}
