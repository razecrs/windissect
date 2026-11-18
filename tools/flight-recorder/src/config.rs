use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum GpuPreference {
    Auto,
    Integrated,
    Discrete,
    Index(u32),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub output_dir: PathBuf,
    pub budget_bytes: u64,
    pub segment_duration: Duration,
    pub bitrate: u32,
    pub max_fps: u32,
    pub output_index: u32,
    pub gpu: GpuPreference,
    pub queue_depth: usize,
    pub library: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from(r"D:\FlightRecorder"),
            budget_bytes: 500 * 1024 * 1024,
            segment_duration: Duration::from_secs(60),
            bitrate: 40_000,
            max_fps: 10,
            output_index: 0,
            gpu: GpuPreference::Auto,
            queue_depth: 3,
            library: false,
        }
    }
}

impl Config {
    pub fn parse() -> Result<Option<Self>, String> {
        let mut config = Self::default();
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            let value = |args: &mut std::iter::Skip<env::Args>, flag: &str| {
                args.next().ok_or_else(|| format!("{flag} requires a value"))
            };
            match arg.as_str() {
                "-h" | "--help" => return Ok(None),
                "--library" => config.library = true,
                "--output" => config.output_dir = PathBuf::from(value(&mut args, &arg)?),
                "--budget-mb" => {
                    config.budget_bytes = parse_u64(&value(&mut args, &arg)?, &arg)?
                        .checked_mul(1024 * 1024)
                        .ok_or_else(|| "disk budget is too large".to_owned())?;
                }
                "--segment-seconds" => {
                    config.segment_duration = Duration::from_secs(parse_u64(&value(&mut args, &arg)?, &arg)?);
                }
                "--bitrate-kbps" => {
                    config.bitrate = u32::try_from(parse_u64(&value(&mut args, &arg)?, &arg)? * 1000)
                        .map_err(|_| "bitrate is too large".to_owned())?;
                }
                "--max-fps" => config.max_fps = parse_u32(&value(&mut args, &arg)?, &arg)?,
                "--output-index" => config.output_index = parse_u32(&value(&mut args, &arg)?, &arg)?,
                "--queue" => config.queue_depth = parse_u32(&value(&mut args, &arg)?, &arg)? as usize,
                "--gpu" => {
                    let selected = value(&mut args, &arg)?;
                    config.gpu = match selected.as_str() {
                        "auto" => GpuPreference::Auto,
                        "igpu" | "integrated" => GpuPreference::Integrated,
                        "dgpu" | "discrete" => GpuPreference::Discrete,
                        _ => GpuPreference::Index(selected.parse().map_err(|_| {
                            "--gpu must be auto, igpu, dgpu, or an adapter index".to_owned()
                        })?),
                    };
                }
                _ => return Err(format!("unknown option: {arg}")),
            }
        }
        if config.budget_bytes < 8 * 1024 * 1024 {
            return Err("--budget-mb must be at least 8".to_owned());
        }
        if config.segment_duration.as_secs() == 0 {
            return Err("--segment-seconds must be greater than zero".to_owned());
        }
        if !(1..=60).contains(&config.max_fps) {
            return Err("--max-fps must be between 1 and 60".to_owned());
        }
        if !(1..=16).contains(&config.queue_depth) {
            return Err("--queue must be between 1 and 16".to_owned());
        }
        Ok(Some(config))
    }

    pub fn print_help() {
        println!("windissect-flight-recorder [options]\n");
        println!(r"  --output DIR          segment directory (default: D:\FlightRecorder)");
        println!("  --library             open the native clip browser instead of recording");
        println!("  --budget-mb N         hard rolling budget (default: 500)");
        println!("  --segment-seconds N   crash-loss boundary (default: 60)");
        println!("  --bitrate-kbps N      video target (default: 40)");
        println!("  --max-fps N           changed-frame ceiling (default: 10)");
        println!("  --gpu auto|igpu|dgpu|N  adapter selection (default: auto)");
        println!("  --output-index N      monitor on selected adapter (default: 0)");
        println!("  --queue N             bounded GPU-frame queue (default: 3)");
    }
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("invalid integer for {flag}: {value}"))
}

fn parse_u32(value: &str, flag: &str) -> Result<u32, String> {
    value.parse().map_err(|_| format!("invalid integer for {flag}: {value}"))
}

