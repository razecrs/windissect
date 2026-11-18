use crate::abi;
use crate::capture::Frame;
use crate::config::Config;
use crate::storage::SegmentStore;
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, coinit: u32) -> i32;
    fn CoUninitialize();
}
const COINIT_MULTITHREADED: u32 = 0;
const RPC_E_CHANGED_MODE: i32 = 0x80010106u32 as i32;

#[derive(Clone, Copy, Debug)]
enum Codec { Hevc, H264 }
impl Codec {
    fn subtype(self) -> &'static windows_sys::core::GUID {
        match self { Self::Hevc => &abi::MFVideoFormat_HEVC, Self::H264 => &abi::MFVideoFormat_H264 }
    }
    fn name(self) -> &'static str { match self { Self::Hevc => "HEVC", Self::H264 => "H.264 fallback" } }
}

struct Segment {
    writer: abi::Com,
    stream: u32,
    partial_path: PathBuf,
    start: Duration,
    last_timestamp: Option<Duration>,
    codec: Codec,
}

impl Segment {
    fn create(path: PathBuf, start: Duration, width: u32, height: u32, config: &Config) -> Result<Self, String> {
        match Self::create_with_codec(path.clone(), start, width, height, config, Codec::Hevc) {
            Ok(segment) => Ok(segment),
            Err(hevc_error) => {
                let _ = fs::remove_file(&path);
                eprintln!("encoder: HEVC unavailable ({hevc_error}); trying H.264");
                Self::create_with_codec(path, start, width, height, config, Codec::H264)
            }
        }
    }

    fn create_with_codec(path: PathBuf, start: Duration, width: u32, height: u32, config: &Config, codec: Codec) -> Result<Self, String> {
        unsafe {
            let mut attributes = null_mut();
            abi::check(abi::MFCreateAttributes(&mut attributes, 4), "MFCreateAttributes")?;
            let result = (|| {
                abi::check(abi::attributes_set_u32(attributes, &abi::MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, 1), "enable hardware transforms")?;
                abi::check(abi::attributes_set_u32(attributes, &abi::MF_SINK_WRITER_DISABLE_THROTTLING, 1), "disable sink throttling")?;
                let path_wide = abi::utf16(&path);
                let mut writer = null_mut();
                abi::check(abi::MFCreateSinkWriterFromURL(path_wide.as_ptr(), null_mut(), attributes, &mut writer), "MFCreateSinkWriterFromURL")?;
                match configure_writer(writer, codec, width, height, config.bitrate, config.max_fps) {
                    Ok(stream) => {
                        eprintln!("encoder: {} {}x{} at {} kbit/s -> {}", codec.name(), width, height, config.bitrate / 1000, path.display());
                        Ok(Self { writer, stream, partial_path: path, start, last_timestamp: None, codec })
                    }
                    Err(error) => { abi::release(writer); Err(error) }
                }
            })();
            abi::release(attributes);
            result
        }
    }

    fn write(&mut self, frame: Frame, max_fps: u32) -> Result<(), String> {
        unsafe {
            let mut buffer = null_mut();
            abi::check(
                abi::MFCreateDXGISurfaceBuffer(&abi::IID_ID3D11Texture2D, frame.texture, 0, 0, &mut buffer),
                "MFCreateDXGISurfaceBuffer",
            )?;
            let mut sample = null_mut();
            let result = (|| {
                abi::check(abi::MFCreateSample(&mut sample), "MFCreateSample")?;
                abi::check(abi::sample_add_buffer(sample, buffer), "IMFSample::AddBuffer")?;
                let relative = frame.timestamp.saturating_sub(self.start);
                let minimum = Duration::from_secs_f64(1.0 / f64::from(max_fps));
                let duration = self.last_timestamp.map_or(minimum, |last| frame.timestamp.saturating_sub(last).max(minimum));
                abi::check(abi::sample_set_time(sample, to_hns(relative)), "IMFSample::SetSampleTime")?;
                abi::check(abi::sample_set_duration(sample, to_hns(duration)), "IMFSample::SetSampleDuration")?;
                abi::check(abi::sink_write_sample(self.writer, self.stream, sample), "IMFSinkWriter::WriteSample")?;
                self.last_timestamp = Some(frame.timestamp);
                Ok(())
            })();
            abi::release(sample);
            abi::release(buffer);
            result
        }
    }

    fn elapsed(&self) -> Duration {
        self.last_timestamp.map_or(Duration::ZERO, |time| time.saturating_sub(self.start))
    }

    fn file_size(&self) -> u64 { fs::metadata(&self.partial_path).map_or(0, |metadata| metadata.len()) }

    fn finish(mut self, store: &SegmentStore) -> Result<PathBuf, String> {
        unsafe {
            abi::check(abi::sink_finalize(self.writer), "IMFSinkWriter::Finalize")?;
            abi::release(self.writer);
            self.writer = null_mut();
        }
        let path = store.commit(&self.partial_path).map_err(|error| format!("commit segment: {error}"))?;
        eprintln!("segment: finalized {} ({}, {} bytes)", path.display(), self.codec.name(), fs::metadata(&path).map_or(0, |m| m.len()));
        Ok(path)
    }
}

impl Drop for Segment {
    fn drop(&mut self) { unsafe { abi::release(self.writer) } }
}

pub fn run(
    receiver: Receiver<Frame>, store: Arc<SegmentStore>, config: Config,
    width: u32, height: u32, stop: Arc<AtomicBool>,
) -> Result<(), String> {
    unsafe {
        let hr = CoInitializeEx(null_mut(), COINIT_MULTITHREADED);
        if abi::failed(hr) && hr != RPC_E_CHANGED_MODE { return Err(format!("CoInitializeEx: 0x{:08X}", hr as u32)); }
        abi::check(abi::MFStartup(abi::MF_VERSION, abi::MFSTARTUP_FULL), "MFStartup")?;
    }
    let result = encoder_loop(receiver, &store, &config, width, height, &stop);
    unsafe { let _ = abi::MFShutdown(); CoUninitialize(); }
    result
}

fn encoder_loop(receiver: Receiver<Frame>, store: &SegmentStore, config: &Config, width: u32, height: u32, stop: &AtomicBool) -> Result<(), String> {
    let mut sequence = 0u64;
    let mut current: Option<Segment> = None;
    let hard_segment_cap = (store.budget() / 8).max(4 * 1024 * 1024);
    while !stop.load(Ordering::Relaxed) {
        let frame = match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(frame) => frame,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let rotate = current.as_ref().is_some_and(|segment| {
            segment.elapsed() >= config.segment_duration || segment.file_size() >= hard_segment_cap
        });
        if rotate {
            current.take().unwrap().finish(store)?;
        }
        if current.is_none() {
            let path = store.new_partial_path(sequence);
            sequence += 1;
            current = Some(Segment::create(path, frame.timestamp, width, height, config)?);
        }
        let active_path = current.as_ref().unwrap().partial_path.clone();
        current.as_mut().unwrap().write(frame, config.max_fps)?;
        store.enforce_budget(Some(&active_path)).map_err(|error| format!("enforce retention: {error}"))?;
    }
    if let Some(segment) = current { segment.finish(store)?; }
    Ok(())
}

unsafe fn configure_writer(writer: abi::Com, codec: Codec, width: u32, height: u32, bitrate: u32, fps: u32) -> Result<u32, String> {
    unsafe {
        let output = create_video_type(codec.subtype(), width, height, fps, Some(bitrate))?;
        let mut stream = 0u32;
        let output_result = abi::check(abi::sink_add_stream(writer, output, &mut stream), "IMFSinkWriter::AddStream");
        abi::release(output);
        output_result?;
        let input = create_video_type(&abi::MFVideoFormat_ARGB32, width, height, fps, None)?;
        let input_result = abi::check(abi::sink_set_input_type(writer, stream, input, null_mut()), "IMFSinkWriter::SetInputMediaType");
        abi::release(input);
        input_result?;
        abi::check(abi::sink_begin(writer), "IMFSinkWriter::BeginWriting")?;
        Ok(stream)
    }
}

unsafe fn create_video_type(subtype: &windows_sys::core::GUID, width: u32, height: u32, fps: u32, bitrate: Option<u32>) -> Result<abi::Com, String> {
    unsafe {
        let mut media_type = null_mut();
        abi::check(abi::MFCreateMediaType(&mut media_type), "MFCreateMediaType")?;
        let result = (|| {
            abi::check(abi::attributes_set_guid(media_type, &abi::MF_MT_MAJOR_TYPE, &abi::MFMediaType_Video), "set major type")?;
            abi::check(abi::attributes_set_guid(media_type, &abi::MF_MT_SUBTYPE, subtype), "set subtype")?;
            abi::check(abi::attributes_set_u64(media_type, &abi::MF_MT_FRAME_SIZE, abi::packed_ratio(width, height)), "set frame size")?;
            abi::check(abi::attributes_set_u64(media_type, &abi::MF_MT_FRAME_RATE, abi::packed_ratio(fps, 1)), "set frame rate")?;
            abi::check(abi::attributes_set_u64(media_type, &abi::MF_MT_PIXEL_ASPECT_RATIO, abi::packed_ratio(1, 1)), "set pixel aspect")?;
            abi::check(abi::attributes_set_u32(media_type, &abi::MF_MT_INTERLACE_MODE, abi::MFVideoInterlace_Progressive), "set progressive scan")?;
            if let Some(bitrate) = bitrate { abi::check(abi::attributes_set_u32(media_type, &abi::MF_MT_AVG_BITRATE, bitrate), "set bitrate")?; }
            Ok(media_type)
        })();
        if result.is_err() { abi::release(media_type); }
        result
    }
}

fn to_hns(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos() / 100).unwrap_or(i64::MAX)
}
