use crate::abi;
use crate::config::{Config, GpuPreference};
use core::ptr::null_mut;
use std::mem::size_of;
use std::time::{Duration, Instant};

pub struct Frame {
    pub texture: abi::Com,
    pub timestamp: Duration,
    pub dirty_rects: u32,
    pub moved_rects: u32,
}
unsafe impl Send for Frame {}
impl Drop for Frame {
    fn drop(&mut self) { unsafe { abi::release(self.texture) } }
}

struct Candidate {
    adapter: abi::Com,
    index: u32,
    desc: abi::AdapterDesc1,
    has_output: bool,
}

pub struct CaptureSession {
    factory: abi::Com,
    adapter: abi::Com,
    output: abi::Com,
    output1: abi::Com,
    device: abi::Com,
    context: abi::Com,
    duplication: abi::Com,
    started: Instant,
    last_emitted: Option<Instant>,
    first_frame: bool,
    pub adapter_name: String,
    pub output_name: String,
    pub width: u32,
    pub height: u32,
}

impl CaptureSession {
    pub fn open(config: &Config) -> Result<Self, String> {
        unsafe {
            let mut factory = null_mut();
            abi::check(abi::CreateDXGIFactory1(&abi::IID_IDXGIFactory1, &mut factory), "CreateDXGIFactory1")?;
            let mut candidates = Vec::new();
            for index in 0..32 {
                let mut adapter = null_mut();
                let hr = abi::factory_enum_adapters1(factory, index, &mut adapter);
                if hr == abi::DXGI_ERROR_NOT_FOUND { break; }
                if abi::failed(hr) { continue; }
                let mut desc = abi::AdapterDesc1::default();
                if abi::failed(abi::adapter_get_desc1(adapter, &mut desc))
                    || desc.flags & abi::DXGI_ADAPTER_FLAG_SOFTWARE != 0
                {
                    abi::release(adapter);
                    continue;
                }
                let mut probe = null_mut();
                let has_output = !abi::failed(abi::adapter_enum_outputs(adapter, config.output_index, &mut probe));
                abi::release(probe);
                candidates.push(Candidate { adapter, index, desc, has_output });
            }
            let selected = select_candidate(&candidates, &config.gpu)
                .ok_or_else(|| "no hardware adapter with the requested desktop output was found".to_owned())?;
            let selected_ptr = selected.adapter;
            let selected_index = selected.index;
            let selected_desc = selected.desc;
            for candidate in &candidates {
                if candidate.adapter != selected_ptr { abi::release(candidate.adapter); }
            }

            let mut device = null_mut();
            let mut context = null_mut();
            let mut level = 0;
            let levels = [abi::D3D_FEATURE_LEVEL_11_1, abi::D3D_FEATURE_LEVEL_11_0];
            let hr = abi::D3D11CreateDevice(
                selected_ptr, abi::D3D_DRIVER_TYPE_UNKNOWN, 0,
                abi::D3D11_CREATE_DEVICE_BGRA_SUPPORT | abi::D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                levels.as_ptr(), levels.len() as u32, abi::D3D11_SDK_VERSION,
                &mut device, &mut level, &mut context,
            );
            if abi::failed(hr) {
                abi::release(selected_ptr); abi::release(factory);
                return Err(format!("D3D11CreateDevice on adapter {selected_index} failed: 0x{:08X}", hr as u32));
            }

            let mut output = null_mut();
            abi::check(abi::adapter_enum_outputs(selected_ptr, config.output_index, &mut output), "IDXGIAdapter::EnumOutputs")?;
            let mut output_desc = abi::OutputDesc::default();
            abi::check(abi::output_get_desc(output, &mut output_desc), "IDXGIOutput::GetDesc")?;
            let output1 = abi::query_interface(output, &abi::IID_IDXGIOutput1)
                .map_err(|hr| format!("IDXGIOutput1 unavailable: 0x{:08X}", hr as u32))?;
            let mut duplication = null_mut();
            abi::check(abi::output1_duplicate_output(output1, device, &mut duplication), "IDXGIOutput1::DuplicateOutput")?;
            let mut duplication_desc = abi::OutduplDesc::default();
            abi::duplication_get_desc(duplication, &mut duplication_desc);
            if duplication_desc.mode_desc.width != 1920 || duplication_desc.mode_desc.height != 1080 {
                abi::release(duplication); abi::release(output1); abi::release(output);
                abi::release(context); abi::release(device); abi::release(selected_ptr); abi::release(factory);
                return Err(format!(
                    "selected desktop is {}x{}; v1 intentionally requires 1920x1080 to avoid a scaling pass",
                    duplication_desc.mode_desc.width, duplication_desc.mode_desc.height
                ));
            }
            let adapter_name = abi::wide_string(&selected_desc.description);
            let output_name = abi::wide_string(&output_desc.device_name);
            eprintln!(
                "capture: adapter {selected_index} {adapter_name} ({} MiB dedicated), output {} {output_name}, feature level 0x{level:X}",
                selected_desc.dedicated_video_memory / 1024 / 1024,
                config.output_index,
            );
            Ok(Self {
                factory, adapter: selected_ptr, output, output1, device, context, duplication,
                started: Instant::now(), last_emitted: None, first_frame: true,
                adapter_name, output_name,
                width: duplication_desc.mode_desc.width, height: duplication_desc.mode_desc.height,
            })
        }
    }

    pub fn next_changed_frame(&mut self, timeout_ms: u32, minimum_interval: Duration) -> Result<Option<Frame>, String> {
        unsafe {
            let mut info = abi::FrameInfo::default();
            let mut resource = null_mut();
            let hr = abi::duplication_acquire_next_frame(self.duplication, timeout_ms, &mut info, &mut resource);
            if hr == abi::DXGI_ERROR_WAIT_TIMEOUT { return Ok(None); }
            if hr == abi::DXGI_ERROR_ACCESS_LOST {
                self.recreate_duplication()?;
                return Ok(None);
            }
            abi::check(hr, "IDXGIOutputDuplication::AcquireNextFrame")?;

            let metadata_bytes = info.total_metadata_buffer_size as usize;
            let mut dirty_count = 0u32;
            let mut moved_count = 0u32;
            if metadata_bytes > 0 {
                let mut required = 0u32;
                let dirty_capacity = metadata_bytes.div_ceil(size_of::<abi::Rect>());
                let mut dirty = vec![abi::Rect::default(); dirty_capacity];
                if !abi::failed(abi::duplication_get_dirty_rects(
                    self.duplication, abi::size_u32::<abi::Rect>(dirty.len()), dirty.as_mut_ptr(), &mut required,
                )) {
                    dirty_count = required / size_of::<abi::Rect>() as u32;
                }
                let move_capacity = metadata_bytes.div_ceil(size_of::<abi::MoveRect>());
                let mut moved = vec![abi::MoveRect::default(); move_capacity];
                required = 0;
                if !abi::failed(abi::duplication_get_move_rects(
                    self.duplication, abi::size_u32::<abi::MoveRect>(moved.len()), moved.as_mut_ptr(), &mut required,
                )) {
                    moved_count = required / size_of::<abi::MoveRect>() as u32;
                }
            }
            let changed = self.first_frame || dirty_count > 0 || moved_count > 0;
            let now = Instant::now();
            let due = self.last_emitted.is_none_or(|last| now.duration_since(last) >= minimum_interval);
            let texture = if changed && due {
                match abi::query_interface(resource, &abi::IID_ID3D11Texture2D) {
                    Ok(texture) => Some(texture),
                    Err(hr) => {
                        abi::release(resource);
                        abi::duplication_release_frame(self.duplication);
                        return Err(format!("captured resource is not ID3D11Texture2D: 0x{:08X}", hr as u32));
                    }
                }
            } else { None };
            abi::release(resource);
            abi::check(abi::duplication_release_frame(self.duplication), "IDXGIOutputDuplication::ReleaseFrame")?;
            if let Some(texture) = texture {
                self.first_frame = false;
                self.last_emitted = Some(now);
                Ok(Some(Frame { texture, timestamp: now.duration_since(self.started), dirty_rects: dirty_count, moved_rects: moved_count }))
            } else { Ok(None) }
        }
    }

    fn recreate_duplication(&mut self) -> Result<(), String> {
        unsafe {
            abi::release(self.duplication);
            self.duplication = null_mut();
            abi::check(
                abi::output1_duplicate_output(self.output1, self.device, &mut self.duplication),
                "recreate desktop duplication after display change",
            )?;
            self.first_frame = true;
            eprintln!("capture: desktop duplication recreated after access loss");
            Ok(())
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) { unsafe {
        abi::release(self.duplication); abi::release(self.output1); abi::release(self.output);
        abi::release(self.context); abi::release(self.device); abi::release(self.adapter); abi::release(self.factory);
    } }
}

fn select_candidate<'a>(candidates: &'a [Candidate], preference: &GpuPreference) -> Option<&'a Candidate> {
    let is_integrated = |candidate: &&Candidate| {
        candidate.desc.vendor_id == 0x8086 || candidate.desc.dedicated_video_memory < 1024 * 1024 * 1024
    };
    let available = candidates.iter().filter(|candidate| candidate.has_output);
    match preference {
        GpuPreference::Index(index) => available.filter(|candidate| candidate.index == *index).next(),
        GpuPreference::Integrated => available.filter(is_integrated).next(),
        GpuPreference::Discrete => available.filter(|candidate| !is_integrated(&candidate)).next(),
        GpuPreference::Auto => available.filter(is_integrated).next().or_else(|| candidates.iter().find(|candidate| candidate.has_output)),
    }
}
