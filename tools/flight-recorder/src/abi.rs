//! Raw SDK fallback ABI.
//!
//! Windissect's exact-build crates are the provenance authority. The public
//! Microsoft PDBs do not carry the SDK COM declarations below, so these few
//! stable interfaces are reproduced from the Windows SDK as raw FFI.

use core::ffi::c_void;
use core::mem::{size_of, transmute};
use core::ptr::{null, null_mut};
use windows_sys::core::GUID;

pub type Com = *mut c_void;
pub type HResult = i32;

pub const S_OK: HResult = 0;
pub const DXGI_ERROR_NOT_FOUND: HResult = 0x887A0002u32 as i32;
pub const DXGI_ERROR_WAIT_TIMEOUT: HResult = 0x887A0027u32 as i32;
pub const DXGI_ERROR_ACCESS_LOST: HResult = 0x887A0026u32 as i32;
pub const DXGI_ADAPTER_FLAG_SOFTWARE: u32 = 2;
pub const D3D_DRIVER_TYPE_UNKNOWN: u32 = 0;
pub const D3D11_CREATE_DEVICE_BGRA_SUPPORT: u32 = 0x20;
pub const D3D11_CREATE_DEVICE_VIDEO_SUPPORT: u32 = 0x800;
pub const D3D11_SDK_VERSION: u32 = 7;
pub const D3D_FEATURE_LEVEL_11_1: u32 = 0xB100;
pub const D3D_FEATURE_LEVEL_11_0: u32 = 0xB000;
pub const MF_VERSION: u32 = 0x0002_0070;
pub const MFSTARTUP_FULL: u32 = 0;
pub const MFVideoInterlace_Progressive: u32 = 2;

pub const IID_IDXGIFactory1: GUID = guid(0x770aae78, 0xf26f, 0x4dba, [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87]);
pub const IID_IDXGIOutput1: GUID = guid(0x00cddea8, 0x939b, 0x4b83, [0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc]);
pub const IID_ID3D11Texture2D: GUID = guid(0x6f15aaf2, 0xd208, 0x4e89, [0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c]);

pub const MF_MT_MAJOR_TYPE: GUID = guid(0x48eba18e, 0xf8c9, 0x4687, [0xbf, 0x11, 0x0a, 0x74, 0xc9, 0xf9, 0x6a, 0x8f]);
pub const MF_MT_SUBTYPE: GUID = guid(0xf7e34c9a, 0x42e8, 0x4714, [0xb7, 0x4b, 0xcb, 0x29, 0xd7, 0x2c, 0x35, 0xe5]);
pub const MF_MT_FRAME_SIZE: GUID = guid(0x1652c33d, 0xd6b2, 0x4012, [0xb8, 0x34, 0x72, 0x03, 0x08, 0x49, 0xa3, 0x7d]);
pub const MF_MT_FRAME_RATE: GUID = guid(0xc459a2e8, 0x3d2c, 0x4e44, [0xb1, 0x32, 0xfe, 0xe5, 0x15, 0x6c, 0x7b, 0xb0]);
pub const MF_MT_PIXEL_ASPECT_RATIO: GUID = guid(0xc6376a1e, 0x8d0a, 0x4027, [0xbe, 0x45, 0x6d, 0x9a, 0x0a, 0xd3, 0x9b, 0xb6]);
pub const MF_MT_AVG_BITRATE: GUID = guid(0x20332624, 0xfb0d, 0x4d9e, [0xbd, 0x0d, 0xcb, 0xf6, 0x78, 0x6c, 0x10, 0x2e]);
pub const MF_MT_INTERLACE_MODE: GUID = guid(0xe2724bb8, 0xe676, 0x4806, [0xb4, 0xb2, 0xa8, 0xd6, 0xef, 0xb4, 0x4c, 0xcd]);
pub const MFMediaType_Video: GUID = guid(0x73646976, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFVideoFormat_HEVC: GUID = guid(0x43564548, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFVideoFormat_H264: GUID = guid(0x34363248, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFVideoFormat_ARGB32: GUID = guid(0x00000015, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS: GUID = guid(0xa634a91c, 0x822b, 0x41b9, [0xa4, 0x94, 0x4d, 0xe4, 0x64, 0x36, 0x12, 0xb0]);
pub const MF_SINK_WRITER_DISABLE_THROTTLING: GUID = guid(0x08b845d8, 0x2b74, 0x4afe, [0x9d, 0x53, 0xbe, 0x16, 0xd2, 0xd5, 0xae, 0x4f]);

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> GUID {
    GUID { data1, data2, data3, data4 }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Luid { pub low_part: u32, pub high_part: i32 }

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AdapterDesc1 {
    pub description: [u16; 128], pub vendor_id: u32, pub device_id: u32,
    pub subsys_id: u32, pub revision: u32, pub dedicated_video_memory: usize,
    pub dedicated_system_memory: usize, pub shared_system_memory: usize,
    pub adapter_luid: Luid, pub flags: u32,
}
impl Default for AdapterDesc1 { fn default() -> Self { unsafe { core::mem::zeroed() } } }

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Point { pub x: i32, pub y: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rational { pub numerator: u32, pub denominator: u32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ModeDesc {
    pub width: u32, pub height: u32, pub refresh_rate: Rational, pub format: u32,
    pub scanline_ordering: u32, pub scaling: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OutputDesc {
    pub device_name: [u16; 32], pub desktop_coordinates: Rect,
    pub attached_to_desktop: i32, pub rotation: u32, pub monitor: isize,
}
impl Default for OutputDesc { fn default() -> Self { unsafe { core::mem::zeroed() } } }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OutduplDesc { pub mode_desc: ModeDesc, pub rotation: u32, pub desktop_image_in_system_memory: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PointerPosition { pub position: Point, pub visible: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FrameInfo {
    pub last_present_time: i64, pub last_mouse_update_time: i64,
    pub accumulated_frames: u32, pub rects_coalesced: i32,
    pub protected_content_masked_out: i32, pub pointer_position: PointerPosition,
    pub total_metadata_buffer_size: u32, pub pointer_shape_buffer_size: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MoveRect { pub source_point: Point, pub destination_rect: Rect }

#[link(name = "dxgi")]
unsafe extern "system" { pub fn CreateDXGIFactory1(riid: *const GUID, factory: *mut Com) -> HResult; }
#[link(name = "d3d11")]
unsafe extern "system" {
    pub fn D3D11CreateDevice(adapter: Com, driver_type: u32, software: isize, flags: u32,
        feature_levels: *const u32, feature_levels_count: u32, sdk_version: u32,
        device: *mut Com, selected_feature_level: *mut u32, immediate_context: *mut Com) -> HResult;
}
#[link(name = "mfplat")]
unsafe extern "system" {
    pub fn MFStartup(version: u32, flags: u32) -> HResult;
    pub fn MFShutdown() -> HResult;
    pub fn MFCreateAttributes(attributes: *mut Com, initial_size: u32) -> HResult;
    pub fn MFCreateMediaType(media_type: *mut Com) -> HResult;
    pub fn MFCreateSample(sample: *mut Com) -> HResult;
    pub fn MFCreateDXGISurfaceBuffer(riid: *const GUID, surface: Com, subresource_index: u32,
        bottom_up_when_linear: i32, buffer: *mut Com) -> HResult;
}
#[link(name = "mfreadwrite")]
unsafe extern "system" {
    pub fn MFCreateSinkWriterFromURL(url: *const u16, byte_stream: Com, attributes: Com, writer: *mut Com) -> HResult;
}

#[inline] pub fn failed(hr: HResult) -> bool { hr < 0 }
pub fn check(hr: HResult, what: &str) -> Result<(), String> {
    if failed(hr) { Err(format!("{what} failed: HRESULT 0x{:08X}", hr as u32)) } else { Ok(()) }
}

unsafe fn slot(object: Com, index: usize) -> *const c_void {
    let table = unsafe { *(object as *mut *const *const c_void) };
    unsafe { *table.add(index) }
}

pub unsafe fn query_interface(object: Com, iid: &GUID) -> Result<Com, HResult> {
    let call: unsafe extern "system" fn(Com, *const GUID, *mut Com) -> HResult = unsafe { transmute(slot(object, 0)) };
    let mut out = null_mut();
    let hr = unsafe { call(object, iid, &mut out) };
    if failed(hr) { Err(hr) } else { Ok(out) }
}
pub unsafe fn release(object: Com) {
    if !object.is_null() {
        let call: unsafe extern "system" fn(Com) -> u32 = unsafe { transmute(slot(object, 2)) };
        unsafe { call(object); }
    }
}
pub unsafe fn factory_enum_adapters1(factory: Com, index: u32, adapter: *mut Com) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, *mut Com) -> HResult = unsafe { transmute(slot(factory, 12)) };
    unsafe { call(factory, index, adapter) }
}
pub unsafe fn adapter_get_desc1(adapter: Com, desc: *mut AdapterDesc1) -> HResult {
    let call: unsafe extern "system" fn(Com, *mut AdapterDesc1) -> HResult = unsafe { transmute(slot(adapter, 10)) };
    unsafe { call(adapter, desc) }
}
pub unsafe fn adapter_enum_outputs(adapter: Com, index: u32, output: *mut Com) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, *mut Com) -> HResult = unsafe { transmute(slot(adapter, 7)) };
    unsafe { call(adapter, index, output) }
}
pub unsafe fn output_get_desc(output: Com, desc: *mut OutputDesc) -> HResult {
    let call: unsafe extern "system" fn(Com, *mut OutputDesc) -> HResult = unsafe { transmute(slot(output, 7)) };
    unsafe { call(output, desc) }
}
pub unsafe fn output1_duplicate_output(output: Com, device: Com, duplication: *mut Com) -> HResult {
    let call: unsafe extern "system" fn(Com, Com, *mut Com) -> HResult = unsafe { transmute(slot(output, 22)) };
    unsafe { call(output, device, duplication) }
}
pub unsafe fn duplication_get_desc(duplication: Com, desc: *mut OutduplDesc) {
    let call: unsafe extern "system" fn(Com, *mut OutduplDesc) = unsafe { transmute(slot(duplication, 7)) };
    unsafe { call(duplication, desc) }
}
pub unsafe fn duplication_acquire_next_frame(duplication: Com, timeout_ms: u32, info: *mut FrameInfo, resource: *mut Com) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, *mut FrameInfo, *mut Com) -> HResult = unsafe { transmute(slot(duplication, 8)) };
    unsafe { call(duplication, timeout_ms, info, resource) }
}
pub unsafe fn duplication_get_dirty_rects(duplication: Com, bytes: u32, rects: *mut Rect, required: *mut u32) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, *mut Rect, *mut u32) -> HResult = unsafe { transmute(slot(duplication, 9)) };
    unsafe { call(duplication, bytes, rects, required) }
}
pub unsafe fn duplication_get_move_rects(duplication: Com, bytes: u32, rects: *mut MoveRect, required: *mut u32) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, *mut MoveRect, *mut u32) -> HResult = unsafe { transmute(slot(duplication, 10)) };
    unsafe { call(duplication, bytes, rects, required) }
}
pub unsafe fn duplication_release_frame(duplication: Com) -> HResult {
    let call: unsafe extern "system" fn(Com) -> HResult = unsafe { transmute(slot(duplication, 14)) };
    unsafe { call(duplication) }
}

pub unsafe fn attributes_set_guid(attributes: Com, key: &GUID, value: &GUID) -> HResult {
    let call: unsafe extern "system" fn(Com, *const GUID, *const GUID) -> HResult = unsafe { transmute(slot(attributes, 24)) };
    unsafe { call(attributes, key, value) }
}
pub unsafe fn attributes_set_u32(attributes: Com, key: &GUID, value: u32) -> HResult {
    let call: unsafe extern "system" fn(Com, *const GUID, u32) -> HResult = unsafe { transmute(slot(attributes, 21)) };
    unsafe { call(attributes, key, value) }
}
pub unsafe fn attributes_set_u64(attributes: Com, key: &GUID, value: u64) -> HResult {
    let call: unsafe extern "system" fn(Com, *const GUID, u64) -> HResult = unsafe { transmute(slot(attributes, 22)) };
    unsafe { call(attributes, key, value) }
}
pub unsafe fn sink_add_stream(writer: Com, output_type: Com, index: *mut u32) -> HResult {
    let call: unsafe extern "system" fn(Com, Com, *mut u32) -> HResult = unsafe { transmute(slot(writer, 3)) };
    unsafe { call(writer, output_type, index) }
}
pub unsafe fn sink_set_input_type(writer: Com, index: u32, input_type: Com, attrs: Com) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, Com, Com) -> HResult = unsafe { transmute(slot(writer, 4)) };
    unsafe { call(writer, index, input_type, attrs) }
}
pub unsafe fn sink_begin(writer: Com) -> HResult {
    let call: unsafe extern "system" fn(Com) -> HResult = unsafe { transmute(slot(writer, 5)) };
    unsafe { call(writer) }
}
pub unsafe fn sink_write_sample(writer: Com, index: u32, sample: Com) -> HResult {
    let call: unsafe extern "system" fn(Com, u32, Com) -> HResult = unsafe { transmute(slot(writer, 6)) };
    unsafe { call(writer, index, sample) }
}
pub unsafe fn sink_finalize(writer: Com) -> HResult {
    let call: unsafe extern "system" fn(Com) -> HResult = unsafe { transmute(slot(writer, 11)) };
    unsafe { call(writer) }
}
pub unsafe fn sample_set_time(sample: Com, time: i64) -> HResult {
    let call: unsafe extern "system" fn(Com, i64) -> HResult = unsafe { transmute(slot(sample, 36)) };
    unsafe { call(sample, time) }
}
pub unsafe fn sample_set_duration(sample: Com, duration: i64) -> HResult {
    let call: unsafe extern "system" fn(Com, i64) -> HResult = unsafe { transmute(slot(sample, 38)) };
    unsafe { call(sample, duration) }
}
pub unsafe fn sample_add_buffer(sample: Com, buffer: Com) -> HResult {
    let call: unsafe extern "system" fn(Com, Com) -> HResult = unsafe { transmute(slot(sample, 42)) };
    unsafe { call(sample, buffer) }
}

pub fn packed_ratio(high: u32, low: u32) -> u64 { (u64::from(high) << 32) | u64::from(low) }
pub fn utf16(value: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.as_os_str().encode_wide().chain(core::iter::once(0)).collect()
}
pub fn wide_string(value: &[u16]) -> String {
    let end = value.iter().position(|unit| *unit == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}
pub fn size_u32<T>(count: usize) -> u32 {
    u32::try_from(size_of::<T>().saturating_mul(count)).unwrap_or(u32::MAX)
}
