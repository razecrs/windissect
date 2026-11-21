//! File-access preflight with Windows locking-process diagnostics.

use anyhow::Result;
use std::path::Path;

pub fn ensure_readable(path: &Path) -> Result<()> {
    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(error) => {
            let lockers = locking_processes(path);
            let detail = if lockers.is_empty() {
                "Windows did not report a locking application; check file permissions and path access"
                    .to_owned()
            } else {
                format!("locking application(s): {}", lockers.join(", "))
            };
            anyhow::bail!("cannot open {}: {error}; {detail}", path.display())
        }
    }
}

#[cfg(windows)]
fn locking_processes(path: &Path) -> Vec<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };

    struct Session(u32);
    impl Drop for Session {
        fn drop(&mut self) {
            unsafe { RmEndSession(self.0) };
        }
    }

    let mut handle = 0u32;
    let mut key = vec![0u16; usize::try_from(CCH_RM_SESSION_KEY).unwrap_or(32) + 1];
    if unsafe { RmStartSession(&raw mut handle, 0, key.as_mut_ptr()) } != 0 {
        return Vec::new();
    }
    let session = Session(handle);
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let files = [wide.as_ptr()];
    if unsafe {
        RmRegisterResources(
            session.0,
            1,
            files.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    } != 0
    {
        return Vec::new();
    }

    let mut needed = 0u32;
    let mut count = 0u32;
    let mut reboot_reasons = 0u32;
    let first = unsafe {
        RmGetList(
            session.0,
            &raw mut needed,
            &raw mut count,
            std::ptr::null_mut(),
            &raw mut reboot_reasons,
        )
    };
    if first != ERROR_MORE_DATA || needed == 0 {
        return Vec::new();
    }

    let mut processes = vec![RM_PROCESS_INFO::default(); needed as usize];
    count = needed;
    if unsafe {
        RmGetList(
            session.0,
            &raw mut needed,
            &raw mut count,
            processes.as_mut_ptr(),
            &raw mut reboot_reasons,
        )
    } != 0
    {
        return Vec::new();
    }
    processes
        .into_iter()
        .take(count as usize)
        .map(|process| {
            let end = process
                .strAppName
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(process.strAppName.len());
            let name = String::from_utf16_lossy(&process.strAppName[..end]);
            format!("{name} (PID {})", process.Process.dwProcessId)
        })
        .collect()
}

#[cfg(not(windows))]
const fn locking_processes(_path: &Path) -> Vec<String> {
    Vec::new()
}
