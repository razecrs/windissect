use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SegmentStore {
    root: PathBuf,
    budget: u64,
}

impl SegmentStore {
    pub fn open(root: PathBuf, budget: u64) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        let store = Self { root, budget };
        store.remove_stale_partials()?;
        store.enforce_budget(None)?;
        Ok(store)
    }

    pub fn new_partial_path(&self, sequence: u64) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.root.join(format!("segment-{now:010}-{sequence:06}.partial.mp4"))
    }

    pub fn commit(&self, partial: &Path) -> io::Result<PathBuf> {
        let name = partial.file_name().and_then(|value| value.to_str()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "segment has no UTF-8 file name")
        })?;
        let final_path = partial.with_file_name(name.replace(".partial.mp4", ".mp4"));
        fs::rename(partial, &final_path)?;
        self.enforce_budget(None)?;
        Ok(final_path)
    }

    pub fn enforce_budget(&self, active: Option<&Path>) -> io::Result<u64> {
        let mut entries = Vec::new();
        let mut total = 0u64;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let is_segment = path.extension().is_some_and(|ext| ext == "mp4");
            if !is_segment {
                continue;
            }
            let metadata = entry.metadata()?;
            total = total.saturating_add(metadata.len());
            if active.is_none_or(|current| current != path) && !path.to_string_lossy().ends_with(".partial.mp4") {
                let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
                entries.push((modified, path, metadata.len()));
            }
        }
        entries.sort_by_key(|(modified, _, _)| *modified);
        for (_, path, size) in entries {
            if total <= self.budget {
                break;
            }
            fs::remove_file(&path)?;
            total = total.saturating_sub(size);
            eprintln!("retention: removed {} ({size} bytes)", path.display());
        }
        Ok(total)
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    fn remove_stale_partials(&self) -> io::Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.to_string_lossy().ends_with(".partial.mp4") {
                eprintln!("recovery: removing unfinalized segment {}", path.display());
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SegmentStore;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn removes_oldest_segments_to_hold_budget() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("windissect-recorder-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.mp4"), [0u8; 8]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(root.join("b.mp4"), [0u8; 8]).unwrap();
        let store = SegmentStore::open(root.clone(), 10).unwrap();
        assert!(!root.join("a.mp4").exists());
        assert!(root.join("b.mp4").exists());
        fs::remove_dir_all(root).unwrap();
        drop(store);
    }
}

