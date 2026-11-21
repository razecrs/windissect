//! Icons the window uses, embedded: a handful of Lucide SVGs (ISC licence,
//! assets/LICENSE-LUCIDE) on top of GPUI Kit's default component icons.

use std::borrow::Cow;

use gpui_kit::{AssetSource, SharedString};

macro_rules! icons {
    ($($name:literal),* $(,)?) => {
        &[$((concat!("windissect/", $name, ".svg"), include_bytes!(concat!("../assets/icons/", $name, ".svg")))),*]
    };
}

const ICONS: &[(&str, &[u8])] = icons![
    "folder-open",
    "book-open",
    "wrench",
    "search",
    "panel-bottom",
    "panel-right",
    "file-code",
    "x",
    "list-tree",
    "braces",
    "layers",
    "binary",
    "shield-check",
    "triangle-alert",
    "hash",
    "package",
    "boxes",
    "file-text",
    "upload",
    "cpu",
    "download",
    "chevron-right",
    "info",
    "terminal",
    "copy",
    "check",
    "chevron-down",
    "windissect-mark",
];

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        if let Some((_, bytes)) = ICONS.iter().find(|(p, _)| *p == path) {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        let mut out: Vec<SharedString> = ICONS
            .iter()
            .filter(|(p, _)| p.starts_with(path))
            .map(|(p, _)| SharedString::from(*p))
            .collect();
        out.extend(gpui_kit::assets::Assets.list(path)?);
        Ok(out)
    }
}

/// The embedded path of one of the icons above.
pub fn icon(name: &str) -> SharedString {
    SharedString::from(format!("windissect/{name}.svg"))
}
