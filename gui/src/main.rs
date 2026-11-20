//! Windissect desktop: a front end for the Windissect CLI.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// GPUI's derive macros name `gpui::`; the Kit stands in for it.
extern crate gpui_kit as gpui;

mod assets;
mod discord;
mod engine;
mod ir;
mod shell;

use gpui_kit::*;

fn main() {
    gpui_kit::application().with_assets(assets::Assets).run(move |cx| {
        gpui_kit::init(cx);
        gpui_kit::component::Theme::change(gpui_kit::component::ThemeMode::Dark, None, cx);
        cx.bind_keys([KeyBinding::new("ctrl-p", shell::GoTo, None)]);
        let bounds = Bounds::centered(None, size(px(1360.), px(860.)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("Windissect".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, |window, cx| cx.new(|cx| shell::Shell::new(window, cx)))
            .expect("failed to open the Windissect window");
    });
}
