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
    gpui_kit::application()
        .with_assets(assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            gpui_kit::component::Theme::change(gpui_kit::component::ThemeMode::Dark, None, cx);
            cx.bind_keys([KeyBinding::new("ctrl-p", shell::GoTo, None)]);
            let bounds = Bounds::centered(None, size(px(1360.), px(860.)), cx);
            gpui_kit::open_window(window_options(bounds), cx, |window, cx| {
                cx.new(|cx| shell::Shell::new(window, cx))
            })
            .expect("failed to open the Windissect window");
        });
}

/// Windows draws its own title bar. Linux compositors often don't (GNOME and
/// WSLg have no server-side decorations), so there the window is client
/// decorated and the shell renders a title bar with its own window buttons.
///
/// The rest of the frame is not ours to draw. `gpui_kit::open_window` mounts
/// the Kit's root, whose window plugin wraps every client-decorated window in
/// gpui-component's `WindowBorder`: it sets the client inset, draws the border
/// and shadow, shows resize cursors along the edges and corners, and starts
/// the compositor's resize on mouse down, skipping tiled sides. Wrapping the
/// shell in a second resize frame would double the inset and the hit bands.
fn window_options(bounds: Bounds<Pixels>) -> WindowOptions {
    let window_bounds = Some(WindowBounds::Windowed(bounds));
    if cfg!(target_os = "linux") {
        WindowOptions {
            window_bounds,
            window_decorations: Some(WindowDecorations::Client),
            titlebar: Some(TitlebarOptions {
                title: Some("Windissect".into()),
                ..gpui_kit::component::TitleBar::title_bar_options()
            }),
            app_id: Some("windissect".into()),
            ..gpui_kit::component::TitleBar::window_options()
        }
    } else {
        WindowOptions {
            window_bounds,
            titlebar: Some(TitlebarOptions {
                title: Some("Windissect".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}
