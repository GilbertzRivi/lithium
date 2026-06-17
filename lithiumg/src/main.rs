mod app;
mod errors;
mod ipc;

use std::{fs, path::PathBuf, process, sync::mpsc, thread};

use app::{Command, LithiumApp, WorkerEvent};
use eframe::egui;

fn find_daemon_binary() -> PathBuf {
    #[cfg(windows)]
    let name = "lithiumd.exe";
    #[cfg(not(windows))]
    let name = "lithiumd";

    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(name)
}

fn try_install_emoji_font(ctx: &egui::Context) {
    let candidates = [
        "/usr/share/fonts/truetype/noto/NotoEmoji-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
        "/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf",
        "/usr/share/fonts/TTF/Symbola.ttf",
    ];

    for path in candidates {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };

        let mut fonts = egui::FontDefinitions::default();

        fonts.font_data.insert(
            "emoji_fallback".to_owned(),
            egui::FontData::from_owned(bytes).into(),
        );

        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            family.push("emoji_fallback".to_owned());
        }

        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            family.push("emoji_fallback".to_owned());
        }

        ctx.set_fonts(fonts);
        eprintln!("loaded emoji fallback font from {path}");
        return;
    }

    eprintln!("no emoji fallback font found; emoji may render as squares");
}

fn main() -> eframe::Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = mpsc::channel::<WorkerEvent>();

    let daemon = process::Command::new(find_daemon_binary()).spawn().ok();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Lithium")
            .with_inner_size([900.0, 600.0])
            .with_min_inner_size([480.0, 360.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Lithium",
        native_options,
        Box::new(move |cc| {
            try_install_emoji_font(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                while let Ok(cmd) = cmd_rx.recv() {
                    let evt = rt.block_on(app::handle_command(cmd));
                    let _ = evt_tx.send(evt);
                    ctx.request_repaint();
                }
            });
            Ok(Box::new(LithiumApp::new(cmd_tx, evt_rx, daemon)))
        }),
    )
}
