mod app;
mod ipc;

use std::{sync::mpsc, thread};

use app::{Command, LithiumApp, WorkerEvent};

fn main() -> eframe::Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = mpsc::channel::<WorkerEvent>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

        while let Ok(cmd) = cmd_rx.recv() {
            let evt = rt.block_on(app::handle_command(cmd));
            let _ = evt_tx.send(evt);
        }
    });

    let native_options = eframe::NativeOptions::default();

    eframe::run_native(
        "lithiumg",
        native_options,
        Box::new(move |_cc| Ok(Box::new(LithiumApp::new(cmd_tx, evt_rx)))),
    )
}
