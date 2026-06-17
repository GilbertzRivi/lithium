use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use tray_icon::{
    Icon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

#[derive(PartialEq, Eq)]
pub enum Action {
    Close,
    Restart,
}

fn make_icon() -> Option<Icon> {
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let cx = size as f32 / 2.0;
    let r = cx - 1.5;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cx;
            if dx * dx + dy * dy <= r * r {
                let i = ((y * size + x) * 4) as usize;
                rgba[i] = 0x2D;
                rgba[i + 1] = 0x5F;
                rgba[i + 2] = 0xCC;
                rgba[i + 3] = 0xFF;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).ok()
}

pub fn run(stop: &tokio::sync::watch::Sender<bool>, daemon_done: &Arc<AtomicBool>) -> Action {
    #[cfg(target_os = "linux")]
    if gtk::init().is_err() {
        return wait_daemon_done(daemon_done);
    }

    let menu = Menu::new();
    let restart_item = MenuItem::new("Restart", true, None);
    let close_item = MenuItem::new("Close", true, None);
    let _ = menu.append(&MenuItem::new("Lithium", false, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&restart_item);
    let _ = menu.append(&close_item);

    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Lithium");
    if let Some(icon) = make_icon() {
        builder = builder.with_icon(icon);
    }
    let _tray = match builder.build() {
        Ok(t) => t,
        Err(_) => return wait_daemon_done(daemon_done),
    };

    let restart_id = restart_item.id().clone();
    let events = MenuEvent::receiver();

    loop {
        #[cfg(target_os = "linux")]
        gtk::main_iteration_do(false);

        if let Ok(event) = events.try_recv() {
            let _ = stop.send(true);
            if event.id == restart_id {
                return Action::Restart;
            }
            return Action::Close;
        }

        if daemon_done.load(Ordering::Acquire) {
            return Action::Close;
        }

        thread::sleep(Duration::from_millis(16));
    }
}

fn wait_daemon_done(daemon_done: &Arc<AtomicBool>) -> Action {
    while !daemon_done.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(100));
    }
    Action::Close
}
