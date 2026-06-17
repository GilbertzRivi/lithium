use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub struct HealthState {
    pub reaper_last_ok: AtomicI64,
    pub reaper_errors: AtomicU64,
    pub mk_rotation_last_ok: AtomicI64,
    pub mk_rotation_errors: AtomicU64,
}

impl HealthState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            reaper_last_ok: AtomicI64::new(0),
            reaper_errors: AtomicU64::new(0),
            mk_rotation_last_ok: AtomicI64::new(0),
            mk_rotation_errors: AtomicU64::new(0),
        })
    }

    pub fn record_reaper_ok(&self) {
        self.reaper_last_ok
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }

    pub fn record_reaper_err(&self) {
        self.reaper_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_mk_rotation_ok(&self) {
        self.mk_rotation_last_ok
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }

    pub fn record_mk_rotation_err(&self) {
        self.mk_rotation_errors.fetch_add(1, Ordering::Relaxed);
    }
}
