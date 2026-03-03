use std::sync::atomic::{AtomicUsize, Ordering};

pub static DROP_LOW: AtomicUsize = AtomicUsize::new(0);
pub static DROP_MEDIUM: AtomicUsize = AtomicUsize::new(0);
pub static DROP_HIGH: AtomicUsize = AtomicUsize::new(0);
pub static OVERLOAD_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn increment_drop_low() {
    DROP_LOW.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_drop_medium() {
    DROP_MEDIUM.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_drop_high() {
    DROP_HIGH.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_overload() {
    OVERLOAD_COUNT.fetch_add(1, Ordering::Relaxed);
}
