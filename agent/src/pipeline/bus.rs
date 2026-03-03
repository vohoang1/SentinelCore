use crate::common::normalized_event::{Priority, SharedEvent};
use crate::pipeline::metrics;
use crossbeam::channel::{bounded, Receiver, Sender, TrySendError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct EventBus {
    pub sender: Sender<SharedEvent>,
    pub receiver: Receiver<SharedEvent>,
    pub capacity: usize,
    pub depth: Arc<AtomicUsize>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = bounded(capacity);
        Self {
            sender,
            receiver,
            capacity,
            depth: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn try_enqueue(&self, event: SharedEvent) {
        match self.sender.try_send(event.clone()) {
            Ok(_) => {
                self.depth.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(ev)) => {
                metrics::increment_overload();
                self.handle_overflow(ev);
            }
            Err(TrySendError::Disconnected(_)) => {
                // log internal error: receiver disconnected
                eprintln!("EventBus disconnected!");
            }
        }
    }

    fn handle_overflow(&self, event: SharedEvent) {
        match event.priority {
            Priority::Low => {
                // Drop silently or increment metric
                metrics::increment_drop_low();
            }
            Priority::Medium => {
                // Drop but log metric
                metrics::increment_drop_medium();
            }
            Priority::High => {
                // Drop high but log metric
                metrics::increment_drop_high();
            }
            Priority::Critical => {
                // Force enqueue with blocking fallback
                // WARNING: short blocking only
                if self.sender.send(event).is_ok() {
                    self.depth.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}
