use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam::channel::{Receiver, Sender};

use crate::common::normalized_event::{EventKind, SharedEvent};
use crate::detection::model::{DetectionEvent, Severity};
use crate::engine::contextual_engine::ContextualEngine;
use crate::engine::correlation::BehavioralEngine;
use crate::engine::injection::InjectionEngine;
use crate::engine::process_graph::ProcessGraph;
use crate::engine::signature::SignatureEngine;
use crate::pipeline::monitor::DEGRADE_MODE;

const BATCH_SIZE: usize = 64;
const BATCH_TIMEOUT_MS: u64 = 5;

pub fn start_worker_pool(
    receiver: Receiver<SharedEvent>,
    depth: Arc<AtomicUsize>,
    graph: Arc<ProcessGraph>,
    sig_engine: Arc<SignatureEngine>,
    ctx_engine: Arc<ContextualEngine>,
    forensic_tx: Sender<SharedEvent>,
    behavioral: Arc<BehavioralEngine>,
    injection: Arc<InjectionEngine>,
    worker_count: usize,
) {
    for _ in 0..worker_count {
        let rx = receiver.clone();
        let q_depth = depth.clone();
        let q_graph = graph.clone();
        let q_sig = sig_engine.clone();
        let q_ctx = ctx_engine.clone();
        let q_forensic = forensic_tx.clone();
        let q_behav = behavioral.clone();
        let q_inject = injection.clone();

        thread::spawn(move || {
            worker_loop(
                rx, q_depth, q_graph, q_sig, q_ctx, q_forensic, q_behav, q_inject,
            );
        });
    }
}

fn worker_loop(
    rx: Receiver<SharedEvent>,
    depth: Arc<AtomicUsize>,
    graph: Arc<ProcessGraph>,
    sig_engine: Arc<SignatureEngine>,
    ctx_engine: Arc<ContextualEngine>,
    forensic_tx: Sender<SharedEvent>,
    behavioral: Arc<BehavioralEngine>,
    injection: Arc<InjectionEngine>,
) {
    let mut batch: Vec<SharedEvent> = Vec::with_capacity(BATCH_SIZE);

    loop {
        batch.clear();

        // 1️⃣ Wait for first event (blocking with timeout)
        match rx.recv_timeout(Duration::from_millis(BATCH_TIMEOUT_MS)) {
            Ok(event) => {
                depth.fetch_sub(1, Ordering::Relaxed);
                batch.push(event);
            }
            Err(_) => continue, // timeout → try next loop
        }

        // 2️⃣ Fill batch using non-blocking receive
        while batch.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(event) => {
                    depth.fetch_sub(1, Ordering::Relaxed);
                    batch.push(event);
                }
                Err(_) => break,
            }
        }

        // 3️⃣ Process entire batch
        crate::health::metrics::CORE_METRICS.worker_enter();
        process_batch(
            &batch,
            &graph,
            &sig_engine,
            &ctx_engine,
            &behavioral,
            &injection,
        );
        crate::health::metrics::CORE_METRICS.record_processed(batch.len() as u64);
        crate::health::metrics::CORE_METRICS.worker_exit();

        // Forward events to forensic writer (non-blocking)
        for event in &batch {
            let _ = forensic_tx.try_send(Arc::clone(event));
        }
    }
}

fn process_batch(
    events: &[SharedEvent],
    graph: &Arc<ProcessGraph>,
    sig_engine: &Arc<SignatureEngine>,
    ctx_engine: &Arc<ContextualEngine>,
    behavioral: &Arc<BehavioralEngine>,
    injection: &Arc<InjectionEngine>,
) {
    // Simulate heavy feature extraction to force queue overflow
    // Increase to 5ms so monitor thread has enough time to switch states
    thread::sleep(Duration::from_millis(5));

    let is_degraded = DEGRADE_MODE.load(Ordering::Relaxed);

    for event in events {
        if is_degraded && event.priority < crate::common::normalized_event::Priority::High {
            // Skip feature extraction for low/medium priority events during flood
            continue;
        }

        match event.kind {
            EventKind::ProcessStart => {
                graph.on_start(event);
            }
            EventKind::ProcessStop => {
                if let Some(ref proc) = event.process {
                    graph.on_stop(proc.pid);
                }
            }
            _ => {}
        }

        // Contextual engine handles all events (including network)
        ctx_engine.evaluate(event);

        // Execute signatures
        sig_engine.analyze(event);

        let risk = compute_risk(event);
        let severity = map_severity(risk);

        let _detection = DetectionEvent {
            base: event.clone(), // Arc clone (cheap)
            risk_score: risk,
            severity,
        };

        // TODO: forward to correlation channel
        // println!("Detection: {:?}", detection);

        // 4️⃣ Behavioral correlation (after signature)
        let now_ts = crate::health::metrics::now_epoch_secs();
        let alerts = behavioral.process(event, now_ts);
        for alert in &alerts {
            println!(
                "🔥 [CORRELATED] Rule={} PID={} Severity={} Evidence={}",
                alert.rule_name, alert.pid, alert.severity, alert.evidence
            );
        }

        // 5️⃣ Injection detection (after behavioral)
        let inject_alerts = injection.process(event, now_ts);
        for alert in &inject_alerts {
            println!(
                "🚨 [INJECTION] [{:?}] {} src={} tgt={} conf={} {}",
                alert.technique,
                alert.rule_name,
                alert.source_pid,
                alert.target_pid,
                alert.confidence,
                alert.evidence
            );
        }
    }
}

fn compute_risk(event: &SharedEvent) -> u32 {
    let mut score = 0;

    match event.kind {
        EventKind::ProcessStart => {
            if let Some(ref proc) = event.process {
                if proc.image.contains("powershell") {
                    score += 40;
                }
            }
        }
        EventKind::RegistrySet => {
            score += 70;
        }
        _ => {}
    }

    score
}

fn map_severity(score: u32) -> Severity {
    match score {
        0..=40 => Severity::Low,
        41..=80 => Severity::Medium,
        81..=120 => Severity::High,
        _ => Severity::Critical,
    }
}
