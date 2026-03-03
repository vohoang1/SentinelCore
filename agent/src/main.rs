#![allow(dead_code, unused_imports, static_mut_refs)]
pub mod audit;
mod cloud;
mod common;
mod detection;
mod engine;
mod health;
mod pipeline;
mod sensor;
mod storage;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use engine::contextual_engine::ContextualEngine;
use engine::health::HealthMonitor;
use engine::process_graph::ProcessGraph;
use engine::signature::SignatureEngine;
use pipeline::bus::EventBus;
use pipeline::metrics;
use pipeline::monitor::start_monitor;
use pipeline::worker::start_worker_pool;
use sensor::etw_listener::{EtwListener, ETW_EVENTS_DROPPED, ETW_EVENTS_RECEIVED};
use sensor::kernel_telemetry::KernelTelemetryListener;
pub mod service;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--service".to_string()) {
        if let Err(e) = service::run_as_service() {
            eprintln!("Service error: {:?}", e);
        }
    } else {
        println!("Starting SentinelCore in Console Mode...");
        run_agent();
    }
}

pub fn run_agent() {
    let bus = Arc::new(EventBus::new(10_000));
    let graph = Arc::new(ProcessGraph::new());
    let sig_engine = Arc::new(SignatureEngine::new(std::path::Path::new("rules")));
    let ctx_engine = Arc::new(ContextualEngine::new(graph.clone()));

    engine::watcher::start_rules_watcher(sig_engine.clone(), std::path::PathBuf::from("rules"));
    HealthMonitor::start(bus.clone());
    engine::integrity::start_integrity_monitor();
    health::monitor::HealthMonitorV2::start(bus.capacity);

    // Forensic storage channel (non-blocking to worker pipeline)
    let (forensic_tx, forensic_rx) = crossbeam::channel::bounded(10_000);
    storage::writer_thread::start_writer_thread(forensic_rx);

    // Behavioral correlation engine (bounded, lock-minimized)
    let behavioral = Arc::new(engine::correlation::BehavioralEngine::new());
    engine::correlation::eviction::start_eviction_thread(behavioral.clone());

    // Injection detection engine (bounded, lock-minimized)
    let injection = Arc::new(engine::injection::InjectionEngine::new());

    let worker_count = num_cpus::get().saturating_sub(1);
    start_worker_pool(
        bus.receiver.clone(),
        bus.depth.clone(),
        graph.clone(),
        sig_engine.clone(),
        ctx_engine.clone(),
        forensic_tx,
        behavioral.clone(),
        injection.clone(),
        worker_count,
    );

    start_monitor(bus.clone());

    println!("Starting SentinelCore - ETW Sensor Integration...");

    EtwListener::start(bus.clone());

    // Cloud telemetry layer
    let identity = Arc::new(cloud::identity::DeviceIdentity::load_or_create());
    cloud::uploader::CloudUploader::start(
        identity.clone(),
        "data/sentinel_forensic.db",
        "https://sentinel-cloud.example.com".to_string(),
    );

    // Kernel Protection Integration
    let kernel_comm = cloud::kernel_comms::KernelComm::connect().map(Arc::new);
    if let Some(ref comm) = kernel_comm {
        let pid = std::process::id();
        if comm.set_protected_pid(pid) {
            println!("Kernel protection enabled for PID: {}", pid);
            KernelTelemetryListener::start(bus.clone(), Arc::clone(comm));
        } else {
            eprintln!("⚠️ Failed to enable kernel protection for PID: {}", pid);
        }
    } else {
        println!("⚠️ Kernel driver not found. Running in unprotected mode.");
    }

    // In production, we would block here or wait for a shutdown signal.
    // For this demonstration, let's keep it running for a few seconds.
    thread::sleep(Duration::from_secs(5));

    if let Some(ref comm) = kernel_comm {
        if let Some(status) = comm.query_status() {
            println!("🛡️ Kernel Stats:");
            println!("  Handles Stripped:  {}", status.handles_stripped);
            println!("  Files Denied:      {}", status.files_denied);
            println!("  Events in Queue:   {}", status.events_in_queue);
        }

        // Authorized shutdown sequence — send token before clearing protection
        comm.authorize_shutdown();
        comm.clear_protection();
    }

    println!("Simulation Complete.");
    println!("Metrics:");
    println!(
        "  OVERLOAD COUNT: {}",
        metrics::OVERLOAD_COUNT.load(Ordering::Relaxed)
    );
    println!(
        "  DROP LOW      : {}",
        metrics::DROP_LOW.load(Ordering::Relaxed)
    );
    println!(
        "  DROP MEDIUM   : {}",
        metrics::DROP_MEDIUM.load(Ordering::Relaxed)
    );
    println!(
        "  DROP HIGH     : {}",
        metrics::DROP_HIGH.load(Ordering::Relaxed)
    );
    println!(
        "  ETW RECEIVED  : {}",
        ETW_EVENTS_RECEIVED.load(Ordering::Relaxed)
    );
    println!(
        "  ETW DROPPED   : {}",
        ETW_EVENTS_DROPPED.load(Ordering::Relaxed)
    );
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
