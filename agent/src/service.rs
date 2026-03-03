use std::ffi::OsString;
use std::time::Duration;
use windows_service::{
    define_windows_service, service::ServiceControl, service_control_handler,
    service_control_handler::ServiceControlHandlerResult, service_dispatcher,
};

define_windows_service!(ffi_service_main, my_service_main);

pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start("SentinelCore", ffi_service_main)
}

fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("Service stopped with error: {:?}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    // Register the control handler
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Service must ignore STOP if we want to be tamper-resistant from graceful stops!
            // However, SCM might get angry if we don't handle it at all.
            // For now, we accept it but the Watchdog will just restart us.
            ServiceControl::Stop => ServiceControlHandlerResult::NoError,
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("SentinelCore", event_handler)?;

    // Tell SCM that we are running
    status_handle.set_service_status(windows_service::service::ServiceStatus {
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Running,
        controls_accepted: windows_service::service::ServiceControlAccept::STOP,
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Now call our actual agent main loop
    crate::run_agent();

    // Tell SCM we stopped
    status_handle.set_service_status(windows_service::service::ServiceStatus {
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Stopped,
        controls_accepted: windows_service::service::ServiceControlAccept::empty(),
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
