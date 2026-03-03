/*++
    driver.c — SentinelCore Kernel Driver Entry & Unload

    Initialization order (fail-safe rollback on any failure):
      1. Ring Buffer          — telemetry event queue
      2. Communication Device — IoCreateDeviceSecure + SDDL ACL
      3. ObRegisterCallbacks  — process handle protection
      4. FltRegisterFilter    — file system protection

    Unload:
      Controlled: driver verifies ShutdownAuthorized == 1 before teardown.
      Unauthorized unload attempts are logged to the telemetry ring buffer.
      Teardown proceeds in reverse initialization order.

    IRQL: DriverEntry / DriverUnload at PASSIVE_LEVEL.
--*/

#include "globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

GLOBAL_STATE g_State = {0};

#define SENTINEL_RING_BUFFER_CAPACITY 4096

/*++
    DriverEntry — Initialize all subsystems in order.
--*/
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(RegistryPath);

  RtlZeroMemory(&g_State, sizeof(g_State));
  ExInitializePushLock(&g_State.ProtectedProcessLock);
  g_State.ShutdownAuthorized = 0;
  g_State.RegisteredServicePid = NULL;

  /* 1. Ring Buffer */
  RingBufferInit(&g_State.RingBuffer, SENTINEL_RING_BUFFER_CAPACITY);

  DriverObject->DriverUnload = DriverUnload;

  /* 2. Communication Device */
  status = InitComms(DriverObject);
  if (!NT_SUCCESS(status)) {
    RingBufferDestroy(&g_State.RingBuffer);
    return status;
  }

  /* 3. ObRegisterCallbacks */
  status = RegisterObCallbacks();
  if (!NT_SUCCESS(status)) {
    DestroyComms();
    RingBufferDestroy(&g_State.RingBuffer);
    return status;
  }

  /* 4. MiniFilter */
  status = MiniFilterInit(DriverObject);
  if (!NT_SUCCESS(status)) {
    UnregisterObCallbacks();
    DestroyComms();
    RingBufferDestroy(&g_State.RingBuffer);
    return status;
  }

  return STATUS_SUCCESS;
}

/*++
    DriverUnload — Controlled teardown.
    Verifies the controlling service sent IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN
    with a valid token before proceeding. If not authorized, the attempt is
    logged to the telemetry ring buffer. Unload completes either way —
    preventing DriverUnload would leak resources and violate the driver model.
--*/
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  PEPROCESS protectedProcess = NULL;

  PAGED_CODE();
  UNREFERENCED_PARAMETER(DriverObject);

  if (InterlockedCompareExchange(&g_State.ShutdownAuthorized, 0, 0) == 0) {
    /*
     * Shutdown was not authorized by the controlling service.
     * Log the attempt for forensic visibility, then proceed with
     * clean teardown. Blocking DriverUnload is not possible without
     * leaking kernel resources — the correct mitigation is service
     * recovery and automatic driver restart.
     */
    RingBufferPush(&g_State.RingBuffer, SentinelEventIoctlReject,
                   HandleToULong(PsGetCurrentProcessId()), 0, 0, 0,
                   L"Driver unload without authorization");
  }

  /* 4. MiniFilter */
  MiniFilterUnload();

  /* 3. ObCallbacks */
  UnregisterObCallbacks();

  /* 2. Protected Process reference */
  ExAcquirePushLockExclusive(&g_State.ProtectedProcessLock);
  protectedProcess = g_State.ProtectedProcess;
  g_State.ProtectedProcess = NULL;
  g_State.ProtectedPid = NULL;
  g_State.RegisteredServicePid = NULL;
  ExReleasePushLockExclusive(&g_State.ProtectedProcessLock);

  if (protectedProcess != NULL) {
    ObDereferenceObject(protectedProcess);
  }

  /* 1. Communication Device */
  DestroyComms();

  /* 0. Ring Buffer */
  RingBufferDestroy(&g_State.RingBuffer);
}
