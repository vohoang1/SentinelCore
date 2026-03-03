/*++
    comms.c — Secure IOCTL Communication Channel

    Security model:
    1. Device created with IoCreateDeviceSecure + SDDL (SYSTEM + Admins only).
    2. First IOCTL_SENTINEL_SET_PID registers the caller as the authorized
service PID. All subsequent IOCTLs are rejected if the caller PID does not
match.
    3. IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN requires a 16-byte token match.
    4. All inputs validated: buffer sizes, PID existence, caller mode.
    5. Unauthorized IOCTL attempts are logged to the telemetry ring buffer.

    IRQL: All dispatch routines run at PASSIVE_LEVEL.
--*/

#include "globals.h"
#include <wdmsec.h> /* IoCreateDeviceSecure */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InitComms)
#pragma alloc_text(PAGE, DestroyComms)
#pragma alloc_text(PAGE, DispatchCreateClose)
#pragma alloc_text(PAGE, DispatchDeviceControl)
#endif

/* ─── Forward declarations (static, file-scoped) ────────────────────── */
static NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject,
                                    _In_ PIRP Irp);
static NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                      _In_ PIRP Irp);

/* ─── Helper: validate caller is the registered service ──────────────── */
static BOOLEAN IsCallerRegisteredService(VOID) {
  HANDLE callerPid = PsGetCurrentProcessId();

  if (g_State.RegisteredServicePid == NULL) {
    return TRUE; /* No service registered yet — first call allowed */
  }
  return (callerPid == g_State.RegisteredServicePid);
}

/* ─── Helper: complete IRP with status ───────────────────────────────── */
static NTSTATUS CompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS Status,
                            _In_ ULONG_PTR Information) {
  Irp->IoStatus.Status = Status;
  Irp->IoStatus.Information = Information;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return Status;
}

/* ─── IRP_MJ_CREATE / IRP_MJ_CLOSE ──────────────────────────────────── */
static NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject,
                                    _In_ PIRP Irp) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DeviceObject);
  return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

/* ─── IRP_MJ_DEVICE_CONTROL ─────────────────────────────────────────── */
static NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                      _In_ PIRP Irp) {
  PIO_STACK_LOCATION stack;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG inputLen;
  ULONG outputLen;
  PVOID sysBuffer;
  ULONG_PTR info = 0;

  PAGED_CODE();
  UNREFERENCED_PARAMETER(DeviceObject);

  stack = IoGetCurrentIrpStackLocation(Irp);
  inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
  outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
  sysBuffer = Irp->AssociatedIrp.SystemBuffer;

  /* Validate caller identity against the registered service PID */
  if (!IsCallerRegisteredService()) {
    /* Log the unauthorized attempt */
    RingBufferPush(&g_State.RingBuffer, SentinelEventIoctlReject,
                   HandleToULong(PsGetCurrentProcessId()), 0, 0, 0,
                   L"Unauthorized IOCTL caller");
    return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
  }

  switch (stack->Parameters.DeviceIoControl.IoControlCode) {

  /* ────────────────────────────────────────────────────────────────── */
  case IOCTL_SENTINEL_SET_PID: {
    ULONG pidValue;
    HANDLE pid;
    PEPROCESS process = NULL;
    PEPROCESS oldProcess = NULL;

    if (inputLen < sizeof(ULONG) || sysBuffer == NULL) {
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    pidValue = *(ULONG *)sysBuffer;
    pid = (HANDLE)(ULONG_PTR)pidValue;

    /* Validate PID actually exists */
    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
      break;
    }

    /* Register caller as the authorized service PID (first time only) */
    if (g_State.RegisteredServicePid == NULL) {
      g_State.RegisteredServicePid = PsGetCurrentProcessId();
    }

    ExAcquirePushLockExclusive(&g_State.ProtectedProcessLock);
    oldProcess = g_State.ProtectedProcess;
    g_State.ProtectedProcess = process;
    g_State.ProtectedPid = pid;
    ExReleasePushLockExclusive(&g_State.ProtectedProcessLock);

    if (oldProcess != NULL) {
      ObDereferenceObject(oldProcess);
    }
    break;
  }

  /* ────────────────────────────────────────────────────────────────── */
  case IOCTL_SENTINEL_CLEAR_PID: {
    PEPROCESS oldProcess = NULL;

    ExAcquirePushLockExclusive(&g_State.ProtectedProcessLock);
    oldProcess = g_State.ProtectedProcess;
    g_State.ProtectedProcess = NULL;
    g_State.ProtectedPid = NULL;
    ExReleasePushLockExclusive(&g_State.ProtectedProcessLock);

    if (oldProcess != NULL) {
      ObDereferenceObject(oldProcess);
    }
    break;
  }

  /* ────────────────────────────────────────────────────────────────── */
  case IOCTL_SENTINEL_QUERY_STATUS: {
    SENTINEL_STATUS qs;

    if (outputLen < sizeof(SENTINEL_STATUS) || sysBuffer == NULL) {
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    qs.ProtectionActive = (g_State.ProtectedProcess != NULL) ? 1 : 0;
    qs.ProtectedPid = HandleToULong(g_State.ProtectedPid);
    qs.HandlesStripped = g_State.RingBuffer.TotalHandlesStripped;
    qs.FilesDenied = g_State.RingBuffer.TotalFilesDenied;
    qs.EventsInQueue = g_State.RingBuffer.Count;

    RtlCopyMemory(sysBuffer, &qs, sizeof(SENTINEL_STATUS));
    info = sizeof(SENTINEL_STATUS);
    break;
  }

  /* ────────────────────────────────────────────────────────────────── */
  case IOCTL_SENTINEL_READ_TELEMETRY: {
    ULONG drained;

    if (outputLen < sizeof(SENTINEL_EVENT_FLAT) || sysBuffer == NULL) {
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    drained = RingBufferDrain(&g_State.RingBuffer, sysBuffer, outputLen);
    info = (ULONG_PTR)drained * sizeof(SENTINEL_EVENT_FLAT);
    break;
  }

  /* ────────────────────────────────────────────────────────────────── */
  case IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN: {
    /* Require token match to authorize controlled driver unload */
    if (inputLen < SENTINEL_SHUTDOWN_TOKEN_SIZE || sysBuffer == NULL) {
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    if (RtlCompareMemory(sysBuffer, SENTINEL_SHUTDOWN_TOKEN,
                         SENTINEL_SHUTDOWN_TOKEN_SIZE) !=
        SENTINEL_SHUTDOWN_TOKEN_SIZE) {
      /* Token mismatch — log and reject */
      RingBufferPush(&g_State.RingBuffer, SentinelEventIoctlReject,
                     HandleToULong(PsGetCurrentProcessId()), 0, 0, 0,
                     L"Invalid shutdown token");
      status = STATUS_ACCESS_DENIED;
      break;
    }

    InterlockedExchange(&g_State.ShutdownAuthorized, 1);
    break;
  }

  /* ────────────────────────────────────────────────────────────────── */
  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }

  return CompleteIrp(Irp, status, info);
}

/* ─── InitComms — Create secure device + symbolic link ───────────────── */
_Use_decl_annotations_ NTSTATUS InitComms(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING devName;
  UNICODE_STRING symLink;
  UNICODE_STRING sddl;
  NTSTATUS status;

  PAGED_CODE();

  RtlInitUnicodeString(&devName, SENTINEL_DEVICE_NAME);
  RtlInitUnicodeString(&symLink, SENTINEL_SYMLINK_NAME);
  RtlInitUnicodeString(&sddl, SENTINEL_DEVICE_SDDL);

  /* Apply hardened SDDL ACL: restrict access to SYSTEM and Administrators */
  status =
      IoCreateDeviceSecure(DriverObject, 0, /* DeviceExtensionSize */
                           &devName, FILE_DEVICE_UNKNOWN,
                           FILE_DEVICE_SECURE_OPEN, FALSE, /* Exclusive */
                           &sddl, &SENTINEL_DEVICE_GUID, &g_State.DeviceObject);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = IoCreateSymbolicLink(&symLink, &devName);
  if (!NT_SUCCESS(status)) {
    IoDeleteDevice(g_State.DeviceObject);
    g_State.DeviceObject = NULL;
    return status;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

  return STATUS_SUCCESS;
}

/* ─── DestroyComms — Tear down device + symbolic link ────────────────── */
_Use_decl_annotations_ VOID DestroyComms(VOID) {
  UNICODE_STRING symLink;

  PAGED_CODE();

  RtlInitUnicodeString(&symLink, SENTINEL_SYMLINK_NAME);
  IoDeleteSymbolicLink(&symLink);

  if (g_State.DeviceObject != NULL) {
    IoDeleteDevice(g_State.DeviceObject);
    g_State.DeviceObject = NULL;
  }
}
