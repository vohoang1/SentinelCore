/*++
    globals.h — SentinelCore Kernel Driver

    Global state, pool tags, telemetry ring buffer, IOCTL codes,
    self-defense state (authorized shutdown, registered service PID),
    SAL-annotated prototypes, strict IRQL discipline.
--*/

#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>

/* ─── Pool Tags (little-endian: read backwards in poolmon) ───────────── */
#define SNTL_TAG_GENERAL 'ltnS' /* General allocations              */
#define SNTL_TAG_EVENT 'vEtS'   /* Ring buffer event nodes           */

/* ─── Device & SDDL ─────────────────────────────────────────────────── */
#define SENTINEL_DEVICE_NAME L"\\Device\\SentinelKM"
#define SENTINEL_SYMLINK_NAME L"\\DosDevices\\SentinelKM"

/*  SDDL: SYSTEM=Full, Administrators=Full, nobody else.
    D:P  = DACL Protected (no inheritance)
    A;;GA;;;SY = Allow Generic All to SYSTEM
    A;;GA;;;BA = Allow Generic All to Built-in Administrators          */
#define SENTINEL_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

/* Device GUID for IoCreateDeviceSecure */
/* {7A8B3C4D-1234-5678-ABCD-EF0123456789} */
static const GUID SENTINEL_DEVICE_GUID = {
    0x7A8B3C4D,
    0x1234,
    0x5678,
    {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89}};

/* ─── IOCTL codes (METHOD_BUFFERED, FILE_ANY_ACCESS) ─────────────────── */
#define IOCTL_SENTINEL_SET_PID                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SENTINEL_CLEAR_PID                                               \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SENTINEL_QUERY_STATUS                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SENTINEL_READ_TELEMETRY                                          \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ─── Shutdown Authorization Token ───────────────────────────────────── */
/* Shared secret for authorized driver unload.
   The controlling service must present this token via
   IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN. In production, derive this value from a
   signed challenge-response exchange. */
#define SENTINEL_SHUTDOWN_TOKEN_SIZE 16

static const UCHAR SENTINEL_SHUTDOWN_TOKEN[SENTINEL_SHUTDOWN_TOKEN_SIZE] = {
    0x53, 0x4E, 0x54, 0x4C, 0x2D, 0x41, 0x55, 0x54,
    0x48, 0x2D, 0x54, 0x4F, 0x4B, 0x45, 0x4E, 0x00};

/* ─── Telemetry Event Types ──────────────────────────────────────────── */
#define SENTINEL_MAX_EVENT_DATA 128

typedef enum _SENTINEL_EVENT_TYPE {
  SentinelEventHandleStrip = 1,
  SentinelEventFileDenied = 2,
  SentinelEventProcessBlock = 3,
  SentinelEventIoctlReject = 4 /* Unauthorized IOCTL attempt      */
} SENTINEL_EVENT_TYPE;

/* ─── Ring Buffer Event Node ─────────────────────────────────────────── */
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _SENTINEL_EVENT {
  LIST_ENTRY ListEntry;
  LARGE_INTEGER Timestamp;
  SENTINEL_EVENT_TYPE Type;
  ULONG SourcePid;
  ULONG TargetPid;
  ACCESS_MASK OriginalAccess;
  ACCESS_MASK StrippedAccess;
  WCHAR Detail[SENTINEL_MAX_EVENT_DATA];
} SENTINEL_EVENT, *PSENTINEL_EVENT;
#pragma warning(pop)

/* ─── Flat Event for Export (no LIST_ENTRY) ───────────────────────────── */
typedef struct _SENTINEL_EVENT_FLAT {
  LARGE_INTEGER Timestamp;
  SENTINEL_EVENT_TYPE Type;
  ULONG SourcePid;
  ULONG TargetPid;
  ACCESS_MASK OriginalAccess;
  ACCESS_MASK StrippedAccess;
  WCHAR Detail[SENTINEL_MAX_EVENT_DATA];
} SENTINEL_EVENT_FLAT, *PSENTINEL_EVENT_FLAT;

/* ─── Query Status (returned to user-mode) ───────────────────────────── */
typedef struct _SENTINEL_STATUS {
  ULONG ProtectionActive;
  ULONG ProtectedPid;
  LONG HandlesStripped;
  LONG FilesDenied;
  ULONG EventsInQueue;
} SENTINEL_STATUS, *PSENTINEL_STATUS;

/* ─── Ring Buffer ────────────────────────────────────────────────────── */
typedef struct _SENTINEL_RING_BUFFER {
  LIST_ENTRY Head;
  KSPIN_LOCK Lock;
  ULONG Count;
  ULONG MaxCount;
  volatile LONG TotalHandlesStripped;
  volatile LONG TotalFilesDenied;
} SENTINEL_RING_BUFFER, *PSENTINEL_RING_BUFFER;

/* ─── Global Driver State ────────────────────────────────────────────── */
typedef struct _GLOBAL_STATE {
  /* Protection target */
  HANDLE ProtectedPid;
  PEPROCESS ProtectedProcess;
  EX_PUSH_LOCK ProtectedProcessLock;

  /* Registered service PID (only this PID can issue IOCTLs) */
  HANDLE RegisteredServicePid;

  /* Authorized shutdown flag */
  volatile LONG ShutdownAuthorized;

  /* Subsystem handles */
  PDEVICE_OBJECT DeviceObject;
  PFLT_FILTER Filter;
  PVOID ObRegistrationHandle;

  /* Telemetry */
  SENTINEL_RING_BUFFER RingBuffer;
} GLOBAL_STATE;

extern GLOBAL_STATE g_State;

/* ─── driver.c ───────────────────────────────────────────────────────── */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

/* ─── handle_protect.c ───────────────────────────────────────────────── */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS RegisterObCallbacks(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL) VOID UnregisterObCallbacks(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL) PEPROCESS
    SentinelGetProtectedProcessReferenced(VOID);

/* ─── minifilter.c ───────────────────────────────────────────────────── */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    MiniFilterInit(_In_ PDRIVER_OBJECT DriverObject);

_IRQL_requires_max_(PASSIVE_LEVEL) VOID MiniFilterUnload(VOID);

/* ─── comms.c ────────────────────────────────────────────────────────── */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    InitComms(_In_ PDRIVER_OBJECT DriverObject);

_IRQL_requires_max_(PASSIVE_LEVEL) VOID DestroyComms(VOID);

/* ─── ringbuffer.c ───────────────────────────────────────────────────── */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID
    RingBufferInit(_Out_ PSENTINEL_RING_BUFFER Rb, _In_ ULONG MaxCount);

_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    RingBufferPush(_Inout_ PSENTINEL_RING_BUFFER Rb,
                   _In_ SENTINEL_EVENT_TYPE Type, _In_ ULONG SourcePid,
                   _In_ ULONG TargetPid, _In_ ACCESS_MASK OriginalAccess,
                   _In_ ACCESS_MASK StrippedAccess, _In_opt_ PCWSTR Detail);

_IRQL_requires_max_(DISPATCH_LEVEL) ULONG
    RingBufferDrain(_Inout_ PSENTINEL_RING_BUFFER Rb,
                    _Out_writes_bytes_(BufferSize) PVOID Buffer,
                    _In_ ULONG BufferSize);

_IRQL_requires_max_(PASSIVE_LEVEL) VOID
    RingBufferDestroy(_Inout_ PSENTINEL_RING_BUFFER Rb);
