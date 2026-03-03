/*++
    handle_protect.c — ObRegisterCallbacks for process handle protection.

    Strips dangerous access rights (TERMINATE, VM_WRITE, CREATE_THREAD,
    DUP_HANDLE) from any non-kernel caller attempting to open a handle to
    the protected process. Pushes a telemetry event to the ring buffer
    on every strip.

    IRQL:
    - PreOperationCallback runs at <= APC_LEVEL.
    - PostOperationCallback not used (stub required by API).
    - Register/Unregister at PASSIVE_LEVEL.

    All functions are SAL-annotated. No paged allocations in callbacks.
--*/

#include "globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegisterObCallbacks)
#pragma alloc_text(PAGE, UnregisterObCallbacks)
#endif

/* ─── Access rights to strip from foreign callers ────────────────────── */
#define SENTINEL_STRIP_MASK_PROCESS                                            \
  (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |              \
   PROCESS_DUP_HANDLE)

#define SENTINEL_STRIP_MASK_THREAD                                             \
  (THREAD_TERMINATE | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)

/*++
    PreOperationCallback — Invoked before a handle is created/duplicated.
    Strips dangerous rights if the target is the protected process.
--*/
static OB_PREOP_CALLBACK_STATUS
PreOperationCallback(_In_ PVOID RegistrationContext,
                     _Inout_ POB_PRE_OPERATION_INFORMATION Info) {
  PEPROCESS protectedProcess;
  ACCESS_MASK originalMask;
  ACCESS_MASK newMask;
  ULONG sourcePid;

  UNREFERENCED_PARAMETER(RegistrationContext);

  /* Only intercept process handles */
  if (Info->ObjectType != *PsProcessType) {
    return OB_PREOP_SUCCESS;
  }

  /* Fast path: no protection active */
  ExAcquirePushLockShared(&g_State.ProtectedProcessLock);
  protectedProcess = g_State.ProtectedProcess;

  if (protectedProcess == NULL || Info->Object != protectedProcess) {
    ExReleasePushLockShared(&g_State.ProtectedProcessLock);
    return OB_PREOP_SUCCESS;
  }
  ExReleasePushLockShared(&g_State.ProtectedProcessLock);

  /* Determine the access mask to modify */
  if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
    originalMask = Info->Parameters->CreateHandleInformation.DesiredAccess;
    newMask = originalMask & ~SENTINEL_STRIP_MASK_PROCESS;
    Info->Parameters->CreateHandleInformation.DesiredAccess = newMask;
  } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
    originalMask = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    newMask = originalMask & ~SENTINEL_STRIP_MASK_PROCESS;
    Info->Parameters->DuplicateHandleInformation.DesiredAccess = newMask;
  } else {
    return OB_PREOP_SUCCESS;
  }

  /* Only push telemetry if we actually changed something */
  if (originalMask != newMask) {
    sourcePid = HandleToULong(PsGetCurrentProcessId());

    RingBufferPush(&g_State.RingBuffer, SentinelEventHandleStrip, sourcePid,
                   HandleToULong(g_State.ProtectedPid), originalMask, newMask,
                   NULL);
  }

  return OB_PREOP_SUCCESS;
}

/*++
    PostOperationCallback — Required stub. No work done here.
--*/
static VOID PostOperationCallback(_In_ PVOID RegistrationContext,
                                  _In_ POB_POST_OPERATION_INFORMATION Info) {
  UNREFERENCED_PARAMETER(RegistrationContext);
  UNREFERENCED_PARAMETER(Info);
}

/*++
    RegisterObCallbacks — Register process handle protection at PASSIVE_LEVEL.
--*/
_Use_decl_annotations_ NTSTATUS RegisterObCallbacks(VOID) {
  OB_OPERATION_REGISTRATION opReg;
  OB_CALLBACK_REGISTRATION cbReg;
  UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370000");

  PAGED_CODE();

  RtlZeroMemory(&opReg, sizeof(opReg));
  RtlZeroMemory(&cbReg, sizeof(cbReg));

  opReg.ObjectType = PsProcessType;
  opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
  opReg.PreOperation = PreOperationCallback;
  opReg.PostOperation = PostOperationCallback;

  cbReg.Version = OB_FLT_REGISTRATION_VERSION;
  cbReg.OperationRegistrationCount = 1;
  cbReg.RegistrationContext = NULL;
  cbReg.Altitude = altitude;
  cbReg.OperationRegistration = &opReg;

  return ObRegisterCallbacks(&cbReg, &g_State.ObRegistrationHandle);
}

/*++
    UnregisterObCallbacks — Remove handle protection at PASSIVE_LEVEL.
--*/
_Use_decl_annotations_ VOID UnregisterObCallbacks(VOID) {
  PAGED_CODE();

  if (g_State.ObRegistrationHandle != NULL) {
    ObUnRegisterCallbacks(g_State.ObRegistrationHandle);
    g_State.ObRegistrationHandle = NULL;
  }
}

/*++
    SentinelGetProtectedProcessReferenced — Return a referenced PEPROCESS
    pointer to the protected process. Caller must ObDereferenceObject.
    Safe at DISPATCH_LEVEL.
--*/
_Use_decl_annotations_ PEPROCESS SentinelGetProtectedProcessReferenced(VOID) {
  PEPROCESS process;

  ExAcquirePushLockShared(&g_State.ProtectedProcessLock);
  process = g_State.ProtectedProcess;
  if (process != NULL) {
    ObReferenceObject(process);
  }
  ExReleasePushLockShared(&g_State.ProtectedProcessLock);

  return process;
}
