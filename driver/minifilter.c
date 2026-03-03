/*++
    minifilter.c — File Protection Mini-Filter (Production-Grade)

    Protects SentinelCore binaries from write/delete/rename by foreign
    processes. Pushes telemetry events to the ring buffer on every deny.

    Protected files (case-insensitive final component match):
      - sentinelcore.exe
      - sentinel_km.sys
      - sentinel_config.yaml

    IRQL:
    - PreCreateCallback runs at PASSIVE_LEVEL (IRP_MJ_CREATE).
    - MiniFilterInit/Unload at PASSIVE_LEVEL.
--*/

#include "globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MiniFilterInit)
#pragma alloc_text(PAGE, MiniFilterUnload)
#endif

/* ─── Protected file names ───────────────────────────────────────────── */
static PCWSTR g_ProtectedFiles[] = {L"sentinelcore.exe", L"sentinel_km.sys",
                                    L"sentinel_config.yaml"};
#define PROTECTED_FILE_COUNT                                                   \
  (sizeof(g_ProtectedFiles) / sizeof(g_ProtectedFiles[0]))

/* ─── Check if a filename matches any protected file ─────────────────── */
static BOOLEAN IsProtectedFileName(_In_ PCUNICODE_STRING FinalComponent) {
  ULONG i;
  UNICODE_STRING target;

  for (i = 0; i < PROTECTED_FILE_COUNT; i++) {
    RtlInitUnicodeString(&target, g_ProtectedFiles[i]);
    if (FsRtlIsNameInExpression(&target, (PUNICODE_STRING)FinalComponent, TRUE,
                                NULL)) {
      return TRUE;
    }
  }
  return FALSE;
}

/* ─── Dangerous access mask for writes/deletes ───────────────────────── */
#define SENTINEL_DANGEROUS_FILE_ACCESS                                         \
  (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | FILE_WRITE_ATTRIBUTES)

/*++
    PreCreateCallback — MiniFilter pre-operation for IRP_MJ_CREATE.
--*/
static FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
  PEPROCESS requestor;
  PEPROCESS protectedProcess;
  PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(FltObjects);
  *CompletionContext = NULL;

  /* Fast exit: no thread, not IRP_MJ_CREATE */
  if (Data->Thread == NULL || Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  /* Fast exit: not requesting dangerous access */
  if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
       SENTINEL_DANGEROUS_FILE_ACCESS) == 0) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  /* Is protection active? */
  protectedProcess = SentinelGetProtectedProcessReferenced();
  if (protectedProcess == NULL) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  /* The protected process itself is allowed to modify its own files */
  requestor = PsGetThreadProcess(Data->Thread);
  if (requestor == protectedProcess) {
    ObDereferenceObject(protectedProcess);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  /* Get the filename and check against protected list */
  status = FltGetFileNameInformation(
      Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
  if (!NT_SUCCESS(status)) {
    ObDereferenceObject(protectedProcess);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  FltParseFileNameInformation(nameInfo);

  if (IsProtectedFileName(&nameInfo->FinalComponent)) {
    /* BLOCK — Push telemetry then deny */
    RingBufferPush(&g_State.RingBuffer, SentinelEventFileDenied,
                   HandleToULong(PsGetProcessId(requestor)),
                   HandleToULong(g_State.ProtectedPid),
                   Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                   0, nameInfo->FinalComponent.Buffer);

    FltReleaseFileNameInformation(nameInfo);
    ObDereferenceObject(protectedProcess);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }

  FltReleaseFileNameInformation(nameInfo);
  ObDereferenceObject(protectedProcess);
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ─── MiniFilter registration ────────────────────────────────────────── */
static CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {IRP_MJ_CREATE, 0, PreCreateCallback, NULL}, {IRP_MJ_OPERATION_END}};

static CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,    /* Flags */
    NULL, /* Context registration */
    g_Callbacks,
    NULL, /* FilterUnloadCallback (handled via DriverUnload) */
    NULL, /* InstanceSetupCallback */
    NULL, /* InstanceQueryTeardownCallback */
    NULL, /* InstanceTeardownStartCallback */
    NULL, /* InstanceTeardownCompleteCallback */
    NULL,
    NULL,
    NULL /* Generate/Normalize/NormalizeContext */
};

/*++
    MiniFilterInit — Register and start the file system mini-filter.
--*/
_Use_decl_annotations_ NTSTATUS MiniFilterInit(PDRIVER_OBJECT DriverObject) {
  NTSTATUS status;

  PAGED_CODE();

  status =
      FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_State.Filter);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = FltStartFiltering(g_State.Filter);
  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(g_State.Filter);
    g_State.Filter = NULL;
  }

  return status;
}

/*++
    MiniFilterUnload — Unregister the mini-filter.
--*/
_Use_decl_annotations_ VOID MiniFilterUnload(VOID) {
  PAGED_CODE();

  if (g_State.Filter != NULL) {
    FltUnregisterFilter(g_State.Filter);
    g_State.Filter = NULL;
  }
}
