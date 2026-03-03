/*++
    ringbuffer.c — Non-paged spinlock-protected telemetry ring buffer.

    Design:
    - Doubly-linked list of SENTINEL_EVENT nodes allocated from NonPagedPool.
    - KSPIN_LOCK protects all operations (safe up to DISPATCH_LEVEL).
    - Hard cap: when Count >= MaxCount, oldest node is evicted and freed.
    - Drain copies events into a user-mode flat buffer via IOCTL.
    - Destroy frees all remaining nodes.

    IRQL discipline:
    - RingBufferInit:    PASSIVE_LEVEL  (called from DriverEntry)
    - RingBufferPush:    <= DISPATCH_LEVEL (called from Ob/Flt callbacks)
    - RingBufferDrain:   <= DISPATCH_LEVEL (called from IOCTL dispatch)
    - RingBufferDestroy: PASSIVE_LEVEL  (called from DriverUnload)
--*/

#include "globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, RingBufferInit)
#pragma alloc_text(PAGE, RingBufferDestroy)
#endif

/* SENTINEL_EVENT_FLAT is defined in globals.h */

/*++
    RingBufferInit — Initialize the ring buffer at PASSIVE_LEVEL.
--*/
_Use_decl_annotations_ VOID RingBufferInit(PSENTINEL_RING_BUFFER Rb,
                                           ULONG MaxCount) {
  InitializeListHead(&Rb->Head);
  KeInitializeSpinLock(&Rb->Lock);
  Rb->Count = 0;
  Rb->MaxCount = MaxCount;
  Rb->TotalHandlesStripped = 0;
  Rb->TotalFilesDenied = 0;
}

/*++
    RingBufferPush — Insert a telemetry event into the ring buffer.
    Safe at DISPATCH_LEVEL. Evicts oldest if buffer is full.
--*/
_Use_decl_annotations_ VOID RingBufferPush(PSENTINEL_RING_BUFFER Rb,
                                           SENTINEL_EVENT_TYPE Type,
                                           ULONG SourcePid, ULONG TargetPid,
                                           ACCESS_MASK OriginalAccess,
                                           ACCESS_MASK StrippedAccess,
                                           PCWSTR Detail) {
  PSENTINEL_EVENT node;
  KIRQL oldIrql;

  node = (PSENTINEL_EVENT)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, sizeof(SENTINEL_EVENT), SNTL_TAG_EVENT);
  if (node == NULL) {
    return; /* Allocation failure — drop silently, never crash */
  }

  KeQuerySystemTimePrecise(&node->Timestamp);
  node->Type = Type;
  node->SourcePid = SourcePid;
  node->TargetPid = TargetPid;
  node->OriginalAccess = OriginalAccess;
  node->StrippedAccess = StrippedAccess;

  if (Detail != NULL) {
    RtlStringCchCopyW(node->Detail, SENTINEL_MAX_EVENT_DATA, Detail);
  } else {
    node->Detail[0] = L'\0';
  }

  /* Update global counters (interlocked, no lock needed) */
  if (Type == SentinelEventHandleStrip) {
    InterlockedIncrement(&Rb->TotalHandlesStripped);
  } else if (Type == SentinelEventFileDenied) {
    InterlockedIncrement(&Rb->TotalFilesDenied);
  }

  KeAcquireSpinLock(&Rb->Lock, &oldIrql);

  InsertTailList(&Rb->Head, &node->ListEntry);
  Rb->Count++;

  /* Evict oldest if over capacity */
  while (Rb->Count > Rb->MaxCount) {
    PLIST_ENTRY oldest = RemoveHeadList(&Rb->Head);
    PSENTINEL_EVENT evicted =
        CONTAINING_RECORD(oldest, SENTINEL_EVENT, ListEntry);
    ExFreePoolWithTag(evicted, SNTL_TAG_EVENT);
    Rb->Count--;
  }

  KeReleaseSpinLock(&Rb->Lock, oldIrql);
}

/*++
    RingBufferDrain — Copy up to N events into a flat user-mode buffer.
    Returns the number of events copied. Frees drained nodes.
--*/
_Use_decl_annotations_ ULONG RingBufferDrain(PSENTINEL_RING_BUFFER Rb,
                                             PVOID Buffer, ULONG BufferSize) {
  KIRQL oldIrql;
  ULONG copied = 0;
  ULONG maxEvents = BufferSize / sizeof(SENTINEL_EVENT_FLAT);
  PSENTINEL_EVENT_FLAT out = (PSENTINEL_EVENT_FLAT)Buffer;

  if (maxEvents == 0 || Buffer == NULL) {
    return 0;
  }

  KeAcquireSpinLock(&Rb->Lock, &oldIrql);

  while (!IsListEmpty(&Rb->Head) && copied < maxEvents) {
    PLIST_ENTRY entry = RemoveHeadList(&Rb->Head);
    PSENTINEL_EVENT node = CONTAINING_RECORD(entry, SENTINEL_EVENT, ListEntry);

    out[copied].Timestamp = node->Timestamp;
    out[copied].Type = node->Type;
    out[copied].SourcePid = node->SourcePid;
    out[copied].TargetPid = node->TargetPid;
    out[copied].OriginalAccess = node->OriginalAccess;
    out[copied].StrippedAccess = node->StrippedAccess;
    RtlCopyMemory(out[copied].Detail, node->Detail, sizeof(node->Detail));

    ExFreePoolWithTag(node, SNTL_TAG_EVENT);
    Rb->Count--;
    copied++;
  }

  KeReleaseSpinLock(&Rb->Lock, oldIrql);
  return copied;
}

/*++
    RingBufferDestroy — Free all remaining nodes. Called at PASSIVE_LEVEL.
--*/
_Use_decl_annotations_ VOID RingBufferDestroy(PSENTINEL_RING_BUFFER Rb) {
  KIRQL oldIrql;

  PAGED_CODE();

  KeAcquireSpinLock(&Rb->Lock, &oldIrql);

  while (!IsListEmpty(&Rb->Head)) {
    PLIST_ENTRY entry = RemoveHeadList(&Rb->Head);
    PSENTINEL_EVENT node = CONTAINING_RECORD(entry, SENTINEL_EVENT, ListEntry);
    ExFreePoolWithTag(node, SNTL_TAG_EVENT);
    Rb->Count--;
  }

  KeReleaseSpinLock(&Rb->Lock, oldIrql);
}
