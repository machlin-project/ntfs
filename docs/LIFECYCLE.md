# FSKit operation ownership and teardown

The adapter serializes a core volume and all of its children with the volume's
operation monitor. A separate short-lived lock owns native admission state. It
is never held while waiting for that monitor, performing core/device I/O or
calling a reply. This lets unmount and deactivation close admission while a
synchronous resource read is still outstanding.

## State and ownership

| State | Allowed work and transition |
| --- | --- |
| Loaded | Activation may publish the root and enter Active. Ordinary item operations and mount require activation. |
| Active | Read-only operations are admitted after checking permanent resource revocation. |
| Draining | Unmount has closed admission; it waits for the serialized operation to return. New operations fail with ESTALE when they acquire the monitor. |
| Unmounted | Transient item caches are closed; core nodes and FSItem identities remain owned for subsequent reclamation. A mount may return the immutable owner to Active. |
| Invalidating | Deactivation or resource unload has permanently closed admission and is waiting to release every child and the core. Mount and activation cannot reopen it. |
| Invalidated | Core ownership and retained resource ownership have been released. Repeated teardown is harmless; ordinary operations remain stale. |

Unmount counts overlapping requests under the admission lock. Admission cannot
reopen while one of those requests still needs to drain the operation monitor.
Invalidation overrides unmount and is terminal. Replies run outside the monitor,
including replies that inspect the owner from another thread.

Unmount closes each item's stream catalog, directory cursor/pending entry and
data stream, including compression-unit caches. It preserves the node and native
item identity until reclaim or deactivation. The immutable core record cache and
mounted metadata snapshot retain their ordinary core lifetime until invalidation;
unmount is not a full core unload. Reclamation after unmount requires no device
I/O. The directory verifier remains valid for the same immutable owner: cookies
are ordinal continuations and rewind/replay produces the same names. Interleaved
callers currently share one cursor and replay when their cookies differ; bounded
checkpoint reuse remains a separate optimization.

A delayed successful read is checked against both admission and resource
availability before reporting success. Closing admission makes that read return
ESTALE with zero reported bytes. Device revocation returns EIO and permanently
fails that resource owner, even if the reader later clears its revoked flag.
The resource checks a late device return before copying its aligned window.
Buffers touched by a failed operation are not a successful or partially granted
read result. Cleanup waits for the synchronous callback to return before closing
the stream/core or releasing the resource's window.

## Cancellation boundary

The adapter uses the synchronous FSBlockDeviceResource read method. Its ordinary
read handlers receive no FSTask cancellation object. FSContext carries initiator
identity information; it is not a cancellation token. FSTask cancellation applies
to separate task-based operations, such as check/format handlers, which this
adapter does not currently implement. The CLI consistency diagnostic is not an
FSKit task handler.

Closing admission suppresses a delayed successful completion, but cannot forcibly
interrupt the native synchronous read. Unmount/deactivation therefore have no
bounded completion-time guarantee if that read never returns. The adapter does
not release or reuse an outstanding buffer to simulate a timeout. Resource
revocation is observed at admission/read completion; the framework owns native
resource removal. Asynchronous resource callbacks, task cancellation, native
request scheduling and installed buffer lifetime still require their own
implementation and acceptance if those surfaces are introduced.

These distinctions follow Apple's [volume operations](https://developer.apple.com/documentation/fskit/fsvolume/operations),
[deactivation contract](https://developer.apple.com/documentation/fskit/fsvolume/operations/deactivate(options:replyhandler:)),
[synchronous block-device reads](https://developer.apple.com/documentation/fskit/fsblockdeviceresource?language=objc),
[task cancellation](https://developer.apple.com/documentation/fskit/fstask/cancellationhandler)
and [initiator context](https://developer.apple.com/documentation/fskit/fscontext),
checked against the selected Xcode SDK headers.

## Local component evidence

`tests/fskit_lifecycle.m` drives the real adapter with a semaphore-gated aligned
reader. The gate is reached only after the resource has accepted the read. Tests
observe synchronized lifecycle transitions rather than assuming scheduling from
a sleep, and use five-second test deadlines. Eight scenarios cover:

- Unmount during a delayed read, plus a queued resident read.
- Protocol deactivation during that read.
- Overlapping unmount requests.
- Unmount overlapping protocol deactivation.
- Reclamation of the item whose read is outstanding.
- Revocation followed by a late successful device return.
- A delayed device error, followed by a successful retry.
- A delayed short device read, followed by a successful retry.

Every scenario starts with stream, compression, catalog and enumeration caches.
Checks cover completion counts, zero failure byte counts in legacy replies,
unchanged sentinel data after rejected device returns, no premature cleanup,
drain without further device reads and zero tracked core allocations after
invalidation. Unmount also checks cache release, retained canonical identities,
repeated teardown and remount. A separate test interleaves one-entry and two-entry
enumerations with zero-capacity rewinds; both recover the complete independently
expected ordered filename list and EOF cookies. Existing namespace budget and
allocation/read fault sweeps remain in the same component run.

The reviewed component run passed under ASan/UBSan. Style and the current unsigned
Debug app/extension build passed. Logs are
`artifacts/plan-lifecycle-component-reviewed.log`,
`artifacts/plan-lifecycle-style.log` and
`artifacts/plan-lifecycle-app-build.log`. The portable C core is unchanged; its
preceding 31-suite evidence remains separate. One modern lifecycle suite and two
modern case-policy checks explicitly SKIP on the current pre-macOS-27 runtime.
Both protocol classes compile. Mutable-buffer doubles exercise Objective-C reply
framing and adapter ownership, not installed kernel buffers or native scheduling.
The modern result classes are opaque; applicable modern tests inspect presence
and error framing without claiming independent inspection of their byte fields.
No installed mount, task cancellation, macOS 27 runtime or native authorization
acceptance is established by these tests.
