# FSKit read-cache retention

The adapter starts observing Dispatch pressure when its immutable volume becomes
active and stops after drained unmount or invalidation. WARN or CRITICAL suspend
optional retention; a later NORMAL permits it
again. Elevated bits outrank NORMAL when Dispatch coalesces events. Zero and
unknown bits do not restore retention. An unavailable observer disables it.
The initial interval permits retention until an elevated event is observed;
remount preserves the last observed level until a new notification changes it.
This follows the selected SDK's `dispatch/source.h` guidance and Apple's
[memory-pressure source](https://developer.apple.com/documentation/dispatch/dispatchsourcememorypressure).

NTFSReadCachePolicy owns the source and a separate short-held monitor. Its
callback does not wait for the volume operation monitor or device I/O, allocate
core objects, traverse the item map or touch dormant caches. Start/stop share
the volume's operation monitor with activation, mount, drained unmount and
invalidation. A weak observer capture avoids retaining the volume through the
source; each observation interval has a distinct identity so a delayed canceled
callback cannot change a replacement source's state. Source cancellation does
not interrupt an outstanding synchronous read or authorize early buffer release.

An admitted item access drops previously retained disposable data when retention
is suspended. Reads and xattr operations also use a completion cleanup boundary,
including their error exits. This frees newly opened caches only after their last
consumer has copied the result. Newly adopted or returned canonical items follow
the same policy. Returning to NORMAL fills caches lazily; no notification scans
items or performs filesystem reads.

| Released on an accessed item | Preserved ownership |
| --- | --- |
| Default stream description, resident bytes/extents and LZNT1 unit buffers | Checked node, immutable stat, canonical FSItem and counted owner |
| WOF private backing streams, table page, encoded/decoded unit and codec scratch | Provider classification, original namespace identity and independent returned bytes |
| Stored stream-name catalog | Stable ADS ordinals and separately owned native response data |
| Raw reparse snapshot | Immutable native readlink target, directory ancestry and per-edge name policy |

Directory cursor, pending entry, position, visited-work budget and failure state
remain owned until ordinary continuation, rewind or teardown. The core's bounded
record cache, mounted MFT/$UpCase state, node record snapshots, retained native
identities and the resource's aligned I/O window also retain their ordinary
lifetimes. Aggregate budgets still apply; elevated pressure is not a promise to
release every allocated byte or reclaim a native vnode. Retained invalid owners
cannot become available through a NORMAL event.

## Component evidence

`tests/fskit_pressure.m` substitutes a Dispatch DATA_OR source for notification
delivery without changing host pressure. The real observer handler changes state
while a semaphore-gated aligned resource read is blocked. A five-second deadline
checks that notification delivery does not depend on that read completing;
buffers and core allocation bytes remain owned until the gate returns. The
completed read then releases its disposable state and returns exact bytes with
one native reply. Source ownership/restart, absent observers, coalesced levels,
zero/unknown flags and inactive notifications have separate checks.

Tracked core allocation bytes in the tested retained/read/xattr scenarios are:

| Independently authored input | Retained | Transient after access | Released |
| --- | ---: | ---: | ---: |
| Standard LZNT1 file | 270,296 | 134,664 | 135,632 |
| WOF XPRESS4K file | 153,480 | 134,664 | 18,816 |
| WOF LZX32K packed file | 214,100 | 134,664 | 79,436 |

The scenarios disable the core record cache to isolate adapter-owned retention.
These are core allocator bytes, excluding Foundation objects, the separate I/O
window, kernel buffers, test input storage and sanitizer overhead. They are not
RSS or throughput benchmarks. Repeated normal reads preserve the warm unit's
no-additional-I/O behavior. Elevated accesses keep exact content, copied reparse
bytes, full stream manifests, stable ADS and canonical identity. Remount preserves
elevated state. Old returned bytes remain valid after cleanup and invalidation.

The complete cold LZX read's 11 allocation/two read failure positions pass under
elevated pressure, including retry, zero native error counts, untouched read
guards and exact cleanup. A separate catalog allocation failure/retry passes.
Permanent revocation cannot be undone by restoration. Two interleaved scans in
the attribute-requested directory view, with full/empty packers, independent name manifests and ADS reads, preserve
the complete independently expected order and EOF cookies while callbacks change
pressure inside packing. A supported relative native link preserves its target
and original-wire oracle after snapshot release.

The sanitized component reports 17 PASS groups and seven explicit macOS-27
runtime SKIPs, including the new pressure group. Both protocol sources, the
current unsigned app/extension and selected-toolchain style pass. Evidence is
`artifacts/plan-pressure-component-final.log`, `plan-pressure-style-final.log`
and `plan-pressure-app-reviewed.log`. The initial component
failure remains in `artifacts/plan-pressure-component-initial.log`: its link
scenario incorrectly selected an escape beyond the explicit owning root. The
corrected scenario uses the existing native-link manifest's supported target and
original bytes; ordinary escape rejection remains in the full link suite.
Portable C sources and their preceding 37-suite/frame/fuzz evidence are unchanged.

Native notification receipt on each supported OS, installed held descriptors and
mappings, aggregate allocation/RSS stress, native reclamation and performance
under pressure still require separate acceptance. Ext4's mounted observations
inform this policy but do not prove NTFS delivery, and successful execution of a
pressure-simulation utility alone does not prove that this observer received it.
