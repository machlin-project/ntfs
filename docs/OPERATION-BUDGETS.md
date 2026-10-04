# Operation resource contracts

The mounted core now bounds each public owning operation, including nested
owning calls. A caller-owned scope can combine several operations into one
budget. FSKit uses that scope for each compound native request and separately
counts physical resource transfers. The limits are execution policies; they
are independent of NTFS wire lengths and do not establish a CPU deadline,
synchronous-I/O interruption or installed-runtime acceptance.

## Configuration and ABI

`NTFS_API_VERSION` is 2 because `ntfs_limits` now includes aggregate live storage
and operation ceilings. Rebuild every caller against the current header, set
the environment's version to `NTFS_API_VERSION`, and initialize limits with
`ntfs_default_limits` before overriding fields. Old partial aggregate
initializers leave required fields zero and are invalid. Version mismatch and
invalid policies are refused before mount's first allocator callback.

| Policy | Default | Meaning |
| --- | ---: | --- |
| `max_live_bytes` | 64 MiB | All live volume-owned core allocations, including mounted state, retained caches and every child |
| `operation.read_calls` | 1,048,576 | Admitted exact-read callback attempts |
| `operation.read_bytes` | 1 GiB | Sum of requested bytes in admitted exact reads |
| `operation.allocation_calls` | 65,536 | Admitted allocator callback attempts |
| `operation.allocation_bytes` | 64 MiB | Sum of requested bytes in admitted allocations, including allocations later freed |
| `operation.work` | 4,294,967,296 units | Sum of the byte/span/iteration charges defined below |
| Scope and public-call depth | 32 each | Finite stack traversal and nested owning-call depth |

The defaults preserve room for the existing bounded reader profiles while
limiting repeated work and allocation churn. They are named, configurable
policies, not NTFS requirements or Windows-derived optimal values. A mount may
select positive finite ceilings; an explicit scope may only tighten that
volume's immutable operation ceilings. A child scope can exceed its parent's
individual ceiling because every admitted charge also consumes every ancestor.
It cannot reset or evade the parent budget.

Mount includes its initial volume allocation and boot exact read in its implicit
usage. It rejects a live/allocation-byte ceiling smaller than the volume object
before allocating. Mount failure has no surviving volume from which to query
usage. Existing `ntfs_io_statistics` retain their earlier meaning and exclude
the bootstrap boot read; operation usage and those statistics need not match.

## Admission, lifetime and results

Scope storage starts zeroed, remains at the same address through begin/end and
must not be copied, mutated or reused while active. The caller still serializes
the volume and every child. Begin/end allocate nothing. While the owner is alive,
end follows reverse begin order. Required refusal propagates the same sticky
result to every active ancestor; begin refuses an exhausted parent. The head
therefore supplies the stack's sticky result without scanning older flags.
Every credit dimension still preflights every ancestor before admission. Begin
clears usage and explicitly assigns all remaining scope fields, including reused
storage. Begin/end and unmount return BUSY during an
active public C call, including from an allocator or exact-read callback.
An out-of-order or otherwise failed end changes neither scope nor output report.
On success, passing `&scope.usage` as the end report is valid.

Before a read/allocation callback, admission checks all dimensions and ancestors
without committing partial credits. An admitted callback attempt counts even
when the backend fails. A refused attempt consumes no callback credit and never
reaches the backend. Required-resource refusal latches the exhausted dimension
on every active ancestor. Later owning operations in that scope fail without
new resource use; ending it permits a fresh operation. A backend I/O/allocation
failure does not by itself latch exhaustion, so retry is possible if remaining
credits and object state permit it.

Memory-limit refusal returns `NTFS_NO_MEMORY`; read/work refusal returns
`NTFS_RANGE`. `ntfs_operation_result` reports the scope's quota result separately
from the operation's format/backend result. `ntfs_operation_check` checks current
ancestor admission without resources. End's return value reports successful
scope closure, not the body result. `ntfs_get_operation_usage` returns the last
completed implicit call or ended explicit scope, rather than a live snapshot.

Close functions and fixed-size immutable getters remain available under
exhaustion, with their ordinary valid-object requirements. Live storage decreases
when allocations are released; cumulative allocation credits do not decrease.
Unmount remains BUSY while counted children exist. Successful unmount detaches
active caller scopes before freeing the owner, preserving usage and safe later
end without dereferencing freed storage. Detached scopes must still be ended
before their caller storage is reused.

Without an explicit scope, a public owning call receives an implicit budget and
all nested calls share it. `core/api.c` supplies the owning boundaries for node,
lookup, directory, stream, catalog, reparse, security, free-cluster counting and
volume-journal opening. Pure standalone parsers and fixed-size getters retain
their own input/caller bounds. Independent logical-journal operations retain
their existing journal limits. Bound-volume journal allocations now use the
core live ledger; an explicit volume scope aggregates their callbacks and backing
stream reads across journal calls. Without one, each backing public stream read
has its own implicit core scope, in addition to the journal operation credits.

A compound caller closes temporary objects on every exit, then ends its scope:

```c
struct ntfs_operation scope = {0};
struct ntfs_operation_usage usage;
struct ntfs_node *node = NULL;
struct ntfs_stat stat;
enum ntfs_result result;

result = ntfs_operation_begin(volume, NULL, &scope);
if (result == NTFS_OK) {
    result = ntfs_root(volume, &node);
    if (result == NTFS_OK) {
        result = ntfs_node_stat(node, &stat);
    }
    ntfs_node_close(node);
    (void)ntfs_operation_end(&scope, &usage);
}
```

Pointer/count outputs start empty at owning admission. Metadata/stat outputs are
zeroed on failure. Existing copy-capacity queries still return required size with
RANGE and leave caller bytes untouched; quota refusal during an actual copy
reports zero. A core stream read may retain an earlier completed prefix when a
later fragment fails. It is not a successful read, and its destination may have
been touched. FSKit's error replies report zero bytes and discard failed values.
A failed directory traversal retains the cursor's failure; reconstruct a fresh
cursor when retry requires traversal, rather than resetting its scope alone.

Optional validated-record cache retention has a soft allocation admission. If
remaining cumulative/live credits do not cover that extra cache allocation,
the reader omits retention without a callback or quota latch. Required output
still succeeds. An admitted optional allocator failure counts its attempt;
only successfully populated immutable records become cache entries.

The second LZNT1/WOF decoded-output slot uses the same soft admission. Its one
output-unit allocation is attempted only once per stream after a useful first
fill; refusal preserves required decoding with one slot. An admitted allocator
failure still charges the attempt. With two outputs, failed replacement
invalidates only the victim and retains the other valid unit; with one output,
the old tag is invalidated before replacement. Both buffers are live-volume
storage and close unconditionally. Required exact/one-below allocation/live
boundaries exclude optional output storage; separate omission tests verify full
content success at the tighter boundary and no exhausted scope.

## Work accounting

Work is a deterministic policy model, not an instruction counter. Fixed bounded
helpers can perform several primitive operations per charged byte or step.
Existing format/run/depth/token/response limits continue to bound their spans.
Stream extent positions are retained in the required stream object and included
in its allocation/live credits. They allocate no read-path storage. A current or
successor mapping hit keeps the same delivered/raw work charges and exact I/O
admission as the binary-search fallback. Retaining a position after failed I/O
does not retain successful content; retry requires a new admitted exact read.
Six original fragmented/sparse/VDL profiles exercise 34 partial/full I/O failures
and 36 exact/one-below compound read-call/read-byte/work limits, including sticky
refusal and fresh retry with two independently owned streams.

The accounting deliberately includes cached and memory-only paths:

| Path | Charges |
| --- | --- |
| Mount and records | Boot/record spans before decoding or cache copying; validated UpCase loop units |
| Attributes and mappings | Base record scans, attribute-list entry spans and each referenced-record scan; mapping attribute spans and validated run counts |
| Streams | EOF-clipped delivered bytes, raw stream spans and additional cold compression-unit output work before decode/copy/zero |
| Directory indexes | Checked frame spans, seek/traversal transitions, visited-table scans, collision probes and rehash steps; diagnostic-only complete bitmap bit scans and visited-block membership probes |
| ADS catalogs | Record/list spans, each name comparison including its minimum UTF-16 span, sort/uniqueness/base lookup and copied entry size |
| Filename counts | Result size on node-local reuse; every inspected full-reference volume-cache payload; cold publication precharge before existing complete record/list/sort/body validation |
| Metadata and reparse | Cold record or cached stat size; actual original-byte and UTF-16 copies |
| Security | Index-frame spans, descriptor hash/validation/copy/duplicate comparison spans, bounded token group scans and each owned DACL SID comparison; whole-store cursor transitions, visited/bitmap membership, locator growth/heap sorting, interval checks and FILE-ID binary probes; per-file diagnostic decoding precharges descriptor bytes to both work planes and shares one operation with the owning node open |
| Free clusters | Bitmap byte scans, with the fixed bits-per-byte loop |

Delivery, backing reads and private decoding are separate work and I/O costs.
No failed cold decoder fill publishes a valid unit tag; a fresh same-stream retry
must refill it. A cached unit copy still consumes work even when it needs no I/O.
Changing this model requires boundary tests and renewed measurement; interpreting
units as elapsed seconds or an exact operation count would be incorrect.

The volume filename-count memo occupies the already required record-cache array;
its sixteen-byte payload per configured entry is included in mount allocation and
live storage. It performs no separate allocation. Zero record-cache entries
disables volume reuse. A miss precharges publication before cold I/O; an exhausted
inventory publishes nothing. A hit compares the full reference and current checked
physical header, then populates the fresh node only after complete admission.
The original complete cold inventory and per-node hit charges remain intact.
tests/links_cache.c checks exact/one-below cold and nested hot work, stale references,
different owners, raw/count replacement, DOS separation, read/allocation failures,
fresh retry, disabled/single/default capacities and zero tracked storage at unmount.

## FSKit physical accounting

Each native lookup, attribute, readlink, xattr list/get, enumeration, content-read
and activation boundary owns a core scope plus a resource read scope under the
existing operation monitor. Constructor free-space scanning is also scoped.
Probe/load separately bound their complete physical-read spans; load covers mount
and native volume construction. Native reentry adds child scopes that charge
every ancestor. Admission checks sticky quotas before packing and after callbacks,
so a provider error cannot normalize a quota refusal into an unknown successful
entry. Replies retain their existing exactly-once and lifecycle checks.

`NTFSResource` counts actual rounded physical fragments before each synchronous
reader callback. Core exact-read bytes are logical callback requests: one may
expand into more physical bytes or several fragments. Both planes use the
selected read ceilings but have separate usage. Resource scopes use caller storage,
LIFO ownership and depth 32. While its reader callback is active, recursive reads
and read-scope begin/end return BUSY. Failed admitted callbacks count; refused
fragments do not reach the reader. All ancestors latch physical exhaustion.

An in-flight native boundary precisely retains its resource through scope cleanup.
Terminal invalidation may detach core scopes while that boundary is active; its
finally block can safely end both planes after all core children are closed.
Lifecycle/revocation errors retain their existing precedence. Quotas do not allow
early release of a buffer still owned by a synchronous reader callback.

The core live cap and resource's aggregate 64-MiB allocation pool are distinct:
the pool also charges native continuation-table storage. The separate 1-MiB
aligned resource window, Foundation objects, native response data, kernel buffers
and allocator overhead are not core cumulative allocation usage or core live
bytes. Native identities, response sizes and namespace scans have separate caps.
These caps are not a complete RSS or aggregate native-memory qualification.

The full consistency diagnostic's reserved boot copy lies immediately outside
the mounted data span. Its private read checks backing-resource bounds and
charges diagnostic read/work limits plus the existing native physical-read scope.
It is not a mounted-core exact-read charge and does not widen ordinary stream
bounds. Sector staging shares the diagnostic memory cap and native resource pool.
See VALIDATION.md for the supported copy profile and partial reports.

## Local qualification and remaining work

`tests/operation.c` checks 12 independently authored storage/operation profiles
and 144 exact/one-below boundaries, with independent callback/byte/live-peak
observations and original content. Profiles include ordinary/deep directory,
bitmap, fragmented/listed MFT, fragmented/sparse/LZNT1 content, ADS, reparse,
Secure/DACL, XPRESS/LZX and fragmented/listed journal pages. Additional tests cover
mount, ABI refusal, nested/LIFO/depth/cross-owner scopes, callback reentry, detached
end, sibling live storage, failed attempts, optional cache omission and cold/cache
decoder retry. A full-depth test denies each of the 32 ancestors, checks all
1,024 propagated sticky flags and zero failed work credits, rejects new children
during unwind and permits fresh successful operations with reused storage.
Images remain unchanged and required cleanup remains available.
The accounting source's bounded image campaign replays all 282 unique authored
seeds and passes 52,898 executions/70 seconds with no OOM, timeout or crash events;
ACCEPTANCE.md retains exact report/log and configured-limit scope.

`tests/fskit_operation.m` checks physical rounding/fragments, nested credits,
guards, callback scope refusal, backend retries, logical versus physical bytes,
cached work, lookup publication, names-only provider refusal, packer reentry and
terminal detach. Legacy replies execute locally; modern protocol sources compile
against SDK 27 but their runtime test explicitly SKIPs on this host. Current
complete qualification and retained failure logs are in ACCEPTANCE.md.

Windows-authored large/fragmented/hostile workloads, longer scheduled campaigns,
native aggregate allocation/RSS stress, installed buffer/scheduling behavior and
broader native/device accounting measurements remain required. PERFORMANCE.md
records paired portable guard cost and the targeted cached resident-read gain;
neither qualifies broader native or installed performance. Native synchronous-I/O
deadlines and cancellation remain separate ownership work in LIFECYCLE.md. This checkpoint
does not complete the full continuation scope in CORE-QUALIFICATION.md.
