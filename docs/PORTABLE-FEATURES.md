# Portable capability and completion map

This map is an implementation plan, not a support claim. It reconciles the
current code with [WRITES](WRITES.md), [native names](NATIVE-NAMESPACE.md),
[access](ACCESS.md), [lifecycle](LIFECYCLE.md), [core qualification](CORE-QUALIFICATION.md)
and the [format research register](format/13-research-and-coverage.md).
Historical read-only paragraphs do not supersede the current ordinary-image
writer. Conversely, passing rejection tests does not implement a feature.

## Current capability and remaining work

| Family | Implemented capability | Missing cloud implementation or tests | Independent/native evidence still needed | Policy boundary |
| --- | --- | --- | --- | --- |
| Ordinary files and directories | Complete-image create, resize, initialized/growing writes, rename, closed-victim replace and remove; owned WAL preparation, recovery and checkpoint reuse; bounded installed ordinary-image evidence. | Extend hostile/fragmented inputs and interruption matrices. New incremental directory shapes need their own oracle batch. | Native recovery and chkdsk of incremental split/merge/root transitions; existing full-tree evidence does not transfer automatically. | Offline authorized regular images only; no block-device write admission. |
| Open unlink and opened-victim replacement | Stable sequence-bearing items, ordinary closed retirement and FILE reuse checks; executable bounded deferred-lifetime/durability model with separate reachability oracle. Open victims explicitly refuse. | Implement the modeled lifetime component in C and couple namespace detachment, held opens/mappings, final release, generation reuse, bounded resources and abort/drain to the actual owner. | On-disk orphan representation and crash reclamation, native handle/mapping lifetime and teardown behavior; Windows deletion-pending is not automatically the chosen macOS policy. | Current refusal protects still-referenced storage. Abstract model orphan authority is not an invented NTFS field or permanent feature exclusion. |
| Ordinary timestamp setters | Creation already selects four independent SI/filename/index timestamps. Experimental later SI-only preparation is described below. | Add complete durable later-setter interruption/recovery and native reply/time-conversion integration after cache/ownership qualification. | Which filename/index caches change, implicit ChangeTime/archive effects, handle-delayed updates and native replay of later setters. | Native general metadata setters remain refused. Windows API zero/-1/-2 sentinels must not be inferred from an exact storage request. |
| Other metadata setters | Stat, raw flags, Windows security and fixed native presentation are readable; Size mutation has its own contract. | Define masks and atomically prepare ordinary DOS attribute changes with all affected cached fields; separately model native request consumption and failures. | Automatic archive/change-time updates and cache publication for each setter. | UID/GID/mode are fixed extraction presentation. Mapping them to Windows principals/ACLs requires an explicit identity/product policy. |
| Hard-link creation and pair mutation | Private selected-cache POSIX link preparation owns complete FILE count/attribute and parent I30/tree/bitmap regions, preserves all existing names/data/ADS/security, and compiles generic redo/undo. Callback-free primary/physical-count admission and whole-byte/failure/inverse tests pass the isolated boundary. | Couple the exact prepared family to complete owned persistence/recovery only after its native gate; attribute-list/extension capacity is separate. | Native API cache/implicit-time placement, complete long/DOS association, high-count storage and new-family Windows replay. | Execution and FSKit remain refused; copied-cache storage is explicitly distinct from Windows API semantics. See [hard-link preparation](HARDLINK-PREPARATION.md). |
| Symlink/junction creation | Immutable reparse decoding and bounded read-only native projection; private bounded payload encoder with independent literal-wire and size/alias tests. | Couple encoded payload, FILE flags, namespace and required Reparse index in one prepared owning mutation; add failure/undo and target-policy tests. | Native reparse index updates, symlink privilege/security behavior, exact WAL/recovery and cross-volume targets. | Cross-volume/provider ownership and native absolute-target presentation are product decisions. Payload encoding alone does not grant filesystem creation admission. |
| Named-stream writes | Bounded exact-name catalog, ADS reading, ordinary writes preserve existing ADS. | Generalize stream target identity beyond the unnamed stream and four-unit private name slot; per-stream create/remove/resize, preserving base names, security and unrelated data; shared lifetime/resource tests. | Windows stream-name comparison, deletion/open-stream lifetime, metadata time/size side effects and native journal target naming. | No native xattr-to-ADS write policy is implied by read-only ADS presentation. |
| Sparse writes | Sparse read mapping and initialized-data clipping; private owned zero/punch transform with before/after maps, full-cluster retirement candidates and partial-cluster zero spans. | Bind whole-volume provenance, capture partial-data before images, add hole allocation for nonzero writes, sparse size/VDL accounting and coupled bitmap/metadata/redo/undo publication. | Native sparse attribute/flag transitions and WAL order for holes, valid-data length and tail allocation. | Ordinary mutation still refuses sparse objects until its full contract is qualified. Transform candidates are not permission to free storage. |
| Compressed/encoded writes | LZNT1 and WOF XPRESS/LZX decoding with bounded unit caches; original bounded LZNT1 encoder, exact-capacity/failure contracts and raw-block fallback. Hosted Windows ntdll independently decoded all 295 original encoded/plain pairs on source 62d2986. | Compression-unit placement, mapping and allocation coupling; complete old/new unit and crash oracles. WOF requires its own provider transform. | Native compression unit shape/publication and provider-specific metadata transitions/recovery. | Decoder support does not imply encoding, WIM/cloud provider ownership or permission to alter externally managed data. |
| ACL and shared security-store mutation | Descriptor framing, ordered DACL evaluation, indexed/per-file acquisition and complete-store validation; bounded creation inheritance. | Pure descriptor editor/inheritance and hash/dedup/index insertion models; owning ID allocation and duplicate SDS storage, then atomic coupled store/FILE updates and fault coverage. | Absent-vs-empty inherited DACL outcomes, token defaults, SACL and advanced ACE inheritance; SDS/SII/SDH allocation and WAL/recovery witnesses. | No invented Windows-to-native identity mapping or privilege grants. Existing writes preserve security. |
| Access decision extensions | Ordinary ordered ACEs, owners, deny-only and restricting contexts, explicit unsupported decisions. | Independent maximum-access and write-restricted-token models; object/callback parsing and bounded expression representation only where published semantics are sufficient. | AccessCheck observations for restricted ownership, conditional/object ACEs and maximum access; full native operation authorization. | DACL success is not full authorization. Mandatory integrity, privileges, auditing and native identities remain separately owned. |
| Attribute-list and extension-record growth | Read resolution binds extent/list provenance; ordinary inline capacity is bounded. | Independent extent packing, extension-generation ownership and list rewrite planner with bounded rollback. | Native allocation/logging/recovery across base/extension records and MFT bootstrap growth. | Slots 16–23 remain reserved; capacity refusal is intentional until extension ownership exists. |
| Change journal and special system indexes | Roles/read framing are partially known; active change-journal profile refuses write admission. | Bounded USN record decoder/encoder and reason aggregation model, followed by coupled mutation; separate ObjId, Quota and Reparse index models. | Versioned Max/J and native reason/coalescing/retention behavior, index ownership and full recovery. | Do not disable or discard a journal to admit writes. |
| EFS | Metadata and independent plaintext ADS remain visible; ciphertext content is refused. | Better classification/framing can be tested without keys; decryption requires an explicitly owned provider/key design. | EFS certificate/key context and native provider/security behavior. | Broad completion does not authorize inventing key handling or requesting credentials. |
| Geometry and lifecycle | Bounded read geometries, operation quotas, serialized owner admission/drain and poisoned uncertain writes. | Broader exact-alignment/geometry, cancellation, held-item and resource-failure models; portable mocks for native request/reply ownership. | 4Kn and broader writer recovery profiles; real FSKit scheduling, mapping, reclaim and cancellation behavior. | Synchronous I/O cannot be made interruptible by freeing its still-owned buffers. |

## Experimental selected SI timestamp preparation

The private planner accepts an exact selected-field storage request for the four
`ntfs_disk_standard` FILETIMEs. The request carries a field mask, so a selected
zero means the 1601 epoch and an unselected field is preserved byte-for-byte.
Values above the existing signed FILETIME ceiling refuse. No automatic clock,
Windows handle sentinel, archive-bit change or filename-cache refresh is implied.
The ordinary base-record admission boundary stays intact, including sequence
checks, flags, geometry and refusal of attribute-list/reparse/encoded objects.

Preparation owns the complete private FILE image and uses the existing sealed
region, predecessor and redo/undo compiler contracts. It leaves the source,
filenames and directory indexes, named/unnamed streams, security, allocation,
and unselected SI fields unchanged. Equal selected values produce an empty plan.
The general execution owner explicitly rejects this operation before callbacks;
there is no CLI or FSKit admission. This is a cloud-feasible storage implementation,
not later-setter native behavior or durability acceptance.

Microsoft's [FILE_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information)
documents the timestamp units and separate API/handle sentinels. Its public
[STANDARD_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/devnotes/standard-information)
and [FILE_NAME](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name)
descriptions do not establish later filename-cache refresh. The existing named
wire fields and SI stat policy supply the storage model; a Windows observation
must settle cache and implicit-update behavior before enabling a native setter.

## Next cloud implementation order

1. Build on the checked timestamp storage/redo/undo/fault tests; retain execution
   refusal and prepare hosted Windows before/after SI/FN/index observations.
2. Complete qualification of the [deferred-retirement executable model](DEFERRED-RETIREMENT.md),
   then implement its C/native lifetime boundary while leaving the unresolved
   on-disk orphan protocol explicit.
3. Build on the private reparse payload encoder's literal-byte, maximum-size and
   output-preservation tests. Establish Reparse-index ownership and a coupled
   FILE/namespace plan before exposing creation. Encoding alone must not expose
   a creation API or claim index ownership.
4. Qualify the [owned sparse transform](SPARSE-PREPARATION.md) and its independent
   byte-range/retirement oracle. Bind it to the existing prepared mutation only
   after whole-volume provenance, partial-data before images, valid-data length,
   sparse storage metadata and inverse ordering are established.
5. Extend portable authorization models against primary protocol definitions and
   hosted Windows AccessCheck observations, without integrating them into FSKit
   until native principal and operation ownership are specified.

Each step has cloud work now. Native evidence blocks only the dependent admission
or verdict, not the independent implementation and tests listed beside it.
