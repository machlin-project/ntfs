# Writable ownership and recovery contract

No writable API is implemented. The current read environment cannot write, and
the FSKit adapter must reject all mutations with EROFS. Do not enable writes by
adding a pwrite callback to individual operations.

Private USA output and native restart-table/entry framing are now implemented;
[WRITE-FOUNDATIONS.md](WRITE-FOUNDATIONS.md) defines their exact admission and
publication contracts. They add no device-write capability. Current physical
history, complete checkpoint ownership/analysis and native durability acceptance
remain prerequisites for the writable owner and mutations below.

The next core implementation sequence is:

1. Establish selected current physical $LogFile history, acquire the owning NTFS
   client restart record, and validate complete checkpoint tables and native
   transaction analysis. Existing read-only packet observers and the reference
   durability model are groundwork; they do not close this recovery contract.
2. Implement the separate writable owner, reservations/credits, native log planning,
   redo/undo recovery and durable barrier/poison contracts. Keep writes disabled
   while these contracts lack native recovery acceptance.
3. Qualify bounded writes to existing initialized file ranges without allocation
   or size changes, with explicit partial-write and fsync semantics. Interrupt
   writes/barriers and verify recovery, metadata and data against Windows/chkdsk.
4. Expand to allocation, resize, creation, deletion and rename, with dedicated
   namespace/security/lifetime and crash tests for each mutation family.

Portable history/table decoders, transaction planning and injected failure models
can be implemented without a VM. Synthetic evidence cannot replace native NTFS
history acquisition, Windows recovery roundtrips or actual device durability checks.

A writable owner must exclusively claim the device, reject Windows hibernation
and Fast Startup state, validate volume/log versions and process native NTFS
$LogFile restart areas and redo/undo records. $UsnJrnl is a change journal, not a
replacement for $LogFile. An incompatible private journal would not give Windows
a recovery contract and must not be presented as native NTFS write support.

The read-only primitives in LOGFILE.md now validate bounded restart/client/page/
LSN/record framing, empty/nonempty-LCN update spans and lossless name-dump framing.
They neither choose a complete
post-crash journal history nor execute recovery. Clean hints and structural parser
success never satisfy writable ownership or permit a dirty mount. The separate
logical-source owner selects only compatible supported restart copies, retaining
bounded conflicts and backend error evidence; physical page reading does not
establish a post-crash journal history. Counted read-only stream binding is now
implemented without admitting dirty mounts. Physical wrapped-record assembly now
has bounded exact-byte/read/fault checks, but does not establish written/current
history or qualify continuation provenance. Native journal admission/drain,
tail/fast-page routing, active circular history, native client checkpoints,
transaction analysis and native crash/durability qualification remain required.
An executable in-memory reference model now exercises serialized ownership,
WAL/commit/home/checkpoint ordering, partial writes and interrupted replay; see
[RECOVERY-MODEL.md](RECOVERY-MODEL.md). Its typed history is not an NTFS journal
format. Native transaction/recovery integration and broader crash/durability
qualification remain required.
The independent client restart decoder observes only the 64-byte common prefix
for client formats 0.0/1.0. Its raw analysis/table LSNs and byte counts authorize
no table reads, transaction state or recovery; containing-record ownership,
selected current history, complete checkpoint tables and optional extensions
must be qualified separately.
Selected-client record binding now checks the exact assembled framing, RESTART
type, active index/sequence, exact NTFS client name and stored restart LSN before
prefix interpretation. This cached snapshot match establishes no native page
provenance or current written history and cannot advance writable qualification.

The future product transaction module owns private snapshots, MFT/$Bitmap reservations,
attribute-list growth, directory B-tree changes, $Secure references and rollback.
Define lock ordering and credits before allocation. All referenced data must be
initialized before metadata publication. FILE/INDX sector fixups must be generated
from a complete private record; no in-place partial metadata edits are allowed.

Commit requires a real device persistence primitive through every volatile cache,
write-ahead log ordering, durable commit publication, recoverable home writes and
checkpoint advancement. FSKit callback completion or metadataFlush alone must not
be called a persistence barrier. An uncertain I/O or barrier failure poisons the
writable owner and retains recovery evidence. Licensing cannot prevent safe flush
or unmount, nor change the bytes committed by a transaction.

Acceptance must interrupt every boundary and each sector of metadata writes;
compare replay by this implementation and Windows, run independent chkdsk, and
verify user data, allocation, links, security IDs and rename atomicity. Cover ENOSPC,
failed log growth, device loss, duplicate names, open-unlinked lifetime, mmap,
concurrent truncation and cancellation. Failed recovery stays failed, never
"repaired" by clearing the dirty flag. NTFS-3G comparison is useful but cannot
replace Windows roundtrips and native recovery verification.
