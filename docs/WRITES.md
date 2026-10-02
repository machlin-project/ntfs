# Writable ownership and recovery contract

No writable API is implemented. The current read environment cannot write, and
the FSKit adapter must reject all mutations with EROFS. Do not enable writes by
adding a pwrite callback to individual operations.

A writable owner must exclusively claim the device, reject Windows hibernation
and Fast Startup state, validate volume/log versions and process native NTFS
$LogFile restart areas and redo/undo records. $UsnJrnl is a change journal, not a
replacement for $LogFile. An incompatible private journal would not give Windows
a recovery contract and must not be presented as native NTFS write support.

The read-only primitives in LOGFILE.md now validate bounded restart/client/page/
LSN/record framing and nonempty-LCN update spans. They neither choose a complete
post-crash journal history nor execute recovery. Clean hints and structural parser
success never satisfy writable ownership or permit a dirty mount. The separate
logical-source owner selects only compatible supported restart copies, retaining
bounded conflicts and backend error evidence; physical page reading does not
establish a post-crash journal history. Counted read-only stream binding is now
implemented without admitting dirty mounts. Physical wrapped-record assembly now
has bounded exact-byte/read/fault checks, but does not establish written/current
history or qualify continuation provenance. Native journal admission/drain,
tail/fast-page routing, active circular history, native client checkpoints,
transaction analysis and the crash/durability simulator remain required.

The future transaction module owns private snapshots, MFT/$Bitmap reservations,
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
