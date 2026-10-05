# Initialized data overwrite

The separate `ntfs_overwrite` owner now physically overwrites an initialized range
of an ordinary, nonresident unnamed stream. This is an experimental offline-image
operation, not the FSKit filesystem's `write(2)` implementation. It leaves every
metadata byte unchanged, including timestamps, archive flags, stream sizes,
allocation, security, names, USN and native journal storage. Metadata transactions
and ordinary writable product admission remain governed by [WRITES.md](WRITES.md).

The immutable version-2 read environment still has no write callback. A distinct
environment supplies an exclusive authorized claim, exact write with a transferred
prefix, a real persistence barrier and release without device I/O. The caller
serializes the owner's lifetime and excludes every other reader and mutator.
Admission performs complete allocation/metadata validation, rejects any root
`hiberfil.sys`, and internally owns the complete native checkpoint and retained
history. Only the qualified clean legacy profile with one targetless Noop followed
by its empty owning client restart is admitted. The Noop's observed transaction
epoch is retained; it is not globally relabeled committed. Dirty, hibernated,
unsupported or nonquiet histories cannot receive writes or an admission barrier.

Operations admit at most 1 MiB and absolute paths of at most 4096 UTF-16 units.
Reparse traversal, system records, directories, read-only/system files, resident,
compressed, encrypted, sparse, WOF and uninitialized ranges refuse explicitly.
Backend alignment must be a power of two from 512 through 65536 bytes and must
fit the volume's cluster geometry. Allocation, aggregate reads and live core memory
are bounded by the named policies. No API returns a mounted read object.

Before mutation, a fresh immutable snapshot checks the complete stream mapping,
prepares every aligned physical span, reads a complete private image and preserves
the bytes surrounding the patch. All streams, nodes and mounted read owners close
before the first physical write. Each write must report exact completion; a real
barrier follows all writes before success. An attempted write failure, short or
oversized completion, or barrier failure permanently poisons the owner. Further
operations return I/O failure without callbacks; close only releases memory and
ownership. Completed bytes after failure describe an exact written prefix, not
durability. Whole-range atomicity is not promised. Prewrite failures leave the
device unchanged and permit retry. Optional read-cache allocation refusal may
retain success through the existing uncached path.

The private POSIX transport opens an existing writable regular image only. It
refuses devices, symlinks, hardlinks and read-only captures; it never creates,
truncates or changes image modes. `flock` excludes cooperating owners, while the
caller must exclude uncooperative users and mappings. Persistence uses `fsync` and,
on macOS, mandatory `F_FULLFSYNC` without a cache-only fallback. This is a regular
file backend and does not establish writable FSKit block-resource durability or
native filesystem authorization.

The experimental command is:

```sh
ntfs-overwrite PRIVATE_WRITABLE_IMAGE /absolute/path DECIMAL_OFFSET REGULAR_INPUT
```

Original captures must remain read-only. Prepare a separately owned writable
copy before using the tool; the input must be a bounded regular file. Its JSON
reports admission, requested/completed/physical bytes, writes, barrier completion
and poisoning. It never reports FSKit write admission or metadata recovery.

## Actual acceptance

Eight independently authored complete images exercise ordinary admission,
hibernation, native nonquiet and mutating histories, dirty volume flags,
overlapping allocation, read-only files and uninitialized ranges. The C owner
tests cover every 256 admission allocation and 193 read boundaries with partial
and full failed read callbacks, all 34 range allocation and ten range read
boundaries, clean retry, exclusive-claim refusal, argument overlap and malformed
environments. Four optional record-cache refusals preserve exact successful writes.
Both 512-byte and 4096-byte fragmented read/modify/write preserve every byte
outside the requested range. Write failures, partial/success-short and oversized
callbacks and failed barriers poison the owner; further lookup/write/close produce
no device I/O. All 169 fatal ASan/UBSan suites, formatting and 32 freestanding
objects on each architecture pass under the 2-KiB frame limit.

The original locked plaintext Windows capture stays read-only. A fresh private
clone received 8193 deterministic bytes at file offset 3997 in `initialized.bin`.
The driver performed one aligned 8704-byte write and the real regular-file
persistence barrier. Independent native boot/MFT/run decoding and full-volume byte
comparison prove that only those file-content bytes changed. Complete validation
still checks all 256 MFT slots, 7620 claimed/allocated clusters, zero unclaimed
clusters and four mirror records. A full-disk candidate preserves the original GPT
and every non-target byte; standalone qcow2 check and exact conversion comparison
pass before boot.

The dedicated Windows VM cold-boots that candidate. Native reading matches the
new complete file hash and the three unchanged files plus named ADS. Native file
identity and ACL observation succeed, and read-only `chkdsk` finds no problems.
The original disposable disk is restored with an identical digest and the baseline
boot/partition/Guest Agent are verified; the post-Windows candidate is retained.
Review `artifacts/overwrite/{full-core-20261006,native-private-20261006,
native-full-disk-20261006,windows-roundtrip-20261006}/`. Original failed compilation,
test-oracle and launcher attempts remain in adjacent evidence directories.

This qualifies the successful metadata-preserving offline-image path and its
injected callback failures. It does not qualify a hardware power interruption,
metadata WAL/replay, allocation/resize/namespace mutation, timestamps, Windows
access enforcement or writable installed FSKit behavior. Those remain required
for the user's complete driver-writing scope.
