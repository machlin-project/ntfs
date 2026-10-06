# Native ordinary-file journal continuation

The implementation now includes a private owning C writer for initialized data,
modified/changed times and the archive bit, and a private native redo/compensation
recovery executor. Both execute real persistence on offline Windows-source clones.
They do not yet admit a writable FSKit product. The immutable environment has no
write method; the public data-only owner keeps its narrower
[DATA-OVERWRITE.md](DATA-OVERWRITE.md) contract.

The Windows-authored source is the retained, unencrypted, clean test volume in
`artifacts/windows-write-vm/native-write-alias-20261006/`. Complete allocation,
metadata, directory and mirror validation succeeds. Experiments use private copies
of that disposable disk. No source flags are cleared and no repair is requested.
Native finally reports, boot events and frozen inactive images retain failures
and successes separately.

The qualified update family binds the physical open-attribute key for `$MFT`:

1. `OpenNonresidentAttribute` binds the sequence-bearing MFT reference and unnamed
   DATA attribute. Its observed modern entry supplies the wire layout; generated
   live name pointers are zero.
2. `InitializeFileRecordSegment` retains the complete restored FILE used region
   before mutation. The MFT VCN, LCN and sector index bind its home location and
   supply reconstruction when home USA protection is torn.
3. `UpdateResidentValue` carries redo and undo for standard information. It changes
   modified/changed times and sets the archive bit, preserving creation/access
   times, security fields, stream mapping and names.
4. The exact observed `ForgetTransaction`/compensation marker closes a confirmed
   family. Other operations and arbitrary Forget markers do not imply commit.
5. A loser instead receives a native `UpdateResidentValue` compensation record
   followed by its exact Forget marker before its FILE undo is published.

The original experiment without MFT binding retained the old time and requested
a full check at boot. Adding the observed binding produced the expected time,
unchanged content and healthy NTFS events. Four complete/torn-home experiments
then passed Windows redo/undo, original file hashes/ADS/identity/ACL and read-only
chkdsk. Seven separate prepare/commit/checkpoint experiments passed six states;
`checkpoint-before-restart-publication` failed initial boot health despite later
healthy events and chkdsk. That complete checkpoint protocol remains disqualified.
Three further diagnostic variants did not close the failure.

Ten C-authored frames subsequently passed three actual Windows states: an
uncommitted torn FILE selected the old time, a committed torn FILE selected the
new time, and complete clean publication selected the new time. All three passed
content, ADS, identity/ACL, chkdsk and healthy this-boot events. Exact original
restoration and an actual baseline boot were verified after that batch. These are
constructed sector-boundary states, not observed hardware power cuts.

An inactive post-Windows image from the uncommitted C case supplies an original
native compensation witness. Its redo bytes equal the original update's undo;
its previous/undo-next links and final Forget bind the same lifetime. Native
compensation declares inactive undo bytes at the body endpoint without storing
them. The decoder preserves that declared count separately and returns an empty
safe undo span; arbitrary out-of-bounds updates remain corrupt. This qualifies
that wire form, not the new recovery executor's Windows acceptance.

The private history owner retains the quiet origin plus at most 64 exact
prepared, committed or compensated transaction families. It resolves completed
tail copies and the endpoint independently of RSTR CurrentLsn, checks every
packet and same-file predecessor, and refuses unknown operations, stale state,
empty-checkpoint advancement, circular wrap and log growth. A narrowly owned
flag-only RSTR conflict chooses the dirty copy; the public read-only selection
still rejects conflicts. `$UsnJrnl`, hibernation and unsupported volume/file
features prevent write admission.

The writer reserves all storage and exact aligned data spans before mutation,
performs complete fresh validation including the planned FILE overlay, and closes
immutable children. It publishes dirty RSTR copies, prepare tail copy/home, data,
commit tail copy/home, complete MFT-cluster RMW, then clean RSTR copies retaining
original client roots. Each boundary has a real persistence barrier. It writes
no empty checkpoint and does not discard retained history. Guarded USA sequences
exclude every actual old sector tail and plausible old USA marker. Failed or
uncertain writes/barriers poison the owner; execution allocates and reads nothing.
Data transfers do not promise atomic rollback of user data.

The recovery owner first captures complete owned history, reconstructs log homes
and latest FILE images, verifies physical disjointness and validates the complete
reconstructed volume. Callers close the immutable volume before execution. It
repairs tail-copy-backed homes before recycling a copy slot. For a loser it
persists compensation copy/home before FILE undo; confirmed and previously
compensated families are redone. It then publishes retained clean roots. Recovery
and interrupted recovery use the same permanent poison contract. A settled reopen
performs no writes and one real persistence barrier. Arbitrary native transaction
families and general checkpoint/truncation remain outside this bounded contract.

All 174 fatal ASan/UBSan suites, selected-Xcode style and both freestanding targets
under the 2-KiB frame ceiling pass. Independent complete FILE/page goldens cover
metadata planning, tail copies, compensation and retained roots. The writer tests
110 write/barrier interruption profiles through actual C recovery. A further 120
profiles interrupt recovery itself, restart it and verify fresh full validation,
whole-image preservation, expected winner/loser FILE bytes and idempotence. Two
settled appends and private owner reopen also pass; the public quiet-only owner
continues to refuse retained transaction history.

Actual `pwrite`/`fsync`/`F_FULLFSYNC` changes 8193 initialized bytes and timestamps
on a private source clone. Every partition/GPT-disk byte agrees with an independent
expected image and full allocation validation passes. Two additional original
C-authored pending source clones execute redo and compensation with real I/O;
complete image comparisons pass and a second recovery writes nothing. Qcow2
conversion, structural checks and comparison pass; source images remain frozen
and unchanged. These new candidates have not booted in Windows. VM access became
unobservable during a later diagnostic batch; an unobserved start or empty QGA
response is not a boot-health pass. The active VM disk is not edited while open.

Next acceptance must qualify the new tail-copy/retained-root writer and recovery
at every publication boundary in Windows, then admit an authorized FSKit
persistence route and coherent metadata lifetimes. Writable FSKit, allocation,
resize and namespace mutations remain under implementation. Boot stills do not
establish continuous video; unavailable event-provider queries remain unavailable.

Evidence is retained under `artifacts/overwrite/`, including
`windows-C-wal-probes-20261006/`, `native-compensation-witness-20261006/`,
`write-existing-native-io-20261006/`, `write-recovery-native-io-20261006/` and
`write-recovery-full-20261006/`. Failed attempts remain separate from later passes.
