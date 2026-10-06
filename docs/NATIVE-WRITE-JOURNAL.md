# Native ordinary-file journal continuation

The native experiments establish one bounded metadata family for an existing
ordinary initialized nonresident file. They do not yet admit a writable product.
`core/write_metadata.c` prepares private FILE snapshots;
`core/write_journal.c` reserves and serializes separate native log pages without
device I/O. The immutable API and FSKit mutation refusal remain intact.

The Windows-authored source is the retained, unencrypted, clean test volume in
`artifacts/windows-write-vm/native-write-alias-20261006/`. Whole allocation,
metadata, directory and mirror validation succeeds. Experiments use independently
authored private copies of that disposable disk. No source flags are cleared, no
native repair is requested, and the original VM disk is restored exactly after
each bounded batch. Native finally reports, boot events and inactive frozen images
retain failures as well as successes.

The qualified update family uses the physical open-attribute key for `$MFT`:

1. `OpenNonresidentAttribute` binds the sequence-bearing MFT reference and unnamed
   DATA attribute to the native open-attribute key. Its original modern entry
   supplies the wire layout; live name pointers are zero in generated entries.
2. `InitializeFileRecordSegment` stores the complete restored FILE used region
   before mutation. The MFT VCN, LCN and sector index bind the target. This native
   snapshot supplies recovery when the home FILE's USA protection is torn.
3. `UpdateResidentValue` stores redo and undo for the standard-information region.
   The C preparation updates modified and changed times and sets the archive bit,
   preserving creation/access times, security fields, stream mapping and names.
4. The observed native `ForgetTransaction`/compensation marker closes this exact
   mutation family. This is not a global rule that every Forget implies commit.
   Other operations, flag meanings and native transaction families remain refused.

The original failed experiment omitted the MFT binding: Windows did not publish
the expected time, and boot events requested a full check. Adding the independently
observed binding produced the expected time with unchanged content and healthy
NTFS events. Four further snapshot experiments passed actual Windows recovery:
confirmed transactions restore the new time with untouched or torn home storage;
unconfirmed transactions restore the original time with already-written or torn
home storage. All four retained original hashes, ADS, file identity and ACL and
passed read-only chkdsk. These are deliberately constructed sector-boundary
interruption states, not observed hardware power cuts.

Seven separate-page experiments then tested prepare, commit and checkpoint
publication. Six passed the expected time, content/ADS/identity/ACL, chkdsk and
healthy this-boot NTFS events. In particular, a separate durable commit page was
recovered with the original home metadata and the old RSTR endpoint. The
`checkpoint-before-restart-publication` state failed: Windows first requested a
full offline check, even though its later native verifier and chkdsk passed. That
failure disqualifies the complete proposed persistence sequence. Later healthy
events do not convert it into a pass. Its original candidate and post-boot image
remain retained for diagnosis.

The C planner currently reproduces private prepare, commit, empty checkpoint and
restart frames for these experiments. Ring wrap and log growth return explicit
refusals. It advances USA again for clean restart publication, so sector mixtures
between its dirty and clean versions cannot pass protection using a reused
sequence. The empty checkpoint extension is admitted only by its exact observed
opaque prefix and quiet last-word binding; this does not interpret arbitrary
native checkpoint extensions. Physical mappings, full current-history ownership,
exclusive resources and real barriers belong to the eventual owning writer.

`write-metadata` compares 23 independently authored complete FILE/address/admission
profiles, required allocation and partial/full read failures, zero outputs, retry,
pointer/geometry guards and compound work admission. `write-journal` compares ten
independent complete FILE/page goldens, stale/binding/profile refusals, bounded
reservations, retry, immutable source and every mixed restart-sector boundary.
These private helpers allocate or write no device storage; they do not replace
native recovery or durability acceptance.

Next work must close the intermediate checkpoint failure, execute the owning C
redo/undo recovery with complete validation before mutation, qualify each write
and barrier interruption, and then provide an authorized FSKit persistence route
and coherent metadata lifetimes. Timestamped file writes and writable FSKit remain
unimplemented while those gates are open. The experimental data-only overwrite
owner keeps its separate narrower contract in [DATA-OVERWRITE.md](DATA-OVERWRITE.md).

Evidence is retained under `artifacts/overwrite/` in the native history, binding,
snapshot and pipeline directories, with C focused/full-suite and native-plan
reports kept separately. Boot screenshot coverage consists of stills, not
continuous video. Failed Wininit/Chkdsk provider queries are retained as unavailable
evidence; their absence is never inferred.
