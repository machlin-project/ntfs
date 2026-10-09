# Exact DACL storage replacement

The private [descriptor editor](../core/security_edit.h) implements one pure
storage operation: replace an original self-relative descriptor's DACL with the
explicit DACL from a second self-relative descriptor. Both complete descriptors
pass the existing [security decoder](../core/security.c). A donor descriptor
keeps the shared ACL/SID/ACE validation in one place and encodes all four ACL
states without an invented raw-ACL convention.

This is an original, allocation-free C implementation and independently authored
test corpus. No external security or filesystem implementation is imported.

## Input and preservation contract

The donor supplies its exact DACL bytes and these five control flags:

| Flag | Stored value |
| --- | --- |
| DACL present | `0x0004` |
| DACL defaulted | `0x0008` |
| DACL auto-inherit request | `0x0100` |
| DACL auto-inherited | `0x0400` |
| DACL protected | `0x1000` |

All remaining control bits, including unassigned bits admitted by the decoder,
come from the original. The original revision, resource-manager byte, owner SID,
group SID and complete SACL are preserved. The donor's owner, group, SACL and
resource-manager byte are not selected, but their framing is still validated.
Malformed old DACLs also refuse even though replacement would discard them.

Absent DACL means present clear and zero offset. NULL means present set and zero
offset. Empty means a stored ACL with zero ACEs; populated means a stored ACL
with at least one ACE. Replacement never collapses these states. In particular,
an explicitly absent donor requests removal of the stored DACL, rather than
leaving the original DACL unchanged. The caller owns that choice and its policy.

The complete declared ACL extent is copied, including free space after its ACEs.
ACE order, generic masks, inheritance flags, callback application data, known ACE
padding and decoder-admitted unknown ACE bodies stay byte-exact. Unknown ACE
types receive framing validation only; this is no claim about their semantics.
Known object ACEs with unsupported object flags still return `NTFS_UNSUPPORTED`;
the editor never turns a rejected known form into an opaque accepted form.

## Layout, bounds and publication

Output stores the fixed header followed by owner, group, SACL and DACL, omitting
absent byte components. Every component starts at a DWORD offset. New alignment
padding is zero. Source gaps and trailing descriptor storage are discarded;
exact or partial component aliases admitted by the existing decoder become
independent copies. Input component order and alignment do not add restrictions
beyond that decoder. Equal inputs are therefore not a promise of identical
whole-descriptor storage; preserved component bytes and states are the contract.

Each input is bounded by `NTFS_SECURITY_MAX_BYTES` (1 MiB). Each ACL's 16-bit size
and the minimum four-byte ACE header further bound iteration to at most 16,381
entries per ACL. Full descriptor validation examines both ACLs in each input,
including donor components that are not copied. The maximum repacked output is
131,227 bytes: a 20-byte header, two 68-byte SIDs, two 65,535-byte ACLs and one
alignment byte. This bound follows the admitted wire widths, not an allocator.

Measurement and encoding share complete validation and checked layout arithmetic.
They use constant stack space without callbacks, allocation or I/O. There is no
allocation-failure path. Callers supply accessible immutable inputs and accessible
output storage. Address-range checks reject arithmetic wrap and overlapping
outputs; they cannot prove the underlying memory is mapped.

The inputs may overlap each other. Output capacity and the size-output slot must
be disjoint from the input structure, both complete input ranges, and each other.
That rule covers unused input tails and unused output capacity. Every failure
preserves both outputs; a capacity shortage returns `NTFS_RANGE` without
publishing the required size. Call measurement to obtain it. Once encoding starts
writing, all potentially failing checks have completed. Success changes only
the returned byte extent and size-output slot.

## Verification and remaining ownership

The [independent regression](../tests/security_edit.c) contains a literal expected
descriptor and a separate raw-component oracle. It covers all original/donor
DACL states, all original SACL states, individual control bits, every truncated
literal prefix, single-bit mutations, component/input/output aliases, unsupported
known object flags, exact-capacity minus/plus one, maximum SID/ACL sizes, maximum
framed ACE counts and over-budget input rejection. Opaque/callback bytes and ACL
free space are explicit preservation cases. Build results are recorded by the
owning cloud qualification rather than inferred from the presence of these tests.

The existing [security fuzzer](../tests/fuzz_structures.c) retains its original
raw descriptor input framing and all descriptor/ACE/SID decoder calls. Each
admitted descriptor additionally receives independently authored absent, NULL,
empty and one-ACE donor descriptors, then its own fuzzed DACL. An independent
raw-component oracle checks preserved bytes and control flags. Whole-input copies,
guard bytes, deliberately unaligned output, exact/short capacities and unchanged
error outputs cover publication. Invalid original descriptors also check error
output preservation. No new fuzzer target or relaxed input limit is introduced.

The [seed author](../scripts/fuzz_seeds.py) adds opaque-SACL/free-space and shared
component inputs while preserving earlier packets. Local focused tests pass
the editor and existing security decoder under ASan/UBSan. The core editor also
passes strict GCC freestanding compilation with the 2-KiB stack-frame limit.
All twelve security seeds pass their standalone 512-mutation runs; all 24 new
Access variants generated from the two descriptors pass their own standalone
harness. These are bounded synthetic checks. Clang/libFuzzer campaign and native
filesystem qualification remain distinct evidence recorded by the owning run.

This operation does not run Windows inheritance, reorder ACEs, substitute creator
SIDs, map native identities, evaluate access, grant privileges or emulate
`SetSecurityInfo`. Flags that request inheritance remain exact storage flags;
no inheritance is performed. Shared `$Secure` hash/deduplication, security ID
allocation, both SDS copies, SII/SDH insertion, FILE updates, journal/recovery and
native authorization are separate owning contracts. The ordinary writer and
FSKit admission remain unchanged. Native setter and recovery verdicts are open.

## Primary format sources

- Microsoft [MS-DTYP SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
  specifies offset-based self-relative storage and arbitrary component order.
- Microsoft [absolute and self-relative descriptors](https://learn.microsoft.com/en-us/windows/win32/secauthz/absolute-and-self-relative-security-descriptors)
  describes the contiguous storage representation and the distinction from host pointers.
- Microsoft [SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control)
  identifies the copied DACL flags and the independent SACL/owner/group flags.
- Microsoft [MS-DTYP ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
  specifies ACL/ACE framing and the distinction between framing and semantic use.
- Microsoft [ACL structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl)
  specifies that declared ACL size includes potential free space and that ACLs
  and ACEs start on DWORD boundaries in the native representation.

These published fields justify the storage contract. They do not establish
Windows filesystem setter side effects or durable shared-store mutation.
