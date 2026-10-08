# Discretionary access evaluation

`ntfs/access.h` is a freestanding, allocation-free DACL decision layer. It accepts
original self-relative descriptor bytes and an immutable caller-owned token.
`ntfs_security_evaluate_dacl` evaluates the same contract directly against an
original storage snapshot without copying or reading the device. These APIs do
not authenticate a principal or replace the owning native authorization layer.
An allowed discretionary result is only one part of a complete access decision.

The token contains a user SID, attributed groups and a separate restricting list.
Extraction from an authenticated native principal and Windows-to-macOS mapping
remain owning-adapter work. Do not substitute the mount owner or UID zero for a
Windows identity. The explicitly selected FSKit
[extraction mode](NATIVE-ACCESS.md) has not adopted this evaluator and does not
enforce Windows ACLs. Its native presentation IDs are process snapshots, not
an authenticated mount initiator or a Windows-to-native mapping.

The independent [AccessCheck observation pipeline](ACCESS-ORACLE.md) captures
Windows token fields and original descriptors, then compares decisions offline.
The first complete hosted capture contains 144 native decisions. Its original
comparison exposes six zero-request mismatches, one in each token context;
unsupported probes and mandatory/privilege boundaries remain explicit gaps.

## Implemented decision contract

The evaluator validates the complete descriptor before evaluating access. Owner
and group SIDs are required at this layer, even though the byte-framing decoder
permits their absence. This follows the documented
[AccessCheck descriptor requirement](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
All applicable DACL entries undergo a feature/mask check before an earlier allow
can cause a decision. Invalid later framing cannot become a successful grant.

Generic file and directory requests map to named specific and standard rights.
READ and WRITE both include SYNCHRONIZE; a concrete FILE_GENERIC_WRITE deny can
therefore deny a generic READ request. Request mapping preserves unknown bits
until explicit validation rather than discarding them. See
[file access rights and mappings](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

Stored ACE masks are evaluated as concrete rights. An applicable ACE containing
generic bits returns UNSUPPORTED, including mixed masks, a nonmatching trustee,
zero-right requests and entries after a sufficient allow. This is the supported
feature boundary; it does not emulate Windows' treatment of every unusual stored
mask. Generic bits in an inherit-only entry remain nonapplicable while its byte
framing is validated. Original descriptor/ACE snapshots preserve these bits.
Microsoft distinguishes request mapping from stored-ACE interpretation in
[MS-DTYP's access mask contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b).
The preceding implementation incorrectly mapped stored masks and could grant
concrete access from a generic ACE. The retained local evaluator reproduces that
behavior under `artifacts/stored-mask-before/`; current checks reject it.

For supported exact masks, entries retain original storage order. Applicable
allow entries satisfy only still-pending rights; an applicable deny fails if it
intersects those pending rights. Denied or unsatisfied requests produce no partial
granted mask. A sufficient allow preceding a deny can succeed; sorting the DACL
would change that result. INHERIT_ONLY entries do not apply to the current
object. Inherited entries that are not inherit-only remain active. This evaluates
the stored effective DACL; it does not synthesize inheritance or modify metadata.
See [ordered DACL checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object).

| Token membership | Allow ACE | Deny ACE | Ownership |
| --- | --- | --- | --- |
| Ordinary user | Matches | Matches | Qualifies if it equals the owner |
| Deny-only user | Ignored | Matches | Does not qualify |
| Enabled group | Matches | Matches | Requires the additional OWNER attribute |
| Disabled group | Ignored | Ignored | Does not qualify |
| Deny-only group | Ignored | Matches | Does not qualify |
| Restricting SID | Used in the separate second check | Used in the separate second check | Restricted-owner interactions below remain unqualified |

ENABLED_BY_DEFAULT alone does not enable a group. Contradictory ENABLED and
DENY_ONLY attributes are invalid. Integrity group attributes are unsupported in
this token contract and require a separate mandatory-integrity context. These
rules derive from [token group attributes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups)
and [SID attributes](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token).

A restricted token must satisfy the same request in both ordinary and restricting
contexts. Restricting SIDs do not augment ordinary membership. `restricted=true`
with an empty list retains an empty second context; it never silently becomes an
unrestricted token. The two contexts share one comparison budget. Duplicate
restricting SIDs are allowed. See
[restricted-token checks](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

Absent and NULL DACLs impose no discretionary restriction; an empty DACL provides
no ACE grant. A qualifying ordinary owner implicitly receives READ_CONTROL and
WRITE_DAC, not FILE_READ_DATA or WRITE_OWNER. Active OWNER RIGHTS (S-1-3-4) entries
suppress those implicit rights and match the current qualifying owner. An
inherit-only OWNER RIGHTS entry does not apply to this object. See
[access-check overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9)
and [OWNER RIGHTS identity](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

## Error, ownership and resource contract

`NTFS_OK` means a valid discretionary decision; `allowed=false` is a denial with
`granted=0`. An allowed result returns exactly the nonzero mapped requested mask.
An original zero-right request is a valid denial, after complete descriptor and
feature validation. It is distinct from a nonzero owner-control request whose
remaining mask becomes zero through implied rights. Errors zero the entire decision. Unsupported
features are errors, not valid denials or successful unsupported-feature support.
The decision reports the aggregate SID comparison count for successful evaluation,
including a valid denial. There are no partial grants on budget exhaustion.

Each token vector is capped at 1,024 SIDs, separate from the user SID. SID
authorities fit their six-byte format and counts fit 15 subauthorities. Defaults
permit 262,144 aggregate SID comparisons; per-call limits can decrease that
budget or increase it up to the hard ceiling of 1,048,576. Each comparison checks
at most 15 subauthorities. Owner detection and both token contexts consume the
same budget, with RANGE on exhaustion. Input counts are checked before walking
their arrays, including SIZE_MAX cases.

Descriptor bytes retain the 1-MiB framing cap. Each ACL has its existing 16-bit
wire size and checked ACE spans. Validation and evaluation use a constant number
of bounded scans and constant stack storage; they allocate nothing and perform
no I/O. The core continues to compile with a 2-KiB per-frame limit. Input data and
output storage must not overlap, and input bytes/context stay immutable for the
operation. Storage snapshots retain their existing volume-child lifetime and
serialization requirements. This does not enable concurrent volume operations.

## Explicit remaining authorization work

Applicable object, callback, conditional, audit or unknown DACL ACEs return
UNSUPPORTED even when a simpler earlier allow would suffice or a trustee would
not match. Stored generic and unknown access bits/attributes also fail explicitly.
Nonapplicable inherit-only entries retain framing validation but do not participate
in the feature policy. MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY are unsupported.

Restricted-token ownership with implicit READ_CONTROL/WRITE_DAC or active OWNER
RIGHTS returns UNSUPPORTED. The detailed interaction needs independent Windows
observations before those combinations can grant access; it is not inferred from
the general two-check overview. Implement and qualify it against AccessCheck.
Write-restricted token contexts also need an explicit separate contract.

SACL byte framing is validated, but this API deliberately makes no SACL decision.
Mandatory integrity, resource claims/conditional ACEs, central policy, privileges,
audit, principal-self/object-type substitution and maximum-access evaluation
remain separate work. Parent DELETE_CHILD alternatives, traversal privileges,
handle/open retention and native operation authorization must be implemented by
the layer that owns those operations. Read-only mutation rejection is independent
of a discretionary mask calculation.

## Evidence

The local suite evaluates 197,201 decisions, including 196,608 comparisons with
an independently implemented per-right first-decisive-ACE oracle. Its ordered
vectors cover enabled/disabled/deny-only groups, ordinary and restricting contexts,
inherit-only entries, accumulating grants and denies before/after grants. Separate
vectors cover ownership, OWNER RIGHTS, generic mappings, absent/NULL/empty ACLs,
all 15 SID subauthorities, six-byte authorities, unsupported features, complete
later-entry validation, output zeroing and aggregate limits. A valid high-integrity
SACL vector demonstrates the DACL-only boundary, not integrity enforcement.

Of these decisions, 392 independently authored stored-mask policy verdicts cover
all four generic families, allow/deny entries, matching/unmatched trustees,
ordinary/owner/restricting contexts and zero/concrete/generic/control requests.
Raw and mixed masks follow a sufficient concrete grant; input bytes remain
unchanged and errors zero the entire result. Inherit-only controls retain their
concrete grants. The transport/SDK/token/cleanup/reporting suite passes 425 checks.

Six identical retained local pre/post-fix packets under
`artifacts/stored-mask-{before,after}/` reproduce the former stored-mask behavior.
Four applicable generic-mask cases now return UNSUPPORTED with zero decisions;
the generic-request and inherit-only controls remain exactly equal. This is local
regression evidence, not a Windows AccessCheck observation.

Storage tests evaluate snapshots after node close with the next allocation/read
forced to fail, preserving exact no-I/O/no-allocation access. The genuine checksum
collision case has a different owner but the same allow trustee, so ownership
does not accidentally imply data-read permission. The earlier incorrect owner-read
test expectation remains recorded in the failed focused log.

`tests/fuzz_access.c` has a separate bounded descriptor/token envelope and tests
deterministic decisions, exact grants, budget bounds and zero errors. The bounded
campaign and all core/component/source-build results are recorded in ACCEPTANCE.md.
The [first hosted AccessCheck run](https://github.com/machlin-project/ntfs/actions/runs/37854379914)
captures 144 original decisions using six queried Windows token contexts. Windows
denies all six original zero-mask requests against an empty DACL; the preceding
core instead reports allowed with zero granted rights. The correction retains
complete descriptor/ACE validation and denies an original zero request. The v2
native matrix adds NULL, absent, allow, deny, owner and OWNER RIGHTS zero-mask
controls; those additional observations remain pending. The verifier still
accepts the unchanged v1 matrix, preserving replay of the exact first failure.
Installed FSKit authorization and commercial-security qualification remain open.
